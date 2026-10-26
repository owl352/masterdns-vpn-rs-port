//! Session-bound extension negotiation and wire integration.
use crate::session::SessionRecord;
use crate::Server;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use vpnproto::{TransportCaps, TransportEnvelope, TransportFeedback};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Legacy,
    Offered,
    Prepared,
    Active,
}
pub(crate) struct SessionTransport {
    pub phase: Phase,
    pub offer: Option<TransportCaps>,
    pub selected: Option<TransportCaps>,
    pub deadline: Option<Instant>,
    pub used_ids: BTreeSet<u16>,
    pub remote_eofs: BTreeMap<u16, u32>,
    pub envelope_logged: bool,
}
impl Default for SessionTransport {
    fn default() -> Self {
        Self {
            phase: Phase::Offered,
            offer: None,
            selected: None,
            deadline: None,
            used_ids: BTreeSet::new(),
            remote_eofs: BTreeMap::new(),
            envelope_logged: false,
        }
    }
}
impl SessionTransport {
    pub fn expire(&mut self, now: Instant) {
        if self.phase != Phase::Active && self.deadline.is_some_and(|at| now >= at) {
            self.phase = Phase::Legacy;
        }
    }
    fn same(a: TransportCaps, b: TransportCaps) -> bool {
        a.features == b.features
            && a.nonce == b.nonce
            && a.feedback_budget == b.feedback_budget
            && a.serial_span == b.serial_span
    }
    pub fn caps(&mut self, c: TransportCaps, now: Instant) -> Option<(TransportCaps, bool)> {
        self.expire(now);
        if self.phase == Phase::Legacy {
            return None;
        }
        let offer = self.offer?;
        if c.nonce != offer.nonce
            || c.features & !vpnproto::TRANSPORT_FEATURE_DATAGRAM != vpnproto::TRANSPORT_FEATURES
            || c.features & !offer.features != 0
            || c.feedback_budget > offer.feedback_budget
            || c.serial_span > offer.serial_span
        {
            return None;
        }
        match c.op {
            vpnproto::TRANSPORT_SELECT => {
                if let Some(selected) = self.selected {
                    if !Self::same(c, selected) {
                        return None;
                    }
                } else {
                    if self.phase != Phase::Offered {
                        return None;
                    }
                    self.selected = Some(c);
                    self.phase = Phase::Prepared;
                }
                Some((
                    TransportCaps {
                        op: vpnproto::TRANSPORT_SELECTED,
                        ..self.selected.unwrap()
                    },
                    false,
                ))
            }
            vpnproto::TRANSPORT_COMMIT => {
                let selected = self.selected?;
                if !Self::same(c, selected) {
                    return None;
                }
                let activated = self.phase == Phase::Prepared;
                if self.phase != Phase::Prepared && self.phase != Phase::Active {
                    return None;
                }
                self.phase = Phase::Active;
                self.deadline = None;
                Some((
                    TransportCaps {
                        op: vpnproto::TRANSPORT_COMMITTED,
                        ..selected
                    },
                    activated,
                ))
            }
            _ => None,
        }
    }
}
impl SessionRecord {
    pub(crate) fn transport_caps(&self) -> Option<TransportCaps> {
        let mut t = self.transport.lock().unwrap();
        t.expire(Instant::now());
        matches!(t.phase, Phase::Prepared | Phase::Active)
            .then_some(t.selected)
            .flatten()
    }
    pub(crate) fn transport_active(&self) -> bool {
        self.transport.lock().unwrap().phase == Phase::Active
    }
    /// Whether this session selected unreliable UDP datagrams.
    pub(crate) fn datagrams_active(&self) -> bool {
        let t = self.transport.lock().unwrap();
        t.phase == Phase::Active && t.selected.is_some_and(|c| c.features & vpnproto::TRANSPORT_FEATURE_DATAGRAM != 0)
    }
    pub(crate) fn prepare_transport_offer(&self, span: u16, datagrams: bool) -> Option<TransportCaps> {
        let mut t = self.transport.lock().unwrap();
        t.expire(Instant::now());
        if t.phase == Phase::Legacy {
            return None;
        }
        if let Some(c) = t.offer {
            return Some(c);
        }
        let capacity = self.upload_mtu.min(self.download_mtu);
        if self.download_mtu < 40 || capacity < 26 || span == 0 {
            t.phase = Phase::Legacy;
            return None;
        }
        let c = TransportCaps {
            op: 1,
            features: vpnproto::TRANSPORT_FEATURES | if datagrams { vpnproto::TRANSPORT_FEATURE_DATAGRAM } else { 0 },
            nonce: rand::random(),
            feedback_budget: capacity,
            serial_span: span.min(16_384),
        };
        t.offer = Some(c);
        t.deadline = Some(Instant::now() + Duration::from_secs(5));
        Some(c)
    }
    pub(crate) fn commit_extended_request(&self) -> bool {
        let mut t = self.transport.lock().unwrap();
        t.expire(Instant::now());
        if t.phase == Phase::Prepared {
            t.phase = Phase::Active;
            t.deadline = None;
            true
        } else {
            false
        }
    }
}
fn arq_ranges(r: &[vpnproto::FeedbackRange]) -> Vec<arq::LogicalRange> {
    r.iter()
        .map(|r| arq::LogicalRange {
            offset: r.offset,
            length: r.length,
        })
        .collect()
}
impl Server {
    pub(crate) fn handle_transport_packet(
        &self,
        p: &vpnproto::Packet,
        now: Instant,
    ) -> Option<bool> {
        if p.packet_type == enums::PACKET_STREAM_CLOSE_READ && p.stream_id != 0 {
            let record = self.sessions.get(p.session_id)?;
            if !record.transport_active() {
                return None;
            }
            let Ok(end) = vpnproto::decode_transport_eof(&p.payload) else {
                return Some(false);
            };
            if let Some(stream) = record.get_stream(p.stream_id) {
                let Some(a) = stream.arq() else {
                    return Some(false);
                };
                if !a.receive_logical_eof(end) {
                    return Some(false);
                }
                record
                    .transport
                    .lock()
                    .unwrap()
                    .remote_eofs
                    .insert(p.stream_id, end);
                // A valid EOF can finalize ARQ immediately. Keep its ACK in
                // the session orphan lane so stream queue cleanup cannot erase it.
                record.enqueue_orphan_reset(
                    enums::PACKET_STREAM_CLOSE_READ_ACK,
                    p.stream_id,
                    p.sequence_num,
                );
            } else {
                if record
                    .transport
                    .lock()
                    .unwrap()
                    .remote_eofs
                    .get(&p.stream_id)
                    != Some(&end)
                {
                    return Some(false);
                }
                record.enqueue_orphan_reset(
                    enums::PACKET_STREAM_CLOSE_READ_ACK,
                    p.stream_id,
                    p.sequence_num,
                );
            }
            return Some(true);
        }
        if !matches!(
            p.packet_type,
            enums::PACKET_TRANSPORT_CAPS
                | enums::PACKET_TRANSPORT_CAPS_ACK
                | enums::PACKET_STREAM_FEEDBACK
                | enums::PACKET_STREAM_ENVELOPE
        ) {
            return None;
        }
        let Some(record) = self.sessions.get(p.session_id) else {
            return Some(false);
        };
        if p.packet_type == enums::PACKET_TRANSPORT_CAPS {
            let Ok(c) = TransportCaps::decode(&p.payload) else {
                return Some(false);
            };
            let decision = record.transport.lock().unwrap().caps(c, now);
            let Some((reply, activated)) = decision else {
                return Some(false);
            };
            if activated {
                self.log.infof("Transport extension v1 activated");
            }
            let response = vpnproto::Packet {
                packet_type: enums::PACKET_TRANSPORT_CAPS_ACK,
                payload: reply.encode().unwrap(),
                ..Default::default()
            };
            record.orphan_queue.push(
                enums::PACKET_PRIORITY_CRITICAL,
                enums::packet_identity_key(0, response.packet_type, reply.op as u16, 0),
                response,
            );
            return Some(true);
        }
        if p.packet_type == enums::PACKET_TRANSPORT_CAPS_ACK {
            return Some(false);
        }
        let Some(c) = record.transport_caps() else {
            return Some(false);
        };
        if p.packet_type == enums::PACKET_STREAM_FEEDBACK {
            let Ok(f) = TransportFeedback::decode(&p.payload, c.feedback_budget, c.serial_span)
            else {
                return Some(false);
            };
            if !self.validate_transport_feedback(&record, &f) {
                return Some(false);
            }
            if record.commit_extended_request() {
                self.log.infof("Transport extension v1 activated");
            }
            self.apply_transport_feedback(&record, &f);
            return Some(true);
        }
        // Outer compression must be OFF: inner payload was already prepared.
        if p.compression_type != compression::TYPE_OFF
            || p.stream_id == 0
            || p.payload.len() > record.upload_mtu as usize
        {
            return Some(false);
        }
        let Ok(e) =
            TransportEnvelope::decode(&p.payload, p.sequence_num, c.feedback_budget, c.serial_span)
        else {
            return Some(false);
        };
        let Some(stream) = record.get_stream(p.stream_id) else {
            return Some(false);
        };
        let Some(arq) = stream.arq() else {
            return Some(false);
        };
        if !arq.validate_logical_receive(e.logical_seq) {
            return Some(false);
        }
        if e.feedback
            .as_ref()
            .is_some_and(|f| !self.validate_transport_feedback(&record, f))
        {
            return Some(false);
        }
        let Ok(data) = e.inflate_data_bounded(record.upload_mtu as usize) else {
            return Some(false);
        };
        if record.commit_extended_request() {
            self.log.infof("Transport extension v1 activated");
        }
        if let Some(f) = &e.feedback {
            self.apply_transport_feedback(&record, f);
        }
        if !arq.receive_logical_data(e.logical_seq, &data) {
            return Some(false);
        }
        {
            let mut t = record.transport.lock().unwrap();
            if !t.envelope_logged {
                t.envelope_logged = true;
                self.log.infof("Transport extension v1 envelope received");
            }
        }
        Some(true)
    }
    fn validate_transport_feedback(&self, record: &SessionRecord, f: &TransportFeedback) -> bool {
        f.records.iter().all(|r| {
            let Some(stream) = record.get_stream(r.stream_id) else {
                // Closed streams are immutable tombstones, not aliases for reused IDs.
                return record
                    .transport
                    .lock()
                    .unwrap()
                    .used_ids
                    .contains(&r.stream_id);
            };
            stream.arq().is_some_and(|a| {
                a.logical_feedback_status(
                    r.ack_next,
                    &arq_ranges(&r.sacks),
                    &arq_ranges(&r.repairs),
                ) != arq::LogicalFeedbackStatus::Invalid
            })
        })
    }
    fn apply_transport_feedback(&self, record: &SessionRecord, f: &TransportFeedback) {
        for r in &f.records {
            if let Some(stream) = record.get_stream(r.stream_id) {
                if let Some(a) = stream.arq() {
                    a.apply_logical_feedback(
                        r.ack_next,
                        &arq_ranges(&r.sacks),
                        &arq_ranges(&r.repairs),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn offered() -> (SessionTransport, TransportCaps) {
        let c = TransportCaps {
            op: 1,
            features: 7,
            nonce: 7,
            feedback_budget: 64,
            serial_span: 300,
        };
        let mut t = SessionTransport::default();
        t.offer = Some(c);
        t.deadline = Some(Instant::now() + Duration::from_secs(5));
        (t, c)
    }
    #[test]
    fn negotiation_replay_and_immutable_commit() {
        let (mut t, c) = offered();
        let now = Instant::now();
        assert_eq!(t.caps(c, now).unwrap().0.op, 2);
        assert_eq!(t.phase, Phase::Prepared);
        assert_eq!(t.caps(c, now).unwrap().0.op, 2);
        assert!(t.caps(TransportCaps { nonce: 8, ..c }, now).is_none());
        assert!(t.caps(TransportCaps { op: 3, ..c }, now).unwrap().1);
        assert!(!t.caps(TransportCaps { op: 3, ..c }, now).unwrap().1);
        t.expire(now + Duration::from_secs(10));
        assert_eq!(t.phase, Phase::Active);
    }
    #[test]
    fn timeout_and_subsets_cannot_activate() {
        let (mut t, c) = offered();
        let now = Instant::now();
        assert!(t.caps(TransportCaps { features: 1, ..c }, now).is_none());
        assert_eq!(t.phase, Phase::Offered);
        assert!(t.caps(TransportCaps { op: 3, ..c }, now).is_none());
        t.expire(now + Duration::from_secs(10));
        assert!(t.caps(c, now).is_none());
        assert_eq!(t.phase, Phase::Legacy);
    }
    #[test]
    fn datagram_bit_needs_the_offer_and_stays_optional() {
        let (mut t, c) = offered();
        let now = Instant::now();
        assert!(t.caps(TransportCaps { features: 15, ..c }, now).is_none());
        t.offer = Some(TransportCaps { features: 15, ..c });
        assert_eq!(t.caps(TransportCaps { features: 15, ..c }, now).unwrap().0.features, 15);
        let (mut t, c) = offered();
        t.offer = Some(TransportCaps { features: 15, ..c });
        assert_eq!(t.caps(c, now).unwrap().0.features, 7);
        assert!(t.caps(TransportCaps { features: 15, ..c }, now).is_none());
    }
}

thread_local! {
    static RESPONSE_TICKET: std::cell::RefCell<Option<ResponseTicket>> = const { std::cell::RefCell::new(None) };
}
/// Wire claims survive encoding, and are committed only after sendto/sendmmsg.
/// Dropping an unsent claim keeps its packet and feedback recoverable.
pub(crate) struct ResponseTicket {
    stream: std::sync::Arc<crate::stream::StreamServer>,
    original: Option<vpnproto::Packet>,
    logical: Option<u32>,
    feedback: Option<arq::FeedbackClaim>,
}
impl ResponseTicket {
    pub(crate) fn sent(mut self) {
        if let Some(original) = self.original.take() {
            if let Some(a) = self.stream.arq() {
                if let Some(seq) = self.logical {
                    a.note_logical_dispatched(seq, original.packet_type);
                }
                if let Some(c) = &self.feedback {
                    a.commit_feedback(c, Instant::now());
                }
            }
        }
    }
}
impl Drop for ResponseTicket {
    fn drop(&mut self) {
        let Some(p) = self.original.take() else {
            return;
        };
        let Some(seq) = self.logical else { return };
        let Some(a) = self.stream.arq() else { return };
        a.cancel_logical_write(seq);
        if a.logical_sequence(seq as u16) != Some(seq) || !a.has_pending_sequence(seq as u16) {
            return;
        }
        use arq::PacketEnqueuer;
        if !self.stream.push_tx_logical_packet(
            enums::default_packet_priority(p.packet_type),
            p.packet_type,
            seq,
            p.fragment_id,
            p.total_fragments,
            p.compression_type,
            Duration::ZERO,
            &p.payload,
        ) {
            a.note_logical_send_failed(seq);
        }
    }
}
impl Server {
    pub(crate) fn handle_packet_with_ticket(
        &self,
        packet: &[u8],
        now: Instant,
    ) -> Option<(Vec<u8>, Option<ResponseTicket>)> {
        RESPONSE_TICKET.with(|t| t.borrow_mut().take());
        let response = self.handle_packet_at(packet, now)?;
        let ticket = RESPONSE_TICKET.with(|t| t.borrow_mut().take());
        Some((response, ticket))
    }
    pub(crate) fn build_transport_response(
        &self,
        question: &[u8],
        name: &str,
        view: &crate::session::SessionRuntimeView,
        p: vpnproto::Packet,
        now: Instant,
    ) -> Option<Vec<u8>> {
        let Some(record) = self.sessions.get(view.id) else {
            return None;
        };
        let Some(c) = record.transport_caps() else {
            return None;
        };
        if !matches!(
            p.packet_type,
            enums::PACKET_STREAM_DATA | enums::PACKET_STREAM_RESEND | enums::PACKET_STREAM_FEEDBACK
        ) {
            return self.build_session_vpn_response(question, name, view, p);
        }
        let stream = record.get_stream(p.stream_id)?;
        let a = stream.arq()?;
        let logical = if p.packet_type == enums::PACKET_STREAM_FEEDBACK {
            None
        } else {
            Some(p.logical_sequence?)
        };
        let mut ticket = ResponseTicket {
            stream: stream.clone(),
            original: Some(p.clone()),
            logical,
            feedback: None,
        };
        let mut wire = p;
        if wire.packet_type == enums::PACKET_STREAM_FEEDBACK {
            // Replace queued snapshot with current state; no stale cursor metadata leaks.
            let claim = a.claim_feedback(now, c.feedback_budget as usize, true)?;
            wire.payload = a.encode_feedback_claim(&claim);
            wire.stream_id = 0;
            wire.compression_type = compression::TYPE_OFF;
            ticket.feedback = Some(claim);
        } else {
            let attempt = wire.compression_type != compression::TYPE_OFF
                && wire.payload.len() > compression::DEFAULT_MIN_SIZE;
            let (data, ctype) = if attempt && !stream.compression_skip.should_try() {
                (wire.payload.clone(), compression::TYPE_OFF)
            } else {
                let prepared = vpnproto::prepare_payload(
                    wire.packet_type,
                    &wire.payload,
                    wire.compression_type,
                    compression::DEFAULT_MIN_SIZE,
                );
                if attempt {
                    stream.compression_skip.record(prepared.1 != compression::TYPE_OFF);
                }
                prepared
            };
            let available = view.download_mtu_bytes.checked_sub(11 + data.len())?;
            let claim = if available >= 14 {
                a.claim_feedback(now, available.min(c.feedback_budget as usize), true)
            } else {
                None
            };
            let feedback = claim.as_ref().and_then(|claim| {
                TransportFeedback::decode(
                    &a.encode_feedback_claim(claim),
                    c.feedback_budget,
                    c.serial_span,
                )
                .ok()
            });
            let envelope = TransportEnvelope {
                inner_kind: wire.packet_type,
                inner_compression: ctype,
                logical_seq: logical.unwrap(),
                feedback,
                data,
            };
            wire.payload = envelope.encode(c.feedback_budget, c.serial_span).ok()?;
            wire.packet_type = enums::PACKET_STREAM_ENVELOPE;
            wire.compression_type = compression::TYPE_OFF;
            ticket.feedback = claim;
        }
        if wire.payload.len() > view.download_mtu_bytes {
            return None;
        }
        let response = self.build_session_vpn_response(question, name, view, wire)?;
        // Check the real encoded TXT bytes against the cached tested DATA budget.
        // Question/OPT/answer-name overhead is identical for the same request.
        if dnsparser::vpn_response_txt_wire_len(&response)? > view.download_txt_budget {
            return None;
        }
        if let Some(seq) = logical {
            if !a.note_logical_write_pending(seq) {
                return None;
            }
        }
        RESPONSE_TICKET.with(|slot| *slot.borrow_mut() = Some(ticket));
        Some(response)
    }
}
