//! Port of `internal/udpserver/server_postsession.go`: post-session packet
//! dispatch, the deferred-packet dedup tracker, and (the parts of
//! `server_session.go` that build responses) `serve_queued_or_pong` /
//! control-block packing.

use crate::session::{SessionRecord, SessionRuntimeView};
use crate::socks5_upstream;
use crate::stream::{ServerStreamTxPacket, StreamServer};
use crate::{DnsFragmentKey, Server, Socks5FragmentKey};
use arq::PacketEnqueuer;
use dashmap::DashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn is_stream_creation_packet_type(t: u8) -> bool {
    matches!(t, x if x == enums::PACKET_STREAM_SYN || x == enums::PACKET_SOCKS5_SYN)
}

/// Takes `p` by value so the caller's (already-dequeued, otherwise-discarded)
/// packet's payload can be moved into the response instead of cloned - this
/// runs on essentially every query that has a queued packet to send.
fn vpn_packet_from_tx(p: ServerStreamTxPacket, stream_id: u16) -> vpnproto::Packet {
    vpnproto::Packet {
        packet_type: p.packet_type,
        stream_id,
        sequence_num: p.sequence_num,
        fragment_id: p.fragment_id,
        total_fragments: p.total_fragments,
        compression_type: p.compression_type,
        has_compression_type: p.compression_type != compression::TYPE_OFF,
        has_sequence_num: p.sequence_num != 0,
        has_fragment_info: p.fragment_id != 0 || p.total_fragments != 0,
        has_stream_id: true,
        payload: p.payload,
        ..Default::default()
    }
}

fn deferred_tracked_packet_key(p: &vpnproto::Packet) -> u64 {
    (p.session_id as u64) << 48 | (p.stream_id as u64) << 32 | (p.packet_type as u64) << 24 | (p.sequence_num as u64) << 8 | (p.fragment_id as u64)
}

pub(crate) struct DeferredInflight {
    keys: DashSet<u64, rustc_hash::FxBuildHasher>,
}

impl DeferredInflight {
    pub(crate) fn new() -> Self {
        DeferredInflight { keys: DashSet::with_hasher(rustc_hash::FxBuildHasher) }
    }
    fn try_begin(&self, p: &vpnproto::Packet) -> bool {
        self.keys.insert(deferred_tracked_packet_key(p))
    }
    fn finish(&self, p: &vpnproto::Packet) {
        self.keys.remove(&deferred_tracked_packet_key(p));
    }
    /// Not currently consulted: Go's `shouldExecuteDeferredPacket` re-validates
    /// tracked-ness right before running deferred work as a last-moment
    /// staleness check; this port relies on the lane cancellation token
    /// (`DeferredRuntime`) for that instead. Kept for parity / future use.
    #[allow(dead_code)]
    fn still_tracked(&self, p: &vpnproto::Packet) -> bool {
        self.keys.contains(&deferred_tracked_packet_key(p))
    }
    fn clear_for_session(&self, session_id: u8) {
        self.keys.retain(|&k| (k >> 48) as u8 != session_id);
    }
    fn clear_for_stream(&self, session_id: u8, stream_id: u16) {
        self.keys.retain(|&k| !((k >> 48) as u8 == session_id && (k >> 32) as u16 == stream_id));
    }
}

impl Server {
    pub(crate) fn clear_deferred_packets_for_session(&self, session_id: u8) {
        if session_id == 0 {
            return;
        }
        self.deferred_inflight().clear_for_session(session_id);
    }

    pub(crate) fn clear_deferred_packets_for_stream(&self, session_id: u8, stream_id: u16) {
        if session_id == 0 || stream_id == 0 {
            return;
        }
        self.deferred_inflight().clear_for_stream(session_id, stream_id);
        self.deferred.remove_lane(session_id, stream_id);
    }

    pub(crate) fn remove_dns_query_fragments_for_session(&self, session_id: u8) {
        if session_id == 0 {
            return;
        }
        self.dns_fragments.remove_if(|key: &DnsFragmentKey| key.session_id == session_id);
    }

    pub(crate) fn purge_dns_query_fragments(&self, now: Instant) {
        self.dns_fragments.purge(now, self.dns_fragment_timeout);
    }

    pub(crate) fn remove_socks5_syn_fragments_for_session(&self, session_id: u8) {
        if session_id == 0 {
            return;
        }
        self.socks5_fragments.remove_if(|key: &Socks5FragmentKey| key.session_id == session_id);
    }

    pub(crate) fn remove_socks5_syn_fragments_for_stream(&self, session_id: u8, stream_id: u16) {
        if session_id == 0 || stream_id == 0 {
            return;
        }
        self.socks5_fragments.remove_if(|key: &Socks5FragmentKey| key.session_id == session_id && key.stream_id == stream_id);
    }

    pub(crate) fn purge_socks5_syn_fragments(&self, now: Instant) {
        self.socks5_fragments.purge(now, self.dns_fragment_timeout);
    }

    /// Called from `ingress::handle_tunnel_candidate`: mutates session/stream
    /// state and queues responses, but never itself produces *this* packet's
    /// DNS reply — `serve_queued_or_pong` does that afterward.
    pub(crate) fn handle_post_session_packet(&self, vpn_packet: &vpnproto::Packet, record: &SessionRuntimeView, now: Instant) -> bool {
        if self.reject_protocol_mismatched_syn(vpn_packet.packet_type) {
            return false;
        }
        if self.preprocess_inbound_packet(vpn_packet, now) {
            return true;
        }
        if vpn_packet.packet_type == enums::PACKET_PACKED_CONTROL_BLOCKS {
            self.handle_packed_control_blocks_request(vpn_packet, record, now);
            return true;
        }
        // Matches Go's `handlePostSessionPacket`: the dispatcher's bool result
        // is used only internally by `dispatchPostSessionPacket`'s callers in
        // Go (there are none outside packed-block replay, which ignores it
        // too - see `handlePackedControlBlocksRequest`), never to decide
        // whether *this* query gets an empty NODATA reply instead of queued
        // data/PONG. A dispatch "miss" (e.g. a duplicate STREAM_DATA_ACK that
        // `preprocessInboundPacket`/`consumeInboundStreamAck` already
        // consumed, or any other packet type the switch's `default` doesn't
        // recognize) must still let the query proceed to
        // `serve_queued_or_pong` so it can carry queued download data/PONG
        // instead of wasting the pull on an empty answer.
        self.dispatch_post_session_packet(vpn_packet, record, now);
        true
    }

    fn dispatch_post_session_packet(&self, p: &vpnproto::Packet, record: &SessionRuntimeView, now: Instant) -> bool {
        match p.packet_type {
            enums::PACKET_PING => true,
            enums::PACKET_STREAM_DATA | enums::PACKET_STREAM_RESEND => self.handle_stream_data_request(p),
            enums::PACKET_STREAM_DATA_NACK => self.handle_stream_data_nack_request(p),
            enums::PACKET_DNS_QUERY_REQ => self.handle_dns_query_request(p, record, now),
            enums::PACKET_STREAM_SYN => self.handle_stream_syn_request(p, record),
            enums::PACKET_SOCKS5_SYN => self.handle_socks5_syn_request(p, record),
            enums::PACKET_STREAM_CLOSE_READ => self.handle_stream_close_read_request(p),
            enums::PACKET_STREAM_CLOSE_WRITE => self.handle_stream_close_write_request(p),
            enums::PACKET_STREAM_RST => self.handle_stream_rst_request(p, now),
            _ => false,
        }
    }

    fn reject_protocol_mismatched_syn(&self, packet_type: u8) -> bool {
        match self.cfg.protocol_type.as_str() {
            "TCP" => packet_type == enums::PACKET_SOCKS5_SYN,
            "SOCKS5" => packet_type == enums::PACKET_STREAM_SYN,
            _ => false,
        }
    }

    fn enqueue_missing_stream_reset(&self, record: &SessionRecord, p: &vpnproto::Packet) -> bool {
        if record.is_closed()
            || p.stream_id == 0
            || p.packet_type == enums::PACKET_STREAM_SYN
            || p.packet_type == enums::PACKET_SOCKS5_SYN
            || p.packet_type == enums::PACKET_PACKED_CONTROL_BLOCKS
            || p.packet_type == enums::PACKET_PING
            || p.packet_type == enums::PACKET_DNS_QUERY_REQ
        {
            return false;
        }

        if p.packet_type == enums::PACKET_STREAM_DATA_ACK || p.packet_type == enums::PACKET_STREAM_DATA_NACK {
            return true;
        }
        if enums::reverse_control_ack_for(p.packet_type).is_some() {
            return true;
        }
        if p.packet_type == enums::PACKET_STREAM_RST {
            record.enqueue_orphan_reset(enums::PACKET_STREAM_RST_ACK, p.stream_id, p.sequence_num);
            return true;
        }
        match enums::get_packet_close_stream(p.packet_type) {
            Some(ack) => record.enqueue_orphan_reset(ack, p.stream_id, 0),
            None => record.enqueue_orphan_reset(enums::PACKET_STREAM_RST, p.stream_id, 0),
        }
        true
    }

    fn ack_recently_closed_stream_packet(&self, record: &SessionRecord, p: &vpnproto::Packet) -> bool {
        if p.stream_id == 0 {
            return false;
        }
        if p.packet_type == enums::PACKET_STREAM_DATA_ACK || p.packet_type == enums::PACKET_STREAM_DATA_NACK {
            return true;
        }
        if enums::reverse_control_ack_for(p.packet_type).is_some() {
            return true;
        }
        if let Some(ack_type) = enums::control_ack_for(p.packet_type) {
            record.enqueue_orphan_reset(ack_type, p.stream_id, p.sequence_num);
            return true;
        }
        false
    }

    fn reject_new_stream_because_limit(&self, record: &SessionRecord, p: &vpnproto::Packet) -> bool {
        let packet_type = if p.packet_type == enums::PACKET_SOCKS5_SYN { enums::PACKET_SOCKS5_CONNECT_FAIL } else { enums::PACKET_STREAM_CONNECT_FAIL };
        record.enqueue_orphan_reset(packet_type, p.stream_id, p.sequence_num);
        let _ = self.queue_immediate_control_ack(record, p);
        self.log.warnf(&format!(
            "Rejected new stream because active stream limit was reached | Session: {} | Stream: {}",
            p.session_id, p.stream_id
        ));
        true
    }

    fn consume_inbound_stream_ack(&self, p: &vpnproto::Packet, stream: &Arc<StreamServer>) -> bool {
        let Some(arq) = stream.arq() else { return false };
        let handled = arq.handle_ack_packet(p.packet_type, p.sequence_num, p.fragment_id);

        if handled && enums::get_packet_close_stream(p.packet_type).is_some() && arq.is_closed() {
            stream.clear_tx_queue();
            if let Some(record) = self.sessions.get(p.session_id) {
                record.deactivate_stream(p.stream_id);
            }
            self.clear_deferred_packets_for_stream(p.session_id, p.stream_id);
            stream.set_status("CLOSED");
        }
        handled
    }

    pub(crate) fn queue_immediate_control_ack(&self, record: &SessionRecord, p: &vpnproto::Packet) -> bool {
        let Some(ack_type) = enums::control_ack_for(p.packet_type) else { return false };
        let ack_packet = vpnproto::Packet {
            packet_type: ack_type,
            stream_id: p.stream_id,
            sequence_num: p.sequence_num,
            fragment_id: p.fragment_id,
            total_fragments: p.total_fragments,
            ..Default::default()
        };

        if p.stream_id == 0 {
            return self.queue_session_packet(record.id, ack_packet);
        }

        let stream = match record.get_stream(p.stream_id) {
            Some(s) => Some(s),
            None if is_stream_creation_packet_type(p.packet_type) => {
                record.get_or_create_stream(p.stream_id, self.stream_arq_config(record.download_compression), record.download_mtu_bytes, self.log.clone())
            }
            None => None,
        };
        let Some(stream) = stream else { return false };

        if (p.packet_type == enums::PACKET_SOCKS5_SYN || p.packet_type == enums::PACKET_STREAM_SYN) && stream.arq().is_some() {
            return stream.arq().unwrap().send_control_packet_with_ttl(
                ack_type,
                p.sequence_num,
                p.fragment_id,
                p.total_fragments,
                &[],
                enums::default_packet_priority(ack_type),
                false,
                None,
                self.cfg.stream_setup_ack_ttl(),
            );
        }

        stream.push_tx_packet(enums::default_packet_priority(ack_type), ack_type, p.sequence_num, p.fragment_id, p.total_fragments, 0, Duration::ZERO, &[])
    }

    fn preprocess_inbound_packet(&self, p: &vpnproto::Packet, now: Instant) -> bool {
        let Some(record) = self.sessions.get(p.session_id) else { return false };

        let existing_stream = record.get_stream(p.stream_id);

        if p.stream_id != 0 && existing_stream.is_none() && record.is_recently_closed(p.stream_id, now) {
            return match p.packet_type {
                enums::PACKET_STREAM_SYN | enums::PACKET_SOCKS5_SYN | enums::PACKET_STREAM_DATA | enums::PACKET_STREAM_RESEND => {
                    record.enqueue_orphan_reset(enums::PACKET_STREAM_RST, p.stream_id, 0);
                    true
                }
                _ => {
                    if self.ack_recently_closed_stream_packet(&record, p) {
                        return true;
                    }
                    if record.should_suppress_orphan_for_closed_stream(p.stream_id, now) {
                        return true;
                    }
                    self.enqueue_missing_stream_reset(&record, p)
                }
            };
        }

        if p.stream_id != 0 && existing_stream.is_none() {
            return self.enqueue_missing_stream_reset(&record, p);
        }

        if !matches!(
            p.packet_type,
            x if x == enums::PACKET_STREAM_DATA || x == enums::PACKET_STREAM_RESEND || x == enums::PACKET_DNS_QUERY_REQ || x == enums::PACKET_STREAM_SYN || x == enums::PACKET_SOCKS5_SYN
        ) {
            let _ = self.queue_immediate_control_ack(&record, p);
        }

        if let Some(stream) = &existing_stream {
            if self.consume_inbound_stream_ack(p, stream) {
                return true;
            }
        }

        false
    }

    fn handle_packed_control_blocks_request(&self, vpn_packet: &vpnproto::Packet, record: &SessionRuntimeView, now: Instant) -> bool {
        if vpn_packet.payload.len() < vpnproto::PACKED_CONTROL_BLOCK_SIZE {
            return false;
        }
        let mut handled = false;
        let mut saw_block = false;
        vpnproto::for_each_packed_control_block(&vpn_packet.payload, |packet_type, stream_id, sequence_num, fragment_id, total_fragments| {
            if packet_type == enums::PACKET_PACKED_CONTROL_BLOCKS {
                return true;
            }
            if self.reject_protocol_mismatched_syn(packet_type) {
                return true;
            }
            saw_block = true;
            let block = vpnproto::Packet {
                session_id: vpn_packet.session_id,
                session_cookie: vpn_packet.session_cookie,
                packet_type,
                stream_id,
                has_stream_id: true,
                sequence_num,
                has_sequence_num: true,
                fragment_id,
                total_fragments,
                ..Default::default()
            };
            if self.preprocess_inbound_packet(&block, now) {
                handled = true;
                return true;
            }
            if self.dispatch_post_session_packet(&block, record, now) {
                handled = true;
            }
            true
        });
        handled || saw_block
    }

    fn handle_stream_data_request(&self, p: &vpnproto::Packet) -> bool {
        let Some(record) = self.sessions.get(p.session_id) else { return true };
        let Some(stream) = record.get_stream(p.stream_id) else { return true };
        let Some(arq) = stream.arq() else {
            record.enqueue_orphan_reset(enums::PACKET_STREAM_RST, p.stream_id, 0);
            return true;
        };
        if arq.is_closed() || arq.is_reset() {
            record.enqueue_orphan_reset(enums::PACKET_STREAM_RST, p.stream_id, 0);
            return true;
        }
        stream.enqueue_inbound_data(p.sequence_num, &p.payload);
        true
    }

    fn handle_stream_data_nack_request(&self, p: &vpnproto::Packet) -> bool {
        let Some(record) = self.sessions.get(p.session_id) else { return true };
        let Some(stream) = record.get_stream(p.stream_id) else { return true };
        if let Some(arq) = stream.arq() {
            arq.handle_data_nack(p.sequence_num);
        }
        true
    }

    fn handle_stream_close_read_request(&self, p: &vpnproto::Packet) -> bool {
        if !p.has_stream_id || p.stream_id == 0 {
            return false;
        }
        let Some(record) = self.sessions.get(p.session_id) else { return true };
        let Some(stream) = record.get_stream(p.stream_id) else { return true };
        self.clear_deferred_packets_for_stream(p.session_id, p.stream_id);
        if let Some(arq) = stream.arq() {
            arq.mark_close_read_received();
        }
        true
    }

    fn handle_stream_close_write_request(&self, p: &vpnproto::Packet) -> bool {
        if !p.has_stream_id || p.stream_id == 0 {
            return false;
        }
        let Some(record) = self.sessions.get(p.session_id) else { return true };
        let Some(stream) = record.get_stream(p.stream_id) else { return true };
        self.clear_deferred_packets_for_stream(p.session_id, p.stream_id);
        if let Some(arq) = stream.arq() {
            arq.mark_close_write_received();
        }
        true
    }

    fn handle_stream_rst_request(&self, p: &vpnproto::Packet, now: Instant) -> bool {
        if !p.has_stream_id || p.stream_id == 0 {
            return false;
        }
        let Some(record) = self.sessions.get(p.session_id) else { return true };

        if let Some(stream) = record.get_stream(p.stream_id) {
            record.enqueue_orphan_reset(enums::PACKET_STREAM_RST_ACK, p.stream_id, p.sequence_num);
            stream.clear_tx_queue();
            record.deactivate_stream(p.stream_id);
            self.clear_deferred_packets_for_stream(p.session_id, p.stream_id);
            if let Some(arq) = stream.arq() {
                if !arq.is_closed() {
                    arq.mark_rst_received();
                    arq.close("peer reset before/while connect", arq::CloseOptions { force: true, ..Default::default() });
                }
            }
            stream.set_status("CLOSED");
        } else {
            record.enqueue_orphan_reset(enums::PACKET_STREAM_RST_ACK, p.stream_id, p.sequence_num);
            record.note_stream_closed(p.stream_id, now, false);
            self.clear_deferred_packets_for_stream(p.session_id, p.stream_id);
        }

        self.remove_socks5_syn_fragments_for_stream(p.session_id, p.stream_id);
        true
    }

    // ---- STREAM_SYN / SOCKS5_SYN (deferred dial) ----

    fn handle_stream_syn_request(&self, p: &vpnproto::Packet, record_view: &SessionRuntimeView) -> bool {
        if !p.has_stream_id || p.stream_id == 0 {
            return false;
        }
        let Some(record) = self.sessions.get(p.session_id) else { return false };
        if !record.can_create_additional_stream(p.stream_id) {
            return self.reject_new_stream_because_limit(&record, p);
        }

        if self.try_handle_immediate_connected_stream_syn(p) {
            let _ = self.queue_immediate_control_ack(&record, p);
            return true;
        }

        let _ = record_view;
        if !self.deferred_inflight().try_begin(p) {
            // Already dispatched for this exact retry; just re-ack, don't re-dial.
            let _ = self.queue_immediate_control_ack(&record, p);
            return true;
        }

        let server = self.self_arc();
        let packet = p.clone();
        let dispatched = self.deferred.enqueue(p.session_id, p.stream_id, move |cancel| async move {
            server.process_deferred_stream_syn(packet.clone(), cancel).await;
            server.deferred_inflight().finish(&packet);
        });

        if !dispatched {
            self.deferred_inflight().finish(p);
            return false;
        }
        let _ = self.queue_immediate_control_ack(&record, p);
        true
    }

    fn try_handle_immediate_connected_stream_syn(&self, p: &vpnproto::Packet) -> bool {
        if p.session_id == 0 || p.stream_id == 0 {
            return false;
        }
        let Some(record) = self.sessions.get(p.session_id) else { return false };
        let Some(stream) = record.get_stream(p.stream_id) else { return false };
        if stream.arq().is_none() {
            return false;
        }
        let (host, port) = stream.target();
        let connected = stream.connected.load(std::sync::atomic::Ordering::SeqCst);
        if !connected || host != self.cfg.forward_ip || port != self.cfg.forward_port as u16 {
            return false;
        }

        stream.arq().unwrap().send_control_packet_with_ttl(
            enums::PACKET_STREAM_CONNECTED,
            p.sequence_num,
            0,
            0,
            &[],
            enums::default_packet_priority(enums::PACKET_STREAM_CONNECTED),
            true,
            None,
            self.cfg.stream_result_packet_ttl(),
        );
        self.clear_deferred_packets_for_stream(p.session_id, p.stream_id);
        true
    }

    async fn process_deferred_stream_syn(&self, p: vpnproto::Packet, cancel: tokio_util::sync::CancellationToken) {
        let Some(record) = self.sessions.get(p.session_id) else { return };
        let Some(stream) = record.get_or_create_stream(p.stream_id, self.stream_arq_config(record.download_compression), record.download_mtu_bytes, self.log.clone()) else {
            return;
        };

        let address = format!("{}:{}", self.cfg.forward_ip, self.cfg.forward_port);
        let result = socks5_upstream::dial_tcp_target(&address, self.socks_connect_timeout, &cancel).await;
        match result {
            Ok(conn) => {
                if stream.attach_upstream_conn(conn, &self.cfg.forward_ip, self.cfg.forward_port as u16, "CONNECTED") {
                    if let Some(arq) = stream.arq() {
                        arq.send_control_packet_with_ttl(
                            enums::PACKET_STREAM_CONNECTED,
                            p.sequence_num,
                            0,
                            0,
                            &[],
                            enums::default_packet_priority(enums::PACKET_STREAM_CONNECTED),
                            true,
                            None,
                            self.cfg.stream_result_packet_ttl(),
                        );
                    }
                }
            }
            Err(e) => {
                let packet_type = socks5_upstream::map_socks_connect_error(&e);
                if let Some(arq) = stream.arq() {
                    arq.send_control_packet_with_ttl(
                        packet_type,
                        p.sequence_num,
                        0,
                        0,
                        &[],
                        enums::default_packet_priority(packet_type),
                        true,
                        None,
                        self.cfg.stream_failure_packet_ttl(),
                    );
                }
                self.cleanup_stream_artifacts(p.session_id, p.stream_id);
            }
        }
    }

    fn handle_socks5_syn_request(&self, p: &vpnproto::Packet, record_view: &SessionRuntimeView) -> bool {
        if !p.has_stream_id || p.stream_id == 0 {
            return false;
        }
        let Some(record) = self.sessions.get(p.session_id) else { return false };
        if !record.can_create_additional_stream(p.stream_id) {
            return self.reject_new_stream_because_limit(&record, p);
        }

        if self.try_handle_immediate_connected_socks5_syn(p) {
            let _ = self.queue_immediate_control_ack(&record, p);
            return true;
        }
        if self.try_handle_immediate_rejected_socks5_syn(p) {
            let _ = self.queue_immediate_control_ack(&record, p);
            return true;
        }

        let _ = record_view;
        if !self.deferred_inflight().try_begin(p) {
            let _ = self.queue_immediate_control_ack(&record, p);
            return true;
        }

        let server = self.self_arc();
        let packet = p.clone();
        let dispatched = self.deferred.enqueue(p.session_id, p.stream_id, move |cancel| async move {
            server.process_deferred_socks5_syn(packet.clone(), cancel).await;
            server.deferred_inflight().finish(&packet);
        });
        if !dispatched {
            self.deferred_inflight().finish(p);
            return false;
        }
        let _ = self.queue_immediate_control_ack(&record, p);
        true
    }

    fn try_handle_immediate_connected_socks5_syn(&self, p: &vpnproto::Packet) -> bool {
        if p.session_id == 0 || p.stream_id == 0 || p.total_fragments > 1 {
            return false;
        }
        let Some(record) = self.sessions.get(p.session_id) else { return false };
        let Some(stream) = record.get_stream(p.stream_id) else { return false };
        if stream.arq().is_none() {
            return false;
        }
        if !stream.connected.load(std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        let (current_host, current_port) = stream.target();

        let target = match socksproto::parse_target_payload(&p.payload) {
            Ok(t) => t,
            Err(_) => return false,
        };

        let packet_type =
            if current_host == target.host && current_port == target.port { enums::PACKET_SOCKS5_CONNECTED } else { enums::PACKET_SOCKS5_CONNECT_FAIL };

        stream.arq().unwrap().send_control_packet_with_ttl(
            packet_type,
            p.sequence_num,
            0,
            0,
            &[],
            enums::default_packet_priority(packet_type),
            true,
            None,
            self.cfg.stream_result_packet_ttl(),
        );
        self.cleanup_stream_artifacts(p.session_id, p.stream_id);
        true
    }

    fn try_handle_immediate_rejected_socks5_syn(&self, p: &vpnproto::Packet) -> bool {
        if p.session_id == 0 || p.stream_id == 0 || p.total_fragments > 1 {
            return false;
        }
        let Some(record) = self.sessions.get(p.session_id) else { return false };
        let Some(stream) = record.get_stream(p.stream_id) else { return false };
        if stream.arq().is_none() {
            return false;
        }
        let target = match socksproto::parse_target_payload(&p.payload) {
            Ok(t) => t,
            Err(_) => return false,
        };
        if let Err(e) = socks5_upstream::validate_socks_target_host(&target.host) {
            let packet_type = socks5_upstream::map_socks_connect_error(&e);
            stream.arq().unwrap().send_control_packet_with_ttl(
                packet_type,
                p.sequence_num,
                0,
                0,
                &[],
                enums::default_packet_priority(packet_type),
                true,
                None,
                self.cfg.stream_failure_packet_ttl(),
            );
            self.cleanup_stream_artifacts(p.session_id, p.stream_id);
            return true;
        }
        false
    }

    async fn process_deferred_socks5_syn(&self, p: vpnproto::Packet, cancel: tokio_util::sync::CancellationToken) {
        let Some(record) = self.sessions.get(p.session_id) else { return };
        let Some(stream) = record.get_or_create_stream(p.stream_id, self.stream_arq_config(record.download_compression), record.download_mtu_bytes, self.log.clone()) else {
            return;
        };

        let target = match socksproto::parse_target_payload(&p.payload) {
            Ok(t) => t,
            Err(_) => return,
        };

        let result =
            socks5_upstream::dial_socks_stream_target(&target.host, target.port, &p.payload, self.use_external_socks5, &self.external_socks5, self.socks_connect_timeout, &cancel)
                .await;

        match result {
            Ok(conn) => {
                if stream.attach_upstream_conn(conn, &target.host, target.port, "CONNECTED") {
                    if let Some(arq) = stream.arq() {
                        arq.send_control_packet_with_ttl(
                            enums::PACKET_SOCKS5_CONNECTED,
                            p.sequence_num,
                            0,
                            0,
                            &[],
                            enums::default_packet_priority(enums::PACKET_SOCKS5_CONNECTED),
                            true,
                            None,
                            self.cfg.stream_result_packet_ttl(),
                        );
                    }
                }
            }
            Err(e) => {
                let packet_type = socks5_upstream::map_socks_connect_error(&e);
                if let Some(arq) = stream.arq() {
                    arq.send_control_packet_with_ttl(
                        packet_type,
                        p.sequence_num,
                        0,
                        0,
                        &[],
                        enums::default_packet_priority(packet_type),
                        true,
                        None,
                        self.cfg.stream_failure_packet_ttl(),
                    );
                }
                self.cleanup_stream_artifacts(p.session_id, p.stream_id);
            }
        }
    }

    // ---- DNS_QUERY_REQ (tunneled DNS resolution-as-a-service) ----

    fn handle_dns_query_request(&self, p: &vpnproto::Packet, record: &SessionRuntimeView, now: Instant) -> bool {
        let mut total_fragments = p.total_fragments;
        if total_fragments == 0 {
            total_fragments = 1;
        }

        let outcome = self.dns_fragments.collect(
            DnsFragmentKey { session_id: p.session_id, sequence_num: p.sequence_num },
            &p.payload,
            p.fragment_id,
            total_fragments,
            now,
            self.dns_fragment_timeout,
        );

        let assembled = match outcome {
            fragmentstore::CollectOutcome::Complete(bytes) => bytes,
            fragmentstore::CollectOutcome::AlreadyCompleted | fragmentstore::CollectOutcome::Rejected => return true,
            fragmentstore::CollectOutcome::Buffered => return true,
        };

        let server = self.self_arc();
        let session_id = p.session_id;
        let session_cookie = p.session_cookie;
        let sequence_num = p.sequence_num;
        let download_compression = record.download_compression;
        let download_mtu_bytes = record.download_mtu_bytes;

        let dispatched = self.deferred.enqueue(p.session_id, p.stream_id, move |cancel| async move {
            server.process_deferred_dns_query(session_id, session_cookie, sequence_num, download_compression, download_mtu_bytes, assembled, cancel).await;
        });
        if !dispatched {
            return false;
        }

        if let Some(rec) = self.sessions.get(p.session_id) {
            let _ = self.queue_immediate_control_ack(&rec, p);
        }
        true
    }

    // ---- Response building / packing (port of the second half of
    // `server_session.go`: serveQueuedOrPong, dequeueSessionResponse,
    // packControlBlocks, vpnPacketFromTX) ----

    pub(crate) fn serve_queued_or_pong(&self, question_packet: &[u8], request_name: &str, record: &SessionRuntimeView, now: Instant) -> Option<Vec<u8>> {
        if let Some(pkt) = self.dequeue_session_response(record.id, now) {
            return self.build_session_vpn_response(question_packet, request_name, record, pkt);
        }
        let payload = self.pong_payload();
        self.build_session_vpn_response(
            question_packet,
            request_name,
            record,
            vpnproto::Packet { packet_type: enums::PACKET_PONG, payload, ..Default::default() },
        )
    }

    fn dequeue_session_response(&self, session_id: u8, now: Instant) -> Option<vpnproto::Packet> {
        let record = self.sessions.get(session_id)?;

        if let Some(pkt) = record.dequeue_duplicated_packed_control_block() {
            return Some(pkt);
        }
        let rr_stream_id = record.rr_stream_id();

        // One snapshot per query; streams are scanned through it without
        // per-stream lookups (see `SessionRecord::active_streams`).
        let active = record.active_stream_snapshot();
        let has_orphan = record.orphan_queue.fast_size() > 0;
        let orphan_slots = usize::from(has_orphan);
        let total_candidates = active.len() + orphan_slots;
        if total_candidates == 0 {
            return None;
        }

        // Candidates are [orphan queue (id -1)] followed by the active streams
        // in id order. Round-robin resumes at the first candidate whose id is
        // >= rr_stream_id, or at candidate 0 if there is none.
        let first_stream_at_or_after = active.partition_point(|(id, _)| (*id as i32) < rr_stream_id);
        let start_idx = if has_orphan && rr_stream_id <= -1 {
            0
        } else if first_stream_at_or_after < active.len() {
            orphan_slots + first_stream_at_or_after
        } else {
            0
        };

        for i in 0..total_candidates {
            let idx = (start_idx + i) % total_candidates;

            let mut item: Option<ServerStreamTxPacket> = None;
            let mut selected_stream_id: u16 = 0;
            let id: i32;

            if has_orphan && idx == 0 {
                id = -1;
                if let Some((p, _priority)) = record.orphan_queue.pop() {
                    selected_stream_id = p.stream_id;
                    item = Some(ServerStreamTxPacket {
                        packet_type: p.packet_type,
                        sequence_num: p.sequence_num,
                        fragment_id: p.fragment_id,
                        total_fragments: p.total_fragments,
                        compression_type: 0,
                        payload: p.payload,
                        created_at: now,
                        ttl: Duration::ZERO,
                    });
                }
            } else {
                let (stream_id, stream) = &active[idx - orphan_slots];
                id = *stream_id as i32;
                if stream.fast_tx_queue_size() == 0 {
                    continue;
                }
                if let Some(arq) = stream.arq() {
                    if arq.is_closed() {
                        stream.clear_tx_queue();
                        record.deactivate_stream(*stream_id);
                        continue;
                    }
                }
                if let Some((popped, _priority)) = stream.pop_next_tx_packet() {
                    stream.note_tx_packet_dequeued(&popped);
                    let should_skip = (popped.packet_type == enums::PACKET_STREAM_DATA || popped.packet_type == enums::PACKET_STREAM_RESEND)
                        && stream.arq().map(|a| !a.has_pending_sequence(popped.sequence_num)).unwrap_or(false);
                    if should_skip {
                        continue;
                    }
                    selected_stream_id = *stream_id;
                    item = Some(popped);
                }
            }

            if let Some(item) = item {
                record.set_rr_stream_id(id + 1);
                if vpnproto::is_packable_control_packet(item.packet_type, item.payload.len()) && record.max_packed_blocks > 1 {
                    let pkt = self.pack_control_blocks(&record, &active, item, id, selected_stream_id);
                    record.cache_packed_control_block_duplicate(self.cfg.packet_block_control_duplication, Some(pkt.clone()));
                    return Some(pkt);
                }
                return Some(vpn_packet_from_tx(item, selected_stream_id));
            }
        }

        None
    }

    /// Fills a PACKED_CONTROL_BLOCKS reply starting from `first`: the rest of
    /// the initial candidate's queue, then the orphan queue, then the other
    /// active streams in id order starting after the initial one.
    fn pack_control_blocks(
        &self,
        record: &Arc<SessionRecord>,
        active: &[(u16, Arc<StreamServer>)],
        first: ServerStreamTxPacket,
        initial_id: i32,
        initial_stream_id: u16,
    ) -> vpnproto::Packet {
        let limit = record.max_packed_blocks;
        if limit <= 1 {
            return vpn_packet_from_tx(first, initial_stream_id);
        }

        let mut payload = Vec::with_capacity((limit as usize) * vpnproto::PACKED_CONTROL_BLOCK_SIZE);
        vpnproto::append_packed_control_block(&mut payload, first.packet_type, initial_stream_id, first.sequence_num, first.fragment_id, first.total_fragments);
        let mut blocks: i64 = 1;

        let has_orphan = record.orphan_queue.fast_size() > 0;

        // Scan cap for the opportunistic cross-stream/orphan draining below:
        // normally CRITICAL..=HIGH (the priority of every packable control
        // packet type) is enough, but `arq::data::REACK_PRIORITY`-tagged
        // delayed re-ACK copies sit at LOW (below outbound STREAM_DATA's
        // NORMAL, so they never preempt it — see that constant's doc comment)
        // and still need to be reachable here, or they would only ever drain
        // one at a time through their own stream's round-robin turn instead
        // of batching into this reply like every other packable control
        // packet does.
        const PACKABLE_SCAN_MAX_PRIORITY: i32 = enums::PACKET_PRIORITY_LOW;

        // Returns true once the reply is full.
        let drain_orphans = |blocks: &mut i64, payload: &mut Vec<u8>| -> bool {
            if *blocks >= limit {
                return true;
            }
            while *blocks < limit {
                if record.orphan_queue.fast_size() == 0 {
                    return false;
                }
                let popped =
                    record.orphan_queue.pop_any_if(PACKABLE_SCAN_MAX_PRIORITY, |p: &vpnproto::Packet| vpnproto::is_packable_control_packet(p.packet_type, 0), |_| 0);
                let Some(popped) = popped else { return false };
                vpnproto::append_packed_control_block(payload, popped.packet_type, popped.stream_id, popped.sequence_num, popped.fragment_id, popped.total_fragments);
                *blocks += 1;
            }
            false
        };
        let drain_stream = |stream_id: u16, stream: &StreamServer, blocks: &mut i64, payload: &mut Vec<u8>| -> bool {
            if *blocks >= limit {
                return true;
            }
            while *blocks < limit {
                if stream.fast_tx_queue_size() == 0 {
                    return false;
                }
                let popped =
                    stream.pop_any_tx_packet(PACKABLE_SCAN_MAX_PRIORITY, |p: &ServerStreamTxPacket| vpnproto::is_packable_control_packet(p.packet_type, p.payload.len()));
                let Some(popped) = popped else { return false };
                stream.note_tx_packet_dequeued(&popped);
                vpnproto::append_packed_control_block(payload, popped.packet_type, stream_id, popped.sequence_num, popped.fragment_id, popped.total_fragments);
                *blocks += 1;
            }
            false
        };

        let initial_index = if initial_id != -1 { active.iter().position(|(id, _)| *id as i32 == initial_id) } else { None };

        'build_result: {
            let initial_full = if initial_id == -1 {
                drain_orphans(&mut blocks, &mut payload)
            } else {
                match initial_index {
                    Some(i) => drain_stream(active[i].0, &active[i].1, &mut blocks, &mut payload),
                    None => blocks >= limit,
                }
            };
            if initial_full {
                break 'build_result;
            }

            if has_orphan && initial_id != -1 && drain_orphans(&mut blocks, &mut payload) {
                break 'build_result;
            }

            let (after, before) = match initial_index {
                Some(i) => (&active[i + 1..], &active[..i]),
                None => (active, &active[..0]),
            };
            for (stream_id, stream) in after.iter().chain(before) {
                if drain_stream(*stream_id, stream, &mut blocks, &mut payload) {
                    break 'build_result;
                }
            }

            if initial_id == -1 && has_orphan {
                for (stream_id, stream) in active {
                    if drain_stream(*stream_id, stream, &mut blocks, &mut payload) {
                        break 'build_result;
                    }
                }
            }
        }

        if blocks <= 1 {
            return vpn_packet_from_tx(first, initial_stream_id);
        }

        vpnproto::Packet { packet_type: enums::PACKET_PACKED_CONTROL_BLOCKS, payload, stream_id: 0, has_stream_id: true, ..Default::default() }
    }

    fn self_arc(&self) -> Arc<Server> {
        // SAFETY-free approach: Server is always constructed via `Arc::new`
        // in `Server::new`; callers hand `Arc<Server>` into `runtime::run`.
        // Deferred closures need their own `Arc<Server>` clone, which we get
        // by threading it in via `set_self` right after construction.
        self.self_ref.get().expect("Server::finish_init must run before deferred work is scheduled").clone()
    }
}
