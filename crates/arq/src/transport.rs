//! Logical-generation bookkeeping. Legacy ARQ never enters these paths.
use crate::{Arq, CloseOptions};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};

// Per feedback record: at most this many resends and resend attempts;
// remaining eligible entries are marked for the retransmit loop.
const MAX_REPAIR_RESENDS: usize = 32;
const MAX_REPAIR_INSPECTED: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogicalRange {
    pub offset: u16,
    pub length: u16,
}
#[derive(Clone, Debug)]
pub struct FeedbackClaim {
    pub generation: u64,
    pub ack_next: u32,
    pub sacks: Vec<LogicalRange>,
    pub repairs: Vec<LogicalRange>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogicalFeedbackStatus {
    Valid,
    WritePending,
    Invalid,
}
#[derive(Clone)]
struct DeferredFeedback {
    ack: u32,
    sacks: Vec<LogicalRange>,
    repairs: Vec<LogicalRange>,
}
#[derive(Default)]
pub(crate) struct Dispatch {
    pub dispatched: bool,
    pub write_pending: bool,
    pub acked: bool,
}
pub(crate) struct TransportState {
    pub span: u16,
    pub budget: u16,
    pub send_next: u32,
    pub send_ack: u32,
    pub ledger: BTreeMap<u32, Dispatch>,
    deferred_feedback: VecDeque<DeferredFeedback>,
    pub rtt_samples: u64,
    pub local_eof: Option<u32>,
    pub remote_eof: Option<u32>,
    pub writer_next: u32,
    pub stored_ack: u32,
    pub stored: BTreeSet<u32>,
    pub highest: Option<u32>,
    pub sack_ranges: BTreeMap<u32, u32>,
    pub repair_ranges: BTreeMap<u32, u32>,
    pub repair_refresh: Option<Instant>,
    pub repair_due: Option<Instant>,
    pub sack_rotation: u32,
    pub repair_rotation: u32,
    pub holes: BTreeMap<u32, (Instant, Option<Instant>)>,
    pub generation: u64,
    pub dirty: bool,
    pub due: Option<Instant>,
    pub reack: Option<Instant>,
    pub range_rotation: usize,
}
impl TransportState {
    pub fn new(span: u16, budget: u16) -> Self {
        Self {
            span,
            budget,
            send_next: 0,
            send_ack: 0,
            ledger: BTreeMap::new(),
            deferred_feedback: VecDeque::new(),
            rtt_samples: 0,
            local_eof: None,
            remote_eof: None,
            writer_next: 0,
            stored_ack: 0,
            stored: BTreeSet::new(),
            highest: None,
            sack_ranges: BTreeMap::new(),
            repair_ranges: BTreeMap::new(),
            repair_refresh: None,
            repair_due: None,
            sack_rotation: 0,
            repair_rotation: 0,
            holes: BTreeMap::new(),
            generation: 0,
            dirty: false,
            due: None,
            reack: None,
            range_rotation: 0,
        }
    }
    pub fn has_send_room(&self) -> bool {
        self.send_next < u32::MAX && self.send_next - self.send_ack < self.span as u32
    }
    pub fn logical_for(&self, sn: u16) -> Option<u32> {
        // At most serialSpan (< half-space) live generations, including SACK tombstones.
        let distance = (self.send_next as u16).wrapping_sub(sn) as u32;
        let seq = self.send_next.checked_sub(distance)?;
        self.ledger.contains_key(&seq).then_some(seq)
    }
    fn changed(&mut self, now: Instant) {
        self.generation = self.generation.wrapping_add(1);
        self.dirty = true;
        self.due.get_or_insert(now + Duration::from_millis(25));
        self.reack = Some(now + Duration::from_millis(150));
    }
}

fn feedback_status(
    t: &TransportState,
    ack: u32,
    sacks: &[LogicalRange],
    repairs: &[LogicalRange],
) -> LogicalFeedbackStatus {
    use LogicalFeedbackStatus::*;
    if ack < t.send_ack {
        return Valid;
    }
    if ack > t.send_next {
        return Invalid;
    }
    let mut pending = false;
    let mut check = |start: u32, end: u32| {
        for seq in start..end {
            let Some(d) = t.ledger.get(&seq) else {
                return false;
            };
            if !d.dispatched {
                if !d.write_pending {
                    return false;
                }
                pending = true;
            }
        }
        true
    };
    if !check(t.send_ack, ack) {
        return Invalid;
    }
    for r in sacks.iter().chain(repairs) {
        let Some(start) = ack.checked_add(r.offset as u32) else {
            return Invalid;
        };
        let Some(end) = start.checked_add(r.length as u32) else {
            return Invalid;
        };
        if r.length == 0 || end > t.send_next || end - ack > t.span as u32 || !check(start, end) {
            return Invalid;
        }
    }
    if pending {
        WritePending
    } else {
        Valid
    }
}

fn ranges(values: impl Iterator<Item = u32>, ack: u32) -> Vec<LogicalRange> {
    let mut result: Vec<LogicalRange> = Vec::new();
    for seq in values {
        let offset = (seq - ack) as u16;
        if let Some(last) = result.last_mut() {
            if last.offset as u32 + last.length as u32 == offset as u32 {
                last.length += 1;
                continue;
            }
        }
        result.push(LogicalRange { offset, length: 1 });
    }
    result
}

fn insert_stored_range(map: &mut BTreeMap<u32, u32>, seq: u32) {
    let mut start = seq;
    let mut end = seq + 1;
    if let Some((&left, &right)) = map.range(..=seq).next_back() {
        if right > seq {
            return;
        }
        if right == seq {
            start = left;
            map.remove(&left);
        }
    }
    if let Some((&right, &right_end)) = map.range(seq + 1..).next() {
        if right == end {
            end = right_end;
            map.remove(&right);
        }
    }
    map.insert(start, end);
}
fn remove_interval(map: &mut BTreeMap<u32, u32>, start: u32, end: u32) {
    let mut remove: Vec<(u32, u32)> = map.range(start..end).map(|(&a, &b)| (a, b)).collect();
    if let Some((&a, &b)) = map.range(..start).next_back() {
        if b > start {
            remove.insert(0, (a, b));
        }
    }
    for (a, b) in remove {
        map.remove(&a);
        if a < start {
            map.insert(a, start);
        }
        if b > end {
            map.insert(end, b);
        }
    }
}
fn page(map: &BTreeMap<u32, u32>, rotation: u32, cap: usize, ack: u32) -> Vec<LogicalRange> {
    let mut selected: Vec<_> = map
        .range(rotation..)
        .chain(map.range(..rotation))
        .take(cap)
        .map(|(&start, &end)| LogicalRange {
            offset: (start - ack) as u16,
            length: (end - start) as u16,
        })
        .collect();
    selected.sort_by_key(|r| r.offset);
    selected
}

impl Arq {
    pub fn transport_enabled(&self) -> bool {
        self.inner.lock().unwrap().transport.is_some()
    }
    pub fn logical_sequence(&self, sn: u16) -> Option<u32> {
        self.inner
            .lock()
            .unwrap()
            .transport
            .as_ref()?
            .logical_for(sn)
    }
    pub fn validate_logical_receive(&self, seq: u32) -> bool {
        let s = self.inner.lock().unwrap();
        let Some(t) = &s.transport else { return false };
        !s.closed
            && !s.rst_received
            && !s.rst_sent
            && seq < u32::MAX
            && t.remote_eof.is_none_or(|end| seq < end)
            && (seq < t.stored_ack || (seq >= t.writer_next && seq - t.writer_next < t.span as u32))
    }
    pub fn receive_logical_data(&self, seq: u32, data: &[u8]) -> bool {
        let now = Instant::now();
        {
            let mut s = self.inner.lock().unwrap();
            if s.closed
                || s.rst_received
                || s.rst_sent
                || s.local_writer_broken
                || s.close_write_sent
                || s.close_write_acked
            {
                return false;
            }
            let Some(t) = s.transport.as_ref() else {
                return false;
            };
            if seq >= u32::MAX
                || t.remote_eof.is_some_and(|end| seq >= end)
                || (seq >= t.stored_ack
                    && (seq < t.writer_next || seq - t.writer_next >= t.span as u32))
            {
                return false;
            }
            let old = seq < t.stored_ack;
            if !old && !s.rcv_buf.contains_key(&(seq as u16)) {
                if s.rcv_buf.len() >= self.receive_window_size {
                    return false;
                }
                s.rcv_buf.insert(seq as u16, data.to_vec());
            }
            s.last_activity = now;
            let t = s.transport.as_mut().unwrap();
            if !old {
                t.stored.insert(seq);
                insert_stored_range(&mut t.sack_ranges, seq);
                t.holes.remove(&seq);
                remove_interval(&mut t.repair_ranges, seq, seq + 1);
                // Discover each hole once, only when the high-water mark advances.
                let start = t
                    .highest
                    .map_or(t.stored_ack, |highest| highest + 1)
                    .max(t.stored_ack);
                if seq >= start {
                    for hole in start..seq {
                        t.holes.insert(hole, (now, None));
                    }
                    if start < seq && self.data_nack_max_gap != 0 {
                        let deadline = now + self.data_nack_initial_delay;
                        t.repair_due = Some(t.repair_due.map_or(deadline, |d| d.min(deadline)));
                    }
                    t.highest = Some(seq);
                }
                let old_ack = t.stored_ack;
                while t.stored.remove(&t.stored_ack) {
                    t.holes.remove(&t.stored_ack);
                    t.stored_ack += 1;
                }
                if t.stored_ack > old_ack {
                    remove_interval(&mut t.sack_ranges, old_ack, t.stored_ack);
                    remove_interval(&mut t.repair_ranges, old_ack, t.stored_ack);
                }
            }
            t.changed(now);
        }
        self.reack_scheduled.notify_one();
        self.signal_flush_ready();
        true
    }
    /// Queued generations are invalid. Only a frame explicitly claimed for
    /// a socket write can defer feedback until that write actually succeeds.
    pub fn logical_feedback_status(
        &self,
        ack: u32,
        sacks: &[LogicalRange],
        repairs: &[LogicalRange],
    ) -> LogicalFeedbackStatus {
        let s = self.inner.lock().unwrap();
        s.transport
            .as_ref()
            .map_or(LogicalFeedbackStatus::Invalid, |t| {
                feedback_status(t, ack, sacks, repairs)
            })
    }
    pub fn validate_logical_feedback(
        &self,
        ack: u32,
        sacks: &[LogicalRange],
        repairs: &[LogicalRange],
    ) -> bool {
        self.logical_feedback_status(ack, sacks, repairs) == LogicalFeedbackStatus::Valid
    }
    pub fn apply_logical_feedback(
        &self,
        ack: u32,
        sacks: &[LogicalRange],
        repairs: &[LogicalRange],
    ) -> bool {
        let retire = {
            let mut s = self.inner.lock().unwrap();
            let Some(t) = s.transport.as_mut() else {
                return false;
            };
            match feedback_status(t, ack, sacks, repairs) {
                LogicalFeedbackStatus::Invalid => return false,
                LogicalFeedbackStatus::WritePending => {
                    if t.deferred_feedback.len() == 16 {
                        t.deferred_feedback.pop_front();
                    }
                    t.deferred_feedback.push_back(DeferredFeedback {
                        ack,
                        sacks: sacks.to_vec(),
                        repairs: repairs.to_vec(),
                    });
                    return true;
                }
                LogicalFeedbackStatus::Valid => {}
            }
            if ack < t.send_ack {
                return true;
            }
            let mut seqs: Vec<u32> = t
                .ledger
                .range(t.send_ack..ack)
                .filter(|(_, d)| !d.acked)
                .map(|(&seq, _)| seq)
                .collect();
            for r in sacks {
                for seq in ack + r.offset as u32..ack + r.offset as u32 + r.length as u32 {
                    if t.ledger.get(&seq).is_some_and(|d| !d.acked) {
                        seqs.push(seq);
                    }
                }
            }
            let mut sample_budget = 8;
            seqs.into_iter()
                .map(|seq| {
                    let eligible = s.snd_buf.get(&(seq as u16)).is_some_and(|item| {
                        item.logical_seq == Some(seq)
                            && item.sample_eligible
                            && item.dispatched
                            && item.last_sent_at.is_some()
                    });
                    let allow_sample = eligible && sample_budget > 0;
                    if allow_sample {
                        sample_budget -= 1;
                    }
                    (seq, allow_sample)
                })
                .collect::<Vec<_>>()
        };
        for (seq, allow_sample) in retire {
            self.receive_ack_generation(seq as u16, Some(seq), allow_sample);
        }
        {
            let mut s = self.inner.lock().unwrap();
            let t = s.transport.as_mut().unwrap();
            if ack > t.send_ack {
                t.send_ack = ack;
                t.ledger = t.ledger.split_off(&ack);
            }
        }
        self.window_not_full.notify_one();
        // Resends and inspected entries are bounded separately, so recently
        // resent entries at the front of a range cannot starve the rest.
        let (mut work, mut inspected) = (0, 0);
        for r in repairs {
            for seq in ack + r.offset as u32..ack + r.offset as u32 + r.length as u32 {

                let eligible = {
                    let s = self.inner.lock().unwrap();
                    s.transport.as_ref().is_some_and(|t| {
                        t.ledger.get(&seq).is_some_and(|d| d.dispatched && !d.acked)
                    })
                };
                if !eligible {
                    continue;
                }
                if work < MAX_REPAIR_RESENDS && inspected < MAX_REPAIR_INSPECTED {
                    inspected += 1;
                    if self.queue_data_retry_with(seq as u16, Instant::now(), None, false, true, true) {
                        work += 1;
                    }
                } else {
                    let mut s = self.inner.lock().unwrap();
                    if let Some(i) = s.snd_buf.get_mut(&(seq as u16)) {
                        i.nack_pending = true;
                    }
                }
            }
        }
        true
    }
    /// Non-destructive ACK/repair snapshot; the caller commits only after encoding.
    pub fn claim_feedback(
        &self,
        now: Instant,
        max_payload: usize,
        force: bool,
    ) -> Option<FeedbackClaim> {
        let mut s = self.inner.lock().unwrap();
        if s.closed
            || s.rst_sent
            || s.rst_received
            || s.local_writer_broken
            || s.close_write_sent
            || s.close_write_acked
        {
            return None;
        }
        let t = s.transport.as_mut()?;
        if !t.dirty && !t.reack.is_some_and(|d| d <= now) && t.holes.is_empty() {
            return None;
        }
        if !force
            && !t.due.is_some_and(|d| d <= now)
            && !t.reack.is_some_and(|d| d <= now)
            && !t.repair_due.is_some_and(|d| d <= now)
        {
            return None;
        }
        if self.data_nack_max_gap == 0 {
            t.repair_ranges.clear();
            t.repair_due = None;
        } else if t.repair_refresh.is_none_or(|due| due <= now) {
            // Repair deadline discovery is cached at a bounded flush cadence,
            // not rescanned for each piggyback/data envelope.
            let due = ranges(
                t.holes
                    .iter()
                    .filter(|(_, (first, last))| {
                        now.saturating_duration_since(last.unwrap_or(*first))
                            >= if last.is_some() {
                                self.data_nack_repeat_interval
                            } else {
                                self.data_nack_initial_delay
                            }
                    })
                    .map(|(&seq, _)| seq),
                t.stored_ack,
            );
            t.repair_ranges = due
                .into_iter()
                .map(|r| {
                    let start = t.stored_ack + r.offset as u32;
                    (start, start + r.length as u32)
                })
                .collect();
            t.repair_due = t
                .holes
                .values()
                .map(|(first, last)| {
                    last.unwrap_or(*first)
                        + if last.is_some() {
                            self.data_nack_repeat_interval
                        } else {
                            self.data_nack_initial_delay
                        }
                })
                .min();
            t.repair_refresh = Some(now + Duration::from_millis(25));
        }
        let capacity = max_payload.min(t.budget as usize).checked_sub(10)? / 4;
        let repair_cap =
            if !t.sack_ranges.is_empty() && !t.repair_ranges.is_empty() && capacity == 1 {
                if t.range_rotation % 2 == 0 {
                    1
                } else {
                    0
                }
            } else {
                capacity
                    .saturating_sub(usize::from(
                        !t.sack_ranges.is_empty() && !t.repair_ranges.is_empty(),
                    ))
                    .min(8)
                    .min(t.repair_ranges.len())
            };
        let repairs = page(
            &t.repair_ranges,
            t.repair_rotation,
            repair_cap,
            t.stored_ack,
        );
        let sacks = page(
            &t.sack_ranges,
            t.sack_rotation,
            capacity.saturating_sub(repairs.len()).min(8),
            t.stored_ack,
        );
        Some(FeedbackClaim {
            generation: t.generation,
            ack_next: t.stored_ack,
            sacks,
            repairs,
        })
    }
    pub fn commit_feedback(&self, claim: &FeedbackClaim, now: Instant) {
        let mut s = self.inner.lock().unwrap();
        let Some(t) = s.transport.as_mut() else {
            return;
        };
        if t.generation != claim.generation || t.stored_ack != claim.ack_next {
            return;
        }
        t.dirty = false;
        t.due = None;
        t.range_rotation = t.range_rotation.wrapping_add(1);
        // One delayed copy per generation; steady-state holes remain independently scheduled.
        if t.reack.is_some_and(|d| d <= now) {
            t.reack = None;
        }
        if let Some(last) = claim.sacks.last() {
            t.sack_rotation = claim.ack_next + last.offset as u32 + last.length as u32;
        }
        if let Some(last) = claim.repairs.last() {
            t.repair_rotation = claim.ack_next + last.offset as u32 + last.length as u32;
        }
        for r in &claim.repairs {
            remove_interval(
                &mut t.repair_ranges,
                claim.ack_next + r.offset as u32,
                claim.ack_next + r.offset as u32 + r.length as u32,
            );
            for seq in
                claim.ack_next + r.offset as u32..claim.ack_next + r.offset as u32 + r.length as u32
            {
                if let Some(h) = t.holes.get_mut(&seq) {
                    h.1 = Some(now);
                }
            }
        }
        if t.stored.len() > claim.sacks.iter().map(|r| r.length as usize).sum::<usize>() {
            t.dirty = true;
            t.due = Some(now + Duration::from_millis(25));
        }
    }
    pub(crate) fn next_feedback_due(&self) -> Option<Instant> {
        let s = self.inner.lock().unwrap();
        if s.closed
            || s.rst_sent
            || s.rst_received
            || s.local_writer_broken
            || s.close_write_sent
            || s.close_write_acked
        {
            return None;
        }
        let t = s.transport.as_ref()?;
        t.due.into_iter().chain(t.reack).chain(t.repair_due).min()
    }
    pub(crate) fn emit_logical_feedback(&self, now: Instant) {
        let budget = {
            let s = self.inner.lock().unwrap();
            let Some(t) = &s.transport else { return };
            t.budget
        };
        let Some(c) = self.claim_feedback(now, budget as usize, false) else {
            return;
        };
        let b = self.encode_feedback_claim(&c);
        // Queueing is not delivery: keep the generation dirty until the wire builder commits it.
        self.enqueuer.push_tx_packet(
            enums::PACKET_PRIORITY_LOW,
            enums::PACKET_STREAM_FEEDBACK,
            0,
            0,
            0,
            0,
            Duration::ZERO,
            &b,
        );
    }
    pub fn encode_feedback_claim(&self, c: &FeedbackClaim) -> Vec<u8> {
        let mut b = vec![1, 1];
        b.extend_from_slice(&self.stream_id.to_be_bytes());
        b.extend_from_slice(&c.ack_next.to_be_bytes());
        b.push(c.sacks.len() as u8);
        b.push(c.repairs.len() as u8);
        for r in c.sacks.iter().chain(&c.repairs) {
            b.extend_from_slice(&r.offset.to_be_bytes());
            b.extend_from_slice(&r.length.to_be_bytes());
        }
        b
    }
    pub(crate) fn stop_on_logical_exhaustion(&self) -> bool {
        let exhausted = self
            .inner
            .lock()
            .unwrap()
            .transport
            .as_ref()
            .is_some_and(|t| t.send_next == u32::MAX);
        if exhausted {
            self.close(
                "Logical sequence space exhausted",
                CloseOptions {
                    send_close_read: true,
                    after_drain: true,
                    ..Default::default()
                },
            );
        }
        exhausted
    }
}

impl Arq {
    pub fn note_logical_dispatched(&self, seq: u32, kind: u8) {
        self.note_tx_generation_dequeued(kind, seq as u16, 0, Some(seq));
        self.flush_deferred_feedback();
    }
    /// If a popped packet cannot be requeued, make it timer-recoverable without
    /// adding false dispatch evidence to the generation ledger.
    pub fn note_logical_send_failed(&self, seq: u32) {
        let mut s = self.inner.lock().unwrap();
        if s.transport.as_ref().and_then(|t| t.logical_for(seq as u16)) != Some(seq) {
            return;
        }
        if let Some(item) = s.snd_buf.get_mut(&(seq as u16)) {
            if !item.dispatched {
                item.dispatched = true;
                item.last_sent_at = Instant::now().checked_sub(item.current_rto);
                s.queued_data = s.queued_data.saturating_sub(1);
            }
        }
        drop(s);
        self.data_dequeued.notify_one();
    }
}

impl Arq {
    pub fn note_logical_write_pending(&self, seq: u32) -> bool {
        let mut s = self.inner.lock().unwrap();
        if !s
            .snd_buf
            .get(&(seq as u16))
            .is_some_and(|i| i.logical_seq == Some(seq))
        {
            return false;
        }
        let Some(t) = s.transport.as_mut() else {
            return false;
        };
        let Some(d) = t.ledger.get_mut(&seq) else {
            return false;
        };
        if d.acked {
            return false;
        }
        if !d.dispatched {
            d.write_pending = true;
        }
        true
    }
    pub fn cancel_logical_write(&self, seq: u32) {
        let mut s = self.inner.lock().unwrap();
        let Some(t) = s.transport.as_mut() else {
            return;
        };
        // A failed retransmission does not invalidate ACKs of its earlier
        // dispatched copy. Nor may a stale ticket erase a newer epoch's ACK.
        let cancel_initial = t.ledger.get_mut(&seq).is_some_and(|d| {
            let pending = !d.dispatched && d.write_pending;
            d.write_pending = false;
            pending
        });
        if !cancel_initial {
            return;
        }
        t.deferred_feedback.retain(|f| {
            !(seq < f.ack
                || f.sacks.iter().chain(&f.repairs).any(|r| {
                    let start = f.ack + r.offset as u32;
                    seq >= start && seq < start + r.length as u32
                }))
        });
    }
    fn flush_deferred_feedback(&self) {
        let pending = {
            let mut s = self.inner.lock().unwrap();
            let Some(t) = s.transport.as_mut() else {
                return;
            };
            std::mem::take(&mut t.deferred_feedback)
        };
        for f in pending {
            self.apply_logical_feedback(f.ack, &f.sacks, &f.repairs);
        }
    }
}

impl TransportState {
    /// Opt-in two-second stall diagnostics only, never per-packet logging.
    pub(crate) fn diagnostic_fields(&self, now: Instant) -> String {
        format!(" logical_send_next={} logical_ack_base={} logical_ledger={} logical_write_pending={} logical_deferred_feedback={} stored_ack={} logical_writer_next={} logical_stored={} logical_holes={} first_logical_hole={:?} feedback_dirty={} feedback_due={} repair_due={} logical_eof={:?}/{:?} logical_rtt_samples={}",
            self.send_next,self.send_ack,self.ledger.len(),self.ledger.values().filter(|d|d.write_pending).count(),self.deferred_feedback.len(),
            self.stored_ack,self.writer_next,self.stored.len(),self.holes.len(),self.holes.first_key_value().map(|(&seq,_)|seq),self.dirty,
            self.due.is_some_and(|at|at<=now),self.repair_due.is_some_and(|at|at<=now),self.local_eof,self.remote_eof,self.rtt_samples)
    }
}

impl Arq {
    /// Observe a negotiated terminal bound without treating the endpoint as
    /// DATA. Only missing retained generations below it become repair holes.
    pub fn receive_logical_eof(&self, end: u32) -> bool {
        let now = Instant::now();
        {
            let mut s = self.inner.lock().unwrap();
            let Some(t) = s.transport.as_ref() else {
                return false;
            };
            if let Some(previous) = t.remote_eof {
                return previous == end;
            }
            if s.closed
                || s.rst_sent
                || s.rst_received
                || end < t.stored_ack
                || end < t.writer_next
                || end - t.stored_ack > t.span as u32
                || t.highest.is_some_and(|highest| highest >= end)
            {
                return false;
            }
            let aborted = s.local_writer_broken;
            let t = s.transport.as_mut().unwrap();
            t.remote_eof = Some(end);
            if !aborted {
                let start = t
                    .highest
                    .map_or(t.stored_ack, |highest| highest + 1)
                    .max(t.stored_ack);
                for seq in start..end {
                    t.holes.insert(seq, (now, None));
                }
                if start < end && self.data_nack_max_gap != 0 {
                    let due = now + self.data_nack_initial_delay;
                    t.repair_due = Some(t.repair_due.map_or(due, |old| old.min(due)));
                    t.repair_refresh = None;
                }
                if end > 0 {
                    t.highest = Some(end - 1);
                }
                t.changed(now);
            }
        }
        self.mark_close_read_received();
        self.reack_scheduled.notify_one();
        true
    }
    pub(crate) fn eof_boundary_drained_locked(s: &crate::state::ArqState) -> bool {
        s.local_writer_broken
            || s.transport
                .as_ref()
                .is_none_or(|t| t.remote_eof.is_some_and(|end| t.writer_next == end))
    }
}

impl TransportState {
    /// Abort retires TX ownership, not by ACK. Retained RX and EOF knowledge
    /// remain valid for the still-live opposite direction.
    pub(crate) fn clear_tx_tracking(&mut self) {
        self.ledger.clear();
        self.deferred_feedback.clear();
        self.send_ack = self.send_next;
    }
    /// Release bounded maps at final close/reset without losing endpoint
    /// scalars needed to validate duplicate EOF controls and late callbacks.
    pub(crate) fn clear_tracking_after_close(&mut self) {
        self.clear_tx_tracking();
        self.stored.clear();
        self.sack_ranges.clear();
        self.repair_ranges.clear();
        self.holes.clear();
        self.dirty = false;
        self.due = None;
        self.reack = None;
        self.repair_due = None;
        self.repair_refresh = None;
        self.generation = self.generation.wrapping_add(1);
    }
}
impl Arq {
    pub fn has_pending_logical_sequence(&self, seq: u32) -> bool {
        let s = self.inner.lock().unwrap();
        s.snd_buf
            .get(&(seq as u16))
            .is_some_and(|item| item.logical_seq == Some(seq))
            && s.transport
                .as_ref()
                .is_some_and(|t| t.ledger.get(&seq).is_some_and(|entry| !entry.acked))
    }
}

impl TransportState {
    #[cfg(test)]
    pub(crate) fn deferred_feedback_count(&self) -> usize {
        self.deferred_feedback.len()
    }
}
