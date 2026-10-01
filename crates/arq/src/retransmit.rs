//! Port of the "Retransmit Scheduler" and "Retransmit Checks" sections of
//! `internal/arq/arq.go`.

use crate::arq::Arq;
use crate::terminal::is_setup_control_packet;
use crate::types::{RtxJob, StreamState};
use crate::util::*;
use std::time::{Duration, Instant};

impl Arq {
    pub(crate) fn check_retransmits(&self) {
        if self.is_closed() {
            return;
        }

        let now = Instant::now();
        self.run_gap_recovery_watchdog(now);
        self.run_final_ack_watchdog(now);
        self.emit_due_reacks(now);
        self.emit_due_fast_acks(now);

        if self.handle_terminal_retransmit_state(now) {
            return;
        }

        let mut jobs: Vec<RtxJob> = Vec::new();
        let mut ttl_expired = false;
        let mut retry_exceeded = false;
        let draining;
        let drain_rto_cap = clamp_duration(Duration::from_secs(2), self.rto, self.max_rto);

        {
            let s = self.inner.lock().unwrap();
            draining = s.deferred_close || matches!(s.state, StreamState::Draining);
            let reorder_grace = self.reorder_grace(&s);
            let data_base = self.current_data_base_rto(&s);

            for (&sn, info) in s.snd_buf.iter() {
                if !info.ttl.is_zero() {
                    if now.duration_since(info.created_at) >= info.ttl {
                        ttl_expired = true;
                        break;
                    }
                } else if now.duration_since(info.created_at) >= self.data_packet_ttl && info.retries >= self.max_data_retries {
                    retry_exceeded = true;
                    break;
                }

                // Packets queued before the first RTT sample must benefit
                // from that sample too, especially when the initial guess
                // was shorter than the actual resolver path.
                let mut effective_rto = info.current_rto.max(data_base);
                if draining && effective_rto > drain_rto_cap {
                    effective_rto = drain_rto_cap;
                }

                if !info.dispatched {
                    continue;
                }
                let last_sent = info.last_sent_at.unwrap_or(now);
                let age = now.saturating_duration_since(last_sent);
                let timed_out = age >= effective_rto;
                let fast_due = info.later_acks >= 4 && age >= reorder_grace;
                if !timed_out && !fast_due {
                    continue;
                }

                jobs.push(RtxJob {
                    sn,
                    sent_at: last_sent,
                    timed_out,
                });
            }
        }

        if ttl_expired {
            self.handle_tracked_packet_ttl_expiry(enums::PACKET_STREAM_DATA, "Packet TTL expired");
            return;
        }
        if retry_exceeded {
            self.close("Max retransmissions exceeded", crate::types::CloseOptions { send_rst: true, ..Default::default() });
            return;
        }

        // Repair the oldest holes first; bound work so a loss burst cannot
        // fill every reply slot with recovery packets in one tick.
        jobs.sort_by_key(|j| j.sent_at);
        jobs.truncate((self.window_size / 10).clamp(1, 32));
        for j in &jobs {
            self.queue_data_retry(j.sn, now, Some(j.sent_at), j.timed_out, false);
        }

        if self.enable_control_reliability {
            self.check_control_retransmits(now);
        }
    }

    pub(crate) fn next_data_retry_due(&self) -> Option<Instant> {
        let s = self.inner.lock().unwrap();
        // Until a genuine RTT sample exists, retain the existing scheduler's
        // cadence. An exact initial-RTO deadline can expire every packet on
        // paths slower than that initial guess, exclude every ACK under Karn,
        // and prevent the estimator from ever learning the actual RTT.
        if !s.data_adaptive_rto.initialized {
            return None;
        }
        let grace = self.reorder_grace(&s);
        let draining = s.deferred_close || matches!(s.state, StreamState::Draining);
        let cap = clamp_duration(Duration::from_secs(2), self.rto, self.max_rto);
        s.snd_buf
            .values()
            .filter(|item| item.dispatched)
            .filter_map(|item| {
                let at = item.last_sent_at?;
                let timeout = item.current_rto.max(self.current_data_base_rto(&s));
                let timeout = if draining { timeout.min(cap) } else { timeout };
                Some(at + if item.later_acks >= 4 { timeout.min(grace) } else { timeout })
            })
            .min()
    }

    fn reorder_grace(&self, s: &crate::state::ArqState) -> Duration {
        let rtt = &s.data_adaptive_rto;
        if !rtt.initialized {
            return self.rto;
        }
        // Four later ACKs alone are not loss evidence on mixed resolvers.
        // Allow a complete RTT plus its observed jitter before early repair.
        (rtt.srtt + rtt.rttvar * 4).max(Duration::from_millis(100)).min(self.max_rto)
    }

    /// Reserve a retry before enqueueing it, shared by timeout, early recovery
    /// and explicit NACK. Never overwrite a concurrent dequeue's timestamp.
    /// Queue failure rolls back only our still-queued reservation.
    pub(crate) fn queue_data_retry(&self, sn: u16, now: Instant, expected_sent: Option<Instant>, timed_out: bool, nack: bool) -> bool {
        let previous = {
            let mut s = self.inner.lock().unwrap();
            if s.closed || s.rst_sent || s.rst_received {
                return false;
            }
            let floor = self.current_data_base_rto(&s);
            let ceiling = if s.deferred_close || matches!(s.state, StreamState::Draining) {
                self.max_rto.min(clamp_duration(Duration::from_secs(2), self.rto, self.max_rto))
            } else {
                self.max_rto
            };
            if nack {
                s.last_activity = now;
            }
            let Some(item) = s.snd_buf.get_mut(&sn) else {
                return false;
            };
            if !item.dispatched || expected_sent.is_some_and(|at| item.last_sent_at != Some(at)) {
                return false;
            }
            if nack
                && item
                    .last_nack_sent_at
                    .is_some_and(|at| now.saturating_duration_since(at) < self.data_nack_repeat_interval)
            {
                return false;
            }
            let previous = item.clone();
            item.dispatched = false;
            item.sample_eligible = false;
            item.later_acks = 0;
            item.retries += 1;
            if nack {
                item.last_nack_sent_at = Some(now);
            }
            if timed_out {
                item.current_rto = clamp_duration(grow_duration(item.current_rto, DATA_RETRANSMIT_RTO_GROWTH_FACTOR), floor, ceiling);
            }
            s.queued_data += 1;
            previous
        };
        let ok = self.enqueuer.push_tx_packet(
            enums::default_packet_priority(enums::PACKET_STREAM_RESEND),
            enums::PACKET_STREAM_RESEND,
            sn,
            0,
            0,
            previous.compression_type,
            previous.ttl,
            &previous.data,
        );
        if !ok {
            let mut s = self.inner.lock().unwrap();
            if let Some(item) = s.snd_buf.get_mut(&sn) {
                if item.created_at == previous.created_at && !item.dispatched && item.retries == previous.retries + 1 {
                    *item = previous;
                    s.queued_data = s.queued_data.saturating_sub(1);
                }
            }
            drop(s);
            self.data_dequeued.notify_one();
            self.note_drain_queue_failure(now);
            return false;
        }
        // An ACK may have arrived between reservation and enqueue. Remove
        // its stale queued retry; the response path also filters stale data.
        if !self.has_pending_sequence(sn) {
            self.enqueuer.remove_queued_data(sn);
        }
        true
    }

    fn handle_terminal_retransmit_state(&self, now: Instant) -> bool {
        enum Outcome {
            SettleTerminalDrain,
            AbortEarly,
            Nothing,
            FinalizePeerResetDrain,
            CloseRstFinalizeAckTimeout,
            CloseRstHandshakeAckTimeout,
            CloseWriteAfterEofGrace,
            CloseInactivityTimeout,
            KeepAlivePending,
        }

        let outcome = {
            let mut s = self.inner.lock().unwrap();
            if s.deferred_close {
                let pending = s.snd_buf.len();
                let should_close = pending == 0;
                let should_abort = s.deferred_deadline.map(|d| now.after(d)).unwrap_or(false);
                let stalled_for = s.drain_progress_at.map(|t| now.duration_since(t)).unwrap_or(Duration::ZERO);
                let queue_blocked = s.drain_queue_fails >= 3
                    && s.drain_queue_fail_at.map(|t| now.duration_since(t) <= Duration::from_secs(30)).unwrap_or(false);
                let should_abort_early = pending > 0 && queue_blocked && stalled_for >= Duration::from_secs(20);
                if should_abort_early && !s.drain_stall_logged {
                    s.drain_stall_logged = true;
                    self.logger.debugf(&format!(
                        "ARQ Drain Stall | Session: {} | Stream: {} | Pending: {} | QueueFails: {} | Reason: {}",
                        self.session_id, self.stream_id, pending, s.drain_queue_fails, s.deferred_reason,
                    ));
                }

                if should_close || should_abort {
                    Outcome::SettleTerminalDrain
                } else if should_abort_early {
                    Outcome::AbortEarly
                } else {
                    // `s` still holds `inner`; calling `self.is_closed()` here
                    // would re-lock it and deadlock (std Mutex is not re-entrant).
                    return s.closed;
                }
            } else if s.waiting_ack && s.ack_wait_deadline.map(|d| now.after(d)).unwrap_or(false) {
                let waiting_for = s.waiting_ack_for;
                if waiting_for == enums::PACKET_STREAM_RST {
                    Outcome::CloseRstFinalizeAckTimeout
                } else if waiting_for == enums::PACKET_STREAM_CLOSE_READ || waiting_for == enums::PACKET_STREAM_CLOSE_WRITE {
                    Outcome::CloseRstHandshakeAckTimeout
                } else {
                    Outcome::Nothing
                }
            } else if s.rst_received && !s.closed {
                Outcome::FinalizePeerResetDrain
            } else {
                let receive_drained_for_close_write = s.rcv_buf.is_empty() && s.pending_inbound == 0 && !s.local_write_pending;
                let peer_finished_sending = s.close_read_received || s.local_writer_broken;
                let should_initiate_close_write_after_eof = self.is_client
                    && (s.client_eof_at.map(|t| now.duration_since(t) >= Duration::from_secs(2)).unwrap_or(false)
                        || s.close_read_acked_at.map(|t| now.duration_since(t) >= Duration::from_secs(2)).unwrap_or(false))
                    && !s.closed
                    && !s.rst_sent
                    && !s.rst_received
                    && s.close_read_sent
                    && s.close_read_acked
                    && !s.close_write_sent
                    && !s.close_write_acked
                    && !s.close_write_received
                    && !(s.waiting_ack && s.waiting_ack_for == enums::PACKET_STREAM_CLOSE_WRITE)
                    && receive_drained_for_close_write
                    && peer_finished_sending;

                if should_initiate_close_write_after_eof {
                    Outcome::CloseWriteAfterEofGrace
                } else if now.duration_since(s.last_activity) > self.inactivity_timeout {
                    let has_pending = !s.snd_buf.is_empty() || (self.enable_control_reliability && !s.control_snd_buf.is_empty());
                    if has_pending {
                        s.last_activity = now;
                        Outcome::KeepAlivePending
                    } else {
                        Outcome::CloseInactivityTimeout
                    }
                } else {
                    Outcome::Nothing
                }
            }
        };

        match outcome {
            Outcome::SettleTerminalDrain => {
                self.settle_terminal_drain();
                self.is_closed()
            }
            Outcome::AbortEarly => {
                self.close(
                    "Deferred drain stalled after resend queue pressure",
                    crate::types::CloseOptions { send_rst: true, ..Default::default() },
                );
                self.is_closed()
            }
            Outcome::CloseRstFinalizeAckTimeout => {
                self.finalize_close("Terminal ACK wait timeout");
                true
            }
            Outcome::CloseRstHandshakeAckTimeout => {
                self.close(
                    "Close handshake ACK wait timeout",
                    crate::types::CloseOptions { send_rst: true, ..Default::default() },
                );
                false
            }
            Outcome::FinalizePeerResetDrain => self.try_finalize_peer_reset_drain(),
            Outcome::CloseWriteAfterEofGrace => {
                self.close(
                    "Client close-read grace elapsed",
                    crate::types::CloseOptions { send_close_write: true, ..Default::default() },
                );
                false
            }
            Outcome::CloseInactivityTimeout => {
                self.close(
                    "Stream Inactivity Timeout (Dead)",
                    crate::types::CloseOptions { send_rst: true, ..Default::default() },
                );
                true
            }
            Outcome::KeepAlivePending | Outcome::Nothing => false,
        }
    }

    fn check_control_retransmits(&self, now: Instant) {
        let mut expired: Option<(u8, &'static str)> = None;
        let mut retries = Vec::new();

        {
            let mut s = self.inner.lock().unwrap();
            let keys: Vec<u32> = s.control_snd_buf.keys().copied().collect();

            'outer: for key in keys {
                let (packet_type, expired_now, reason) = {
                    let info = match s.control_snd_buf.get(&key) {
                        Some(i) => i,
                        None => continue,
                    };

                    if !info.ttl.is_zero() {
                        if now.duration_since(info.created_at) >= info.ttl {
                            (info.packet_type, true, "Packet TTL expired")
                        } else {
                            (info.packet_type, false, "")
                        }
                    } else {
                        let mut max_retries = self.control_max_retries;
                        let mut packet_ttl = self.control_packet_ttl;

                        if is_setup_control_packet(info.packet_type) {
                            max_retries = max_retries.max(120);
                            packet_ttl = packet_ttl.max(Duration::from_secs(300));
                        }

                        let expired_by_ttl = now.duration_since(info.created_at) >= packet_ttl;
                        let exceeded_retries = info.retries >= max_retries;
                        if expired_by_ttl || exceeded_retries {
                            let reason = if exceeded_retries { "Control packet max retransmissions exceeded" } else { "Control packet expired" };
                            (info.packet_type, true, reason)
                        } else {
                            (info.packet_type, false, "")
                        }
                    }
                };

                if expired_now {
                    s.control_snd_buf.remove(&key);
                    expired = Some((packet_type, reason));
                    break 'outer;
                }

                let info = s.control_snd_buf.get(&key).unwrap();
                if !info.dispatched || info.last_sent_at.map(|t| now.duration_since(t) < info.current_rto).unwrap_or(true) {
                    continue;
                }

                retries.push((key, info.clone()));
            }
        }

        if let Some((packet_type, reason)) = expired {
            self.handle_tracked_packet_ttl_expiry(packet_type, reason);
            return;
        }

        for (key, previous) in retries {
            {
                let mut s = self.inner.lock().unwrap();
                if s.closed { return; }
                let mut floor = self.current_control_base_rto(&s);
                let Some(item) = s.control_snd_buf.get_mut(&key) else { continue; };
                if !item.dispatched || item.last_sent_at != previous.last_sent_at || item.created_at != previous.created_at {
                    continue;
                }
                let growth = if is_setup_control_packet(item.packet_type) {
                    floor = floor.min(Duration::from_millis(350));
                    SETUP_CONTROL_RTO_GROWTH_FACTOR
                } else { CONTROL_RETRANSMIT_RTO_GROWTH_FACTOR };
                item.dispatched = false;
                item.retries += 1;
                item.sample_eligible = false;
                item.current_rto = clamp_duration(grow_duration(item.current_rto, growth), floor, self.control_max_rto);
            }
            let ok = self.enqueuer.push_tx_packet(previous.priority, previous.packet_type, previous.sequence_num,
                previous.fragment_id, previous.total_fragments, 0, previous.ttl, &previous.payload);
            if !ok {
                let mut s = self.inner.lock().unwrap();
                if let Some(item) = s.control_snd_buf.get_mut(&key) {
                    if item.created_at == previous.created_at && !item.dispatched && item.retries == previous.retries + 1 {
                        *item = previous.clone();
                    }
                }
            }
            if !self.inner.lock().unwrap().control_snd_buf.contains_key(&key) {
                self.enqueuer.remove_queued_control(previous.packet_type, previous.sequence_num, previous.fragment_id);
            }
        }
    }
}

trait InstantExt {
    fn after(&self, other: Instant) -> bool;
}
impl InstantExt for Instant {
    fn after(&self, other: Instant) -> bool {
        *self > other
    }
}
