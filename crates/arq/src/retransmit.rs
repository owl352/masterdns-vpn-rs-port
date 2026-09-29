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

                let mut effective_rto = info.current_rto;
                if draining && effective_rto > drain_rto_cap {
                    effective_rto = drain_rto_cap;
                }

                if !info.dispatched {
                    continue;
                }
                let last_sent = info.last_sent_at.unwrap_or(now);
                if now.duration_since(last_sent) < effective_rto {
                    continue;
                }

                jobs.push(RtxJob { sn, data: info.data.clone(), compression_type: info.compression_type });
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

        let priority_kinds = self.retransmit_priority_kinds(&jobs);
        for (i, j) in jobs.iter().enumerate() {
            let mut priority = enums::default_packet_priority(enums::PACKET_STREAM_DATA);
            let mut packet_type = enums::PACKET_STREAM_DATA;

            if priority_kinds[i] {
                priority = enums::default_packet_priority(enums::PACKET_STREAM_RESEND);
                packet_type = enums::PACKET_STREAM_RESEND;
            }

            let ok = self.enqueuer.push_tx_packet(priority, packet_type, j.sn, 0, 0, j.compression_type, Duration::ZERO, &j.data);
            if !ok {
                self.note_drain_queue_failure(now);
                continue;
            }

            let mut s = self.inner.lock().unwrap();
            let data_floor = self.current_data_base_rto(&s);
            let mut requeued = false;
            if let Some(info) = s.snd_buf.get_mut(&j.sn) {
                info.last_sent_at = Some(now);
                requeued = info.dispatched;
                info.dispatched = false;
                info.retries += 1;
                info.sample_eligible = false;
                let grown_rto = grow_duration(info.current_rto, DATA_RETRANSMIT_RTO_GROWTH_FACTOR);
                let mut max_rto = self.max_rto;
                if draining && max_rto > drain_rto_cap {
                    max_rto = drain_rto_cap;
                }
                info.current_rto = clamp_duration(grown_rto, data_floor, max_rto);
            }
            if requeued {
                s.queued_data += 1;
            }
        }

        if self.enable_control_reliability {
            self.check_control_retransmits(now);
        }
    }

    fn retransmit_priority_kinds(&self, jobs: &[RtxJob]) -> Vec<bool> {
        if jobs.is_empty() {
            return Vec::new();
        }

        let mut kinds = vec![false; jobs.len()];
        if jobs.len() == 1 {
            kinds[0] = true;
            return kinds;
        }

        let mut front_budget = self.window_size / 10;
        if front_budget < 1 {
            front_budget = 1;
        }
        if front_budget > 64 {
            front_budget = 64;
        }
        if front_budget > jobs.len() {
            front_budget = jobs.len();
        }

        let snd_nxt = self.inner.lock().unwrap().snd_nxt;

        let mut best_idx: Vec<usize> = Vec::with_capacity(front_budget);
        let mut best_dist: Vec<u16> = Vec::with_capacity(front_budget);

        let insert_best = |idx: usize, dist: u16, best_idx: &mut Vec<usize>, best_dist: &mut Vec<u16>| {
            let mut pos = best_idx.len();
            while pos > 0 {
                let prev = pos - 1;
                let prev_dist = best_dist[prev];
                let prev_idx = best_idx[prev];
                if prev_dist > dist || (prev_dist == dist && jobs[prev_idx].sn <= jobs[idx].sn) {
                    break;
                }
                pos -= 1;
            }

            best_idx.insert(pos, idx);
            best_dist.insert(pos, dist);

            if best_idx.len() > front_budget {
                best_idx.truncate(front_budget);
                best_dist.truncate(front_budget);
            }
        };

        for i in 0..jobs.len() {
            let dist = snd_nxt.wrapping_sub(jobs[i].sn);
            if best_idx.len() < front_budget {
                insert_best(i, dist, &mut best_idx, &mut best_dist);
                continue;
            }

            let last = best_idx.len() - 1;
            if dist > best_dist[last] || (dist == best_dist[last] && jobs[i].sn < jobs[best_idx[last]].sn) {
                insert_best(i, dist, &mut best_idx, &mut best_dist);
            }
        }

        for idx in best_idx {
            kinds[idx] = true;
        }

        kinds
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
        let mut retries: Vec<(u32, u8, u16, u8, u8, i32, Vec<u8>, Duration)> = Vec::new();

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

                retries.push((
                    key,
                    info.packet_type,
                    info.sequence_num,
                    info.fragment_id,
                    info.total_fragments,
                    info.priority,
                    info.payload.clone(),
                    info.ttl,
                ));
            }
        }

        if let Some((packet_type, reason)) = expired {
            self.handle_tracked_packet_ttl_expiry(packet_type, reason);
            return;
        }

        for (key, packet_type, sequence_num, fragment_id, total_fragments, priority, payload, ttl) in retries {
            let ok = self.enqueuer.push_tx_packet(priority, packet_type, sequence_num, fragment_id, total_fragments, 0, ttl, &payload);
            if !ok {
                continue;
            }

            let mut s = self.inner.lock().unwrap();
            let mut floor_rto = self.current_control_base_rto(&s);
            if let Some(info) = s.control_snd_buf.get_mut(&key) {
                info.last_sent_at = Some(now);
                info.dispatched = false;
                info.retries += 1;
                info.sample_eligible = false;
                let mut growth = CONTROL_RETRANSMIT_RTO_GROWTH_FACTOR;

                if is_setup_control_packet(packet_type) {
                    growth = SETUP_CONTROL_RTO_GROWTH_FACTOR;
                    let alt_floor = Duration::from_millis(350);
                    if alt_floor < floor_rto {
                        floor_rto = alt_floor;
                    }
                }

                let grown_rto = grow_duration(info.current_rto, growth);
                info.current_rto = clamp_duration(grown_rto, floor_rto, self.control_max_rto);
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
