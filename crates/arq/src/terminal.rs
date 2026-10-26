//! Port of the "Terminal Emit / Drain Helpers" section of `internal/arq/arq.go`.

use crate::arq::Arq;
use crate::types::{setup_control_packet_types, CloseOptions, StreamState};
use std::time::{Duration, Instant};

impl Arq {
    pub(crate) fn is_graceful_close_in_progress(&self) -> bool {
        let s = self.inner.lock().unwrap();

        if s.closed {
            return true;
        }
        if s.waiting_ack && (s.waiting_ack_for == enums::PACKET_STREAM_CLOSE_READ || s.waiting_ack_for == enums::PACKET_STREAM_CLOSE_WRITE) {
            return true;
        }
        if s.deferred_close && (s.deferred_packet == enums::PACKET_STREAM_CLOSE_READ || s.deferred_packet == enums::PACKET_STREAM_CLOSE_WRITE) {
            return true;
        }
        match s.state {
            StreamState::HalfClosedLocal
            | StreamState::HalfClosedRemote
            | StreamState::Closing
            | StreamState::Draining
            | StreamState::TimeWait => return true,
            _ => {}
        }
        s.close_read_sent || s.close_read_received || s.close_write_sent || s.close_write_received
    }

    /// Arms a drain-before-terminal phase. Stops new local reads, waits for
    /// pending outbound data to drain, then [`Arq::settle_terminal_drain`]
    /// decides whether to emit the requested close packet or fall back to RST.
    pub(crate) fn defer_terminal_packet(&self, reason: &str, packet_type: u8) {
        let snd_buf_len;
        {
            let mut s = self.inner.lock().unwrap();
            if s.closed || s.is_virtual {
                return;
            }

            if !matches!(s.state, StreamState::Reset | StreamState::Closed) {
                let ns = StreamState::Draining;
                Arq::set_state(&mut s, ns);
            }

            s.stop_local_read = true;
            s.deferred_close = true;
            s.deferred_reason = reason.to_string();
            s.deferred_packet = packet_type;

            let deadline = Instant::now() + self.terminal_drain_timeout;
            s.deferred_deadline = Some(match s.deferred_deadline {
                Some(existing) if existing >= deadline => existing,
                _ => deadline,
            });
            let now = Instant::now();
            Arq::reset_drain_tracking_locked(&mut s, now);

            snd_buf_len = s.snd_buf.len();
        }

        if snd_buf_len == 0 {
            self.settle_terminal_drain();
        }
    }

    /// Completes a previously deferred terminal close.
    pub(crate) fn settle_terminal_drain(&self) {
        let packet_type;
        let should_emit;
        let reason;
        {
            let mut s = self.inner.lock().unwrap();
            if s.closed || !s.deferred_close {
                return;
            }

            if s.snd_buf.is_empty() {
                should_emit = true;
                packet_type = s.deferred_packet;
                reason = s.deferred_reason.clone();
            } else if s.deferred_deadline.map(|d| Instant::now() > d).unwrap_or(false) {
                should_emit = true;
                packet_type = enums::PACKET_STREAM_RST;
                reason = format!("{} but drain timeout expired", s.deferred_reason);
            } else {
                return;
            }

            s.deferred_close = false;
            s.deferred_reason.clear();
            s.deferred_deadline = None;
            s.deferred_packet = 0;
        }

        if should_emit {
            self.close(
                &reason,
                CloseOptions {
                    send_close_read: packet_type == enums::PACKET_STREAM_CLOSE_READ,
                    send_close_write: packet_type == enums::PACKET_STREAM_CLOSE_WRITE,
                    send_rst: packet_type == enums::PACKET_STREAM_RST,
                    ..Default::default()
                },
            );
        }
    }

    pub(crate) fn emit_terminal_packet_with_ttl(&self, packet_type: u8, reason: &str, ttl: Duration) {
        enum Action {
            None,
            CloseRead { seq: u16, payload: Vec<u8> },
            CloseWrite { seq: u16 },
            Rst { seq: u16 },
        }

        let action = {
            let mut s = self.inner.lock().unwrap();
            if s.closed || s.is_virtual {
                return;
            }

            s.close_reason = reason.to_string();
            s.stop_local_read = true;
            s.deferred_close = false;
            s.deferred_reason.clear();
            s.deferred_deadline = None;
            s.deferred_packet = 0;

            if s.waiting_ack && s.waiting_ack_for == packet_type {
                return;
            }

            match packet_type {
                enums::PACKET_STREAM_CLOSE_READ => {
                    if s.rst_sent || s.rst_received || s.close_read_sent {
                        return;
                    }
                    let seq = *s.close_read_seq_sent.get_or_insert(0);
                    s.waiting_ack = true;
                    s.waiting_ack_for = packet_type;
                    s.ack_wait_deadline = Some(Instant::now() + self.terminal_ack_wait);
                    let payload = if self.stream_id != 0 {
                        s.transport.as_mut().map(|t| {
                            let end = *t.local_eof.get_or_insert(t.send_next);
                            end.to_be_bytes().to_vec()
                        }).unwrap_or_default()
                    } else { Vec::new() };
                    Action::CloseRead { seq, payload }
                }
                enums::PACKET_STREAM_CLOSE_WRITE => {
                    if s.rst_received || s.rst_sent || s.close_write_sent {
                        return;
                    }
                    let seq = *s.close_write_seq_sent.get_or_insert(0);
                    s.waiting_ack = true;
                    s.waiting_ack_for = packet_type;
                    s.ack_wait_deadline = Some(Instant::now() + self.terminal_ack_wait);
                    Action::CloseWrite { seq }
                }
                enums::PACKET_STREAM_RST => {
                    if s.rst_received || s.rst_sent {
                        return;
                    }
                    let seq = *s.rst_seq_sent.get_or_insert(0);
                    crate::arq::clear_all_queues(&mut s, true, &self.window_not_full);
                    s.waiting_ack = true;
                    s.waiting_ack_for = packet_type;
                    s.ack_wait_deadline = Some(Instant::now() + self.terminal_ack_wait);
                    Action::Rst { seq }
                }
                _ => Action::None,
            }
        };

        match action {
            Action::CloseRead { seq, payload } => {
                self.mark_close_read_sent();
                self.send_control_packet_with_ttl(
                    enums::PACKET_STREAM_CLOSE_READ,
                    seq,
                    0,
                    0,
                    &payload,
                    enums::default_packet_priority(enums::PACKET_STREAM_CLOSE_READ),
                    self.enable_control_reliability,
                    Some(enums::PACKET_STREAM_CLOSE_READ_ACK),
                    ttl,
                );
            }
            Action::CloseWrite { seq } => {
                self.mark_close_write_sent();
                self.send_control_packet_with_ttl(
                    enums::PACKET_STREAM_CLOSE_WRITE,
                    seq,
                    0,
                    0,
                    &[],
                    enums::default_packet_priority(enums::PACKET_STREAM_CLOSE_WRITE),
                    self.enable_control_reliability,
                    Some(enums::PACKET_STREAM_CLOSE_WRITE_ACK),
                    ttl,
                );
            }
            Action::Rst { seq } => {
                self.mark_rst_sent();
                self.send_control_packet_with_ttl(
                    enums::PACKET_STREAM_RST,
                    seq,
                    0,
                    0,
                    &[],
                    enums::default_packet_priority(enums::PACKET_STREAM_RST),
                    self.enable_control_reliability,
                    Some(enums::PACKET_STREAM_RST_ACK),
                    ttl,
                );
            }
            Action::None => {}
        }
    }
}

/// Whether `packet_type` is a setup control packet (SYN-class), used to widen
/// RTO/retry floors for those specifically.
pub(crate) fn is_setup_control_packet(packet_type: u8) -> bool {
    setup_control_packet_types().contains_key(&packet_type)
}
