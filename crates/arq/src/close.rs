//! Port of the "Final Close Path" section of `internal/arq/arq.go`.

use crate::arq::{clear_all_queues, Arq};
use crate::types::{CloseOptions, StreamState};

impl Arq {
    pub(crate) fn finalize_close(&self, reason: &str) {
        {
            let mut s = self.inner.lock().unwrap();
            if s.closed || s.is_virtual {
                return;
            }

            s.close_reason = reason.to_string();
            s.closed = true;
            s.deferred_close = false;
            s.deferred_reason.clear();
            s.deferred_deadline = None;
            s.deferred_packet = 0;
            s.waiting_ack = false;
            s.waiting_ack_for = 0;
            s.ack_wait_deadline = None;

            let new_state = if matches!(s.state, StreamState::Reset) || s.rst_received || s.rst_sent {
                StreamState::Reset
            } else if s.close_read_sent || s.close_read_received || s.close_write_sent || s.close_write_received {
                StreamState::TimeWait
            } else {
                StreamState::Closing
            };
            Arq::set_state(&mut s, new_state);

            clear_all_queues(&mut s, true, &self.window_not_full);
        }

        self.cancel_token.cancel();

        // Drop (force-close) the local connection halves. If a loop currently
        // has one "checked out" across an `.await` (see loops.rs), this finds
        // `None` here and the loop closes it itself once it next checks
        // `is_closed()` — see the comment on these fields in `arq.rs`.
        self.local_conn_read.lock().unwrap().take();
        self.local_conn_write.lock().unwrap().take();

        self.logger.debugf(&format!(
            "ARQ Stream Closed | Session: {} | Stream: {} | Reason: {}",
            self.session_id, self.stream_id, reason,
        ));

        self.enqueuer.on_arq_closed(reason);
    }

    /// The single close entrypoint for this ARQ stream. Modes are expressed
    /// through `opts`:
    /// - `force`: finalize immediately
    /// - `send_close_read`: local read side ended; peer should finish draining inbound and close writer
    /// - `send_close_write`: local write side ended; peer should stop sending to us
    /// - `send_rst`: reset close, optionally after drain
    pub fn close(&self, reason: &str, opts: CloseOptions) {
        let is_virtual = self.inner.lock().unwrap().is_virtual;
        if is_virtual && !opts.force {
            return;
        }

        if opts.force || (!opts.send_rst && !opts.send_close_read && !opts.send_close_write) {
            self.inner.lock().unwrap().is_virtual = false;
            self.finalize_close(reason);
            return;
        }

        if opts.send_close_read {
            if opts.after_drain {
                self.defer_terminal_packet(reason, enums::PACKET_STREAM_CLOSE_READ);
                return;
            }
            self.emit_terminal_packet_with_ttl(enums::PACKET_STREAM_CLOSE_READ, reason, opts.ttl);
            return;
        }

        if opts.send_close_write {
            self.emit_terminal_packet_with_ttl(enums::PACKET_STREAM_CLOSE_WRITE, reason, opts.ttl);
            return;
        }

        let has_pending_data;
        {
            let mut s = self.inner.lock().unwrap();
            if s.closed {
                return;
            }

            let already_resetting = s.rst_sent
                || s.rst_received
                || (s.waiting_ack && s.waiting_ack_for == enums::PACKET_STREAM_RST)
                || (s.deferred_close && s.deferred_packet == enums::PACKET_STREAM_RST);
            if already_resetting {
                return;
            }

            has_pending_data = !s.snd_buf.is_empty();
            s.close_reason = reason.to_string();
            let ns = StreamState::Reset;
            Arq::set_state(&mut s, ns);
            s.deferred_close = false;
            s.deferred_reason.clear();
            s.deferred_deadline = None;
            s.deferred_packet = 0;
        }

        if opts.after_drain && has_pending_data {
            self.defer_terminal_packet(reason, enums::PACKET_STREAM_RST);
            return;
        }

        self.emit_terminal_packet_with_ttl(enums::PACKET_STREAM_RST, reason, opts.ttl);
    }
}
