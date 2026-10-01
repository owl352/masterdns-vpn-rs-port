//! Port of the "Control Plane Verification" section of `internal/arq/arq.go`.

use crate::arq::{control_key, Arq};
use crate::terminal::is_setup_control_packet;
use crate::types::ControlItem;
use std::time::{Duration, Instant};

impl Arq {
    #[allow(clippy::too_many_arguments)]
    pub fn send_control_packet_with_ttl(
        &self,
        packet_type: u8,
        sequence_num: u16,
        fragment_id: u8,
        total_fragments: u8,
        payload: &[u8],
        priority: i32,
        track_for_ack: bool,
        custom_ack_type: Option<u8>,
        ttl: Duration,
    ) -> bool {
        let copy_data = payload.to_vec();
        let priority = enums::normalize_packet_priority(packet_type, priority);

        if !self.enable_control_reliability || !track_for_ack {
            return self.enqueuer.push_tx_packet(priority, packet_type, sequence_num, fragment_id, total_fragments, 0, ttl, &copy_data);
        }

        let expected_ack = match custom_ack_type {
            Some(v) => v,
            None => match enums::control_ack_for(packet_type) {
                Some(v) => v,
                None => return true,
            },
        };

        let key = control_key(packet_type, sequence_num, fragment_id);
        let now = Instant::now();

        let mut s = self.inner.lock().unwrap();
        if s.control_snd_buf.contains_key(&key) {
            return true;
        }

        let mut initial_rto = self.current_control_base_rto(&s);
        if is_setup_control_packet(packet_type) {
            let alt_rto = Duration::from_millis(350);
            if alt_rto < initial_rto {
                initial_rto = alt_rto;
            }
        }

        s.control_snd_buf.insert(
            key,
            ControlItem {
                packet_type,
                sequence_num,
                fragment_id,
                total_fragments,
                ack_type: expected_ack,
                payload: copy_data,
                priority,
                created_at: now,
                last_sent_at: None,
                dispatched: false,
                retries: 0,
                current_rto: initial_rto,
                sample_eligible: true,
                ttl,
            },
        );

        drop(s);
        let ok = self.enqueuer.push_tx_packet(priority, packet_type, sequence_num, fragment_id, total_fragments, 0, ttl, payload);
        if !ok {
            let mut s = self.inner.lock().unwrap();
            if let Some(item) = s.control_snd_buf.get_mut(&key) {
                if item.created_at == now && !item.dispatched {
                    item.dispatched = true;
                    item.last_sent_at = now.checked_sub(initial_rto);
                    item.sample_eligible = false;
                }
            }
        }
        if !self.inner.lock().unwrap().control_snd_buf.contains_key(&key) {
            self.enqueuer.remove_queued_control(packet_type, sequence_num, fragment_id);
        }
        ok
    }

    pub(crate) fn handle_tracked_packet_ttl_expiry(&self, packet_type: u8, reason: &str) {
        if let Some(close_ack) = enums::get_packet_close_stream(packet_type) {
            let _ = close_ack;
            if packet_type != enums::PACKET_STREAM_CLOSE_READ && packet_type != enums::PACKET_STREAM_CLOSE_WRITE {
                self.finalize_close(reason);
                return;
            }
        }

        self.close(reason, crate::types::CloseOptions { send_rst: true, ..Default::default() });
    }

    fn handle_tracked_terminal_ack(&self, origin_ptype: u8) -> bool {
        if enums::get_packet_close_stream(origin_ptype).is_some()
            && origin_ptype != enums::PACKET_STREAM_CLOSE_READ
            && origin_ptype != enums::PACKET_STREAM_CLOSE_WRITE
            && origin_ptype != enums::PACKET_STREAM_RST
        {
            self.finalize_close(&format!("{} acknowledged", enums::packet_type_name(origin_ptype)));
            return true;
        }
        false
    }

    fn handle_waiting_terminal_ack(
        &self,
        ack_packet_type: u8,
        is_waiting_close_read: bool,
        is_waiting_close_write: bool,
        is_waiting_rst: bool,
    ) -> bool {
        if ack_packet_type == enums::PACKET_STREAM_CLOSE_READ_ACK && is_waiting_close_read {
            self.mark_close_read_acked();
            self.clear_waiting_ack(enums::PACKET_STREAM_CLOSE_READ);
            self.try_finalize_remote_eof();
            return true;
        }

        if ack_packet_type == enums::PACKET_STREAM_CLOSE_WRITE_ACK && is_waiting_close_write {
            self.mark_close_write_acked();
            self.clear_waiting_ack(enums::PACKET_STREAM_CLOSE_WRITE);
            self.maybe_initiate_client_close_read_after_writer_break();
            self.try_finalize_remote_eof();
            return true;
        }

        if ack_packet_type == enums::PACKET_STREAM_RST_ACK && is_waiting_rst {
            self.mark_rst_acked();
            self.finalize_close("RST acknowledged");
            return true;
        }

        false
    }

    fn handle_tracked_close_or_reset_ack(&self, origin_ptype: u8) -> bool {
        match origin_ptype {
            enums::PACKET_STREAM_CLOSE_READ => {
                self.mark_close_read_acked();
                self.clear_waiting_ack(enums::PACKET_STREAM_CLOSE_READ);
                self.try_finalize_remote_eof();
                true
            }
            enums::PACKET_STREAM_CLOSE_WRITE => {
                self.mark_close_write_acked();
                self.clear_waiting_ack(enums::PACKET_STREAM_CLOSE_WRITE);
                self.maybe_initiate_client_close_read_after_writer_break();
                self.try_finalize_remote_eof();
                true
            }
            enums::PACKET_STREAM_RST => {
                self.mark_rst_acked();
                self.finalize_close("RST acknowledged");
                true
            }
            _ => false,
        }
    }

    pub fn receive_control_ack(&self, ack_packet_type: u8, sequence_num: u16, fragment_id: u8) -> bool {
        let now = Instant::now();
        let origin_ptype;
        let mut tracked;
        let is_close_stream_packet;
        let mut sample = Duration::ZERO;
        let mut sample_eligible = false;
        let is_waiting_close_read;
        let is_waiting_close_write;
        let is_waiting_rst;

        {
            let mut s = self.inner.lock().unwrap();
            s.last_activity = now;

            origin_ptype = match enums::reverse_control_ack_for(ack_packet_type) {
                Some(v) => v,
                None => return false,
            };

            let key = control_key(origin_ptype, sequence_num, fragment_id);
            tracked = s.control_snd_buf.contains_key(&key);
            is_close_stream_packet = enums::get_packet_close_stream(origin_ptype).is_some();

            if !tracked && is_close_stream_packet {
                tracked = s.control_snd_buf.values().any(|info| info.packet_type == origin_ptype);
            }

            let waiting_for = s.waiting_ack_for;
            is_waiting_close_read = ack_packet_type == enums::PACKET_STREAM_CLOSE_READ_ACK && waiting_for == enums::PACKET_STREAM_CLOSE_READ;
            is_waiting_close_write = ack_packet_type == enums::PACKET_STREAM_CLOSE_WRITE_ACK && waiting_for == enums::PACKET_STREAM_CLOSE_WRITE;
            is_waiting_rst = ack_packet_type == enums::PACKET_STREAM_RST_ACK && waiting_for == enums::PACKET_STREAM_RST;

            if !tracked && !is_waiting_close_read && !is_waiting_close_write && !is_waiting_rst {
                return false;
            }

            if tracked {
                if let Some(info) = s.control_snd_buf.get(&key) {
                    if info.sample_eligible && info.dispatched {
                        if let Some(last_sent_at) = info.last_sent_at {
                            sample = now.duration_since(last_sent_at);
                            sample_eligible = true;
                        }
                    }
                }
                if is_close_stream_packet {
                    s.control_snd_buf.retain(|_, info| info.packet_type != origin_ptype);
                } else {
                    s.control_snd_buf.remove(&key);
                }
            }
        }

        if tracked {
            self.enqueuer.remove_queued_control(origin_ptype, sequence_num, fragment_id);
        }
        if tracked && sample_eligible {
            self.note_successful_control_sample(sample);
        }

        if tracked && self.handle_tracked_close_or_reset_ack(origin_ptype) {
            return true;
        }
        if tracked && self.handle_tracked_terminal_ack(origin_ptype) {
            return true;
        }
        if self.handle_waiting_terminal_ack(ack_packet_type, is_waiting_close_read, is_waiting_close_write, is_waiting_rst) {
            return true;
        }

        tracked
    }

    pub fn handle_ack_packet(&self, packet_type: u8, sequence_num: u16, fragment_id: u8) -> bool {
        if packet_type == enums::PACKET_STREAM_DATA_ACK {
            return self.receive_ack(packet_type, sequence_num);
        }

        if enums::reverse_control_ack_for(packet_type).is_none() {
            return false;
        }

        self.receive_control_ack(packet_type, sequence_num, fragment_id)
    }
}
