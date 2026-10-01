//! Opt-in, rate-limited metadata snapshots. No packet payloads or secrets.

use crate::arq::Arq;
use std::time::{Duration, Instant};

impl Arq {
    pub(crate) fn emit_diagnostic_snapshot(&self, now: Instant) {
        let Some(tick) = &self.diagnostic_tick else { return; };
        {
            let mut tick = tick.lock().unwrap();
            if now.saturating_duration_since(*tick) < Duration::from_secs(2) { return; }
            *tick = now;
        }
        // Never log while holding the stream state lock.
        let line = {
            let s = self.inner.lock().unwrap();
            let oldest = s.snd_buf.iter().min_by_key(|(_, item)| item.created_at);
            let hole = s.rcv_buf.keys().filter_map(|sn| {
                let gap = sn.wrapping_sub(s.rcv_nxt);
                (gap < 32768).then_some(gap)
            }).min();
            let line = format!("ARQ Snapshot session={} stream={} state={:?} snd_next={} pending={} queued={} oldest={:?} oldest_ms={} retries={} rcv_next={} buffered={} first_gap={:?} inbound={} writing={} writer_closed={} writer_broken={} close_read={}/{}/{} close_write={}/{}/{} drain={} waiting={} fast_acks={} reacks={} rto_ms={} srtt_ms={} nack_pending={}",
                self.session_id, self.stream_id, s.state, s.snd_nxt, s.snd_buf.len(), s.queued_data,
                oldest.map(|(sn, _)| *sn), oldest.map(|(_, i)| now.saturating_duration_since(i.created_at).as_millis()).unwrap_or(0),
                oldest.map(|(_, i)| i.retries).unwrap_or(0), s.rcv_nxt, s.rcv_buf.len(), hole,
                s.pending_inbound, s.local_write_pending, s.local_write_closed, s.local_writer_broken,
                s.close_read_sent, s.close_read_received, s.close_read_acked,
                s.close_write_sent, s.close_write_received, s.close_write_acked,
                s.deferred_close, s.waiting_ack_for, s.pending_fast_acks.len(), s.pending_reacks.len(),
                s.data_adaptive_rto.current_base.as_millis(), s.data_adaptive_rto.srtt.as_millis(), s.last_data_nack_sent.len());
            format!("{} retry_requested={:?} retry_queued={:?} retry_dispatched={:?} retry_coalesced={:?} original_dispatched={} recovery_scans={}",
                line, s.recovery.requested, s.recovery.queued, s.recovery.dispatched,
                s.recovery.coalesced, s.recovery.original, s.recovery.scans)
        };
        self.logger.infof(&line);
    }
}
