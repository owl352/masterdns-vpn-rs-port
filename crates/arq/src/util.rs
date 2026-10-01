//! Small helpers ported from the "Small Utilities" section of `internal/arq/arq.go`.

use crate::types::AdaptiveRtoState;
use std::time::Duration;

pub(crate) fn clamp_duration(v: Duration, min_v: Duration, max_v: Duration) -> Duration {
    v.clamp(min_v, max_v)
}

pub(crate) fn abs_duration(a: Duration, b: Duration) -> Duration {
    if a > b {
        a - b
    } else {
        b - a
    }
}

pub(crate) fn update_adaptive_rto(mut state: AdaptiveRtoState, sample: Duration, min_rto: Duration, max_rto: Duration) -> AdaptiveRtoState {
    // The configured floor bounds the timeout, not the RTT observation.
    // Clamping samples to it hides fast paths and inflates the measured
    // variance, which also makes reordering-aware recovery unnecessarily slow.
    let sample = sample.min(max_rto).max(Duration::from_micros(1));

    if !state.initialized {
        state.srtt = sample;
        state.rttvar = sample / 2;
        state.initialized = true;
    } else {
        let delta = abs_duration(state.srtt, sample);
        state.rttvar = (state.rttvar * 3 + delta) / 4;
        state.srtt = (state.srtt * 7 + sample) / 8;
    }

    state.current_base = clamp_duration(state.srtt + state.rttvar * 4, min_rto, max_rto);
    state
}

/// `candidate` is strictly behind `base` in wrapping sequence-number space
/// (mirrors Go's `seqBehind`).
pub(crate) fn seq_behind(base: u16, candidate: u16) -> bool {
    candidate != base && base.wrapping_sub(candidate) < 32768
}

pub(crate) const DATA_RETRANSMIT_RTO_GROWTH_FACTOR: f64 = 1.35;
pub(crate) const CONTROL_RETRANSMIT_RTO_GROWTH_FACTOR: f64 = 1.25;
pub(crate) const SETUP_CONTROL_RTO_GROWTH_FACTOR: f64 = 1.15;

pub(crate) fn grow_duration(d: Duration, factor: f64) -> Duration {
    Duration::from_secs_f64(d.as_secs_f64() * factor)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_observation_is_not_raised_to_timeout_floor() {
        let min = Duration::from_secs(1);
        let max = Duration::from_secs(10);
        let state = update_adaptive_rto(AdaptiveRtoState::default(), Duration::from_millis(20), min, max);
        assert_eq!(state.srtt, Duration::from_millis(20));
        assert_eq!(state.rttvar, Duration::from_millis(10));
        assert_eq!(state.current_base, min);
        let state = update_adaptive_rto(state, Duration::from_millis(28), min, max);
        assert_eq!(state.srtt, Duration::from_millis(21));
        assert_eq!(state.rttvar, Duration::from_micros(9500));
        assert_eq!(state.current_base, min);
    }

    #[test]
    fn rto_preserves_upper_bound_and_zero_sample_is_safe() {
        let min = Duration::from_millis(100);
        let max = Duration::from_secs(2);
        let state = update_adaptive_rto(AdaptiveRtoState::default(), Duration::from_secs(20), min, max);
        assert_eq!(state.current_base, max);
        let state = update_adaptive_rto(AdaptiveRtoState::default(), Duration::ZERO, min, max);
        assert_eq!(state.srtt, Duration::from_micros(1));
        assert_eq!(state.current_base, min);
    }
}

/// Conservative evidence: eviction can delay repair, never invent loss.
pub(crate) fn later_ack_count(state: &crate::state::ArqState, sn: u16, item: &crate::types::DataItem) -> usize {
    let Some(sent_at) = item.last_sent_at else { return 0; };
    state.ack_evidence.iter().rev().filter(|ack| seq_behind(ack.sn, sn)
        && item.created_at <= ack.created_at && sent_at <= ack.sent_at).take(4).count()
}
