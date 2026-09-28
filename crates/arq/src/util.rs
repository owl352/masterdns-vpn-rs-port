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

pub(crate) fn update_adaptive_rto(
    mut state: AdaptiveRtoState,
    sample: Duration,
    min_rto: Duration,
    max_rto: Duration,
) -> AdaptiveRtoState {
    let sample = clamp_duration(sample, min_rto, max_rto);

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
