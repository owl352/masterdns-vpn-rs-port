//! Port of `internal/vpnproto/utils.go`.

use crate::packing::PACKED_CONTROL_BLOCK_SIZE;

/// Calculates the optimal number of control blocks that can be packed into a
/// single VPN packet based on the MTU, a safety percentage, and an absolute maximum.
pub fn calculate_max_packed_blocks(mtu: i64, percent: i64, absolute_max: i64) -> i64 {
    let mtu = mtu.max(1);
    let percent = percent.max(30);
    let effective_size = (mtu * percent) / 100;
    (effective_size / PACKED_CONTROL_BLOCK_SIZE as i64).max(1).min(absolute_max).max(1)
}
