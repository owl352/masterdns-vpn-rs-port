//! Port of `internal/vpnproto` (builder.go, parser.go, packing.go, payload.go,
//! session_accept.go, utils.go) from the Go MasterDnsVPN source.

mod builder;
mod flags;
mod packing;
mod parser;
mod payload;
mod session_accept;
mod utils;

pub use builder::*;
pub use flags::{has_compression_extension, has_fragment_extension, has_sequence_extension, has_stream_extension};
pub use packing::*;
pub use parser::*;
pub use payload::*;
pub use session_accept::*;
pub use utils::*;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VpnProtoError {
    #[error("vpn packet too short")]
    PacketTooShort,
    #[error("invalid vpn packet type")]
    InvalidPacketType,
    #[error("invalid vpn header check")]
    InvalidHeaderCheck,
    #[error("invalid encoded vpn labels")]
    InvalidEncodedData,
    #[error("vpn codec unavailable")]
    CodecUnavailable,
    #[error("invalid compressed vpn payload")]
    InvalidCompressedPayload,
}

mod transport;
pub use transport::*;
