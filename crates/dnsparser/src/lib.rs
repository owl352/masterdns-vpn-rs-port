//! Port of `internal/dnsparser` (parser.go, response.go, transport.go, policy.go).

mod parser;
mod policy;
mod response;
mod transport;

pub use parser::*;
pub use policy::*;
pub use response::*;
pub use transport::*;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DnsParserError {
    #[error("dns packet too short")]
    PacketTooShort,
    #[error("invalid dns name")]
    InvalidName,
    #[error("invalid dns question section")]
    InvalidQuestion,
    #[error("invalid dns resource record section")]
    InvalidAnswer,
    #[error("packet does not look like a complete dns message")]
    NotDnsMessage,
    #[error("packet does not look like a supported dns request")]
    NotDnsRequest,
    #[error("dns txt answer missing")]
    TxtAnswerMissing,
    #[error("dns txt answer malformed")]
    TxtAnswerMalformed,
    #[error("dns txt answer too large")]
    TxtAnswerTooLarge,
}
