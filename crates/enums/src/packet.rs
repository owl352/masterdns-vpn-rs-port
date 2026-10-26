//! Wire packet type bytes, ported from `internal/enums/dns.go`.

// MTU discovery packets
pub const PACKET_MTU_UP_REQ: u8 = 0x01;
pub const PACKET_MTU_UP_RES: u8 = 0x02;
pub const PACKET_MTU_DOWN_REQ: u8 = 0x03;
pub const PACKET_MTU_DOWN_RES: u8 = 0x04;

// Session management packets
pub const PACKET_SESSION_INIT: u8 = 0x05;
pub const PACKET_SESSION_ACCEPT: u8 = 0x06;
pub const PACKET_PING: u8 = 0x07;
pub const PACKET_PONG: u8 = 0x08;

// Stream transport packets
pub const PACKET_STREAM_SYN: u8 = 0x09;
pub const PACKET_STREAM_SYN_ACK: u8 = 0x0A;
pub const PACKET_STREAM_CONNECTED: u8 = 0x0B;
pub const PACKET_STREAM_CONNECTED_ACK: u8 = 0x0C;
pub const PACKET_STREAM_CONNECT_FAIL: u8 = 0x0D;
pub const PACKET_STREAM_CONNECT_FAIL_ACK: u8 = 0x0E;
pub const PACKET_STREAM_DATA: u8 = 0x0F;
pub const PACKET_STREAM_DATA_ACK: u8 = 0x10;
pub const PACKET_STREAM_DATA_NACK: u8 = 0x11;
pub const PACKET_STREAM_RESEND: u8 = 0x12;
pub const PACKET_PACKED_CONTROL_BLOCKS: u8 = 0x13;
pub const PACKET_STREAM_CLOSE_WRITE: u8 = 0x14;
pub const PACKET_STREAM_CLOSE_WRITE_ACK: u8 = 0x15;
pub const PACKET_STREAM_CLOSE_READ: u8 = 0x16;
pub const PACKET_STREAM_CLOSE_READ_ACK: u8 = 0x17;
pub const PACKET_STREAM_RST: u8 = 0x18;
pub const PACKET_STREAM_RST_ACK: u8 = 0x19;

// SOCKS5 stream setup packets
pub const PACKET_SOCKS5_SYN: u8 = 0x1A;
pub const PACKET_SOCKS5_SYN_ACK: u8 = 0x1B;

// SOCKS5 result packets
pub const PACKET_SOCKS5_CONNECT_FAIL: u8 = 0x1C;
pub const PACKET_SOCKS5_CONNECT_FAIL_ACK: u8 = 0x1D;
pub const PACKET_SOCKS5_RULESET_DENIED: u8 = 0x1E;
pub const PACKET_SOCKS5_RULESET_DENIED_ACK: u8 = 0x1F;
pub const PACKET_SOCKS5_NETWORK_UNREACHABLE: u8 = 0x20;
pub const PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK: u8 = 0x21;
pub const PACKET_SOCKS5_HOST_UNREACHABLE: u8 = 0x22;
pub const PACKET_SOCKS5_HOST_UNREACHABLE_ACK: u8 = 0x23;
pub const PACKET_SOCKS5_CONNECTION_REFUSED: u8 = 0x24;
pub const PACKET_SOCKS5_CONNECTION_REFUSED_ACK: u8 = 0x25;
pub const PACKET_SOCKS5_TTL_EXPIRED: u8 = 0x26;
pub const PACKET_SOCKS5_TTL_EXPIRED_ACK: u8 = 0x27;
pub const PACKET_SOCKS5_COMMAND_UNSUPPORTED: u8 = 0x28;
pub const PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK: u8 = 0x29;
pub const PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED: u8 = 0x2A;
pub const PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK: u8 = 0x2B;
pub const PACKET_SOCKS5_AUTH_FAILED: u8 = 0x2C;
pub const PACKET_SOCKS5_AUTH_FAILED_ACK: u8 = 0x2D;
pub const PACKET_SOCKS5_UPSTREAM_UNAVAILABLE: u8 = 0x2E;
pub const PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK: u8 = 0x2F;
pub const PACKET_SOCKS5_CONNECTED: u8 = 0x30;
pub const PACKET_SOCKS5_CONNECTED_ACK: u8 = 0x31;

// DNS tunnel packets
pub const PACKET_DNS_QUERY_REQ: u8 = 0x32;
pub const PACKET_DNS_QUERY_RES: u8 = 0x33;
pub const PACKET_DNS_QUERY_REQ_ACK: u8 = 0x34;
pub const PACKET_DNS_QUERY_RES_ACK: u8 = 0x35;

// Session control packets
pub const PACKET_SESSION_CLOSE: u8 = 0x36;
pub const PACKET_SESSION_BUSY: u8 = 0x37;

// Generic error packets
pub const PACKET_ERROR_DROP: u8 = 0xFF;

// Stream states
pub const STREAM_STATE_OPEN: u8 = 1;
pub const STREAM_STATE_HALF_CLOSED_LOCAL: u8 = 2;
pub const STREAM_STATE_HALF_CLOSED_REMOTE: u8 = 3;
pub const STREAM_STATE_DRAINING: u8 = 4;
pub const STREAM_STATE_CLOSING: u8 = 5;
pub const STREAM_STATE_TIME_WAIT: u8 = 6;
pub const STREAM_STATE_RESET: u8 = 7;
pub const STREAM_STATE_CLOSED: u8 = 8;

// Negotiated transport extension v1 (never emitted to unselected peers).
pub const PACKET_TRANSPORT_CAPS: u8 = 0x38;
pub const PACKET_TRANSPORT_CAPS_ACK: u8 = 0x39;
pub const PACKET_STREAM_FEEDBACK: u8 = 0x3A;
pub const PACKET_STREAM_ENVELOPE: u8 = 0x3B;
/// Unreliable UDP datagram on stream 0, only after the datagram feature is selected.
pub const PACKET_UDP_DATAGRAM: u8 = 0x3C;
