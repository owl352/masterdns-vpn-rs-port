//! Port of `internal/socksproto` (target.go, udp.go): SOCKS4/5 wire-format
//! helpers — pure parse/build functions, no state, no negotiation logic.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const ADDRESS_TYPE_IPV4: u8 = 0x01;
pub const ADDRESS_TYPE_DOMAIN: u8 = 0x03;
pub const ADDRESS_TYPE_IPV6: u8 = 0x04;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SocksProtoError {
    #[error("socks target payload too short")]
    TargetTooShort,
    #[error("unsupported socks address type")]
    UnsupportedAddressType,
    #[error("invalid socks domain length")]
    InvalidDomainLength,
    #[error("socks udp datagram too short")]
    UdpDatagramTooShort,
    #[error("socks udp fragmentation unsupported")]
    UdpFragmented,
}

use SocksProtoError as Error;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Target {
    pub address_type: u8,
    pub host: String,
    pub port: u16,
}

pub fn parse_target_payload(payload: &[u8]) -> Result<Target, Error> {
    if payload.len() < 3 {
        return Err(Error::TargetTooShort);
    }

    let mut target = Target { address_type: payload[0], ..Default::default() };
    let mut offset = 1usize;

    match payload[0] {
        ADDRESS_TYPE_IPV4 => {
            if payload.len() < offset + 4 + 2 {
                return Err(Error::TargetTooShort);
            }
            let ip = Ipv4Addr::new(payload[offset], payload[offset + 1], payload[offset + 2], payload[offset + 3]);
            target.host = ip.to_string();
            offset += 4;
        }
        ADDRESS_TYPE_DOMAIN => {
            if payload.len() < offset + 1 {
                return Err(Error::TargetTooShort);
            }
            let domain_length = payload[offset] as usize;
            offset += 1;
            if domain_length < 1 || payload.len() < offset + domain_length + 2 {
                return Err(Error::InvalidDomainLength);
            }
            target.host = String::from_utf8_lossy(&payload[offset..offset + domain_length]).into_owned();
            offset += domain_length;
        }
        ADDRESS_TYPE_IPV6 => {
            if payload.len() < offset + 16 + 2 {
                return Err(Error::TargetTooShort);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&payload[offset..offset + 16]);
            target.host = Ipv6Addr::from(octets).to_string();
            offset += 16;
        }
        _ => return Err(Error::UnsupportedAddressType),
    }

    target.port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    Ok(target)
}

/// Parses `host` as an IPv4 address, falling back to `0.0.0.0` if it isn't a
/// valid IPv4 literal — mirrors Go's never-fails `ParseIPv4`.
pub fn parse_ipv4(host: &str) -> Ipv4Addr {
    host.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED)
}

/// Parses `host` as an IPv6 address, falling back to `::` if it isn't a
/// valid IPv6 literal (an IPv4 literal also falls back to `::`, matching Go's
/// `ParseIPv6`, which only accepts genuinely non-IPv4-mapped addresses here).
pub fn parse_ipv6(host: &str) -> Ipv6Addr {
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) => v6,
        _ => Ipv6Addr::UNSPECIFIED,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UdpDatagram {
    pub target: Target,
    pub payload: Vec<u8>,
}

pub fn parse_udp_datagram(packet: &[u8]) -> Result<UdpDatagram, Error> {
    if packet.len() < 4 {
        return Err(Error::UdpDatagramTooShort);
    }
    if packet[2] != 0 {
        return Err(Error::UdpFragmented);
    }

    let (target, mut offset) = parse_target_with_offset(&packet[3..])?;
    offset += 3;
    if packet.len() < offset {
        return Err(Error::UdpDatagramTooShort);
    }

    Ok(UdpDatagram { target, payload: packet[offset..].to_vec() })
}

pub fn build_udp_datagram(target: &Target, payload: &[u8]) -> Vec<u8> {
    let mut target_len = 1 + 2; // Type + Port
    let host_bytes = target.host.as_bytes();
    match target.address_type {
        ADDRESS_TYPE_IPV4 => target_len += 4,
        ADDRESS_TYPE_IPV6 => target_len += 16,
        ADDRESS_TYPE_DOMAIN => target_len += 1 + host_bytes.len(),
        _ => {}
    }

    let mut packet = vec![0u8; 3 + target_len + payload.len()];
    // Header: RSV(2) + FRAG(1), already zero.

    let mut offset = 3usize;
    packet[offset] = target.address_type;
    offset += 1;

    match target.address_type {
        ADDRESS_TYPE_IPV4 => {
            packet[offset..offset + 4].copy_from_slice(&parse_ipv4(&target.host).octets());
            offset += 4;
        }
        ADDRESS_TYPE_IPV6 => {
            packet[offset..offset + 16].copy_from_slice(&parse_ipv6(&target.host).octets());
            offset += 16;
        }
        ADDRESS_TYPE_DOMAIN => {
            packet[offset] = host_bytes.len() as u8;
            offset += 1;
            packet[offset..offset + host_bytes.len()].copy_from_slice(host_bytes);
            offset += host_bytes.len();
        }
        _ => {}
    }

    packet[offset..offset + 2].copy_from_slice(&target.port.to_be_bytes());
    offset += 2;
    packet[offset..].copy_from_slice(payload);

    packet
}

pub fn build_target_payload(target: &Target) -> Vec<u8> {
    match target.address_type {
        ADDRESS_TYPE_IPV4 => {
            let mut packet = vec![0u8; 1 + 4 + 2];
            packet[0] = ADDRESS_TYPE_IPV4;
            packet[1..5].copy_from_slice(&parse_ipv4(&target.host).octets());
            packet[5..7].copy_from_slice(&target.port.to_be_bytes());
            packet
        }
        ADDRESS_TYPE_IPV6 => {
            let mut packet = vec![0u8; 1 + 16 + 2];
            packet[0] = ADDRESS_TYPE_IPV6;
            packet[1..17].copy_from_slice(&parse_ipv6(&target.host).octets());
            packet[17..19].copy_from_slice(&target.port.to_be_bytes());
            packet
        }
        _ => {
            let host_bytes = target.host.as_bytes();
            let mut packet = vec![0u8; 1 + 1 + host_bytes.len() + 2];
            packet[0] = ADDRESS_TYPE_DOMAIN;
            packet[1] = host_bytes.len() as u8;
            packet[2..2 + host_bytes.len()].copy_from_slice(host_bytes);
            packet[2 + host_bytes.len()..].copy_from_slice(&target.port.to_be_bytes());
            packet
        }
    }
}

fn parse_target_with_offset(payload: &[u8]) -> Result<(Target, usize), Error> {
    let target = parse_target_payload(payload)?;

    let mut offset = 1usize;
    match target.address_type {
        ADDRESS_TYPE_IPV4 => offset += 4 + 2,
        ADDRESS_TYPE_IPV6 => offset += 16 + 2,
        ADDRESS_TYPE_DOMAIN => {
            if payload.len() < 2 {
                return Err(Error::TargetTooShort);
            }
            offset += 1 + payload[1] as usize + 2;
        }
        _ => return Err(Error::UnsupportedAddressType),
    }
    Ok((target, offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_payload_round_trip_ipv4() {
        let target = Target { address_type: ADDRESS_TYPE_IPV4, host: "192.168.1.1".to_string(), port: 8080 };
        let built = build_target_payload(&target);
        let parsed = parse_target_payload(&built).unwrap();
        assert_eq!(parsed, target);
    }

    #[test]
    fn target_payload_round_trip_ipv6() {
        let target = Target { address_type: ADDRESS_TYPE_IPV6, host: "::1".to_string(), port: 443 };
        let built = build_target_payload(&target);
        let parsed = parse_target_payload(&built).unwrap();
        assert_eq!(parsed, target);
    }

    #[test]
    fn target_payload_round_trip_domain() {
        let target = Target { address_type: ADDRESS_TYPE_DOMAIN, host: "example.com".to_string(), port: 53 };
        let built = build_target_payload(&target);
        let parsed = parse_target_payload(&built).unwrap();
        assert_eq!(parsed, target);
    }

    #[test]
    fn udp_datagram_round_trip() {
        let target = Target { address_type: ADDRESS_TYPE_DOMAIN, host: "example.com".to_string(), port: 53 };
        let built = build_udp_datagram(&target, b"hello");
        let parsed = parse_udp_datagram(&built).unwrap();
        assert_eq!(parsed.target, target);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn udp_datagram_rejects_fragmentation() {
        let mut packet = vec![0u8, 0, 1, ADDRESS_TYPE_IPV4, 1, 2, 3, 4, 0, 80];
        packet[2] = 1; // FRAG != 0
        assert_eq!(parse_udp_datagram(&packet).unwrap_err(), SocksProtoError::UdpFragmented);
    }

    #[test]
    fn truncated_target_errors() {
        assert_eq!(parse_target_payload(&[ADDRESS_TYPE_IPV4, 1, 2]).unwrap_err(), SocksProtoError::TargetTooShort);
    }

    #[test]
    fn ip_parsers_never_fail() {
        assert_eq!(parse_ipv4("not-an-ip"), Ipv4Addr::UNSPECIFIED);
        assert_eq!(parse_ipv6("not-an-ip"), Ipv6Addr::UNSPECIFIED);
        assert_eq!(parse_ipv6("192.168.1.1"), Ipv6Addr::UNSPECIFIED);
    }
}
