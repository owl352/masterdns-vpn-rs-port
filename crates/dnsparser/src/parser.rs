//! Port of `internal/dnsparser/parser.go`.

use crate::DnsParserError;

pub(crate) const DNS_HEADER_SIZE: usize = 12;
const MAX_NAME_JUMPS: usize = 10;
const MAX_NAME_WIRE_LENGTH: usize = 255;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub qr: u8,
    pub op_code: u8,
    pub aa: u8,
    pub tc: u8,
    pub rd: u8,
    pub ra: u8,
    pub z: u8,
    pub rcode: u8,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub q_type: u16,
    pub class: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: String,
    pub r_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rd_len: u16,
    pub r_data: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LitePacket {
    pub header: Header,
    pub questions: Vec<Question>,
    pub first_question: Question,
    pub has_question: bool,
    pub question_end_offset: usize,
}

pub fn parse_packet_lite(data: &[u8]) -> Result<LitePacket, DnsParserError> {
    if data.len() < DNS_HEADER_SIZE {
        return Err(DnsParserError::PacketTooShort);
    }
    let header = parse_header(data);
    parse_packet_lite_with_header(data, header)
}

pub fn parse_dns_request_lite(data: &[u8]) -> Result<LitePacket, DnsParserError> {
    if data.len() < DNS_HEADER_SIZE {
        return Err(DnsParserError::PacketTooShort);
    }
    let header = parse_header(data);
    if !crate::response::is_likely_dns_request_header(header) {
        return Err(DnsParserError::NotDnsRequest);
    }
    parse_packet_lite_with_header(data, header)
}

/// Parses a complete, structurally plausible DNS request or response. Unlike
/// [`parse_dns_request_lite`], it validates every declared section and rejects
/// trailing data so callers can use success as a routing boundary.
pub fn parse_dns_datagram_lite(data: &[u8]) -> Result<LitePacket, DnsParserError> {
    if data.len() < DNS_HEADER_SIZE {
        return Err(DnsParserError::PacketTooShort);
    }

    let header = parse_header(data);
    if !crate::response::is_likely_dns_message_header(header) {
        return Err(DnsParserError::NotDnsMessage);
    }

    let mut offset = crate::response::skip_questions(data, DNS_HEADER_SIZE, header.qd_count as usize)?;
    offset = crate::response::skip_resource_records(data, offset, header.an_count as usize)?;
    offset = crate::response::skip_resource_records(data, offset, header.ns_count as usize)?;
    offset = crate::response::skip_resource_records(data, offset, header.ar_count as usize)?;
    if offset != data.len() {
        return Err(DnsParserError::NotDnsMessage);
    }

    parse_packet_lite_with_header(data, header)
}

fn parse_packet_lite_with_header(data: &[u8], header: Header) -> Result<LitePacket, DnsParserError> {
    let mut packet = LitePacket {
        header,
        ..Default::default()
    };
    if header.qd_count == 0 {
        packet.question_end_offset = DNS_HEADER_SIZE;
        return Ok(packet);
    }

    let (questions, offset) =
        parse_questions(data, DNS_HEADER_SIZE, header.qd_count as usize).map_err(|_| DnsParserError::InvalidQuestion)?;

    packet.has_question = !questions.is_empty();
    if packet.has_question {
        packet.first_question = questions[0].clone();
    }
    packet.questions = questions;
    packet.question_end_offset = offset;
    Ok(packet)
}

pub fn parse_packet(data: &[u8]) -> Result<Packet, DnsParserError> {
    if data.len() < DNS_HEADER_SIZE {
        return Err(DnsParserError::PacketTooShort);
    }

    let header = parse_header(data);
    let mut offset = DNS_HEADER_SIZE;

    let (questions, next_offset) = parse_questions(data, offset, header.qd_count as usize)?;
    offset = next_offset;

    let (answers, next_offset) = parse_resource_records(data, offset, header.an_count as usize)?;
    offset = next_offset;

    let (authorities, next_offset) = parse_resource_records(data, offset, header.ns_count as usize)?;
    offset = next_offset;

    let (additional, _) = parse_resource_records(data, offset, header.ar_count as usize)?;

    Ok(Packet {
        header,
        questions,
        answers,
        authorities,
        additional,
    })
}

pub(crate) fn parse_header(data: &[u8]) -> Header {
    let flags = u16::from_be_bytes([data[2], data[3]]);
    Header {
        id: u16::from_be_bytes([data[0], data[1]]),
        flags,
        qr: ((flags >> 15) & 0x1) as u8,
        op_code: ((flags >> 11) & 0xF) as u8,
        aa: ((flags >> 10) & 0x1) as u8,
        tc: ((flags >> 9) & 0x1) as u8,
        rd: ((flags >> 8) & 0x1) as u8,
        ra: ((flags >> 7) & 0x1) as u8,
        z: ((flags >> 4) & 0x7) as u8,
        rcode: (flags & 0xF) as u8,
        qd_count: u16::from_be_bytes([data[4], data[5]]),
        an_count: u16::from_be_bytes([data[6], data[7]]),
        ns_count: u16::from_be_bytes([data[8], data[9]]),
        ar_count: u16::from_be_bytes([data[10], data[11]]),
    }
}

fn parse_questions(data: &[u8], mut offset: usize, count: usize) -> Result<(Vec<Question>, usize), DnsParserError> {
    if count == 0 {
        return Ok((Vec::new(), offset));
    }

    let mut questions = Vec::with_capacity(count);
    for _ in 0..count {
        let (name, next_offset) = parse_name(data, offset).map_err(|_| DnsParserError::InvalidQuestion)?;
        offset = next_offset;

        if offset + 4 > data.len() {
            return Err(DnsParserError::InvalidQuestion);
        }

        questions.push(Question {
            name,
            q_type: u16::from_be_bytes([data[offset], data[offset + 1]]),
            class: u16::from_be_bytes([data[offset + 2], data[offset + 3]]),
        });
        offset += 4;
    }

    Ok((questions, offset))
}

fn parse_resource_records(
    data: &[u8],
    mut offset: usize,
    count: usize,
) -> Result<(Vec<ResourceRecord>, usize), DnsParserError> {
    if count == 0 {
        return Ok((Vec::new(), offset));
    }

    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let (name, next_offset) = parse_name(data, offset).map_err(|_| DnsParserError::InvalidAnswer)?;
        offset = next_offset;

        if offset + 10 > data.len() {
            return Err(DnsParserError::InvalidAnswer);
        }

        let r_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let class = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let ttl = u32::from_be_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);
        let rd_len = u16::from_be_bytes([data[offset + 8], data[offset + 9]]);
        offset += 10;

        let end = offset + rd_len as usize;
        if end > data.len() {
            return Err(DnsParserError::InvalidAnswer);
        }

        records.push(ResourceRecord {
            name,
            r_type,
            class,
            ttl,
            rd_len,
            r_data: data[offset..end].to_vec(),
        });
        offset = end;
    }

    Ok((records, offset))
}

pub(crate) fn parse_name(data: &[u8], offset: usize) -> Result<(String, usize), DnsParserError> {
    let mut name = String::new();
    let (next_offset, has_label) = walk_name(data, offset, Some(&mut name))?;
    if !has_label {
        return Ok((".".to_string(), next_offset));
    }
    Ok((name, next_offset))
}

/// Walks a (possibly compressed) DNS name starting at `offset`. When `name` is
/// `Some`, the decoded (lowercased) label text is appended to it.
pub(crate) fn walk_name(
    data: &[u8],
    offset: usize,
    mut name: Option<&mut String>,
) -> Result<(usize, bool), DnsParserError> {
    let data_len = data.len();
    if offset >= data_len {
        return Err(DnsParserError::InvalidName);
    }

    let mut jumped = false;
    let mut jumps = 0usize;
    let mut next_offset = offset;
    let mut has_label = false;
    let mut wire_len = 1usize;
    let mut offset = offset;

    loop {
        if offset >= data_len {
            return Err(DnsParserError::InvalidName);
        }

        let length = data[offset] as usize;
        if length == 0 {
            if !jumped {
                next_offset = offset + 1;
            }
            return Ok((next_offset, has_label));
        }

        if length >= 192 {
            if offset + 1 >= data_len || jumps >= MAX_NAME_JUMPS {
                return Err(DnsParserError::InvalidName);
            }
            let ptr = (u16::from_be_bytes([data[offset], data[offset + 1]]) & 0x3FFF) as usize;
            if ptr < DNS_HEADER_SIZE || ptr >= offset || ptr >= data_len {
                return Err(DnsParserError::InvalidName);
            }
            if !jumped {
                next_offset = offset + 2;
                jumped = true;
            }
            offset = ptr;
            jumps += 1;
            continue;
        }

        if length > 63 {
            return Err(DnsParserError::InvalidName);
        }
        if wire_len + length + 1 > MAX_NAME_WIRE_LENGTH {
            return Err(DnsParserError::InvalidName);
        }
        wire_len += length + 1;

        offset += 1;
        let end = offset + length;
        if end > data_len {
            return Err(DnsParserError::InvalidName);
        }

        if let Some(name) = name.as_deref_mut() {
            if has_label {
                name.push('.');
            }
            write_lower_ascii_label(name, &data[offset..end]);
        }
        has_label = true;
        offset = end;
        if !jumped {
            next_offset = offset;
        }
    }
}

fn write_lower_ascii_label(dst: &mut String, label: &[u8]) {
    for &b in label {
        if b.is_ascii_uppercase() {
            dst.push((b + (b'a' - b'A')) as char);
        } else {
            dst.push(b as char);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_name(labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for label in labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    #[test]
    fn parses_simple_question() {
        let mut packet = vec![0u8; DNS_HEADER_SIZE];
        packet[0] = 0x12;
        packet[1] = 0x34;
        packet[2] = 0x01;
        packet[4] = 0x00;
        packet[5] = 0x01; // QDCOUNT = 1
        packet.extend(encode_name(&["Example", "COM"]));
        packet.extend_from_slice(&1u16.to_be_bytes()); // A
        packet.extend_from_slice(&1u16.to_be_bytes()); // IN

        let parsed = parse_packet(&packet).unwrap();
        assert_eq!(parsed.header.id, 0x1234);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name, "example.com");
        assert_eq!(parsed.questions[0].q_type, 1);
    }

    #[test]
    fn name_compression_pointer_resolves() {
        let mut packet = vec![0u8; DNS_HEADER_SIZE];
        let name_offset = packet.len();
        packet.extend(encode_name(&["example", "com"]));

        let pointer_offset = packet.len();
        let pointer = 0xC000u16 | (name_offset as u16);
        packet.extend_from_slice(&pointer.to_be_bytes());

        let (name, next) = parse_name(&packet, pointer_offset).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(next, pointer_offset + 2);
    }
}
