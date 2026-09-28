//! Port of `internal/dnsparser/response.go`.

use crate::parser::{parse_header, walk_name, Header, DNS_HEADER_SIZE};
use crate::DnsParserError;

const MAX_LIKELY_QUESTIONS: u16 = 64;
const MAX_LIKELY_ANSWERS: u16 = 256;
const MAX_LIKELY_AUTHORITY: u16 = 256;
const MAX_LIKELY_ADDITIONAL: u16 = 256;

pub fn build_empty_no_error_response(request: &[u8]) -> Result<Vec<u8>, DnsParserError> {
    build_response_with_rcode(request, enums::DNSR_CODE_NO_ERROR)
}

pub fn build_empty_no_error_response_from_lite(
    request: &[u8],
    parsed: &crate::LitePacket,
) -> Result<Vec<u8>, DnsParserError> {
    build_response_with_rcode_lite(request, parsed, enums::DNSR_CODE_NO_ERROR)
}

pub fn build_no_data_response(request: &[u8]) -> Result<Vec<u8>, DnsParserError> {
    let parsed = crate::parse_dns_request_lite(request)?;
    build_no_data_response_from_lite(request, &parsed)
}

pub fn build_no_data_response_from_lite(request: &[u8], parsed: &crate::LitePacket) -> Result<Vec<u8>, DnsParserError> {
    build_response_with_rcode_lite(request, parsed, enums::DNSR_CODE_NO_ERROR)
}

pub fn build_name_error_response_from_lite(
    request: &[u8],
    parsed: &crate::LitePacket,
) -> Result<Vec<u8>, DnsParserError> {
    build_authoritative_response_with_rcode_lite(request, parsed, enums::DNSR_CODE_NAME_ERROR)
}

pub fn build_format_error_response(request: &[u8]) -> Result<Vec<u8>, DnsParserError> {
    build_response_with_rcode(request, enums::DNSR_CODE_FORMAT_ERROR)
}

pub fn build_format_error_response_from_lite(
    request: &[u8],
    parsed: &crate::LitePacket,
) -> Result<Vec<u8>, DnsParserError> {
    build_response_with_rcode_lite(request, parsed, enums::DNSR_CODE_FORMAT_ERROR)
}

pub fn build_refused_response_from_lite(request: &[u8], parsed: &crate::LitePacket) -> Result<Vec<u8>, DnsParserError> {
    build_response_with_rcode_lite(request, parsed, enums::DNSR_CODE_REFUSED)
}

pub fn build_server_failure_response(request: &[u8]) -> Result<Vec<u8>, DnsParserError> {
    build_response_with_rcode(request, enums::DNSR_CODE_SERVER_FAILURE)
}

pub fn build_server_failure_response_from_lite(
    request: &[u8],
    parsed: &crate::LitePacket,
) -> Result<Vec<u8>, DnsParserError> {
    build_response_with_rcode_lite(request, parsed, enums::DNSR_CODE_SERVER_FAILURE)
}

pub fn build_not_implemented_response_from_lite(
    request: &[u8],
    parsed: &crate::LitePacket,
) -> Result<Vec<u8>, DnsParserError> {
    build_response_with_rcode_lite(request, parsed, enums::DNSR_CODE_NOT_IMPLEMENTED)
}

fn build_response_with_rcode(request: &[u8], rcode: u8) -> Result<Vec<u8>, DnsParserError> {
    if request.len() < DNS_HEADER_SIZE {
        return Err(DnsParserError::PacketTooShort);
    }

    let header = parse_header(request);
    if !is_likely_dns_request_header(header) {
        return Err(DnsParserError::NotDnsRequest);
    }

    let question_end_offset = skip_questions(request, DNS_HEADER_SIZE, header.qd_count as usize);
    let (question_len, question_count) = match question_end_offset {
        Ok(end) if end >= DNS_HEADER_SIZE && end <= request.len() => (end - DNS_HEADER_SIZE, header.qd_count),
        _ => (0, 0),
    };
    let question_end_offset = question_end_offset.unwrap_or(DNS_HEADER_SIZE);

    let (opt_start, opt_len) = find_opt_record_range(request, header, question_end_offset);

    let mut response = vec![0u8; DNS_HEADER_SIZE + question_len + opt_len];
    response[0..2].copy_from_slice(&header.id.to_be_bytes());
    response[2..4].copy_from_slice(&build_response_flags(header.flags, rcode).to_be_bytes());
    response[4..6].copy_from_slice(&question_count.to_be_bytes());
    response[10..12].copy_from_slice(&(get_ar_count(opt_len) as u16).to_be_bytes());

    if question_len > 0 {
        response[DNS_HEADER_SIZE..DNS_HEADER_SIZE + question_len]
            .copy_from_slice(&request[DNS_HEADER_SIZE..question_end_offset]);
    }
    if opt_len > 0 {
        response[DNS_HEADER_SIZE + question_len..].copy_from_slice(&request[opt_start..opt_start + opt_len]);
    }

    Ok(response)
}

fn build_response_with_rcode_lite(
    request: &[u8],
    parsed: &crate::LitePacket,
    rcode: u8,
) -> Result<Vec<u8>, DnsParserError> {
    build_response_with_flags_lite(request, parsed, build_response_flags(parsed.header.flags, rcode))
}

fn build_authoritative_response_with_rcode_lite(
    request: &[u8],
    parsed: &crate::LitePacket,
    rcode: u8,
) -> Result<Vec<u8>, DnsParserError> {
    build_response_with_flags_lite(request, parsed, build_authoritative_response_flags(parsed.header.flags, rcode))
}

fn build_response_with_flags_lite(
    request: &[u8],
    parsed: &crate::LitePacket,
    flags: u16,
) -> Result<Vec<u8>, DnsParserError> {
    if request.len() < DNS_HEADER_SIZE {
        return Err(DnsParserError::PacketTooShort);
    }
    if !is_likely_dns_request_header(parsed.header) {
        return Err(DnsParserError::NotDnsRequest);
    }

    let (opt_start, opt_len) = find_opt_record_range(request, parsed.header, parsed.question_end_offset);

    let question_len = if parsed.question_end_offset >= DNS_HEADER_SIZE && parsed.question_end_offset <= request.len() {
        parsed.question_end_offset - DNS_HEADER_SIZE
    } else {
        0
    };

    let mut response = vec![0u8; DNS_HEADER_SIZE + question_len + opt_len];
    response[0..2].copy_from_slice(&parsed.header.id.to_be_bytes());
    response[2..4].copy_from_slice(&flags.to_be_bytes());
    response[4..6].copy_from_slice(&parsed.header.qd_count.to_be_bytes());
    response[10..12].copy_from_slice(&(get_ar_count(opt_len) as u16).to_be_bytes());

    if question_len > 0 {
        response[DNS_HEADER_SIZE..DNS_HEADER_SIZE + question_len]
            .copy_from_slice(&request[DNS_HEADER_SIZE..parsed.question_end_offset]);
    }
    if opt_len > 0 {
        response[DNS_HEADER_SIZE + question_len..].copy_from_slice(&request[opt_start..opt_start + opt_len]);
    }

    Ok(response)
}

fn get_ar_count(opt_len: usize) -> usize {
    if opt_len > 0 {
        1
    } else {
        0
    }
}

pub(crate) fn is_likely_dns_request_header(header: Header) -> bool {
    if header.qr != 0 || header.qd_count == 0 {
        return false;
    }
    is_likely_dns_message_header(header)
}

pub(crate) fn is_likely_dns_message_header(header: Header) -> bool {
    if (header.qr == 0 && header.qd_count == 0) || header.qd_count > MAX_LIKELY_QUESTIONS {
        return false;
    }
    if header.op_code > 6 {
        return false;
    }
    if header.flags & 0x0040 != 0 {
        return false;
    }
    if header.an_count > MAX_LIKELY_ANSWERS {
        return false;
    }
    if header.ns_count > MAX_LIKELY_AUTHORITY {
        return false;
    }
    if header.ar_count > MAX_LIKELY_ADDITIONAL {
        return false;
    }
    true
}

const FLAG_QR: u16 = 1 << 15;
const FLAG_AA: u16 = 1 << 10;
const FLAG_TC: u16 = 1 << 9;
const FLAG_RD: u16 = 1 << 8;
const FLAG_RA: u16 = 1 << 7;
const FLAG_CD: u16 = 1 << 4;
const OPCODE_MASK: u16 = 0x7800;

pub(crate) fn build_response_flags(request_flags: u16, rcode: u8) -> u16 {
    let mut flags = FLAG_QR | FLAG_RA | (request_flags & OPCODE_MASK) | (rcode & 0x0F) as u16;
    if request_flags & FLAG_RD != 0 {
        flags |= FLAG_RD;
    }
    if request_flags & FLAG_CD != 0 {
        flags |= FLAG_CD;
    }
    flags &= !(FLAG_AA | FLAG_TC);
    flags
}

fn build_authoritative_response_flags(request_flags: u16, rcode: u8) -> u16 {
    let mut flags = FLAG_QR | FLAG_AA | (request_flags & OPCODE_MASK) | (rcode & 0x0F) as u16;
    if request_flags & FLAG_RD != 0 {
        flags |= FLAG_RD;
    }
    if request_flags & FLAG_CD != 0 {
        flags |= FLAG_CD;
    }
    flags &= !(FLAG_RA | FLAG_TC);
    flags
}

pub(crate) fn extract_question_section(request: &[u8], header: Header) -> (&[u8], u16, usize) {
    if header.qd_count == 0 {
        return (&[], 0, DNS_HEADER_SIZE);
    }

    match skip_questions(request, DNS_HEADER_SIZE, header.qd_count as usize) {
        Ok(offset) => (&request[DNS_HEADER_SIZE..offset], header.qd_count, offset),
        Err(_) => (&[], 0, 0),
    }
}

pub(crate) fn find_opt_record_range(request: &[u8], header: Header, question_end_offset: usize) -> (usize, usize) {
    if header.ar_count == 0 || question_end_offset < DNS_HEADER_SIZE || question_end_offset > request.len() {
        return (0, 0);
    }

    let mut offset = question_end_offset;
    if header.an_count > 0 {
        match skip_resource_records(request, offset, header.an_count as usize) {
            Ok(next) => offset = next,
            Err(_) => return (0, 0),
        }
    }

    if header.ns_count > 0 {
        match skip_resource_records(request, offset, header.ns_count as usize) {
            Ok(next) => offset = next,
            Err(_) => return (0, 0),
        }
    }

    find_first_opt_record_in_additional(request, offset, header.ar_count as usize)
}

fn find_first_opt_record_in_additional(data: &[u8], mut offset: usize, count: usize) -> (usize, usize) {
    for _ in 0..count {
        let record_start = offset;

        let next_offset = match skip_name(data, offset) {
            Ok(n) => n,
            Err(_) => return (0, 0),
        };
        if next_offset + 10 > data.len() {
            return (0, 0);
        }

        let record_type = u16::from_be_bytes([data[next_offset], data[next_offset + 1]]);
        let rd_len = u16::from_be_bytes([data[next_offset + 8], data[next_offset + 9]]) as usize;
        let record_end = next_offset + 10 + rd_len;
        if record_end > data.len() {
            return (0, 0);
        }

        if record_type == enums::DNS_RECORD_TYPE_OPT {
            return (record_start, record_end - record_start);
        }

        offset = record_end;
    }

    (0, 0)
}

pub(crate) fn skip_questions(data: &[u8], mut offset: usize, count: usize) -> Result<usize, DnsParserError> {
    for _ in 0..count {
        let next_offset = skip_name(data, offset).map_err(|_| DnsParserError::InvalidQuestion)?;
        if next_offset + 4 > data.len() {
            return Err(DnsParserError::InvalidQuestion);
        }
        offset = next_offset + 4;
    }
    Ok(offset)
}

pub(crate) fn skip_resource_records(data: &[u8], mut offset: usize, count: usize) -> Result<usize, DnsParserError> {
    for _ in 0..count {
        let next_offset = skip_name(data, offset).map_err(|_| DnsParserError::InvalidAnswer)?;
        if next_offset + 10 > data.len() {
            return Err(DnsParserError::InvalidAnswer);
        }

        let rd_len = u16::from_be_bytes([data[next_offset + 8], data[next_offset + 9]]) as usize;
        let record_end = next_offset + 10 + rd_len;
        if record_end > data.len() {
            return Err(DnsParserError::InvalidAnswer);
        }

        offset = record_end;
    }
    Ok(offset)
}

pub(crate) fn skip_name(data: &[u8], offset: usize) -> Result<usize, DnsParserError> {
    walk_name(data, offset, None).map(|(next, _)| next)
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

    fn build_request(id: u16, name: &[&str]) -> Vec<u8> {
        let mut packet = vec![0u8; DNS_HEADER_SIZE];
        packet[0..2].copy_from_slice(&id.to_be_bytes());
        packet[2..4].copy_from_slice(&0x0100u16.to_be_bytes()); // RD set
        packet[4..6].copy_from_slice(&1u16.to_be_bytes());
        packet.extend(encode_name(name));
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    #[test]
    fn no_error_response_preserves_id_and_question() {
        let request = build_request(0xBEEF, &["example", "com"]);
        let response = build_empty_no_error_response(&request).unwrap();

        let header = parse_header(&response);
        assert_eq!(header.id, 0xBEEF);
        assert_eq!(header.qr, 1);
        assert_eq!(header.rcode, enums::DNSR_CODE_NO_ERROR);
        assert_eq!(header.qd_count, 1);
        assert_eq!(&response[DNS_HEADER_SIZE..], &request[DNS_HEADER_SIZE..]);
    }

    #[test]
    fn format_error_sets_rcode() {
        let request = build_request(1, &["a"]);
        let response = build_format_error_response(&request).unwrap();
        let header = parse_header(&response);
        assert_eq!(header.rcode, enums::DNSR_CODE_FORMAT_ERROR);
    }
}
