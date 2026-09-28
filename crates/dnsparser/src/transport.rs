//! Port of `internal/dnsparser/transport.go`.

use crate::parser::{parse_header, parse_name, parse_packet, DNS_HEADER_SIZE};
use crate::response::{build_response_flags, extract_question_section, find_opt_record_range};
use crate::{DnsParserError, ResourceRecord};
use rand::RngCore;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

const MAX_DNS_NAME_LEN: usize = 253;
const MAX_DNS_LABEL_LEN: usize = 63;
#[cfg(test)]
const MAX_TXT_ANSWER_PAYLOAD: usize = 255;
#[cfg(test)]
const MAX_TXT_ENCODED_CHUNK: usize = 191;

pub fn build_txt_question_packet(name: &str, q_type: u16, edns_udp_size: u16) -> Result<Vec<u8>, DnsParserError> {
    let qname = encode_dns_name_strict(name)?;
    Ok(build_txt_question_packet_prepared(&qname, q_type, edns_udp_size))
}

pub fn build_tunnel_txt_question_packet(
    domain: &str,
    encoded_frame: &[u8],
    q_type: u16,
    edns_udp_size: u16,
) -> Result<Vec<u8>, DnsParserError> {
    let (normalized_domain, domain_qname) = prepare_tunnel_domain_qname(domain)?;
    build_tunnel_txt_question_packet_prepared(&normalized_domain, &domain_qname, encoded_frame, q_type, edns_udp_size)
}

pub fn build_tunnel_txt_question_packet_prepared(
    normalized_domain: &str,
    domain_qname: &[u8],
    encoded_frame: &[u8],
    q_type: u16,
    edns_udp_size: u16,
) -> Result<Vec<u8>, DnsParserError> {
    if normalized_domain.is_empty() || domain_qname.is_empty() {
        return Err(DnsParserError::InvalidName);
    }
    if encoded_frame.is_empty() {
        return Ok(build_txt_question_packet_prepared(domain_qname, q_type, edns_udp_size));
    }

    if encoded_qname_len(encoded_frame.len(), normalized_domain.len()) > MAX_DNS_NAME_LEN {
        return Err(DnsParserError::InvalidName);
    }

    let label_count = encoded_frame.len().div_ceil(MAX_DNS_LABEL_LEN);
    let qname_len = encoded_frame.len() + label_count + domain_qname.len();

    let (ar_count, opt_len) = if edns_udp_size > 0 { (1u16, 11usize) } else { (0, 0) };

    let mut packet = vec![0u8; DNS_HEADER_SIZE + qname_len + 4 + opt_len];
    packet[0..2].copy_from_slice(&next_dns_request_id().to_be_bytes());
    packet[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
    packet[4..6].copy_from_slice(&1u16.to_be_bytes());
    packet[10..12].copy_from_slice(&ar_count.to_be_bytes());

    let mut offset = DNS_HEADER_SIZE;
    let mut start = 0usize;
    while start < encoded_frame.len() {
        let end = (start + MAX_DNS_LABEL_LEN).min(encoded_frame.len());
        packet[offset] = (end - start) as u8;
        offset += 1;
        packet[offset..offset + (end - start)].copy_from_slice(&encoded_frame[start..end]);
        offset += end - start;
        start = end;
    }
    packet[offset..offset + domain_qname.len()].copy_from_slice(domain_qname);
    offset += domain_qname.len();
    packet[offset..offset + 2].copy_from_slice(&q_type.to_be_bytes());
    packet[offset + 2..offset + 4].copy_from_slice(&enums::DNSQ_CLASS_IN.to_be_bytes());
    offset += 4;

    write_opt_record(&mut packet, offset, edns_udp_size);

    Ok(packet)
}

pub fn prepare_tunnel_domain_qname(domain: &str) -> Result<(String, Vec<u8>), DnsParserError> {
    let normalized_domain = domain.trim().to_lowercase();
    let normalized_domain = normalized_domain.strip_suffix('.').unwrap_or(&normalized_domain).to_string();
    if normalized_domain.is_empty() {
        return Err(DnsParserError::InvalidName);
    }

    let domain_qname = encode_dns_name_strict(&normalized_domain)?;
    Ok((normalized_domain, domain_qname))
}

fn build_txt_question_packet_prepared(qname: &[u8], q_type: u16, edns_udp_size: u16) -> Vec<u8> {
    let request_id = next_dns_request_id();
    let (ar_count, opt_len) = if edns_udp_size > 0 { (1u16, 11usize) } else { (0, 0) };

    let mut packet = vec![0u8; DNS_HEADER_SIZE + qname.len() + 4 + opt_len];
    packet[0..2].copy_from_slice(&request_id.to_be_bytes());
    packet[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
    packet[4..6].copy_from_slice(&1u16.to_be_bytes());
    packet[10..12].copy_from_slice(&ar_count.to_be_bytes());

    let mut offset = DNS_HEADER_SIZE;
    packet[offset..offset + qname.len()].copy_from_slice(qname);
    offset += qname.len();
    packet[offset..offset + 2].copy_from_slice(&q_type.to_be_bytes());
    packet[offset + 2..offset + 4].copy_from_slice(&enums::DNSQ_CLASS_IN.to_be_bytes());
    offset += 4;

    write_opt_record(&mut packet, offset, edns_udp_size);
    packet
}

fn write_opt_record(packet: &mut [u8], mut offset: usize, edns_udp_size: u16) {
    if edns_udp_size == 0 {
        return;
    }
    packet[offset] = 0x00;
    offset += 1;
    packet[offset..offset + 2].copy_from_slice(&enums::DNS_RECORD_TYPE_OPT.to_be_bytes());
    offset += 2;
    packet[offset..offset + 2].copy_from_slice(&edns_udp_size.to_be_bytes());
    offset += 2;
    offset += 4;
    packet[offset..offset + 2].copy_from_slice(&0u16.to_be_bytes());
}

pub fn build_txt_response_packet(
    question_packet: &[u8],
    answer_name: &str,
    answer_payloads: &[Vec<u8>],
) -> Result<Vec<u8>, DnsParserError> {
    if answer_payloads.len() == 1 {
        return build_single_txt_response_packet(question_packet, answer_name, &answer_payloads[0]);
    }

    if question_packet.len() < DNS_HEADER_SIZE {
        return Err(DnsParserError::PacketTooShort);
    }

    let header = parse_header(question_packet);
    let (question_bytes, question_count, question_end_offset) = extract_question_section(question_packet, header);
    let (opt_start, opt_len) = find_opt_record_range(question_packet, header, question_end_offset);

    let name_bytes = response_answer_name_bytes(question_packet, question_count > 0, answer_name)?;

    let mut answer_len = 0usize;
    // Already a pointer to the question name: reuse it for every answer rather
    // than chaining pointers through the first answer.
    let use_answer_name_compression = answer_payloads.len() > 1 && name_bytes != QUESTION_NAME_POINTER;
    for (i, payload) in answer_payloads.iter().enumerate() {
        let name_len = if use_answer_name_compression && i > 0 { 2 } else { name_bytes.len() };
        answer_len += name_len + 10 + payload.len();
    }

    let mut response = vec![0u8; DNS_HEADER_SIZE + question_bytes.len() + answer_len + opt_len];
    response[0..2].copy_from_slice(&header.id.to_be_bytes());
    response[2..4].copy_from_slice(&build_response_flags(header.flags, enums::DNSR_CODE_NO_ERROR).to_be_bytes());
    response[4..6].copy_from_slice(&question_count.to_be_bytes());
    response[6..8].copy_from_slice(&(answer_payloads.len() as u16).to_be_bytes());
    response[8..10].copy_from_slice(&0u16.to_be_bytes());
    response[10..12].copy_from_slice(&(if opt_len > 0 { 1u16 } else { 0 }).to_be_bytes());

    let mut offset = DNS_HEADER_SIZE;
    response[offset..offset + question_bytes.len()].copy_from_slice(question_bytes);
    offset += question_bytes.len();
    let first_answer_name_offset = offset;

    for (i, payload) in answer_payloads.iter().enumerate() {
        if use_answer_name_compression && i > 0 && first_answer_name_offset <= 0x3FFF {
            let pointer = 0xC000u16 | (first_answer_name_offset as u16);
            response[offset..offset + 2].copy_from_slice(&pointer.to_be_bytes());
            offset += 2;
        } else {
            response[offset..offset + name_bytes.len()].copy_from_slice(&name_bytes);
            offset += name_bytes.len();
        }
        response[offset..offset + 2].copy_from_slice(&enums::DNS_RECORD_TYPE_TXT.to_be_bytes());
        response[offset + 2..offset + 4].copy_from_slice(&enums::DNSQ_CLASS_IN.to_be_bytes());
        response[offset + 4..offset + 8].copy_from_slice(&0u32.to_be_bytes());
        response[offset + 8..offset + 10].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        offset += 10;
        response[offset..offset + payload.len()].copy_from_slice(payload);
        offset += payload.len();
    }

    if opt_len > 0 {
        response[offset..].copy_from_slice(&question_packet[opt_start..opt_start + opt_len]);
    }

    Ok(response)
}

pub fn build_vpn_response_packet(
    question_packet: &[u8],
    answer_name: &str,
    packet: &vpnproto::Packet,
    base_encode: bool,
) -> Result<Vec<u8>, DnsParserError> {
    let raw_frame = vpnproto::build_raw_auto(
        vpnproto::BuildOptions {
            session_id: packet.session_id,
            packet_type: packet.packet_type,
            session_cookie: packet.session_cookie,
            stream_id: packet.stream_id,
            sequence_num: packet.sequence_num,
            fragment_id: packet.fragment_id,
            total_fragments: packet.total_fragments,
            compression_type: packet.compression_type,
            payload: packet.payload.clone(),
        },
        compression::DEFAULT_MIN_SIZE,
    )
    .map_err(|_| DnsParserError::TxtAnswerMalformed)?;

    // The whole frame always goes into ONE TXT record, split into as many
    // 255-byte character-strings as needed. Clients (Go and Rust alike)
    // concatenate the strings of a lone TXT answer and parse the result as a
    // raw frame, so this stays compatible while dropping the legacy
    // multi-record layout's per-record overhead (12-byte RR header + 1-2 byte
    // chunk prefix per 255 bytes) and its sensitivity to resolvers reordering
    // RRsets.
    let rdata = if base_encode { append_base64_txt_strings(&raw_frame) } else { append_length_prefixed_txt(&raw_frame) };
    if rdata.len() > u16::MAX as usize {
        return Err(DnsParserError::TxtAnswerTooLarge);
    }
    build_single_txt_response_packet(question_packet, answer_name, &rdata)
}

/// Raw-base64 encodes `data` as a single string, then splits it into TXT
/// character-strings; concatenating them yields the original encoding.
fn append_base64_txt_strings(data: &[u8]) -> Vec<u8> {
    let mut encoded = vec![0u8; basecodec::encoded_raw_base64_len(data.len())];
    basecodec::encode_raw_base64_into(&mut encoded, data);
    append_length_prefixed_txt(&encoded)
}

fn build_single_txt_response_packet(
    question_packet: &[u8],
    answer_name: &str,
    answer_payload: &[u8],
) -> Result<Vec<u8>, DnsParserError> {
    if question_packet.len() < DNS_HEADER_SIZE {
        return Err(DnsParserError::PacketTooShort);
    }

    let header = parse_header(question_packet);
    let (question_bytes, question_count, question_end_offset) = extract_question_section(question_packet, header);
    let (opt_start, opt_len) = find_opt_record_range(question_packet, header, question_end_offset);

    let name_bytes = response_answer_name_bytes(question_packet, question_count > 0, answer_name)?;

    let mut response = vec![0u8; DNS_HEADER_SIZE + question_bytes.len() + name_bytes.len() + 10 + answer_payload.len() + opt_len];
    response[0..2].copy_from_slice(&header.id.to_be_bytes());
    response[2..4].copy_from_slice(&build_response_flags(header.flags, enums::DNSR_CODE_NO_ERROR).to_be_bytes());
    response[4..6].copy_from_slice(&question_count.to_be_bytes());
    response[6..8].copy_from_slice(&1u16.to_be_bytes());
    response[8..10].copy_from_slice(&0u16.to_be_bytes());
    response[10..12].copy_from_slice(&(if opt_len > 0 { 1u16 } else { 0 }).to_be_bytes());

    let mut offset = DNS_HEADER_SIZE;
    response[offset..offset + question_bytes.len()].copy_from_slice(question_bytes);
    offset += question_bytes.len();
    response[offset..offset + name_bytes.len()].copy_from_slice(&name_bytes);
    offset += name_bytes.len();
    response[offset..offset + 2].copy_from_slice(&enums::DNS_RECORD_TYPE_TXT.to_be_bytes());
    response[offset + 2..offset + 4].copy_from_slice(&enums::DNSQ_CLASS_IN.to_be_bytes());
    response[offset + 4..offset + 8].copy_from_slice(&0u32.to_be_bytes());
    response[offset + 8..offset + 10].copy_from_slice(&(answer_payload.len() as u16).to_be_bytes());
    offset += 10;
    response[offset..offset + answer_payload.len()].copy_from_slice(answer_payload);
    offset += answer_payload.len();

    if opt_len > 0 {
        response[offset..].copy_from_slice(&question_packet[opt_start..opt_start + opt_len]);
    }

    Ok(response)
}

/// Compression pointer to the first question name, which always sits right
/// after the 12-byte header because the question section is copied verbatim.
const QUESTION_NAME_POINTER: [u8; 2] = [0xC0, DNS_HEADER_SIZE as u8];

/// When the answer name equals the question name (the normal tunnel case),
/// returns a 2-byte pointer instead of repeating the full qname: the qname
/// carries the upload payload and can be ~250 bytes, which would otherwise be
/// paid twice in every response. Any RFC 1035 parser (including the Go
/// client's) follows the pointer.
fn response_answer_name_bytes(question_packet: &[u8], question_copied: bool, answer_name: &str) -> Result<Vec<u8>, DnsParserError> {
    if !question_copied {
        return encode_dns_name_strict(answer_name);
    }
    if let Some(parsed_name) = extract_first_question_name(question_packet) {
        if same_dns_name(&parsed_name, answer_name) {
            return Ok(QUESTION_NAME_POINTER.to_vec());
        }
    }
    encode_dns_name_strict(answer_name)
}

fn extract_first_question_name(packet: &[u8]) -> Option<String> {
    if packet.len() < DNS_HEADER_SIZE {
        return None;
    }
    let header = parse_header(packet);
    if header.qd_count == 0 {
        return None;
    }

    let (name, next_offset) = parse_name(packet, DNS_HEADER_SIZE).ok()?;
    if next_offset <= DNS_HEADER_SIZE || next_offset > packet.len() {
        return None;
    }

    Some(name)
}

fn same_dns_name(a: &str, b: &str) -> bool {
    let a = a.strip_suffix('.').unwrap_or(a);
    let b = b.strip_suffix('.').unwrap_or(b);
    a.eq_ignore_ascii_case(b)
}

pub fn extract_vpn_response(packet: &[u8], base_encoded: bool) -> Result<vpnproto::Packet, DnsParserError> {
    let parsed = parse_packet(packet)?;

    let raw_answers = extract_txt_answer_payloads(&parsed);
    if raw_answers.is_empty() {
        return Err(DnsParserError::TxtAnswerMissing);
    }

    assemble_vpn_response(&raw_answers, base_encoded)
}

pub fn describe_response_without_tunnel_payload(packet: &[u8]) -> String {
    let parsed = match parse_packet(packet) {
        Ok(p) => p,
        Err(e) => return format!("unparseable dns response: {e}"),
    };

    let q_name = if !parsed.questions.is_empty() && !parsed.questions[0].name.is_empty() {
        parsed.questions[0].name.clone()
    } else {
        "-".to_string()
    };

    let mut answer_kinds = summarize_record_types(&parsed.answers);
    if answer_kinds.is_empty() {
        answer_kinds = "none".to_string();
    }

    format!(
        "RCODE={} QD={} AN={} NS={} AR={} QName={} Answers={}",
        parsed.header.rcode,
        parsed.header.qd_count,
        parsed.header.an_count,
        parsed.header.ns_count,
        parsed.header.ar_count,
        q_name,
        answer_kinds,
    )
}

fn summarize_record_types(records: &[ResourceRecord]) -> String {
    if records.is_empty() {
        return String::new();
    }

    let mut order: Vec<u16> = Vec::new();
    let mut counts: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();
    for rr in records {
        if !counts.contains_key(&rr.r_type) {
            order.push(rr.r_type);
        }
        *counts.entry(rr.r_type).or_insert(0) += 1;
    }

    order
        .iter()
        .map(|&t| format!("{} x{}", enums::dns_record_type_name(t), counts[&t]))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn calculate_max_encoded_qname_chars(domain: &str) -> usize {
    let domain_len = domain.trim().strip_suffix('.').unwrap_or(domain.trim()).len();
    if domain_len == 0 {
        return MAX_DNS_NAME_LEN;
    }

    let mut low = 0usize;
    let mut high = MAX_DNS_NAME_LEN;
    let mut best = 0usize;
    while low <= high {
        let mid = (low + high) / 2;
        if encoded_qname_len(mid, domain_len) <= MAX_DNS_NAME_LEN {
            best = mid;
            low = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            high = mid - 1;
        }
    }
    best
}

pub fn encode_data_to_labels(data: &str) -> String {
    if data.len() <= MAX_DNS_LABEL_LEN {
        return data.to_string();
    }

    let mut out = String::with_capacity(data.len() + data.len() / MAX_DNS_LABEL_LEN);
    let bytes = data.as_bytes();
    let mut start = 0usize;
    while start < bytes.len() {
        if start > 0 {
            out.push('.');
        }
        let end = (start + MAX_DNS_LABEL_LEN).min(bytes.len());
        out.push_str(&data[start..end]);
        start = end;
    }
    out
}

pub fn build_tunnel_question_name(domain: &str, encoded_frame: &str) -> Result<String, DnsParserError> {
    let domain = domain.trim().to_lowercase();
    let domain = domain.strip_suffix('.').unwrap_or(&domain).to_string();
    if domain.is_empty() {
        return Err(DnsParserError::InvalidName);
    }
    if encoded_frame.is_empty() {
        return Ok(domain);
    }

    let name = format!("{}.{}", encode_data_to_labels(encoded_frame), domain);
    if name.len() > MAX_DNS_NAME_LEN {
        return Err(DnsParserError::InvalidName);
    }
    Ok(name)
}

/// Legacy multi-record TXT layout (one chunk per RR, chunk 0 prefixed with
/// `0x00, total`), still emitted by the Go server. The builder is kept only
/// so tests can check that `assemble_vpn_response` keeps accepting it.
#[cfg(test)]
fn build_txt_answer_chunks(raw_frame: &[u8], base_encode: bool) -> Result<Vec<Vec<u8>>, DnsParserError> {
    let max_chunk = if base_encode { MAX_TXT_ENCODED_CHUNK } else { MAX_TXT_ANSWER_PAYLOAD };

    if raw_frame.is_empty() {
        return Ok(vec![append_length_prefixed_txt(&[])]);
    }

    if raw_frame.len() <= max_chunk {
        return Ok(vec![build_txt_answer_chunk(raw_frame, base_encode)]);
    }

    let header = match vpnproto::parse(raw_frame) {
        Ok(h) => h,
        Err(_) => return Ok(vec![build_txt_answer_chunk(raw_frame, base_encode)]),
    };

    let header_len = header.header_length;
    let chunk0_prefix_len = 2usize;
    let max_chunk0_data = max_chunk.saturating_sub(chunk0_prefix_len + header_len);

    let remaining = header.payload.len() as isize - max_chunk0_data as isize;
    let max_chunk_n_data = max_chunk - 1;
    let mut total_chunks = 1usize;
    if remaining > 0 {
        total_chunks += (remaining as usize).div_ceil(max_chunk_n_data);
    }
    if total_chunks > 255 {
        return Err(DnsParserError::TxtAnswerTooLarge);
    }

    let mut chunks = Vec::with_capacity(total_chunks);
    let chunk0_data_len = max_chunk0_data.min(header.payload.len());
    let mut raw_chunk0 = vec![0u8; 2 + header_len + chunk0_data_len];
    raw_chunk0[0] = 0x00;
    raw_chunk0[1] = total_chunks as u8;
    raw_chunk0[2..2 + header_len].copy_from_slice(&raw_frame[..header_len]);
    raw_chunk0[2 + header_len..].copy_from_slice(&header.payload[..chunk0_data_len]);

    if !base_encode {
        chunks.push(append_length_prefixed_txt(&raw_chunk0));
        append_raw_txt_answer_chunks(&mut chunks, &header.payload, max_chunk0_data, max_chunk_n_data);
    } else {
        chunks.push(append_length_prefixed_base64_txt(&raw_chunk0));
        append_base64_txt_answer_chunks(&mut chunks, &header.payload, max_chunk0_data, max_chunk_n_data);
    }

    Ok(chunks)
}

#[cfg(test)]
fn build_txt_answer_chunk(data: &[u8], base_encode: bool) -> Vec<u8> {
    if !base_encode {
        append_length_prefixed_txt(data)
    } else {
        append_length_prefixed_base64_txt(data)
    }
}

#[cfg(test)]
fn append_raw_txt_answer_chunks(chunks: &mut Vec<Vec<u8>>, payload: &[u8], mut cursor: usize, max_chunk_n_data: usize) {
    let mut chunk_id = 1u8;
    while cursor < payload.len() {
        let end = (cursor + max_chunk_n_data).min(payload.len());
        chunks.push(build_length_prefixed_txt_chunk(chunk_id, &payload[cursor..end]));
        cursor = end;
        chunk_id = chunk_id.wrapping_add(1);
    }
}

#[cfg(test)]
fn append_base64_txt_answer_chunks(chunks: &mut Vec<Vec<u8>>, payload: &[u8], mut cursor: usize, max_chunk_n_data: usize) {
    let mut chunk_id = 1u8;
    while cursor < payload.len() {
        let end = (cursor + max_chunk_n_data).min(payload.len());
        let mut raw_chunk = vec![0u8; 1 + (end - cursor)];
        raw_chunk[0] = chunk_id;
        raw_chunk[1..].copy_from_slice(&payload[cursor..end]);
        chunks.push(append_length_prefixed_base64_txt(&raw_chunk));
        cursor = end;
        chunk_id = chunk_id.wrapping_add(1);
    }
}

#[cfg(test)]
fn build_length_prefixed_txt_chunk(prefix: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 2 + data.len()];
    out[0] = (1 + data.len()) as u8;
    out[1] = prefix;
    out[2..].copy_from_slice(data);
    out
}

fn append_length_prefixed_txt(data: &[u8]) -> Vec<u8> {
    if data.len() <= 255 {
        let mut out = vec![0u8; 1 + data.len()];
        out[0] = data.len() as u8;
        out[1..].copy_from_slice(data);
        return out;
    }

    let parts = 1 + (data.len() - 1) / 255;
    let mut out = vec![0u8; data.len() + parts];
    let mut write_offset = 0usize;
    let mut start = 0usize;
    while start < data.len() {
        let end = (start + 255).min(data.len());
        out[write_offset] = (end - start) as u8;
        write_offset += 1;
        out[write_offset..write_offset + (end - start)].copy_from_slice(&data[start..end]);
        write_offset += end - start;
        start = end;
    }
    out
}

#[cfg(test)]
fn append_length_prefixed_base64_txt(data: &[u8]) -> Vec<u8> {
    let encoded_len = basecodec::encoded_raw_base64_len(data.len());
    let mut out = vec![0u8; 1 + encoded_len];
    out[0] = encoded_len as u8;
    basecodec::encode_raw_base64_into(&mut out[1..], data);
    out
}

fn extract_txt_answer_payloads(parsed: &crate::Packet) -> Vec<Vec<u8>> {
    let mut payloads = Vec::with_capacity(parsed.answers.len());
    for answer in &parsed.answers {
        if answer.r_type != enums::DNS_RECORD_TYPE_TXT {
            continue;
        }
        let raw = extract_txt_bytes(&answer.r_data);
        if !raw.is_empty() {
            payloads.push(raw);
        }
    }
    payloads
}

fn extract_txt_bytes(r_data: &[u8]) -> Vec<u8> {
    if r_data.is_empty() {
        return Vec::new();
    }
    if r_data[0] as usize + 1 == r_data.len() {
        return r_data[1..].to_vec();
    }

    let mut total_len = 0usize;
    let mut offset = 0usize;
    while offset < r_data.len() {
        let size = r_data[offset] as usize;
        offset += 1;
        if size == 0 {
            continue;
        }
        if offset + size > r_data.len() {
            total_len += r_data.len() - offset;
            break;
        }
        total_len += size;
        offset += size;
    }

    if total_len == 0 {
        return Vec::new();
    }

    let mut out = vec![0u8; total_len];
    let mut write_offset = 0usize;
    let mut offset = 0usize;
    while offset < r_data.len() {
        let size = r_data[offset] as usize;
        offset += 1;
        if size == 0 {
            continue;
        }
        if offset + size > r_data.len() {
            let remaining = r_data.len() - offset;
            out[write_offset..write_offset + remaining].copy_from_slice(&r_data[offset..]);
            break;
        }
        out[write_offset..write_offset + size].copy_from_slice(&r_data[offset..offset + size]);
        write_offset += size;
        offset += size;
    }
    out
}

fn assemble_vpn_response(raw_answers: &[Vec<u8>], base_encoded: bool) -> Result<vpnproto::Packet, DnsParserError> {
    if raw_answers.len() == 1 {
        let raw = if base_encoded {
            basecodec::decode_raw_base64(&raw_answers[0]).map_err(|_| DnsParserError::TxtAnswerMalformed)?
        } else {
            raw_answers[0].clone()
        };
        return vpnproto::parse_inflated(&raw).map_err(|_| DnsParserError::TxtAnswerMalformed);
    }

    let mut chunks: Vec<Option<Vec<u8>>> = vec![None; 256];
    let mut total_expected = 0usize;
    let mut seen_chunks = 0usize;
    let mut header: Option<vpnproto::Packet> = None;

    for raw in raw_answers {
        let raw = if base_encoded {
            basecodec::decode_raw_base64(raw).map_err(|_| DnsParserError::TxtAnswerMalformed)?
        } else {
            raw.clone()
        };
        if raw.is_empty() {
            continue;
        }

        if raw[0] == 0x00 {
            if raw.len() < 3 {
                return Err(DnsParserError::TxtAnswerMalformed);
            }
            total_expected = raw[1] as usize;
            if total_expected == 0 || total_expected > chunks.len() {
                return Err(DnsParserError::TxtAnswerMalformed);
            }
            let parsed = vpnproto::parse_at_offset(&raw, 2).map_err(|_| DnsParserError::TxtAnswerMalformed)?;
            if chunks[0].is_none() {
                seen_chunks += 1;
            }
            chunks[0] = Some(parsed.payload.clone());
            header = Some(parsed);
            continue;
        }

        let chunk_id = raw[0] as usize;
        if chunk_id >= chunks.len() {
            return Err(DnsParserError::TxtAnswerMalformed);
        }
        if chunks[chunk_id].is_none() {
            seen_chunks += 1;
        }
        chunks[chunk_id] = Some(raw[1..].to_vec());
    }

    let mut header = match header {
        Some(h) if total_expected > 0 && seen_chunks == total_expected => h,
        _ => return Err(DnsParserError::TxtAnswerMalformed),
    };

    for chunk in chunks.iter().take(total_expected) {
        if chunk.is_none() {
            return Err(DnsParserError::TxtAnswerMalformed);
        }
    }
    for chunk in chunks.iter().skip(total_expected) {
        if chunk.is_some() {
            return Err(DnsParserError::TxtAnswerMalformed);
        }
    }

    let mut payload = Vec::new();
    for chunk in chunks.iter().take(total_expected) {
        payload.extend_from_slice(chunk.as_ref().unwrap());
    }
    header.payload = payload;
    vpnproto::inflate_payload(header).map_err(|_| DnsParserError::TxtAnswerMalformed)
}

fn encode_dns_name_strict(name: &str) -> Result<Vec<u8>, DnsParserError> {
    let name = name.trim();
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return Ok(vec![0]);
    }
    if name.len() > MAX_DNS_NAME_LEN {
        return Err(DnsParserError::InvalidName);
    }

    let bytes = name.as_bytes();
    let mut encoded = vec![0u8; name.len() + 2];
    let mut write_offset = 0usize;
    let mut label_start = 0usize;
    for i in 0..=bytes.len() {
        if i < bytes.len() && bytes[i] != b'.' {
            continue;
        }
        let label_len = i - label_start;
        if label_len == 0 || label_len > MAX_DNS_LABEL_LEN {
            return Err(DnsParserError::InvalidName);
        }
        encoded[write_offset] = label_len as u8;
        write_offset += 1;
        encoded[write_offset..write_offset + label_len].copy_from_slice(&bytes[label_start..i]);
        write_offset += label_len;
        label_start = i + 1;
    }
    encoded[write_offset] = 0;
    write_offset += 1;
    encoded.truncate(write_offset);
    Ok(encoded)
}

fn encoded_qname_len(encoded_chars: usize, domain_len: usize) -> usize {
    if encoded_chars == 0 {
        return domain_len;
    }
    let label_splits = (encoded_chars - 1) / MAX_DNS_LABEL_LEN;
    encoded_chars + label_splits + 1 + domain_len
}

fn next_dns_request_id() -> u16 {
    static COUNTER: OnceLock<AtomicU32> = OnceLock::new();
    let counter = COUNTER.get_or_init(|| {
        let seed = rand::thread_rng().next_u32();
        AtomicU32::new(seed)
    });
    counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse_txt_question() {
        let packet = build_txt_question_packet("v.example.com", enums::DNS_RECORD_TYPE_TXT, 0).unwrap();
        let parsed = parse_packet(&packet).unwrap();
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name, "v.example.com");
        assert_eq!(parsed.questions[0].q_type, enums::DNS_RECORD_TYPE_TXT);
    }

    #[test]
    fn single_txt_answer_round_trip() {
        let question = build_txt_question_packet("v.example.com", enums::DNS_RECORD_TYPE_TXT, 0).unwrap();
        // TXT RDATA is a list of length-prefixed character-strings.
        let rdata = append_length_prefixed_txt(b"hello");
        let response = build_txt_response_packet(&question, "v.example.com", &[rdata]).unwrap();
        let parsed = parse_packet(&response).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(extract_txt_bytes(&parsed.answers[0].r_data), b"hello");
    }

    #[test]
    fn vpn_response_round_trip_small_payload() {
        let question = build_txt_question_packet("v.example.com", enums::DNS_RECORD_TYPE_TXT, 0).unwrap();
        let vpn_packet = vpnproto::Packet {
            session_id: 1,
            packet_type: enums::PACKET_PING,
            session_cookie: 2,
            ..Default::default()
        };
        let response = build_vpn_response_packet(&question, "v.example.com", &vpn_packet, false).unwrap();
        let extracted = extract_vpn_response(&response, false).unwrap();
        assert_eq!(extracted.session_id, 1);
        assert_eq!(extracted.packet_type, enums::PACKET_PING);
        assert_eq!(extracted.session_cookie, 2);
    }

    #[test]
    fn vpn_response_round_trip_large_payload_chunks() {
        let question = build_txt_question_packet("v.example.com", enums::DNS_RECORD_TYPE_TXT, 0).unwrap();
        let big_payload = vec![0xABu8; 2000];
        let vpn_packet = vpnproto::Packet {
            session_id: 9,
            packet_type: enums::PACKET_STREAM_DATA,
            session_cookie: 3,
            stream_id: 5,
            sequence_num: 10,
            payload: big_payload.clone(),
            ..Default::default()
        };
        let response = build_vpn_response_packet(&question, "v.example.com", &vpn_packet, false).unwrap();
        let extracted = extract_vpn_response(&response, false).unwrap();
        assert_eq!(extracted.payload, big_payload);
    }

    /// A query whose name is as long as the upload MTU allows, like a real
    /// data-carrying tunnel query.
    fn long_tunnel_question() -> (Vec<u8>, String) {
        let domain = "v.example.com";
        let frame = vec![b'a'; calculate_max_encoded_qname_chars(domain)];
        let question = build_tunnel_txt_question_packet(domain, &frame, enums::DNS_RECORD_TYPE_TXT, 1232).unwrap();
        let qname = parse_packet(&question).unwrap().questions[0].name.clone();
        (question, qname)
    }

    fn data_packet(payload_len: usize) -> vpnproto::Packet {
        vpnproto::Packet {
            session_id: 9,
            packet_type: enums::PACKET_STREAM_DATA,
            session_cookie: 3,
            stream_id: 5,
            sequence_num: 10,
            payload: (0..payload_len).map(|i| (i * 7) as u8).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn answer_name_points_at_question_name() {
        let (question, qname) = long_tunnel_question();
        let (question_bytes, _, _) = extract_question_section(&question, parse_header(&question));
        let response = build_vpn_response_packet(&question, &qname, &data_packet(10), false).unwrap();

        let answer_offset = DNS_HEADER_SIZE + question_bytes.len();
        assert_eq!(response[answer_offset..answer_offset + 2], QUESTION_NAME_POINTER);

        let parsed = parse_packet(&response).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].name, parsed.questions[0].name);
        assert_eq!(extract_vpn_response(&response, false).unwrap().payload, data_packet(10).payload);
    }

    #[test]
    fn answer_name_not_matching_question_is_written_in_full() {
        let question = build_txt_question_packet("v.example.com", enums::DNS_RECORD_TYPE_TXT, 0).unwrap();
        let response = build_txt_response_packet(&question, "other.example.com", &[append_length_prefixed_txt(b"x")]).unwrap();
        let parsed = parse_packet(&response).unwrap();
        assert_eq!(parsed.answers[0].name, "other.example.com");
    }

    #[test]
    fn large_frame_uses_single_multi_string_txt_record() {
        let (question, qname) = long_tunnel_question();
        for base_encode in [false, true] {
            let packet = data_packet(1500);
            let response = build_vpn_response_packet(&question, &qname, &packet, base_encode).unwrap();
            let parsed = parse_packet(&response).unwrap();
            assert_eq!(parsed.answers.len(), 1, "base_encode={base_encode}");
            assert!(parsed.answers[0].r_data.len() > 255);
            assert_eq!(extract_vpn_response(&response, base_encode).unwrap().payload, packet.payload);
        }
    }

    #[test]
    fn single_record_layout_is_smaller_than_legacy_layout() {
        let (question, qname) = long_tunnel_question();
        let packet = data_packet(1000);
        let response = build_vpn_response_packet(&question, &qname, &packet, false).unwrap();

        let raw_frame = vpnproto::build_raw_auto(
            vpnproto::BuildOptions {
                session_id: packet.session_id,
                packet_type: packet.packet_type,
                session_cookie: packet.session_cookie,
                stream_id: packet.stream_id,
                sequence_num: packet.sequence_num,
                payload: packet.payload.clone(),
                ..Default::default()
            },
            compression::DEFAULT_MIN_SIZE,
        )
        .unwrap();
        let legacy = build_txt_response_packet(&question, &qname, &build_txt_answer_chunks(&raw_frame, false).unwrap()).unwrap();
        assert!(response.len() < legacy.len(), "new={} legacy={}", response.len(), legacy.len());
    }

    #[test]
    fn legacy_multi_record_layout_still_parses() {
        // What the Go server sends; a Rust client talking to it must keep reading it.
        let (question, qname) = long_tunnel_question();
        let packet = data_packet(1500);
        let raw_frame = vpnproto::build_raw(&vpnproto::BuildOptions {
            session_id: packet.session_id,
            packet_type: packet.packet_type,
            session_cookie: packet.session_cookie,
            stream_id: packet.stream_id,
            sequence_num: packet.sequence_num,
            payload: packet.payload.clone(),
            ..Default::default()
        })
        .unwrap();
        for base_encode in [false, true] {
            let chunks = build_txt_answer_chunks(&raw_frame, base_encode).unwrap();
            assert!(chunks.len() > 1);
            let response = build_txt_response_packet(&question, &qname, &chunks).unwrap();
            assert_eq!(extract_vpn_response(&response, base_encode).unwrap().payload, packet.payload);
        }
    }

    #[test]
    fn max_encoded_qname_chars_round_trip() {
        let domain = "v.example.com";
        let max_chars = calculate_max_encoded_qname_chars(domain);
        assert!(encoded_qname_len(max_chars, domain.len()) <= MAX_DNS_NAME_LEN);
        assert!(encoded_qname_len(max_chars + 1, domain.len()) > MAX_DNS_NAME_LEN);
    }
}
