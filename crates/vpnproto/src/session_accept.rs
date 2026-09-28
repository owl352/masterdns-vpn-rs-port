//! Port of `internal/vpnproto/session_accept.go`.

pub const SESSION_ACCEPT_BASE_PAYLOAD_SIZE: usize = 7;
pub const SESSION_ACCEPT_POLICY_PAYLOAD_SIZE: usize = 13;
pub const SESSION_ACCEPT_PAYLOAD_SIZE: usize = SESSION_ACCEPT_BASE_PAYLOAD_SIZE + SESSION_ACCEPT_POLICY_PAYLOAD_SIZE;

pub const SESSION_POLICY_SCALED_MIN: f64 = 0.05;
pub const SESSION_POLICY_SCALED_MAX: f64 = 1.0;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionAcceptPayload {
    pub session_id: u8,
    pub session_cookie: u8,
    pub compression_pair: u8,
    pub verify_code: [u8; 4],
    pub client_policy: SessionAcceptClientPolicy,
    pub has_client_policy_sync: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionAcceptClientSettings {
    pub packet_duplication_count: i64,
    pub setup_packet_duplication_count: i64,
    pub max_upload_mtu: i64,
    pub max_download_mtu: i64,
    pub rx_tx_workers: i64,
    pub ping_aggressive_interval: f64,
    pub max_packets_per_batch: i64,
    pub arq_window_size: i64,
    pub arq_data_nack_max_gap: i64,
    pub compression_min_size: i64,
    pub arq_initial_rto_seconds: f64,
    pub arq_control_initial_rto_seconds: f64,
    pub arq_max_rto_seconds: f64,
    pub arq_control_max_rto_seconds: f64,
}

/// Server-side client limits/minimums appended to SESSION_ACCEPT after the
/// legacy 7-byte prefix.
///
/// Wire layout after the first 7 bytes:
/// ```text
/// byte 7  : lower nibble = max packet duplication, upper nibble = max setup duplication
/// byte 8  : max upload MTU (u8)
/// bytes 9-10  : max download MTU (u16, big endian)
/// byte 11 : max RX/TX workers (u8)
/// byte 12 : min ping aggressive interval, scaled 0..255 => 0.05..1.00 seconds
/// byte 13 : max packets per batch (u8)
/// bytes 14-15 : max ARQ window size (u16, big endian)
/// byte 16 : max ARQ data NACK max gap (u8)
/// bytes 17-18 : min compression min-size (u16, big endian)
/// byte 19 : min ARQ initial RTO, scaled 0..255 => 0.05..1.00 seconds
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionAcceptClientPolicy {
    pub max_packet_duplication_count: i64,
    pub max_setup_duplication_count: i64,
    pub max_upload_mtu: i64,
    pub max_download_mtu: i64,
    pub max_rx_tx_workers: i64,
    pub min_ping_aggressive_interval: f64,
    pub max_packets_per_batch: i64,
    pub max_arq_window_size: i64,
    pub max_arq_data_nack_max_gap: i64,
    pub min_compression_min_size: i64,
    pub min_arq_initial_rto_seconds: f64,
}

pub fn encode_session_accept_payload(payload: &SessionAcceptPayload) -> Vec<u8> {
    let size = if payload.has_client_policy_sync {
        SESSION_ACCEPT_PAYLOAD_SIZE
    } else {
        SESSION_ACCEPT_BASE_PAYLOAD_SIZE
    };

    let mut buf = vec![0u8; size];
    buf[0] = payload.session_id;
    buf[1] = payload.session_cookie;
    buf[2] = payload.compression_pair;
    buf[3..7].copy_from_slice(&payload.verify_code);

    if payload.has_client_policy_sync {
        let policy = encode_session_accept_client_policy(&payload.client_policy);
        buf[SESSION_ACCEPT_BASE_PAYLOAD_SIZE..].copy_from_slice(&policy);
    }

    buf
}

pub fn decode_session_accept_payload(payload: &[u8]) -> Result<SessionAcceptPayload, String> {
    if payload.len() < SESSION_ACCEPT_BASE_PAYLOAD_SIZE {
        return Err(format!(
            "session accept payload too short: got={} want>={}",
            payload.len(),
            SESSION_ACCEPT_BASE_PAYLOAD_SIZE
        ));
    }

    let mut result = SessionAcceptPayload {
        session_id: payload[0],
        session_cookie: payload[1],
        compression_pair: payload[2],
        ..Default::default()
    };
    result.verify_code.copy_from_slice(&payload[3..7]);

    if payload.len() >= SESSION_ACCEPT_PAYLOAD_SIZE {
        let policy = decode_session_accept_client_policy(
            &payload[SESSION_ACCEPT_BASE_PAYLOAD_SIZE..SESSION_ACCEPT_PAYLOAD_SIZE],
        )?;
        result.client_policy = policy;
        result.has_client_policy_sync = true;
    }

    Ok(result)
}

pub fn apply_session_accept_client_policy(
    current: SessionAcceptClientSettings,
    policy: &SessionAcceptClientPolicy,
) -> SessionAcceptClientSettings {
    let mut current = current;
    current.packet_duplication_count = clamp_i64(
        current.packet_duplication_count,
        1,
        max_i64(policy.max_packet_duplication_count, 1),
    );
    current.setup_packet_duplication_count = clamp_i64(
        current.setup_packet_duplication_count,
        current.packet_duplication_count,
        max_i64(policy.max_setup_duplication_count, current.packet_duplication_count),
    );

    current.max_upload_mtu = clamp_i64(current.max_upload_mtu, 1, max_i64(policy.max_upload_mtu, 1));
    current.max_download_mtu = clamp_i64(current.max_download_mtu, 1, max_i64(policy.max_download_mtu, 1));
    current.rx_tx_workers = clamp_i64(current.rx_tx_workers, 1, max_i64(policy.max_rx_tx_workers, 1));
    current.ping_aggressive_interval = clamp_f64(current.ping_aggressive_interval, policy.min_ping_aggressive_interval, 30.0);
    current.max_packets_per_batch = clamp_i64(current.max_packets_per_batch, 1, max_i64(policy.max_packets_per_batch, 1));
    current.arq_window_size = clamp_i64(current.arq_window_size, 1, max_i64(policy.max_arq_window_size, 1));
    current.arq_data_nack_max_gap = clamp_i64(current.arq_data_nack_max_gap, 0, max_i64(policy.max_arq_data_nack_max_gap, 0));
    current.compression_min_size = max_i64(current.compression_min_size, max_i64(policy.min_compression_min_size, 1));
    current.arq_initial_rto_seconds = clamp_f64(
        current.arq_initial_rto_seconds,
        policy.min_arq_initial_rto_seconds,
        current.arq_max_rto_seconds,
    );
    current.arq_control_initial_rto_seconds = clamp_f64(
        current.arq_control_initial_rto_seconds,
        policy.min_arq_initial_rto_seconds,
        current.arq_control_max_rto_seconds,
    );
    current
}

pub fn encode_session_accept_client_policy(policy: &SessionAcceptClientPolicy) -> [u8; SESSION_ACCEPT_POLICY_PAYLOAD_SIZE] {
    let mut payload = [0u8; SESSION_ACCEPT_POLICY_PAYLOAD_SIZE];

    payload[0] = ((clamp_i64(policy.max_setup_duplication_count, 0, 15) << 4)
        | clamp_i64(policy.max_packet_duplication_count, 0, 15)) as u8;
    payload[1] = clamp_i64(policy.max_upload_mtu, 0, 0xFF) as u8;
    payload[2..4].copy_from_slice(&(clamp_i64(policy.max_download_mtu, 0, 0xFFFF) as u16).to_be_bytes());
    payload[4] = clamp_i64(policy.max_rx_tx_workers, 0, 0xFF) as u8;
    payload[5] = encode_session_scaled_byte(policy.min_ping_aggressive_interval);
    payload[6] = clamp_i64(policy.max_packets_per_batch, 0, 0xFF) as u8;
    payload[7..9].copy_from_slice(&(clamp_i64(policy.max_arq_window_size, 0, 0xFFFF) as u16).to_be_bytes());
    payload[9] = clamp_i64(policy.max_arq_data_nack_max_gap, 0, 0xFF) as u8;
    payload[10..12].copy_from_slice(&(clamp_i64(policy.min_compression_min_size, 0, 0xFFFF) as u16).to_be_bytes());
    payload[12] = encode_session_scaled_byte(policy.min_arq_initial_rto_seconds);

    payload
}

pub fn decode_session_accept_client_policy(payload: &[u8]) -> Result<SessionAcceptClientPolicy, String> {
    if payload.len() < SESSION_ACCEPT_POLICY_PAYLOAD_SIZE {
        return Err(format!(
            "session accept policy payload too short: got={} want={}",
            payload.len(),
            SESSION_ACCEPT_POLICY_PAYLOAD_SIZE
        ));
    }

    Ok(SessionAcceptClientPolicy {
        max_packet_duplication_count: (payload[0] & 0x0F) as i64,
        max_setup_duplication_count: ((payload[0] >> 4) & 0x0F) as i64,
        max_upload_mtu: payload[1] as i64,
        max_download_mtu: u16::from_be_bytes([payload[2], payload[3]]) as i64,
        max_rx_tx_workers: payload[4] as i64,
        min_ping_aggressive_interval: decode_session_scaled_byte(payload[5]),
        max_packets_per_batch: payload[6] as i64,
        max_arq_window_size: u16::from_be_bytes([payload[7], payload[8]]) as i64,
        max_arq_data_nack_max_gap: payload[9] as i64,
        min_compression_min_size: u16::from_be_bytes([payload[10], payload[11]]) as i64,
        min_arq_initial_rto_seconds: decode_session_scaled_byte(payload[12]),
    })
}

pub fn encode_session_scaled_byte(value: f64) -> u8 {
    let clamped = clamp_f64(value, SESSION_POLICY_SCALED_MIN, SESSION_POLICY_SCALED_MAX);
    if SESSION_POLICY_SCALED_MAX <= SESSION_POLICY_SCALED_MIN {
        return 0;
    }

    let normalized = (clamped - SESSION_POLICY_SCALED_MIN) / (SESSION_POLICY_SCALED_MAX - SESSION_POLICY_SCALED_MIN);
    (normalized * 255.0).round() as u8
}

pub fn decode_session_scaled_byte(value: u8) -> f64 {
    let normalized = value as f64 / 255.0;
    SESSION_POLICY_SCALED_MIN + normalized * (SESSION_POLICY_SCALED_MAX - SESSION_POLICY_SCALED_MIN)
}

fn clamp_f64(value: f64, min_value: f64, max_value: f64) -> f64 {
    value.clamp(min_value, max_value)
}

fn clamp_i64(value: i64, min_value: i64, max_value: i64) -> i64 {
    value.clamp(min_value, max_value)
}

fn max_i64(a: i64, b: i64) -> i64 {
    a.max(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_accept_round_trip_without_policy() {
        let payload = SessionAcceptPayload {
            session_id: 5,
            session_cookie: 9,
            compression_pair: 0x12,
            verify_code: [1, 2, 3, 4],
            ..Default::default()
        };
        let encoded = encode_session_accept_payload(&payload);
        assert_eq!(encoded.len(), SESSION_ACCEPT_BASE_PAYLOAD_SIZE);
        let decoded = decode_session_accept_payload(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn session_accept_round_trip_with_policy() {
        let policy = SessionAcceptClientPolicy {
            max_packet_duplication_count: 5,
            max_setup_duplication_count: 6,
            max_upload_mtu: 150,
            max_download_mtu: 4096,
            max_rx_tx_workers: 255,
            min_ping_aggressive_interval: 0.05,
            max_packets_per_batch: 20,
            max_arq_window_size: 8000,
            max_arq_data_nack_max_gap: 255,
            min_compression_min_size: 120,
            min_arq_initial_rto_seconds: 0.05,
        };
        let payload = SessionAcceptPayload {
            session_id: 5,
            session_cookie: 9,
            compression_pair: 0x12,
            verify_code: [1, 2, 3, 4],
            client_policy: policy.clone(),
            has_client_policy_sync: true,
        };
        let encoded = encode_session_accept_payload(&payload);
        assert_eq!(encoded.len(), SESSION_ACCEPT_PAYLOAD_SIZE);
        let decoded = decode_session_accept_payload(&encoded).unwrap();
        assert!(decoded.has_client_policy_sync);
        assert_eq!(decoded.client_policy.max_upload_mtu, policy.max_upload_mtu);
        assert_eq!(decoded.client_policy.max_download_mtu, policy.max_download_mtu);
    }

    #[test]
    fn scaled_byte_round_trip_endpoints() {
        assert_eq!(encode_session_scaled_byte(0.05), 0);
        assert_eq!(encode_session_scaled_byte(1.0), 255);
        assert!((decode_session_scaled_byte(0) - 0.05).abs() < 1e-9);
        assert!((decode_session_scaled_byte(255) - 1.0).abs() < 1e-9);
    }
}
