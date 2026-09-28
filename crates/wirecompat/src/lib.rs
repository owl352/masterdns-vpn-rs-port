//! Wire-compatibility fixtures shared with the Go implementation.
//!
//! The JSON schema mirrors `compat/wirefix/main.go`. Two directions:
//! - `compat/fixtures/go-wire.json` holds bytes produced by the Go code; the
//!   tests in `tests/go_fixtures.rs` check this crate's protocol crates
//!   against them.
//! - [`produce`] builds the same kinds of cases with the Rust code; the
//!   `wirecompat-dump` binary writes them out and `compat/wirefix.sh check`
//!   parses them with the Go client's own code.

use serde::{Deserialize, Serialize};

pub const CODEC_KEY: &str = "compat-fixture-key";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    pub packet_type: u8,
    pub session_id: u8,
    pub session_cookie: u8,
    pub stream_id: u16,
    pub sequence_num: u16,
    pub fragment_id: u8,
    pub total_fragments: u8,
    pub compression_type: u8,
    pub payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameCase {
    #[serde(flatten)]
    pub frame: Frame,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackedCase {
    pub blocks: Vec<[u32; 5]>,
    pub raw: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Policy {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAcceptCase {
    pub session_id: u8,
    pub session_cookie: u8,
    pub compression_pair: u8,
    pub verify_code: String,
    pub has_policy: bool,
    pub policy: Policy,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingCase {
    pub data: String,
    pub encoded: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodecCase {
    pub method: u8,
    pub key: String,
    pub plain: String,
    pub encoded: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionCase {
    #[serde(rename = "type")]
    pub comp_type: u8,
    pub data: String,
    pub compressed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryCase {
    pub domain: String,
    pub method: u8,
    pub key: String,
    pub frame: Frame,
    pub encoded: String,
    pub packet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseCase {
    pub base_encode: bool,
    pub question: String,
    pub answer_name: String,
    pub frame: Frame,
    pub response: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Fixtures {
    pub producer: String,
    pub frames: Vec<FrameCase>,
    #[serde(default)]
    pub invalid_packet_types: Vec<u8>,
    pub packed: Vec<PackedCase>,
    pub session_accept: Vec<SessionAcceptCase>,
    pub base36: Vec<EncodingCase>,
    pub base64: Vec<EncodingCase>,
    pub codec: Vec<CodecCase>,
    pub compression: Vec<CompressionCase>,
    #[serde(default)]
    pub queries: Vec<QueryCase>,
    pub responses: Vec<ResponseCase>,
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex")).collect()
}

impl Frame {
    pub fn build_options(&self) -> vpnproto::BuildOptions {
        vpnproto::BuildOptions {
            session_id: self.session_id,
            packet_type: self.packet_type,
            session_cookie: self.session_cookie,
            stream_id: self.stream_id,
            sequence_num: self.sequence_num,
            fragment_id: self.fragment_id,
            total_fragments: self.total_fragments,
            compression_type: self.compression_type,
            payload: unhex(&self.payload),
        }
    }

    pub fn to_packet(&self) -> vpnproto::Packet {
        let o = self.build_options();
        vpnproto::Packet {
            session_id: o.session_id,
            packet_type: o.packet_type,
            session_cookie: o.session_cookie,
            stream_id: o.stream_id,
            sequence_num: o.sequence_num,
            fragment_id: o.fragment_id,
            total_fragments: o.total_fragments,
            compression_type: o.compression_type,
            payload: o.payload,
            ..Default::default()
        }
    }

    /// The frame as a receiver sees it: fields the packet type does not carry
    /// on the wire read back as zero.
    pub fn from_packet(p: &vpnproto::Packet) -> Frame {
        Frame {
            packet_type: p.packet_type,
            session_id: p.session_id,
            session_cookie: p.session_cookie,
            stream_id: if p.has_stream_id { p.stream_id } else { 0 },
            sequence_num: if p.has_sequence_num { p.sequence_num } else { 0 },
            fragment_id: if p.has_fragment_info { p.fragment_id } else { 0 },
            total_fragments: if p.has_fragment_info { p.total_fragments } else { 0 },
            compression_type: if p.has_compression_type { p.compression_type } else { 0 },
            payload: hex(&p.payload),
        }
    }

    /// Zeroes the fields this packet type does not carry on the wire.
    pub fn as_received(&self) -> Frame {
        let t = self.packet_type;
        let mut f = self.clone();
        if !vpnproto::has_stream_extension(t) {
            f.stream_id = 0;
        }
        if !vpnproto::has_sequence_extension(t) {
            f.sequence_num = 0;
        }
        if !vpnproto::has_fragment_extension(t) {
            f.fragment_id = 0;
            f.total_fragments = 0;
        }
        if !vpnproto::has_compression_extension(t) {
            f.compression_type = 0;
        }
        f
    }
}

impl Policy {
    pub fn to_vpn(&self) -> vpnproto::SessionAcceptClientPolicy {
        vpnproto::SessionAcceptClientPolicy {
            max_packet_duplication_count: self.max_packet_duplication_count,
            max_setup_duplication_count: self.max_setup_duplication_count,
            max_upload_mtu: self.max_upload_mtu,
            max_download_mtu: self.max_download_mtu,
            max_rx_tx_workers: self.max_rx_tx_workers,
            min_ping_aggressive_interval: self.min_ping_aggressive_interval,
            max_packets_per_batch: self.max_packets_per_batch,
            max_arq_window_size: self.max_arq_window_size,
            max_arq_data_nack_max_gap: self.max_arq_data_nack_max_gap,
            min_compression_min_size: self.min_compression_min_size,
            min_arq_initial_rto_seconds: self.min_arq_initial_rto_seconds,
        }
    }
}

/// Small deterministic generator so the dump is reproducible without extra
/// dependencies.
struct Lcg(u64);
impl Lcg {
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n)
            .map(|_| {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (self.0 >> 33) as u8
            })
            .collect()
    }
}

fn compressible_bytes(n: usize) -> Vec<u8> {
    b"masterdnsvpn compat payload ".iter().copied().cycle().take(n).collect()
}

/// Builds every case kind with the Rust code, for the Go side to parse.
pub fn produce() -> Fixtures {
    let mut rng = Lcg(20260928);
    let mut fx = Fixtures { producer: "rust".into(), ..Default::default() };

    for t in 0..=255u8 {
        let f = Frame {
            packet_type: t,
            session_id: 7,
            session_cookie: 0x5A,
            stream_id: 0x1234,
            sequence_num: 0xBEEF,
            fragment_id: 2,
            total_fragments: 5,
            compression_type: 0,
            payload: hex(b"hello-compat"),
        };
        match vpnproto::build_raw(&f.build_options()) {
            Ok(raw) => fx.frames.push(FrameCase { frame: f.as_received(), raw: hex(&raw) }),
            Err(_) => fx.invalid_packet_types.push(t),
        }
    }

    let blocks: Vec<[u32; 5]> = vec![
        [enums::PACKET_STREAM_DATA_ACK as u32, 1, 0, 0, 0],
        [enums::PACKET_STREAM_DATA_ACK as u32, 1, 65535, 0, 0],
        [enums::PACKET_STREAM_DATA_NACK as u32, 0x1234, 0xBEEF, 3, 9],
        [enums::PACKET_SOCKS5_CONNECTED_ACK as u32, 65535, 1, 0, 0],
    ];
    let mut packed = Vec::new();
    for b in &blocks {
        vpnproto::append_packed_control_block(&mut packed, b[0] as u8, b[1] as u16, b[2] as u16, b[3] as u8, b[4] as u8);
    }
    fx.packed.push(PackedCase { blocks, raw: hex(&packed) });

    let policy = Policy {
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
        min_arq_initial_rto_seconds: 0.35,
    };
    for with_policy in [false, true] {
        let payload = vpnproto::SessionAcceptPayload {
            session_id: 9,
            session_cookie: 0xA7,
            compression_pair: 0x13,
            verify_code: [1, 2, 3, 4],
            client_policy: if with_policy { policy.to_vpn() } else { Default::default() },
            has_client_policy_sync: with_policy,
        };
        fx.session_accept.push(SessionAcceptCase {
            session_id: 9,
            session_cookie: 0xA7,
            compression_pair: 0x13,
            verify_code: hex(&[1, 2, 3, 4]),
            has_policy: with_policy,
            policy: if with_policy { policy.clone() } else { Policy::default() },
            raw: hex(&vpnproto::encode_session_accept_payload(&payload)),
        });
    }

    let mut inputs: Vec<Vec<u8>> = vec![vec![], vec![0], vec![0, 0, 1], vec![0xFF], b"abc".to_vec()];
    for n in [7, 32, 63, 100, 150] {
        inputs.push(rng.bytes(n));
    }
    for input in &inputs {
        fx.base36.push(EncodingCase { data: hex(input), encoded: basecodec::encode_lower_base36(input) });
        fx.base64.push(EncodingCase { data: hex(input), encoded: String::from_utf8(basecodec::encode_raw_base64(input)).unwrap() });
    }

    for method in 0..=5u8 {
        let codec = security::Codec::new(method, CODEC_KEY).expect("codec");
        for plain in [b"x".to_vec(), rng.bytes(140)] {
            let encoded = codec.encrypt_and_encode(&plain).expect("encrypt");
            fx.codec.push(CodecCase { method, key: CODEC_KEY.into(), plain: hex(&plain), encoded });
        }
    }

    for comp_type in [compression::TYPE_ZSTD, compression::TYPE_LZ4, compression::TYPE_ZLIB] {
        let data = compressible_bytes(2000);
        let (compressed, used) = compression::compress_payload(&data, comp_type, compression::DEFAULT_MIN_SIZE);
        assert_eq!(used, comp_type, "compression type {comp_type} not applied");
        fx.compression.push(CompressionCase { comp_type, data: hex(&data), compressed: hex(&compressed) });
    }

    // Responses as this server builds them, for both short and full-length
    // query names (the answer name is a pointer to the question name).
    for encoded_frame in [b"aaaa0123456789".to_vec(), vec![b'a'; dnsparser::calculate_max_encoded_qname_chars("v.example.com")]] {
        let question = dnsparser::build_tunnel_txt_question_packet("v.example.com", &encoded_frame, enums::DNS_RECORD_TYPE_TXT, 1232).unwrap();
        let qname = dnsparser::parse_packet(&question).unwrap().questions[0].name.clone();
        let frames = [
            Frame { packet_type: enums::PACKET_PONG, session_id: 3, session_cookie: 0x33, payload: hex(&rng.bytes(7)), ..Default::default() },
            Frame { packet_type: enums::PACKET_STREAM_DATA, session_id: 3, session_cookie: 0x33, stream_id: 5, sequence_num: 42, payload: hex(&rng.bytes(180)), ..Default::default() },
            Frame { packet_type: enums::PACKET_STREAM_DATA, session_id: 3, session_cookie: 0x33, stream_id: 5, sequence_num: 43, payload: hex(&rng.bytes(1500)), ..Default::default() },
            Frame { packet_type: enums::PACKET_STREAM_DATA, session_id: 3, session_cookie: 0x33, stream_id: 5, sequence_num: 44, payload: hex(&rng.bytes(4000)), ..Default::default() },
            Frame {
                packet_type: enums::PACKET_STREAM_DATA,
                session_id: 3,
                session_cookie: 0x33,
                stream_id: 5,
                sequence_num: 45,
                compression_type: compression::TYPE_ZSTD,
                payload: hex(&compressible_bytes(3000)),
                ..Default::default()
            },
            Frame { packet_type: enums::PACKET_PACKED_CONTROL_BLOCKS, session_id: 3, session_cookie: 0x33, payload: hex(&packed), ..Default::default() },
        ];
        for base_encode in [false, true] {
            for f in &frames {
                let response = dnsparser::build_vpn_response_packet(&question, &qname, &f.to_packet(), base_encode).unwrap();
                let mut expected = f.as_received();
                expected.compression_type = 0;
                fx.responses.push(ResponseCase { base_encode, question: hex(&question), answer_name: qname.clone(), frame: expected, response: hex(&response) });
            }
        }
    }

    fx
}
