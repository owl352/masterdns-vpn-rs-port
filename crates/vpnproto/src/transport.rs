//! Strict, session-independent wire codecs for negotiated transport v1.
use crate::VpnProtoError;

pub const TRANSPORT_VERSION: u8 = 1;
pub const TRANSPORT_FEATURES: u8 = 7;
/// Optional feature bit: unreliable UDP datagrams. Old peers mask it off.
pub const TRANSPORT_FEATURE_DATAGRAM: u8 = 8;
pub const TRANSPORT_MIN_FEEDBACK: u16 = 14;
pub const TRANSPORT_MAX_SPAN: u16 = 16_384;
pub const TRANSPORT_ENVELOPE_OVERHEAD: usize = 11;
pub const TRANSPORT_SELECT: u8 = 1;
pub const TRANSPORT_SELECTED: u8 = 2;
pub const TRANSPORT_COMMIT: u8 = 3;
pub const TRANSPORT_COMMITTED: u8 = 4;

fn invalid() -> VpnProtoError {
    VpnProtoError::InvalidEncodedData
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportCaps {
    pub op: u8,
    pub features: u8,
    pub nonce: u64,
    pub feedback_budget: u16,
    pub serial_span: u16,
}
impl TransportCaps {
    pub fn valid(&self) -> bool {
        (1..=4).contains(&self.op)
            && self.features & !TRANSPORT_FEATURE_DATAGRAM == TRANSPORT_FEATURES
            && self.feedback_budget >= TRANSPORT_MIN_FEEDBACK
            && (1..=TRANSPORT_MAX_SPAN).contains(&self.serial_span)
    }
    pub fn encode(&self) -> Result<Vec<u8>, VpnProtoError> {
        if !self.valid() {
            return Err(invalid());
        }
        let mut b = vec![1, self.op, self.features];
        b.extend_from_slice(&self.nonce.to_be_bytes());
        b.extend_from_slice(&self.feedback_budget.to_be_bytes());
        b.extend_from_slice(&self.serial_span.to_be_bytes());
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self, VpnProtoError> {
        if b.len() != 15 || b[0] != 1 {
            return Err(invalid());
        }
        let c = Self {
            op: b[1],
            features: b[2],
            nonce: u64::from_be_bytes(b[3..11].try_into().unwrap()),
            feedback_budget: u16::from_be_bytes(b[11..13].try_into().unwrap()),
            serial_span: u16::from_be_bytes(b[13..15].try_into().unwrap()),
        };
        if !c.valid() {
            return Err(invalid());
        }
        Ok(c)
    }
    pub fn offer(&self) -> Result<Vec<u8>, VpnProtoError> {
        let caps = self.encode()?;
        let mut b = b"MDX1\0\x0e".to_vec();
        b.push(1);
        b.push(self.features);
        b.extend_from_slice(&caps[3..]);
        Ok(b)
    }
    pub fn decode_offer(accept: &[u8]) -> Result<Option<Self>, VpnProtoError> {
        if accept.len() == 20 {
            return Ok(None);
        }
        if accept.len() != 40 || &accept[20..26] != b"MDX1\0\x0e" {
            return Err(invalid());
        }
        let mut b = vec![
            accept[26],
            TRANSPORT_SELECT,
            accept[27] & (TRANSPORT_FEATURES | TRANSPORT_FEATURE_DATAGRAM),
        ];
        b.extend_from_slice(&accept[28..40]);
        Self::decode(&b).map(Some)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeedbackRange {
    pub offset: u16,
    pub length: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedbackRecord {
    pub stream_id: u16,
    pub ack_next: u32,
    pub sacks: Vec<FeedbackRange>,
    pub repairs: Vec<FeedbackRange>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportFeedback {
    pub records: Vec<FeedbackRecord>,
}

fn validate_ranges(ranges: &[FeedbackRange], ack: u32, span: u16, sack: bool) -> bool {
    if ranges.len() > 8 {
        return false;
    }
    let mut end = 0u32;
    for (i, r) in ranges.iter().enumerate() {
        let start = r.offset as u32;
        let next = start + r.length as u32;
        // Adjacent intervals must be merged: the wire representation is canonical.
        if r.length == 0
            || (sack && start == 0)
            || (i > 0 && start <= end)
            || next > span as u32
            || ack.checked_add(next).is_none()
        {
            return false;
        }
        end = next;
    }
    true
}
impl FeedbackRecord {
    pub fn valid(&self, span: u16) -> bool {
        validate_ranges(&self.sacks, self.ack_next, span, true)
            && validate_ranges(&self.repairs, self.ack_next, span, false)
            && !self.sacks.iter().any(|a| {
                self.repairs.iter().any(|b| {
                    (a.offset as u32) < b.offset as u32 + b.length as u32
                        && (b.offset as u32) < a.offset as u32 + a.length as u32
                })
            })
    }
    pub fn encoded_len(&self) -> usize {
        8 + 4 * (self.sacks.len() + self.repairs.len())
    }
}
impl TransportFeedback {
    pub fn encode(&self, budget: u16, span: u16) -> Result<Vec<u8>, VpnProtoError> {
        if self.records.len() > 16 || !(1..=TRANSPORT_MAX_SPAN).contains(&span) {
            return Err(invalid());
        }
        let mut b = vec![1, self.records.len() as u8];
        for r in &self.records {
            if !r.valid(span) {
                return Err(invalid());
            }
            b.extend_from_slice(&r.stream_id.to_be_bytes());
            b.extend_from_slice(&r.ack_next.to_be_bytes());
            b.push(r.sacks.len() as u8);
            b.push(r.repairs.len() as u8);
            for range in r.sacks.iter().chain(&r.repairs) {
                b.extend_from_slice(&range.offset.to_be_bytes());
                b.extend_from_slice(&range.length.to_be_bytes());
            }
        }
        if b.len() > budget as usize {
            return Err(invalid());
        }
        Ok(b)
    }
    pub fn decode(b: &[u8], budget: u16, span: u16) -> Result<Self, VpnProtoError> {
        if b.len() < 2
            || b.len() > budget as usize
            || b[0] != 1
            || b[1] > 16
            || !(1..=TRANSPORT_MAX_SPAN).contains(&span)
        {
            return Err(invalid());
        }
        let mut pos = 2;
        let mut records = Vec::with_capacity(b[1] as usize);
        for _ in 0..b[1] {
            if b.len() - pos < 8 {
                return Err(invalid());
            }
            let mut r = FeedbackRecord {
                stream_id: u16::from_be_bytes(b[pos..pos + 2].try_into().unwrap()),
                ack_next: u32::from_be_bytes(b[pos + 2..pos + 6].try_into().unwrap()),
                sacks: Vec::new(),
                repairs: Vec::new(),
            };
            let ns = b[pos + 6] as usize;
            let nr = b[pos + 7] as usize;
            pos += 8;
            if ns > 8 || nr > 8 || b.len() - pos < (ns + nr) * 4 {
                return Err(invalid());
            }
            for i in 0..ns + nr {
                let range = FeedbackRange {
                    offset: u16::from_be_bytes(b[pos..pos + 2].try_into().unwrap()),
                    length: u16::from_be_bytes(b[pos + 2..pos + 4].try_into().unwrap()),
                };
                pos += 4;
                if i < ns {
                    r.sacks.push(range);
                } else {
                    r.repairs.push(range);
                }
            }
            if !r.valid(span) {
                return Err(invalid());
            }
            records.push(r);
        }
        if pos != b.len() {
            return Err(invalid());
        }
        Ok(Self { records })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportEnvelope {
    pub inner_kind: u8,
    pub inner_compression: u8,
    pub logical_seq: u32,
    pub feedback: Option<TransportFeedback>,
    pub data: Vec<u8>,
}
impl TransportEnvelope {
    pub fn encode(&self, budget: u16, span: u16) -> Result<Vec<u8>, VpnProtoError> {
        if !matches!(
            self.inner_kind,
            enums::PACKET_STREAM_DATA | enums::PACKET_STREAM_RESEND
        ) || !valid_compression(self.inner_compression)
            || self.data.len() > u16::MAX as usize
        {
            return Err(invalid());
        }
        let fb = match &self.feedback {
            Some(f) => f.encode(budget, span)?,
            None => Vec::new(),
        };
        let mut b = vec![1, self.inner_kind, self.inner_compression];
        b.extend_from_slice(&self.logical_seq.to_be_bytes());
        b.extend_from_slice(&(fb.len() as u16).to_be_bytes());
        b.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        b.extend_from_slice(&fb);
        b.extend_from_slice(&self.data);
        Ok(b)
    }
    pub fn decode(b: &[u8], outer_seq: u16, budget: u16, span: u16) -> Result<Self, VpnProtoError> {
        if b.len() < 11
            || b[0] != 1
            || !matches!(
                b[1],
                enums::PACKET_STREAM_DATA | enums::PACKET_STREAM_RESEND
            )
            || !valid_compression(b[2])
        {
            return Err(invalid());
        }
        let seq = u32::from_be_bytes(b[3..7].try_into().unwrap());
        let nf = u16::from_be_bytes(b[7..9].try_into().unwrap()) as usize;
        let nd = u16::from_be_bytes(b[9..11].try_into().unwrap()) as usize;
        if seq as u16 != outer_seq || b.len() != 11 + nf + nd {
            return Err(invalid());
        }
        let feedback = if nf == 0 {
            None
        } else {
            Some(TransportFeedback::decode(&b[11..11 + nf], budget, span)?)
        };
        Ok(Self {
            inner_kind: b[1],
            inner_compression: b[2],
            logical_seq: seq,
            feedback,
            data: b[11 + nf..].to_vec(),
        })
    }
    pub fn inflate_data_bounded(&self, maximum: usize) -> Result<Vec<u8>, VpnProtoError> {
        compression::try_decompress_payload_bounded(&self.data, self.inner_compression, maximum)
            .ok_or(VpnProtoError::InvalidCompressedPayload)
    }
    pub fn inflate_data(&self) -> Result<Vec<u8>, VpnProtoError> {
        if self.inner_compression == compression::TYPE_OFF {
            return Ok(self.data.clone());
        }
        compression::try_decompress_payload(&self.data, self.inner_compression)
            .ok_or(VpnProtoError::InvalidCompressedPayload)
    }
}
fn valid_compression(c: u8) -> bool {
    matches!(
        c,
        compression::TYPE_OFF
            | compression::TYPE_ZSTD
            | compression::TYPE_LZ4
            | compression::TYPE_ZLIB
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn caps_and_offer_exact_layout() {
        let c = TransportCaps {
            op: 1,
            features: 7,
            nonce: 0x0102030405060708,
            feedback_budget: 128,
            serial_span: 300,
        };
        assert_eq!(
            c.encode().unwrap(),
            vec![1, 1, 7, 1, 2, 3, 4, 5, 6, 7, 8, 0, 128, 1, 44]
        );
        let mut accept = vec![0; 20];
        accept.extend(c.offer().unwrap());
        assert_eq!(TransportCaps::decode_offer(&accept).unwrap(), Some(c));
        accept.push(0);
        assert!(TransportCaps::decode_offer(&accept).is_err());
    }
    #[test]
    fn strict_feedback_and_envelope() {
        let f = TransportFeedback {
            records: vec![FeedbackRecord {
                stream_id: 2,
                ack_next: 65536,
                sacks: vec![FeedbackRange {
                    offset: 2,
                    length: 3,
                }],
                repairs: vec![FeedbackRange {
                    offset: 0,
                    length: 2,
                }],
            }],
        };
        let b = f.encode(64, 300).unwrap();
        assert_eq!(TransportFeedback::decode(&b, 64, 300).unwrap(), f);
        for i in 0..b.len() {
            assert!(TransportFeedback::decode(&b[..i], 64, 300).is_err());
        }
        let mut trailing = b.clone();
        trailing.push(0);
        assert!(TransportFeedback::decode(&trailing, 64, 300).is_err());
        assert!(TransportFeedback::decode(&b, 14, 300).is_err());
        let e = TransportEnvelope {
            inner_kind: 15,
            inner_compression: 0,
            logical_seq: 65536,
            feedback: Some(f),
            data: b"app".to_vec(),
        };
        let eb = e.encode(64, 300).unwrap();
        assert_eq!(TransportEnvelope::decode(&eb, 0, 64, 300).unwrap(), e);
        assert!(TransportEnvelope::decode(&eb, 1, 64, 300).is_err());
        let mut bad = e.clone();
        bad.inner_kind = 59;
        assert!(bad.encode(64, 300).is_err());
    }
    #[test]
    fn rejects_overlap_noncanonical_and_overflow() {
        let mut r = FeedbackRecord {
            stream_id: 1,
            ack_next: 0,
            sacks: vec![FeedbackRange {
                offset: 1,
                length: 2,
            }],
            repairs: vec![FeedbackRange {
                offset: 2,
                length: 1,
            }],
        };
        assert!(!r.valid(300));
        r.repairs.clear();
        r.sacks.push(FeedbackRange {
            offset: 3,
            length: 1,
        });
        assert!(!r.valid(300));
        r.sacks.pop();
        r.ack_next = u32::MAX - 1;
        assert!(!r.valid(300));
    }
}

#[cfg(test)]
mod framed_transport_tests {
    use super::*;
    #[test]
    fn envelopes_preserve_fragmentation_and_inflate_original_exactly_once_under_crypto() {
        let original = vec![b'a'; 130];
        for comp in [
            compression::TYPE_ZSTD,
            compression::TYPE_LZ4,
            compression::TYPE_ZLIB,
        ] {
            let (data, ctype) = compression::compress_payload(&original, comp, 1);
            let envelope = TransportEnvelope {
                inner_kind: enums::PACKET_STREAM_RESEND,
                inner_compression: ctype,
                logical_seq: 65537,
                feedback: None,
                data,
            };
            for method in [
                security::METHOD_NONE,
                security::METHOD_XOR,
                security::METHOD_CHACHA20,
                security::METHOD_AES128GCM,
            ] {
                let codec = security::Codec::new(method, "shared key").unwrap();
                let options = crate::BuildOptions {
                    session_id: 7,
                    session_cookie: 9,
                    packet_type: enums::PACKET_STREAM_ENVELOPE,
                    stream_id: 12,
                    sequence_num: 1,
                    fragment_id: 1,
                    total_fragments: 3,
                    compression_type: compression::TYPE_OFF,
                    payload: envelope.encode(64, 300).unwrap(),
                };
                let encoded = crate::build_encoded_auto(options, Some(&codec), 1).unwrap();
                let packet = crate::parse_inflated_from_labels(&encoded, Some(&codec)).unwrap();
                assert_eq!((packet.fragment_id, packet.total_fragments), (1, 3));
                assert!(
                    packet.has_fragment_info
                        && packet.has_stream_id
                        && packet.has_sequence_num
                        && packet.has_compression_type
                );
                assert_eq!(packet.compression_type, compression::TYPE_OFF);
                let decoded =
                    TransportEnvelope::decode(&packet.payload, packet.sequence_num, 64, 300)
                        .unwrap();
                assert_eq!(decoded, envelope);
                assert_eq!(decoded.inflate_data_bounded(150).unwrap(), original);
            }
        }
    }
    #[test]
    fn unknown_offer_bits_are_ignored_but_subset_selections_are_rejected() {
        let c = TransportCaps {
            op: 1,
            features: 7,
            nonce: 1,
            feedback_budget: 64,
            serial_span: 300,
        };
        let mut accept = vec![0; 20];
        accept.extend(c.offer().unwrap());
        accept[27] |= 0x80;
        assert_eq!(TransportCaps::decode_offer(&accept).unwrap(), Some(c));
        assert!(TransportCaps { features: 1, ..c }.encode().is_err());
    }
}

/// Only negotiated non-control streams use this body; the legacy header and
/// matching control ACK sequence remain unchanged.
pub fn encode_transport_eof(end_exclusive: u32) -> [u8; 4] {
    end_exclusive.to_be_bytes()
}
pub fn decode_transport_eof(payload: &[u8]) -> Result<u32, VpnProtoError> {
    let bytes: [u8; 4] = payload.try_into().map_err(|_| invalid())?;
    Ok(u32::from_be_bytes(bytes))
}
