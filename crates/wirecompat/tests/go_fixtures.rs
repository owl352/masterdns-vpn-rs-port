//! Checks the Rust protocol code against bytes produced by the Go
//! implementation (`compat/fixtures/go-wire.json`, regenerate with
//! `compat/wirefix.sh gen`).

use wirecompat::{hex, unhex, Fixtures, Frame};

fn go_fixtures() -> Fixtures {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/fixtures/go-wire.json");
    let data = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let fx: Fixtures = serde_json::from_str(&data).expect("parse go-wire.json");
    assert_eq!(fx.producer, "go");
    fx
}

#[test]
fn frames_build_and_parse_like_go() {
    let fx = go_fixtures();
    assert!(!fx.frames.is_empty());
    for case in &fx.frames {
        let t = case.frame.packet_type;
        let raw = vpnproto::build_raw(&case.frame.build_options()).unwrap_or_else(|e| panic!("type 0x{t:02x}: Rust refused to build: {e:?}"));
        assert_eq!(hex(&raw), case.raw, "type 0x{t:02x}: Rust frame bytes differ from Go");

        let parsed = vpnproto::parse(&unhex(&case.raw)).unwrap_or_else(|e| panic!("type 0x{t:02x}: Rust could not parse Go frame: {e:?}"));
        assert_eq!(Frame::from_packet(&parsed), case.frame, "type 0x{t:02x}: parsed fields differ");
    }
}

#[test]
fn same_packet_types_are_valid_as_in_go() {
    let fx = go_fixtures();
    let rust_invalid: Vec<u8> = (0..=255u8).filter(|&t| vpnproto::build_raw(&vpnproto::BuildOptions { packet_type: t, ..Default::default() }).is_err()).collect();
    // The retained legacy fixture predates the negotiated v1 types.
    let expected:Vec<u8> = fx.invalid_packet_types.into_iter().filter(|t| !matches!(*t,
        enums::PACKET_TRANSPORT_CAPS | enums::PACKET_TRANSPORT_CAPS_ACK | enums::PACKET_STREAM_FEEDBACK | enums::PACKET_STREAM_ENVELOPE | enums::PACKET_UDP_DATAGRAM)).collect();
    assert_eq!(rust_invalid, expected);
}

#[test]
fn packed_control_blocks_match_go() {
    for case in &go_fixtures().packed {
        let mut raw = Vec::new();
        for b in &case.blocks {
            vpnproto::append_packed_control_block(&mut raw, b[0] as u8, b[1] as u16, b[2] as u16, b[3] as u8, b[4] as u8);
        }
        assert_eq!(hex(&raw), case.raw);

        let mut read = Vec::new();
        vpnproto::for_each_packed_control_block(&unhex(&case.raw), |t, s, sn, f, tot| {
            read.push([t as u32, s as u32, sn as u32, f as u32, tot as u32]);
            true
        });
        assert_eq!(read, case.blocks);
    }
}

#[test]
fn session_accept_matches_go() {
    for case in &go_fixtures().session_accept {
        let mut verify_code = [0u8; 4];
        verify_code.copy_from_slice(&unhex(&case.verify_code));
        let payload = vpnproto::SessionAcceptPayload {
            session_id: case.session_id,
            session_cookie: case.session_cookie,
            compression_pair: case.compression_pair,
            verify_code,
            client_policy: if case.has_policy { case.policy.to_vpn() } else { Default::default() },
            has_client_policy_sync: case.has_policy,
        };
        assert_eq!(hex(&vpnproto::encode_session_accept_payload(&payload)), case.raw, "policy={}", case.has_policy);

        let decoded = vpnproto::decode_session_accept_payload(&unhex(&case.raw)).unwrap();
        assert_eq!((decoded.session_id, decoded.session_cookie, decoded.compression_pair, decoded.verify_code), (case.session_id, case.session_cookie, case.compression_pair, verify_code));
        assert_eq!(decoded.has_client_policy_sync, case.has_policy);
    }
}

#[test]
fn label_and_txt_encodings_match_go() {
    let fx = go_fixtures();
    for case in &fx.base36 {
        let data = unhex(&case.data);
        assert_eq!(basecodec::encode_lower_base36(&data), case.encoded, "base36 encode of {}", case.data);
        assert_eq!(basecodec::decode_lower_base36_string(&case.encoded).unwrap(), data, "base36 decode of {}", case.encoded);
    }
    for case in &fx.base64 {
        let data = unhex(&case.data);
        assert_eq!(String::from_utf8(basecodec::encode_raw_base64(&data)).unwrap(), case.encoded);
        assert_eq!(basecodec::decode_raw_base64(case.encoded.as_bytes()).unwrap(), data);
    }
}

#[test]
fn go_ciphertexts_decrypt_in_rust() {
    for case in &go_fixtures().codec {
        let codec = security::Codec::new(case.method, &case.key).unwrap();
        let plain = codec.decode_string_and_decrypt(&case.encoded).unwrap_or_else(|e| panic!("method {}: {e:?}", case.method));
        assert_eq!(hex(&plain), case.plain, "method {}", case.method);
        if case.method <= security::METHOD_XOR {
            // No nonce: output must be byte-identical.
            assert_eq!(codec.encrypt_and_encode(&unhex(&case.plain)).unwrap(), case.encoded, "method {}", case.method);
        }
    }
}

#[test]
fn go_compressed_payloads_decompress_in_rust() {
    for case in &go_fixtures().compression {
        let data = compression::try_decompress_payload(&unhex(&case.compressed), case.comp_type).unwrap_or_else(|| panic!("type {}", case.comp_type));
        assert_eq!(compression::try_decompress_payload_bounded(&unhex(&case.compressed),case.comp_type,data.len()).unwrap(),data);
        assert_eq!(hex(&data), case.data, "type {}", case.comp_type);
    }
}

/// Go-client queries through the same steps `udpserver::ingress` uses.
#[test]
fn go_client_queries_parse_on_the_server_path() {
    let fx = go_fixtures();
    assert!(!fx.queries.is_empty());
    for case in &fx.queries {
        let packet = unhex(&case.packet);
        let lite = dnsparser::parse_dns_request_lite(&packet).expect("lite parse");
        let matcher = domainmatcher::Matcher::new(&[case.domain.clone()], 1);
        let decision = matcher.matches(&lite);
        assert!(matches!(decision.action, Some(domainmatcher::Action::Process)), "method {}: not routed to the tunnel ({})", case.method, decision.reason);

        let codec = security::Codec::new(case.method, &case.key).unwrap();
        let vpn = vpnproto::parse_inflated_from_labels(&decision.labels, Some(&codec)).unwrap_or_else(|e| panic!("method {}: {e:?}", case.method));
        assert_eq!(Frame::from_packet(&vpn), case.frame, "method {}", case.method);

        // Same question bytes from the Rust builder, apart from the random DNS ID.
        let rebuilt = dnsparser::build_tunnel_txt_question_packet(&case.domain, case.encoded.as_bytes(), enums::DNS_RECORD_TYPE_TXT, 1232).unwrap();
        assert_eq!(hex(&rebuilt[2..]), hex(&packet[2..]), "method {}: question bytes differ", case.method);
    }
}

/// Responses as the Go server builds them (legacy multi-record TXT layout
/// for big frames) must stay readable by a Rust client.
#[test]
fn go_server_responses_parse_in_rust() {
    let fx = go_fixtures();
    assert!(!fx.responses.is_empty());
    for (i, case) in fx.responses.iter().enumerate() {
        let packet = dnsparser::extract_vpn_response(&unhex(&case.response), case.base_encode).unwrap_or_else(|e| panic!("response[{i}] base={}: {e:?}", case.base_encode));
        let mut got = Frame::from_packet(&packet);
        got.compression_type = 0;
        assert_eq!(got, case.frame, "response[{i}] base={}", case.base_encode);
    }
}

#[test]
fn negotiated_transport_matches_shared_vectors() {
    use vpnproto::{FeedbackRange, FeedbackRecord, TransportCaps, TransportEnvelope, TransportFeedback};
    let fx:serde_json::Value=serde_json::from_str(include_str!("../../../compat/fixtures/transport-v1.json")).unwrap();
    let number=|v:&serde_json::Value,key:&str|v[key].as_u64().unwrap();
    let range=|v:&serde_json::Value| FeedbackRange{offset:v[0].as_u64().unwrap() as u16,length:v[1].as_u64().unwrap() as u16};
    for v in fx["feedback"].as_array().unwrap() {
        let f=TransportFeedback{records:v["records"].as_array().unwrap().iter().map(|r|FeedbackRecord{
            stream_id:number(r,"streamId") as u16,ack_next:number(r,"ackNext") as u32,
            sacks:r["sack"].as_array().unwrap().iter().map(range).collect(),
            repairs:r["repair"].as_array().unwrap().iter().map(range).collect(),
        }).collect()};
        let budget=number(v,"budget") as u16;let span=number(v,"span") as u16;
        assert_eq!(hex(&f.encode(budget,span).unwrap()),v["hex"].as_str().unwrap(),"{}",v["name"]);
        assert_eq!(TransportFeedback::decode(&unhex(v["hex"].as_str().unwrap()),budget,span).unwrap(),f);
    }
    for v in fx["envelopes"].as_array().unwrap() {
        let budget=number(v,"budget") as u16;let span=number(v,"span") as u16;
        let fb=unhex(v["feedbackHex"].as_str().unwrap());
        let e=TransportEnvelope{inner_kind:number(v,"kind") as u8,inner_compression:number(v,"compression") as u8,
            logical_seq:number(v,"logicalSeq") as u32,feedback:if fb.is_empty(){None}else{Some(TransportFeedback::decode(&fb,budget,span).unwrap())},
            data:unhex(v["dataHex"].as_str().unwrap())};
        assert_eq!(hex(&e.encode(budget,span).unwrap()),v["hex"].as_str().unwrap());
        assert_eq!(TransportEnvelope::decode(&unhex(v["hex"].as_str().unwrap()),number(v,"outerSeq") as u16,budget,span).unwrap(),e);
    }
    for v in fx["selections"].as_array().unwrap() {
        let c=TransportCaps{op:number(v,"op") as u8,features:number(v,"features") as u8,
            nonce:u64::from_be_bytes(unhex(v["nonce"].as_str().unwrap()).try_into().unwrap()),feedback_budget:number(v,"budget") as u16,serial_span:number(v,"span") as u16};
        assert_eq!(hex(&c.encode().unwrap()),v["hex"].as_str().unwrap());
        assert_eq!(TransportCaps::decode(&unhex(v["hex"].as_str().unwrap())).unwrap(),c);
    }
    for v in fx["eof"].as_array().unwrap() {
        let end=number(v,"end") as u32;
        assert_eq!(hex(&vpnproto::encode_transport_eof(end)),v["hex"].as_str().unwrap());
        assert_eq!(vpnproto::decode_transport_eof(&unhex(v["hex"].as_str().unwrap())).unwrap(),end);
    }
    for v in fx["invalidEof"].as_array().unwrap() {
        assert!(vpnproto::decode_transport_eof(&unhex(v.as_str().unwrap())).is_err());
    }
    for v in fx["invalidFeedback"].as_array().unwrap() {
        assert!(TransportFeedback::decode(&unhex(v["hex"].as_str().unwrap()),number(v,"budget") as u16,number(v,"span") as u16).is_err(),"{}",v["name"]);
    }
}
