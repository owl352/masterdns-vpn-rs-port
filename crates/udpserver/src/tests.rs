//! End-to-end tests driving `Server::handle_packet` by playing the client
//! role directly with the already-shipped protocol crates (`dnsparser`,
//! `vpnproto`, `security`) — there is no Rust client yet (that's Phase 3),
//! so this is the server's own verification per the Phase 2 plan.

use crate::Server;
use std::net::SocketAddr;
use std::sync::Arc;

fn test_config() -> config::ServerConfig {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server_config.toml.simple");
    let mut cfg = config::load_server_toml(&path).expect("reference server_config.toml.simple should load");
    // Keep the reused-across-tests session/stream tables small and fast.
    cfg.udp_port = 0;
    cfg
}

fn test_server() -> Arc<Server> {
    let cfg = test_config();
    let log = Arc::new(logger::Logger::new("test", "ERROR"));
    let codec = Arc::new(security::Codec::new(0, "test-key").unwrap()); // method 0 = NONE, simplest for a wire-format test
    Server::new(cfg, log, codec)
}

fn domain(server: &Server) -> String {
    server.cfg.domain[0].clone()
}

fn build_query(server: &Server, vpn_packet: &vpnproto::Packet) -> Vec<u8> {
    let raw = vpnproto::build_raw_auto(
        vpnproto::BuildOptions {
            session_id: vpn_packet.session_id,
            packet_type: vpn_packet.packet_type,
            session_cookie: vpn_packet.session_cookie,
            stream_id: vpn_packet.stream_id,
            sequence_num: vpn_packet.sequence_num,
            fragment_id: vpn_packet.fragment_id,
            total_fragments: vpn_packet.total_fragments,
            compression_type: vpn_packet.compression_type,
            payload: vpn_packet.payload.clone(),
        },
        compression::DEFAULT_MIN_SIZE,
    )
    .unwrap();
    let encoded = basecodec::encode_to_bytes(&raw);
    dnsparser::build_tunnel_txt_question_packet(&domain(server), &encoded, enums::DNS_RECORD_TYPE_TXT, 0).unwrap()
}

fn extract_response(response: &[u8]) -> vpnproto::Packet {
    dnsparser::extract_vpn_response(response, false).unwrap()
}

fn session_init_payload(response_mode: u8, upload_mtu: u16, download_mtu: u16, upload_compression: u8, download_compression: u8) -> Vec<u8> {
    let mut payload = vec![0u8; 10];
    payload[0] = response_mode;
    payload[1] = compression::pack_pair(upload_compression, download_compression);
    payload[2..4].copy_from_slice(&upload_mtu.to_be_bytes());
    payload[4..6].copy_from_slice(&download_mtu.to_be_bytes());
    payload[6..10].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // verify code
    payload
}

fn do_session_init(server: &Server) -> vpnproto::SessionAcceptPayload {
    let query = build_query(
        server,
        &vpnproto::Packet {
            packet_type: enums::PACKET_SESSION_INIT,
            payload: session_init_payload(0, 150, 1200, 0, 0),
            ..Default::default()
        },
    );
    let response = server.handle_packet(&query).expect("SESSION_INIT should get a response");
    let vpn_response = extract_response(&response);
    assert_eq!(vpn_response.packet_type, enums::PACKET_SESSION_ACCEPT);
    vpnproto::decode_session_accept_payload(&vpn_response.payload).unwrap()
}

#[test]
fn session_init_yields_session_accept_with_matching_verify_code() {
    let server = test_server();
    let accept = do_session_init(&server);
    assert_eq!(accept.verify_code, [0xDE, 0xAD, 0xBE, 0xEF]);
    assert_ne!(accept.session_id, 0);
    assert!(accept.has_client_policy_sync);
}

#[test]
fn retried_session_init_with_same_signature_reuses_session() {
    let server = test_server();
    let query = build_query(
        &server,
        &vpnproto::Packet {
            packet_type: enums::PACKET_SESSION_INIT,
            payload: session_init_payload(0, 150, 1200, 0, 0),
            ..Default::default()
        },
    );

    let r1 = server.handle_packet(&query).unwrap();
    let a1 = vpnproto::decode_session_accept_payload(&extract_response(&r1).payload).unwrap();
    let r2 = server.handle_packet(&query).unwrap();
    let a2 = vpnproto::decode_session_accept_payload(&extract_response(&r2).payload).unwrap();

    assert_eq!(a1.session_id, a2.session_id);
    assert_eq!(a1.session_cookie, a2.session_cookie);
}

#[test]
fn unknown_session_gets_error_drop() {
    let server = test_server();
    let query = build_query(
        &server,
        &vpnproto::Packet { packet_type: enums::PACKET_PING, session_id: 42, session_cookie: 7, ..Default::default() },
    );
    let response = server.handle_packet(&query).unwrap();
    let vpn_response = extract_response(&response);
    assert_eq!(vpn_response.packet_type, enums::PACKET_ERROR_DROP);
}

#[test]
fn ping_on_valid_session_gets_pong() {
    let server = test_server();
    let accept = do_session_init(&server);

    let query = build_query(
        &server,
        &vpnproto::Packet { packet_type: enums::PACKET_PING, session_id: accept.session_id, session_cookie: accept.session_cookie, ..Default::default() },
    );
    let response = server.handle_packet(&query).unwrap();
    let vpn_response = extract_response(&response);
    assert_eq!(vpn_response.packet_type, enums::PACKET_PONG);
    assert_eq!(vpn_response.session_id, accept.session_id);
}

/// Full end-to-end stream flow: SOCKS5_SYN -> (deferred TCP dial to a local
/// listener) -> poll until CONNECTED -> send STREAM_DATA -> poll until the
/// byte we wrote shows up on the accepted TCP connection, proving the whole
/// chain (session, stream, ARQ, deferred dial, TX queue draining) works.
#[tokio::test]
async fn stream_syn_dials_and_forwards_data_end_to_end() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr: SocketAddr = listener.local_addr().unwrap();
    let accept_task = tokio::spawn(async move { listener.accept().await.unwrap().0 });

    let mut cfg = test_config();
    // Plain-TCP mode dials a server-operator-configured fixed target
    // (`FORWARD_IP`/`FORWARD_PORT`) directly, bypassing the client-supplied-
    // target SSRF guard (`socks5_upstream::validate_socks_target_host`) that
    // rejects loopback/private targets — that guard only applies to the
    // SOCKS5 path, where the target comes from the (untrusted) client.
    cfg.protocol_type = "TCP".to_string();
    cfg.forward_ip = target_addr.ip().to_string();
    cfg.forward_port = target_addr.port();
    let log = Arc::new(logger::Logger::new("test", "ERROR"));
    let codec = Arc::new(security::Codec::new(0, "test-key").unwrap());
    let server = Server::new(cfg, log, codec);

    let accept = do_session_init(&server);
    let stream_id: u16 = 1;

    let syn_query = build_query(
        &server,
        &vpnproto::Packet {
            packet_type: enums::PACKET_STREAM_SYN,
            session_id: accept.session_id,
            session_cookie: accept.session_cookie,
            stream_id,
            has_stream_id: true,
            ..Default::default()
        },
    );
    let syn_response = server.handle_packet(&syn_query).unwrap();
    let syn_vpn_response = extract_response(&syn_response);
    assert_eq!(syn_vpn_response.packet_type, enums::PACKET_STREAM_SYN_ACK);

    // The dial happens on the deferred runtime; poll session-level PINGs
    // (stream 0) until the CONNECTED result shows up in the queue.
    let mut server_conn =
        tokio::time::timeout(std::time::Duration::from_secs(5), accept_task).await.expect("listener should accept the dialed connection").unwrap();

    let mut connected = false;
    for _ in 0..200 {
        let poll_query = build_query(
            &server,
            &vpnproto::Packet { packet_type: enums::PACKET_PING, session_id: accept.session_id, session_cookie: accept.session_cookie, ..Default::default() },
        );
        let response = server.handle_packet(&poll_query).unwrap();
        let vpn_response = extract_response(&response);
        if vpn_response.packet_type == enums::PACKET_STREAM_CONNECTED {
            connected = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(connected, "expected a PACKET_STREAM_CONNECTED within the poll budget");

    // Send one STREAM_DATA frame and confirm it reaches the dialed TCP socket.
    let data_query = build_query(
        &server,
        &vpnproto::Packet {
            packet_type: enums::PACKET_STREAM_DATA,
            session_id: accept.session_id,
            session_cookie: accept.session_cookie,
            stream_id,
            has_stream_id: true,
            sequence_num: 0,
            has_sequence_num: true,
            payload: b"hello upstream".to_vec(),
            ..Default::default()
        },
    );
    let data_response = extract_response(&server.handle_packet(&data_query).unwrap());
    // The ACK is queued while the data is handled, so it rides the reply to
    // this same query instead of waiting for the client's next one.
    let mut acked = data_response.packet_type == enums::PACKET_STREAM_DATA_ACK && data_response.stream_id == stream_id && data_response.sequence_num == 0;
    if data_response.packet_type == enums::PACKET_PACKED_CONTROL_BLOCKS {
        vpnproto::for_each_packed_control_block(&data_response.payload, |ptype, sid, sn, _, _| {
            acked |= ptype == enums::PACKET_STREAM_DATA_ACK && sid == stream_id && sn == 0;
            true
        });
    }
    assert!(acked, "reply to the data query should carry its ACK, got packet type 0x{:02x}", data_response.packet_type);

    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), server_conn.read(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"hello upstream");
}

/// Regression test for the `handlePostSessionPacket`/`handle_post_session_packet`
/// parity bug: Go always lets the query fall through to `serveQueuedOrPong`
/// after post-session dispatch (it calls `dispatchPostSessionPacket` but
/// discards the bool and unconditionally returns `true`), so a post-session
/// packet type the dispatcher doesn't specifically handle - like a second,
/// duplicate copy of a client `STREAM_DATA_ACK` for a sequence number that's
/// already been acknowledged (exactly what happens with
/// `PACKET_DUPLICATION_COUNT` = 2, the real-world default) - still gets
/// queued download data or a PONG in reply. Before the fix, the Rust port
/// returned the dispatcher's `false` straight through, which made
/// `ingress::handle_tunnel_candidate` answer with an empty NODATA response
/// instead - burning a pull on a query the real client will send routinely.
#[tokio::test]
async fn duplicate_stream_data_ack_gets_tunnel_response_not_empty_answer() {
    use tokio::io::AsyncWriteExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr: SocketAddr = listener.local_addr().unwrap();
    let accept_task = tokio::spawn(async move { listener.accept().await.unwrap().0 });

    let mut cfg = test_config();
    cfg.protocol_type = "TCP".to_string();
    cfg.forward_ip = target_addr.ip().to_string();
    cfg.forward_port = target_addr.port();
    let log = Arc::new(logger::Logger::new("test", "ERROR"));
    let codec = Arc::new(security::Codec::new(0, "test-key").unwrap());
    let server = Server::new(cfg, log, codec);

    let accept = do_session_init(&server);
    let stream_id: u16 = 1;

    let syn_query = build_query(
        &server,
        &vpnproto::Packet {
            packet_type: enums::PACKET_STREAM_SYN,
            session_id: accept.session_id,
            session_cookie: accept.session_cookie,
            stream_id,
            has_stream_id: true,
            ..Default::default()
        },
    );
    let syn_response = server.handle_packet(&syn_query).unwrap();
    assert_eq!(extract_response(&syn_response).packet_type, enums::PACKET_STREAM_SYN_ACK);

    let mut server_conn =
        tokio::time::timeout(std::time::Duration::from_secs(5), accept_task).await.expect("listener should accept the dialed connection").unwrap();

    let mut connected = false;
    for _ in 0..200 {
        let poll_query = build_query(
            &server,
            &vpnproto::Packet { packet_type: enums::PACKET_PING, session_id: accept.session_id, session_cookie: accept.session_cookie, ..Default::default() },
        );
        let response = server.handle_packet(&poll_query).unwrap();
        if extract_response(&response).packet_type == enums::PACKET_STREAM_CONNECTED {
            connected = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(connected, "expected a PACKET_STREAM_CONNECTED within the poll budget");

    // Write bytes on the upstream side so the server queues a STREAM_DATA
    // (download) packet for the client to pull.
    server_conn.write_all(b"download payload").await.unwrap();

    // Poll session queries until the download data packet shows up in a
    // reply, capturing its sequence number (matches the client's normal
    // download-then-ACK flow).
    let mut acked_sequence_num: Option<u16> = None;
    for _ in 0..200 {
        let poll_query = build_query(
            &server,
            &vpnproto::Packet { packet_type: enums::PACKET_PING, session_id: accept.session_id, session_cookie: accept.session_cookie, ..Default::default() },
        );
        let response = server.handle_packet(&poll_query).unwrap();
        let vpn_response = extract_response(&response);
        if vpn_response.packet_type == enums::PACKET_STREAM_DATA && vpn_response.stream_id == stream_id {
            acked_sequence_num = Some(vpn_response.sequence_num);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let sequence_num = acked_sequence_num.expect("expected a STREAM_DATA download packet within the poll budget");

    // First STREAM_DATA_ACK: a genuinely new ack, consumed by
    // `consume_inbound_stream_ack` / `arq::receive_ack`.
    let ack_query = build_query(
        &server,
        &vpnproto::Packet {
            packet_type: enums::PACKET_STREAM_DATA_ACK,
            session_id: accept.session_id,
            session_cookie: accept.session_cookie,
            stream_id,
            has_stream_id: true,
            sequence_num,
            has_sequence_num: true,
            ..Default::default()
        },
    );
    let first_ack_response = server.handle_packet(&ack_query).expect("first ACK query should get a response");
    // Whatever this carries (queued data/PONG), it must be a real tunnel
    // reply, not an empty NODATA answer.
    dnsparser::extract_vpn_response(&first_ack_response, false).expect("first ACK's reply should carry a tunnel payload");

    // Second, duplicate copy of the same STREAM_DATA_ACK (as sent by the
    // real client under PACKET_DUPLICATION_COUNT=2): the sequence is already
    // removed from the ARQ's send buffer, so `arq::receive_ack` returns
    // false and dispatch "misses" it - this must still fall through to
    // `serve_queued_or_pong` instead of an empty answer.
    let duplicate_ack_response = server.handle_packet(&ack_query).expect("duplicate ACK query should get a response");
    let vpn_response = dnsparser::extract_vpn_response(&duplicate_ack_response, false)
        .expect("duplicate ACK's reply should carry a tunnel payload (queued data/PONG), not an empty NODATA answer");
    assert!(
        vpn_response.packet_type == enums::PACKET_PONG
            || vpn_response.packet_type == enums::PACKET_STREAM_DATA
            || vpn_response.packet_type == enums::PACKET_PACKED_CONTROL_BLOCKS,
        "unexpected packet type in reply to duplicate ACK: 0x{:02x}",
        vpn_response.packet_type
    );
}
