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

/// `StreamServer::has_queued_download_data` (used by `arq::data::
/// store_received_data` to decide whether to skip queuing a freshly-stored
/// upload packet's immediate ACK) must reflect NORMAL-priority (download
/// STREAM_DATA) backlog exactly, and popping must still return that queued
/// download data - i.e. nothing about detecting the backlog disturbs the
/// stream's own strict-priority queue order.
///
/// (An earlier version of this fix instead demoted the immediate ACK to
/// `PACKET_PRIORITY_LOW` and added a dequeue-time bound that force-released
/// a LOW-priority ACK once it had aged past a short window. That bound could
/// not tell a freshly-demoted ACK apart from an ordinary already-scheduled
/// `arq::data::REACK_PRIORITY` duplicate re-ACK sitting at the front of the
/// same LOW level - and since a re-ACK is by construction already
/// `REACK_DELAY` (150ms) old by the time it is pushed, the bound force-
/// released it *ahead of any waiting NORMAL data too* on essentially every
/// call, inverting priority order instead of only bending it as a last
/// resort. Measured on `socks-echo-multi` (8 duplex SOCKS streams,
/// `-client-dup 2 -client-setup-dup 2 -client-batch 1`), this starved
/// download data almost completely and made most runs time out instead of
/// completing in ~1-3s. This version does not add any such per-item bound or
/// queue-level change at all - see `arq::data::store_received_data`'s doc
/// comment for the corrected design, which relies entirely on the
/// already-scheduled, already-proven-safe delayed re-ACK instead.)
#[tokio::test]
async fn has_queued_download_data_reflects_backlog_without_disturbing_pop_order() {
    use crate::stream::StreamServer;
    use arq::PacketEnqueuer;

    let logger: Arc<dyn arq::ArqLogger> = Arc::new(logger::Logger::new("test", "ERROR"));
    let stream = StreamServer::new(1, 1, arq::Config::default(), 1200, 8, logger);
    assert!(!stream.has_queued_download_data());

    assert!(stream.push_tx_packet(enums::PACKET_PRIORITY_NORMAL, enums::PACKET_STREAM_DATA, 0, 0, 0, 0, std::time::Duration::ZERO, b"chunk0"));
    assert!(stream.has_queued_download_data());

    // A CRITICAL-priority ACK queued alongside it (as `store_received_data`
    // does when there is *no* backlog) must still come out first - detecting
    // the backlog must not itself change ordinary priority order.
    assert!(stream.push_tx_packet(enums::default_packet_priority(enums::PACKET_STREAM_DATA_ACK), enums::PACKET_STREAM_DATA_ACK, 7, 0, 0, 0, std::time::Duration::ZERO, &[]));
    let (first, priority) = stream.pop_next_tx_packet().expect("expected the CRITICAL ACK first");
    assert_eq!(first.packet_type, enums::PACKET_STREAM_DATA_ACK);
    assert_eq!(priority, enums::PACKET_PRIORITY_CRITICAL);

    let (second, _priority) = stream.pop_next_tx_packet().expect("expected the queued download data");
    assert_eq!(second.packet_type, enums::PACKET_STREAM_DATA);
    assert_eq!(second.sequence_num, 0);
    assert!(!stream.has_queued_download_data(), "backlog signal must clear once the data is dequeued");
}

fn transport_init(server:&Server,up:u16,down:u16)->(vpnproto::SessionAcceptPayload,Option<vpnproto::TransportCaps>) {
    let query=build_query(server,&vpnproto::Packet{packet_type:enums::PACKET_SESSION_INIT,payload:session_init_payload(0,up,down,0,0),..Default::default()});
    let reply=extract_response(&server.handle_packet(&query).unwrap());
    (vpnproto::decode_session_accept_payload(&reply.payload).unwrap(),vpnproto::TransportCaps::decode_offer(&reply.payload).unwrap())
}
fn transport_request(server:&Server,accept:&vpnproto::SessionAcceptPayload,kind:u8,stream:u16,seq:u16,payload:Vec<u8>)->Option<vpnproto::Packet> {
    let query=build_query(server,&vpnproto::Packet{session_id:accept.session_id,session_cookie:accept.session_cookie,packet_type:kind,stream_id:stream,sequence_num:seq,payload,..Default::default()});
    let (response,ticket)=server.handle_packet_with_ticket(&query,std::time::Instant::now())?;
    if let Some(ticket)=ticket{ticket.sent();}
    dnsparser::extract_vpn_response(&response,false).ok()
}
fn activate_transport(server:&Server)->(vpnproto::SessionAcceptPayload,vpnproto::TransportCaps) {
    let(a,c)=transport_init(server,150,1200);let c=c.unwrap();
    let selected=transport_request(server,&a,enums::PACKET_TRANSPORT_CAPS,0,0,c.encode().unwrap()).unwrap();
    assert_eq!(selected.packet_type,enums::PACKET_TRANSPORT_CAPS_ACK);
    assert_eq!(vpnproto::TransportCaps::decode(&selected.payload).unwrap().op,2);
    let committed=transport_request(server,&a,enums::PACKET_TRANSPORT_CAPS,0,0,vpnproto::TransportCaps{op:3,..c}.encode().unwrap()).unwrap();
    assert_eq!(vpnproto::TransportCaps::decode(&committed.payload).unwrap().op,4);(a,c)
}

#[tokio::test]
async fn extension_wire_integration_strips_metadata_once_and_acks_only_sent_generations() {
    use tokio::io::{AsyncReadExt,AsyncWriteExt};
    let server=test_server();let(a,c)=activate_transport(&server);
    let record=server.sessions.get(a.session_id).unwrap();
    let stream=record.get_or_create_stream(1,server.stream_arq_config(0),1200,server.log.clone()).unwrap();
    let arq=stream.arq().unwrap();assert!(arq.transport_enabled());
    let(mut app,conn)=tokio::io::duplex(8192);assert!(stream.attach_upstream_conn(conn,"test",1,"CONNECTED"));
    let original=vec![b'q';130];let(compressed,ctype)=compression::compress_payload(&original,compression::TYPE_ZSTD,1);
    let envelope=vpnproto::TransportEnvelope{inner_kind:enums::PACKET_STREAM_DATA,inner_compression:ctype,logical_seq:0,feedback:None,data:compressed};
    assert!(transport_request(&server,&a,enums::PACKET_STREAM_ENVELOPE,1,0,envelope.encode(c.feedback_budget,c.serial_span).unwrap()).is_some());
    let mut delivered=vec![0;original.len()];tokio::time::timeout(std::time::Duration::from_secs(1),app.read_exact(&mut delivered)).await.unwrap().unwrap();
    assert_eq!(delivered,original);
    transport_request(&server,&a,enums::PACKET_STREAM_ENVELOPE,1,0,envelope.encode(c.feedback_budget,c.serial_span).unwrap());
    let mut extra=[0;1];assert!(tokio::time::timeout(std::time::Duration::from_millis(30),app.read(&mut extra)).await.is_err());
    app.write_all(b"response bytes").await.unwrap();
    for _ in 0..50 {if stream.fast_tx_queue_size()>0 && arq.has_pending_sequence(0){break;}tokio::time::sleep(std::time::Duration::from_millis(2)).await;}
    assert!(!arq.validate_logical_feedback(1,&[],&[]));
    let ping=build_query(&server,&vpnproto::Packet{session_id:a.session_id,session_cookie:a.session_cookie,packet_type:enums::PACKET_PING,..Default::default()});
    let(response,ticket)=server.handle_packet_with_ticket(&ping,std::time::Instant::now()).unwrap();
    let response=extract_response(&response);assert_eq!(response.packet_type,enums::PACKET_STREAM_ENVELOPE);
    let decoded=vpnproto::TransportEnvelope::decode(&response.payload,response.sequence_num,c.feedback_budget,c.serial_span).unwrap();
    assert_eq!(decoded.inflate_data_bounded(1200).unwrap(),b"response bytes");
    if let Some(feedback)=decoded.feedback { assert_eq!(feedback.records[0].ack_next,1); }
    assert!(!arq.validate_logical_feedback(1,&[],&[]));
    // Model a socket write failure: queued original remains recoverable and cannot be ACKed.
    drop(ticket);assert!(stream.fast_tx_queue_size()>0);assert!(!arq.validate_logical_feedback(1,&[],&[]));
    let(_,ticket)=server.handle_packet_with_ticket(&ping,std::time::Instant::now()).unwrap();ticket.unwrap().sent();
    assert!(arq.validate_logical_feedback(1,&[],&[]));
    // Untagged ACKs cannot retire the activated generation.
    transport_request(&server,&a,enums::PACKET_STREAM_DATA_ACK,1,0,vec![]);assert!(arq.has_pending_sequence(0));
    let f=vpnproto::TransportFeedback{records:vec![vpnproto::FeedbackRecord{stream_id:1,ack_next:1,sacks:vec![],repairs:vec![]}]};
    let mut malformed=vpnproto::TransportEnvelope{inner_kind:15,inner_compression:0,logical_seq:1,feedback:Some(f.clone()),data:b"must not arrive".to_vec()}.encode(c.feedback_budget,c.serial_span).unwrap();
    malformed.push(0);
    assert!(transport_request(&server,&a,enums::PACKET_STREAM_ENVELOPE,1,1,malformed).is_none());assert!(arq.has_pending_sequence(0));
    assert!(tokio::time::timeout(std::time::Duration::from_millis(30),app.read(&mut extra)).await.is_err());
    transport_request(&server,&a,enums::PACKET_STREAM_FEEDBACK,0,0,f.encode(c.feedback_budget,c.serial_span).unwrap());assert!(!arq.has_pending_sequence(0));
    arq.close("test",arq::CloseOptions::default());
    record.remove_stream(1,std::time::Instant::now(),true);
    assert!(record.get_or_create_stream(1,server.stream_arq_config(0),1200,server.log.clone()).is_none());
}

#[tokio::test]
async fn low_mtu_and_legacy_stream_before_commit_freeze_legacy() {
    let server=test_server();let(_,offer)=transport_init(&server,25,39);assert!(offer.is_none());
    let server=test_server();let(a,c)=transport_init(&server,150,1200);let c=c.unwrap();
    transport_request(&server,&a,enums::PACKET_TRANSPORT_CAPS,0,0,c.encode().unwrap()).unwrap();
    let record=server.sessions.get(a.session_id).unwrap();
    let stream=record.get_or_create_stream(1,server.stream_arq_config(0),1200,server.log.clone()).unwrap();
    assert!(!stream.arq().unwrap().transport_enabled());
    assert!(transport_request(&server,&a,enums::PACKET_TRANSPORT_CAPS,0,0,vpnproto::TransportCaps{op:3,..c}.encode().unwrap()).is_none());
    assert!(!record.transport_active());stream.arq().unwrap().close("test",arq::CloseOptions::default());
}

#[tokio::test]
async fn bounded_inner_inflate_failure_applies_no_feedback_or_data() {
    let server=test_server();let(a,c)=activate_transport(&server);let record=server.sessions.get(a.session_id).unwrap();
    let stream=record.get_or_create_stream(1,server.stream_arq_config(0),1200,server.log.clone()).unwrap();
    let(comp,kind)=compression::compress_payload(&vec![b'x';4096],compression::TYPE_LZ4,1);
    let bad=vpnproto::TransportEnvelope{inner_kind:15,inner_compression:kind,logical_seq:0,feedback:None,data:comp};
    assert!(transport_request(&server,&a,enums::PACKET_STREAM_ENVELOPE,1,0,bad.encode(c.feedback_budget,c.serial_span).unwrap()).is_none());
    assert!(stream.arq().unwrap().claim_feedback(std::time::Instant::now(),64,true).is_none());
    stream.arq().unwrap().close("test",arq::CloseOptions::default());
}

#[tokio::test]
async fn feedback_racing_response_ticket_is_replayed_on_write_success() {
    use tokio::io::AsyncWriteExt;
    let server=test_server();let(a,c)=activate_transport(&server);let record=server.sessions.get(a.session_id).unwrap();
    let stream=record.get_or_create_stream(1,server.stream_arq_config(0),1200,server.log.clone()).unwrap();
    let arq=stream.arq().unwrap();let(mut app,conn)=tokio::io::duplex(8192);assert!(stream.attach_upstream_conn(conn,"test",1,"CONNECTED"));
    app.write_all(b"reply").await.unwrap();
    for _ in 0..50 {if arq.has_pending_sequence(0){break;}tokio::time::sleep(std::time::Duration::from_millis(2)).await;}
    let query=build_query(&server,&vpnproto::Packet{session_id:a.session_id,session_cookie:a.session_cookie,packet_type:enums::PACKET_PING,..Default::default()});
    let(reply,ticket)=server.handle_packet_with_ticket(&query,std::time::Instant::now()).unwrap();
    assert_eq!(extract_response(&reply).packet_type,enums::PACKET_STREAM_ENVELOPE);
    let feedback=vpnproto::TransportFeedback{records:vec![vpnproto::FeedbackRecord{stream_id:1,ack_next:1,sacks:vec![],repairs:vec![]}]};
    assert!(transport_request(&server,&a,enums::PACKET_STREAM_FEEDBACK,0,0,feedback.encode(c.feedback_budget,c.serial_span).unwrap()).is_some());
    assert!(arq.has_pending_sequence(0));ticket.unwrap().sent();assert!(!arq.has_pending_sequence(0));
    arq.close("test",arq::CloseOptions::default());
}

#[tokio::test]
async fn negotiated_ready_upstream_serves_full_32_query_burst_and_idle_read_ahead_is_bounded() {
    use tokio::io::AsyncWriteExt;
    let server=test_server();let(a,c)=activate_transport(&server);let record=server.sessions.get(a.session_id).unwrap();
    let stream=record.get_or_create_stream(1,server.stream_arq_config(0),1200,server.log.clone()).unwrap();
    let arq=stream.arq().unwrap();let(mut app,conn)=tokio::io::duplex(256*1024);assert!(stream.attach_upstream_conn(conn,"test",1,"CONNECTED"));
    // More ready bytes than the negotiated two-batch cushion. No polls means
    // local reads must stop at the bounded threshold, not fill the ARQ window.
    app.write_all(&vec![42;128*1175]).await.unwrap();
    for _ in 0..100 {if stream.fast_tx_queue_size()>=64{break;}tokio::time::sleep(std::time::Duration::from_millis(2)).await;}
    assert_eq!(stream.fast_tx_queue_size(),64);
    tokio::time::sleep(std::time::Duration::from_millis(60)).await;assert_eq!(stream.fast_tx_queue_size(),64);
    for _ in 0..32 {
        let response=transport_request(&server,&a,enums::PACKET_PING,0,0,vec![]).unwrap();
        assert_eq!(response.packet_type,enums::PACKET_STREAM_ENVELOPE);
        let inner=vpnproto::TransportEnvelope::decode(&response.payload,response.sequence_num,c.feedback_budget,c.serial_span).unwrap();
        assert_eq!(inner.data.len(),1175);
    }
    arq.close("test",arq::CloseOptions::default());
}

#[tokio::test]
async fn upload_only_uses_current_response_for_ack_instead_of_waiting_for_timer() {
    let server=test_server();let(a,c)=activate_transport(&server);let record=server.sessions.get(a.session_id).unwrap();
    let stream=record.get_or_create_stream(1,server.stream_arq_config(0),1200,server.log.clone()).unwrap();
    let envelope=vpnproto::TransportEnvelope{inner_kind:15,inner_compression:0,logical_seq:0,feedback:None,data:b"upload".to_vec()};
    let response=transport_request(&server,&a,enums::PACKET_STREAM_ENVELOPE,1,0,envelope.encode(c.feedback_budget,c.serial_span).unwrap()).unwrap();
    assert_eq!(response.packet_type,enums::PACKET_STREAM_FEEDBACK);
    let f=vpnproto::TransportFeedback::decode(&response.payload,c.feedback_budget,c.serial_span).unwrap();
    assert_eq!(f.records.len(),1);assert_eq!(f.records[0].ack_next,1);assert_eq!(f.records[0].stream_id,1);
    stream.arq().unwrap().close("test",arq::CloseOptions::default());
}

#[tokio::test]
async fn offered_serial_span_preserves_existing_doubled_receive_capacity() {
    let server=test_server();let(a,c)=activate_transport(&server);
    let expected=(2*server.cfg.arq_window_size.max(300).min(arq::MAX_WINDOW_SIZE))
        .min(2*(server.cfg.max_allowed_client_arq_window_size.max(1) as usize).min(arq::MAX_WINDOW_SIZE)).min(16384);
    assert_eq!(c.serial_span as usize,expected);
    let record=server.sessions.get(a.session_id).unwrap();let stream=record.get_or_create_stream(1,server.stream_arq_config(0),1200,server.log.clone()).unwrap();
    assert!(stream.arq().unwrap().receive_logical_data(c.serial_span as u32-1,b"far reorder"));
    assert!(!stream.arq().unwrap().receive_logical_data(c.serial_span as u32,b"out of window"));
    stream.arq().unwrap().close("test",arq::CloseOptions::default());
}

#[tokio::test]
async fn queued_download_wins_over_immediate_upload_feedback_fallback() {
    use tokio::io::{AsyncReadExt,AsyncWriteExt};
    let server=test_server();let(a,c)=activate_transport(&server);let record=server.sessions.get(a.session_id).unwrap();
    let stream=record.get_or_create_stream(1,server.stream_arq_config(0),1200,server.log.clone()).unwrap();
    let arq=stream.arq().unwrap();let(mut app,conn)=tokio::io::duplex(8192);assert!(stream.attach_upstream_conn(conn,"test",1,"CONNECTED"));
    app.write_all(b"download").await.unwrap();
    for _ in 0..50 {if arq.has_pending_sequence(0){break;}tokio::time::sleep(std::time::Duration::from_millis(2)).await;}
    let e=vpnproto::TransportEnvelope{inner_kind:15,inner_compression:0,logical_seq:0,feedback:None,data:b"upload".to_vec()};
    let response=transport_request(&server,&a,enums::PACKET_STREAM_ENVELOPE,1,0,e.encode(c.feedback_budget,c.serial_span).unwrap()).unwrap();
    assert_eq!(response.packet_type,enums::PACKET_STREAM_ENVELOPE);
    let decoded=vpnproto::TransportEnvelope::decode(&response.payload,response.sequence_num,c.feedback_budget,c.serial_span).unwrap();
    assert_eq!(decoded.data,b"download");assert_eq!(decoded.feedback.unwrap().records[0].ack_next,1);
    let mut received=[0;6];tokio::time::timeout(std::time::Duration::from_secs(1),app.read_exact(&mut received)).await.unwrap().unwrap();assert_eq!(&received,b"upload");
    arq.close("test",arq::CloseOptions::default());
}

#[tokio::test]
async fn negotiated_eof_validates_before_ack_and_replays_after_stream_cleanup() {
    let server=test_server();let(a,_)=activate_transport(&server);let record=server.sessions.get(a.session_id).unwrap();
    let stream=record.get_or_create_stream(1,server.stream_arq_config(0),1200,server.log.clone()).unwrap();
    assert!(transport_request(&server,&a,enums::PACKET_STREAM_CLOSE_READ,1,0,vec![]).is_none());
    assert_eq!(stream.arq().unwrap().state(),arq::StreamState::Open);
    let mut packed=Vec::new();vpnproto::append_packed_control_block(&mut packed,enums::PACKET_STREAM_CLOSE_READ,1,0,0,0);
    transport_request(&server,&a,enums::PACKET_PACKED_CONTROL_BLOCKS,0,0,packed);
    assert_eq!(stream.arq().unwrap().state(),arq::StreamState::Open);
    let reply=transport_request(&server,&a,enums::PACKET_STREAM_CLOSE_READ,1,0,vpnproto::encode_transport_eof(2).to_vec()).unwrap();
    if reply.packet_type==enums::PACKET_PACKED_CONTROL_BLOCKS {
        assert!(reply.payload.chunks_exact(7).any(|p|p[0]==enums::PACKET_STREAM_CLOSE_READ_ACK));
    }else{assert_eq!(reply.packet_type,enums::PACKET_STREAM_CLOSE_READ_ACK);assert_eq!(reply.sequence_num,0);}
    assert!(transport_request(&server,&a,enums::PACKET_STREAM_CLOSE_READ,1,0,vpnproto::encode_transport_eof(3).to_vec()).is_none());
    stream.arq().unwrap().close("test",arq::CloseOptions::default());record.remove_stream(1,std::time::Instant::now(),true);
    let replay=transport_request(&server,&a,enums::PACKET_STREAM_CLOSE_READ,1,0,vpnproto::encode_transport_eof(2).to_vec()).unwrap();
    assert!(matches!(replay.packet_type,enums::PACKET_STREAM_CLOSE_READ_ACK|enums::PACKET_PACKED_CONTROL_BLOCKS));
    assert!(transport_request(&server,&a,enums::PACKET_STREAM_CLOSE_READ,1,0,vpnproto::encode_transport_eof(3).to_vec()).is_none());
}

#[tokio::test]
async fn captured_enqueue_and_write_callbacks_after_tx_abort_cannot_restore_ownership() {
    use tokio::io::{AsyncReadExt,AsyncWriteExt};
    use arq::PacketEnqueuer;
    let server=test_server();let(a,_)=activate_transport(&server);let record=server.sessions.get(a.session_id).unwrap();
    let stream=record.get_or_create_stream(1,server.stream_arq_config(0),1200,server.log.clone()).unwrap();
    let arq=stream.arq().unwrap();let(mut app,conn)=tokio::io::duplex(8192);assert!(stream.attach_upstream_conn(conn,"test",1,"CONNECTED"));
    assert!(arq.receive_logical_data(1,b"tail"));assert!(arq.receive_logical_eof(2));
    app.write_all(b"captured outbound").await.unwrap();
    for _ in 0..50 {if arq.has_pending_sequence(0){break;}tokio::time::sleep(std::time::Duration::from_millis(2)).await;}
    let captured=stream.pop_next_tx_packet().unwrap().0;let seq=captured.logical_sequence.unwrap();
    assert!(arq.note_logical_write_pending(seq));assert!(arq.apply_logical_feedback(seq+1,&[],&[]));
    arq.mark_close_write_received();
    assert!(!stream.push_tx_logical_packet(3,captured.packet_type,seq,captured.fragment_id,captured.total_fragments,captured.compression_type,std::time::Duration::ZERO,&captured.payload));
    arq.note_logical_dispatched(seq,captured.packet_type);arq.note_logical_send_failed(seq);
    assert!(!arq.has_pending_logical_sequence(seq));assert_eq!(stream.fast_tx_queue_size(),0);
    // Opposite-direction retained data and the EOF bound survived TX cleanup.
    assert!(arq.receive_logical_data(0,b"head"));let mut received=[0;8];
    tokio::time::timeout(std::time::Duration::from_secs(1),app.read_exact(&mut received)).await.unwrap().unwrap();assert_eq!(&received,b"headtail");
    assert!(arq.receive_logical_eof(2));assert!(!arq.receive_logical_eof(3));
    arq.close("test",arq::CloseOptions::default());
}
