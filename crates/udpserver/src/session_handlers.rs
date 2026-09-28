//! Port of the session-lifecycle half of `internal/udpserver/server_session.go`
//! (SESSION_INIT/ACCEPT, MTU probes, session-close notice, post-session
//! validation, response-queueing helpers). The response-building/packing
//! half (`serveQueuedOrPong` and friends) lives in `postsession.rs`.

use crate::ingress::PostSessionValidation;
use crate::session::{FindOrCreateOutcome, SessionRecord, SessionRuntimeView};
use crate::stream::StreamServer;
use crate::{parse_mtu_probe_base_encoding, session_response_mode_name, Server};
use arq::PacketEnqueuer;
use domainmatcher::Decision;
use std::sync::Arc;
use std::time::Instant;

pub(crate) const SESSION_INIT_DATA_SIZE: usize = crate::session::SESSION_INIT_DATA_SIZE;

impl Server {
    pub(crate) fn validate_post_session_packet(&self, packet: &[u8], request_name: &str, vpn_packet: &vpnproto::Packet, now: Instant) -> PostSessionValidation {
        let validation = self.sessions.validate_and_touch(vpn_packet.session_id, vpn_packet.session_cookie, now);

        if validation.valid {
            return PostSessionValidation::Ok(validation.active.unwrap());
        }

        if !validation.known {
            let mode = self.next_unknown_invalid_drop_mode();
            return PostSessionValidation::Response(self.build_invalid_session_error_response(packet, request_name, vpn_packet.session_id, mode));
        }

        if validation.lookup.state == crate::session::SessionLookupState::Closed {
            return PostSessionValidation::Response(self.build_invalid_session_error_response(
                packet,
                request_name,
                vpn_packet.session_id,
                validation.lookup.response_mode,
            ));
        }

        let escalate = self.invalid_cookie_tracker.note(
            vpn_packet.session_id,
            validation.lookup,
            validation.known,
            vpn_packet.session_cookie,
            now,
            self.invalid_cookie_window,
            self.invalid_cookie_threshold,
        );
        if !escalate {
            return PostSessionValidation::Response(None);
        }

        PostSessionValidation::Response(self.build_invalid_session_error_response(
            packet,
            request_name,
            vpn_packet.session_id,
            validation.lookup.response_mode,
        ))
    }

    pub(crate) fn handle_session_close_notice(&self, vpn_packet: &vpnproto::Packet, now: Instant) {
        if vpn_packet.session_id == 0 {
            return;
        }
        let Some(lookup) = self.sessions.lookup(vpn_packet.session_id) else { return };
        if lookup.state != crate::session::SessionLookupState::Active || lookup.cookie != vpn_packet.session_cookie {
            return;
        }
        if let Some(record) = self.sessions.close(vpn_packet.session_id, now, self.cfg.closed_session_retention()) {
            self.cleanup_closed_session(vpn_packet.session_id, &record);
            self.log.infof(&format!("Session Closed By Client, Session: {}", vpn_packet.session_id));
        }
    }

    fn build_invalid_session_error_response(&self, packet: &[u8], request_name: &str, session_id: u8, response_mode: u8) -> Option<Vec<u8>> {
        let payload = self.next_invalid_drop_payload();
        dnsparser::build_vpn_response_packet(
            packet,
            request_name,
            &vpnproto::Packet { session_id, packet_type: enums::PACKET_ERROR_DROP, payload: payload.to_vec(), ..Default::default() },
            response_mode == crate::MTU_PROBE_MODE_BASE64,
        )
        .ok()
    }

    pub(crate) fn build_session_busy_response(&self, packet: &[u8], request_name: &str, response_mode: u8, verify_code: &[u8]) -> Option<Vec<u8>> {
        if verify_code.len() < crate::MTU_PROBE_CODE_LENGTH {
            return None;
        }
        let mut payload = [0u8; crate::MTU_PROBE_CODE_LENGTH];
        payload.copy_from_slice(&verify_code[..crate::MTU_PROBE_CODE_LENGTH]);
        dnsparser::build_vpn_response_packet(
            packet,
            request_name,
            &vpnproto::Packet { session_id: 0, packet_type: enums::PACKET_SESSION_BUSY, payload: payload.to_vec(), ..Default::default() },
            response_mode == crate::MTU_PROBE_MODE_BASE64,
        )
        .ok()
    }

    pub(crate) fn build_session_vpn_response(
        &self,
        packet: &[u8],
        request_name: &str,
        record: &SessionRuntimeView,
        mut vpn_packet: vpnproto::Packet,
    ) -> Option<Vec<u8>> {
        vpn_packet.session_id = record.id;
        vpn_packet.session_cookie = record.cookie;
        dnsparser::build_vpn_response_packet(packet, request_name, &vpn_packet, record.response_base64).ok()
    }

    pub(crate) fn queue_session_packet(&self, session_id: u8, mut packet: vpnproto::Packet) -> bool {
        let Some(record) = self.sessions.get(session_id) else { return false };
        let stream_id = packet.stream_id;

        if stream_id == 0 {
            record.ensure_stream0(self.log.clone());
        }

        let Some(stream) = record.get_stream(stream_id) else { return false };
        let priority = enums::normalize_packet_priority(packet.packet_type, 3);
        packet.stream_id = stream_id;
        stream.push_tx_packet(priority, packet.packet_type, packet.sequence_num, packet.fragment_id, packet.total_fragments, packet.compression_type, std::time::Duration::ZERO, &packet.payload)
    }

    pub(crate) fn queue_main_session_packet(&self, session_id: u8, mut packet: vpnproto::Packet) -> bool {
        packet.stream_id = 0;
        self.queue_session_packet(session_id, packet)
    }

    pub(crate) fn stream_arq_config(&self, compression_type: u8) -> arq::Config {
        arq::Config {
            window_size: self.cfg.arq_window_size,
            rto: self.cfg.arq_initial_rto_seconds,
            max_rto: self.cfg.arq_max_rto_seconds,
            enable_control_reliability: true,
            control_rto: self.cfg.arq_control_initial_rto_seconds,
            control_max_rto: self.cfg.arq_control_max_rto_seconds,
            control_max_retries: self.cfg.arq_max_control_retries,
            inactivity_timeout: self.cfg.arq_inactivity_timeout_seconds,
            data_packet_ttl: self.cfg.arq_data_packet_ttl_seconds,
            max_data_retries: self.cfg.arq_max_data_retries,
            data_nack_max_gap: self.cfg.arq_data_nack_max_gap,
            data_nack_initial_delay_seconds: self.cfg.arq_data_nack_initial_delay_seconds,
            data_nack_repeat_seconds: self.cfg.arq_data_nack_repeat_seconds,
            control_packet_ttl: self.cfg.arq_control_packet_ttl_seconds,
            terminal_drain_timeout: self.cfg.arq_terminal_drain_timeout_seconds,
            terminal_ack_wait_timeout: self.cfg.arq_terminal_ack_wait_timeout_seconds,
            compression_type,
            is_client: false,
            ..Default::default()
        }
    }

    pub(crate) fn cleanup_closed_session(&self, session_id: u8, record: &SessionRecord) {
        if session_id == 0 {
            return;
        }
        self.clear_deferred_packets_for_session(session_id);
        self.remove_socks5_syn_fragments_for_session(session_id);
        record.close_all_streams("session closed cleanup");
        self.cleanup_deferred_session_state(session_id);
    }

    pub(crate) fn cleanup_deferred_session_state(&self, session_id: u8) {
        if session_id == 0 {
            return;
        }
        self.deferred.remove_session(session_id);
        self.remove_dns_query_fragments_for_session(session_id);
    }

    pub(crate) fn cleanup_stream_artifacts(&self, session_id: u8, stream_id: u16) {
        if session_id == 0 || stream_id == 0 {
            return;
        }
        self.deferred.remove_lane(session_id, stream_id);
        self.remove_socks5_syn_fragments_for_stream(session_id, stream_id);
    }

    fn next_pong_payload(&self) -> [u8; 7] {
        let mut payload = [0u8; 7];
        payload[0] = b'P';
        payload[1] = b'O';
        payload[2] = b':';
        let nonce = self.next_scrambled_nonce();
        payload[3..7].copy_from_slice(&nonce.to_be_bytes());
        payload
    }

    fn next_invalid_drop_payload(&self) -> [u8; 8] {
        let mut payload = [0u8; 8];
        payload[0] = b'I';
        payload[1] = b'N';
        payload[2] = b'V';
        let nonce = self.next_scrambled_nonce();
        payload[3..7].copy_from_slice(&nonce.to_be_bytes());
        payload[7] = nonce as u8;
        payload
    }

    fn next_scrambled_nonce(&self) -> u32 {
        let mut nonce = self.pong_nonce.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        nonce ^= nonce << 13;
        nonce ^= nonce >> 17;
        nonce ^= nonce << 5;
        nonce
    }

    fn next_unknown_invalid_drop_mode(&self) -> u8 {
        if self.invalid_drop_mode.fetch_add(1, std::sync::atomic::Ordering::Relaxed) & 1 == 0 {
            crate::MTU_PROBE_MODE_RAW
        } else {
            crate::MTU_PROBE_MODE_BASE64
        }
    }

    pub(crate) fn pong_payload(&self) -> Vec<u8> {
        self.next_pong_payload().to_vec()
    }
}

pub(crate) fn handle_session_init_request(server: &Server, packet: &[u8], decision: &Decision, vpn_packet: &vpnproto::Packet) -> Option<Vec<u8>> {
    if vpn_packet.session_id != 0 || vpn_packet.payload.len() != SESSION_INIT_DATA_SIZE {
        return None;
    }

    let (requested_upload, requested_download) = compression::split_pair(vpn_packet.payload[1]);
    let resolved_upload = resolve_compression_type(requested_upload, server.upload_compression_mask);
    let resolved_download = resolve_compression_type(requested_download, server.download_compression_mask);

    let outcome = server.sessions.find_or_create(
        &vpn_packet.payload,
        resolved_upload,
        resolved_download,
        server.cfg.effective_max_packets_per_batch(),
        server.cfg.max_allowed_client_upload_mtu as i64,
        server.cfg.max_allowed_client_download_mtu as i64,
    );

    let (record, reused) = match outcome {
        FindOrCreateOutcome::Existing(r) => (r, true),
        FindOrCreateOutcome::Created(r) => (r, false),
        FindOrCreateOutcome::InvalidPayload => return None,
        FindOrCreateOutcome::TableFull => {
            server.log.errorf(&format!("Session Table Full Request: SESSION_INIT, Domain: {}", decision.request_name));
            return server.build_session_busy_response(packet, &decision.request_name, vpn_packet.payload[0], &vpn_packet.payload[6..10]);
        }
    };

    if !reused {
        server.log.infof(&format!(
            "Session Created, ID: {}, Mode: {}, Upload Compression: {}, Download Compression: {}, Max Packed Blocks: {}",
            record.id,
            session_response_mode_name(record.response_mode),
            compression::type_name(record.upload_compression),
            compression::type_name(record.download_compression),
            record.max_packed_blocks,
        ));
    }

    let response_payload = vpnproto::encode_session_accept_payload(&vpnproto::SessionAcceptPayload {
        session_id: record.id,
        session_cookie: record.cookie,
        compression_pair: compression::pack_pair(record.upload_compression, record.download_compression),
        verify_code: record.verify_code,
        client_policy: vpnproto::SessionAcceptClientPolicy {
            max_packet_duplication_count: server.cfg.max_allowed_client_packet_duplication_count as i64,
            max_setup_duplication_count: server.cfg.max_allowed_client_setup_packet_duplication_count as i64,
            max_upload_mtu: server.cfg.max_allowed_client_upload_mtu as i64,
            max_download_mtu: server.cfg.max_allowed_client_download_mtu as i64,
            max_rx_tx_workers: server.cfg.max_allowed_client_rx_tx_workers as i64,
            min_ping_aggressive_interval: server.cfg.min_allowed_client_ping_aggressive_interval_seconds,
            max_packets_per_batch: server.cfg.max_allowed_client_packets_per_batch as i64,
            max_arq_window_size: (server.cfg.max_allowed_client_arq_window_size as i64).clamp(1, arq::MAX_WINDOW_SIZE as i64),
            max_arq_data_nack_max_gap: server.cfg.max_allowed_client_arq_data_nack_max_gap as i64,
            min_compression_min_size: server.cfg.min_allowed_client_compression_min_size as i64,
            min_arq_initial_rto_seconds: server.cfg.min_allowed_client_arq_initial_rto_seconds,
        },
        has_client_policy_sync: true,
    });

    dnsparser::build_vpn_response_packet(
        packet,
        &decision.request_name,
        &vpnproto::Packet { session_id: 0, packet_type: enums::PACKET_SESSION_ACCEPT, payload: response_payload, ..Default::default() },
        record.response_mode == crate::MTU_PROBE_MODE_BASE64,
    )
    .ok()
}

fn resolve_compression_type(requested: u8, allowed_mask: u8) -> u8 {
    if requested <= compression::TYPE_ZLIB && allowed_mask & (1 << requested) != 0 {
        requested
    } else {
        compression::TYPE_OFF
    }
}

pub(crate) fn handle_mtu_up_request(_server: &Server, packet: &[u8], decision: &Decision, vpn_packet: &vpnproto::Packet) -> Option<Vec<u8>> {
    if vpn_packet.payload.len() < crate::MTU_PROBE_UP_MIN_SIZE {
        return None;
    }
    let base_encode = parse_mtu_probe_base_encoding(vpn_packet.payload[0])?;

    let mut response_payload = [0u8; crate::MTU_PROBE_META_LENGTH];
    response_payload[..crate::MTU_PROBE_CODE_LENGTH].copy_from_slice(&vpn_packet.payload[1..crate::MTU_PROBE_UP_MIN_SIZE]);
    response_payload[crate::MTU_PROBE_CODE_LENGTH..].copy_from_slice(&(vpn_packet.payload.len() as u16).to_be_bytes());

    dnsparser::build_vpn_response_packet(
        packet,
        &decision.request_name,
        &vpnproto::Packet {
            session_id: vpn_packet.session_id,
            packet_type: enums::PACKET_MTU_UP_RES,
            payload: response_payload.to_vec(),
            ..Default::default()
        },
        base_encode,
    )
    .ok()
}

pub(crate) fn handle_mtu_down_request(server: &Server, packet: &[u8], decision: &Decision, vpn_packet: &vpnproto::Packet) -> Option<Vec<u8>> {
    let _ = server;
    if vpn_packet.payload.len() < crate::MTU_PROBE_DOWN_MIN_SIZE {
        return None;
    }
    let base_encode = parse_mtu_probe_base_encoding(vpn_packet.payload[0])?;
    let download_size = u16::from_be_bytes([
        vpn_packet.payload[crate::MTU_PROBE_UP_MIN_SIZE],
        vpn_packet.payload[crate::MTU_PROBE_UP_MIN_SIZE + 1],
    ]) as usize;
    if !(crate::MTU_PROBE_MIN_DOWN_SIZE..=crate::MTU_PROBE_MAX_DOWN_SIZE).contains(&download_size) {
        return None;
    }

    let mut payload = vec![0u8; download_size];
    payload[..crate::MTU_PROBE_CODE_LENGTH].copy_from_slice(&vpn_packet.payload[1..crate::MTU_PROBE_UP_MIN_SIZE]);
    payload[crate::MTU_PROBE_CODE_LENGTH..crate::MTU_PROBE_META_LENGTH].copy_from_slice(&(download_size as u16).to_be_bytes());

    dnsparser::build_vpn_response_packet(
        packet,
        &decision.request_name,
        &vpnproto::Packet {
            session_id: vpn_packet.session_id,
            packet_type: enums::PACKET_MTU_DOWN_RES,
            stream_id: vpn_packet.stream_id,
            sequence_num: vpn_packet.sequence_num,
            fragment_id: vpn_packet.fragment_id,
            total_fragments: vpn_packet.total_fragments,
            payload,
            ..Default::default()
        },
        base_encode,
    )
    .ok()
}

#[allow(dead_code)]
fn unused_stream_ref(_: &Arc<StreamServer>) {}
