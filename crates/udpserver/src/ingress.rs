//! Port of `internal/udpserver/server_ingress.go`: the top of the
//! synchronous request→response pipeline.

use crate::session_handlers::{handle_mtu_down_request, handle_mtu_up_request, handle_session_init_request};
use crate::Server;
use dnsparser::LitePacket;
use domainmatcher::Action;

fn is_pre_session_request_type(packet_type: u8) -> bool {
    matches!(packet_type, enums::PACKET_SESSION_INIT | enums::PACKET_MTU_UP_REQ | enums::PACKET_MTU_DOWN_REQ)
}

thread_local! {
    /// Reused across calls to `vpnproto::parse_inflated_from_labels_into` on
    /// whichever OS thread is currently polling a serve task: avoids
    /// allocating fresh decode/decrypt buffers for every incoming query on
    /// this (very hot, always-synchronous) path. Not tied to a particular
    /// session or task - it's pure scratch space, cleared and refilled by
    /// each call before use.
    static LABEL_PARSE_SCRATCH: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

impl Server {
    pub fn handle_packet(&self, packet: &[u8]) -> Option<Vec<u8>> {
        self.handle_packet_at(packet, std::time::Instant::now())
    }

    /// Like [`Self::handle_packet`], with the clock read once by the caller:
    /// every timestamp taken while handling this query (session touch,
    /// stream activity, queue entries) uses `now`.
    pub fn handle_packet_at(&self, packet: &[u8], now: std::time::Instant) -> Option<Vec<u8>> {
        match dnsparser::parse_dns_request_lite(packet) {
            Ok(parsed) => self.handle_parsed_packet(packet, &parsed, now),
            Err(dnsparser::DnsParserError::NotDnsRequest) | Err(dnsparser::DnsParserError::PacketTooShort) => None,
            Err(_) => self.build_no_data_response_logged(packet),
        }
    }

    pub(crate) fn handle_parsed_packet(&self, packet: &[u8], parsed: &LitePacket, now: std::time::Instant) -> Option<Vec<u8>> {
        if parsed.header.qr != 0 {
            return None;
        }
        if !parsed.has_question {
            return self.build_no_data_response_lite_logged(packet, parsed);
        }

        let decision = self.domain_matcher.matches(parsed);
        match decision.action {
            Some(Action::Process) => {
                self.handle_tunnel_candidate(packet, parsed, &decision, now).or_else(|| self.build_no_data_response_lite_logged(packet, parsed))
            }
            Some(Action::FormatError) => self.build_format_error_response_lite_logged(packet, parsed),
            Some(Action::NoData) => {
                if decision.reason == "unauthorized-domain" {
                    self.build_name_error_response_lite_logged(packet, parsed)
                } else {
                    self.build_no_data_response_lite_logged(packet, parsed)
                }
            }
            None => self.build_no_data_response_lite_logged(packet, parsed),
        }
    }

    fn handle_tunnel_candidate(&self, packet: &[u8], parsed: &LitePacket, decision: &domainmatcher::Decision, now: std::time::Instant) -> Option<Vec<u8>> {
        let vpn_packet = LABEL_PARSE_SCRATCH
            .with(|scratch| vpnproto::parse_from_labels_into(&decision.labels, Some(&self.codec), &mut scratch.borrow_mut()))
            .ok()?;

        // Envelope bytes are not an outer compressed application payload.
        // Standalone feedback also uses its negotiated bound before inflation.
        let vpn_packet = if vpn_packet.packet_type == enums::PACKET_STREAM_ENVELOPE {
            if vpn_packet.compression_type != compression::TYPE_OFF { return None; }
            vpn_packet
        } else if vpn_packet.packet_type == enums::PACKET_STREAM_FEEDBACK {
            let record = self.sessions.get(vpn_packet.session_id)?;
            let caps = record.transport_caps()?;
            let mut packet = vpn_packet;
            packet.payload = compression::try_decompress_payload_bounded(&packet.payload,packet.compression_type,caps.feedback_budget as usize)?;
            packet
        } else { vpnproto::inflate_payload(vpn_packet).ok()? };

        if vpn_packet.packet_type == enums::PACKET_SESSION_CLOSE {
            self.handle_session_close_notice(&vpn_packet, now);
            return self.build_no_data_response_lite_logged(packet, parsed);
        }

        if !is_pre_session_request_type(vpn_packet.packet_type) {
            let validation = self.validate_post_session_packet(packet, &decision.request_name, &vpn_packet, now);
            let record = match validation {
                PostSessionValidation::Ok(record) => record,
                PostSessionValidation::Response(resp) => return resp,
            };

            if !self.handle_post_session_packet(&vpn_packet, &record, now) {
                return self.build_no_data_response_lite_logged(packet, parsed);
            }

            let feedback_stream = (vpn_packet.packet_type == enums::PACKET_STREAM_ENVELOPE).then_some(vpn_packet.stream_id);
            return self.serve_queued_or_pong(packet, &decision.request_name, &record, now, feedback_stream);
        }

        match vpn_packet.packet_type {
            enums::PACKET_MTU_UP_REQ => handle_mtu_up_request(self, packet, decision, &vpn_packet),
            enums::PACKET_MTU_DOWN_REQ => handle_mtu_down_request(self, packet, decision, &vpn_packet),
            enums::PACKET_SESSION_INIT => handle_session_init_request(self, packet, decision, &vpn_packet),
            _ => self.build_no_data_response_lite_logged(packet, parsed),
        }
    }

    pub(crate) fn build_no_data_response_logged(&self, packet: &[u8]) -> Option<Vec<u8>> {
        dnsparser::build_empty_no_error_response(packet).ok()
    }

    pub(crate) fn build_no_data_response_lite_logged(&self, packet: &[u8], parsed: &LitePacket) -> Option<Vec<u8>> {
        dnsparser::build_empty_no_error_response_from_lite(packet, parsed).ok()
    }

    pub(crate) fn build_name_error_response_lite_logged(&self, packet: &[u8], parsed: &LitePacket) -> Option<Vec<u8>> {
        dnsparser::build_name_error_response_from_lite(packet, parsed).ok()
    }

    pub(crate) fn build_format_error_response_lite_logged(&self, packet: &[u8], parsed: &LitePacket) -> Option<Vec<u8>> {
        dnsparser::build_format_error_response_from_lite(packet, parsed).ok()
    }
}

pub(crate) enum PostSessionValidation {
    Ok(crate::session::SessionRuntimeView),
    Response(Option<Vec<u8>>),
}
