//! Simplified port of `internal/udpserver/dns_tunnel.go`: the tunneled
//! generic-DNS-resolution service the client's local DNS listener forwards
//! queries to (`PACKET_DNS_QUERY_REQ`/`PACKET_DNS_QUERY_RES`).
//!
//! Simplification vs. Go: this resolves sequentially through the configured
//! `DNS_UPSTREAM_SERVERS` (first success wins) instead of Go's hedged
//! parallel-query strategy (fire resolver 1, then race the rest after a
//! short delay). Functionally equivalent when the first upstream is healthy
//! (the common case); adds up to `DNS_UPSTREAM_TIMEOUT` of latency per dead
//! upstream in the list before falling through to the next one.

use crate::Server;
use std::time::{Duration, SystemTime};
use tokio_util::sync::CancellationToken;

const MAX_DNS_RESPONSE_FRAGMENTS: usize = 255;

impl Server {
    pub(crate) async fn process_deferred_dns_query(
        &self,
        session_id: u8,
        _session_cookie: u8,
        sequence_num: u16,
        download_compression: u8,
        download_mtu_bytes: usize,
        assembled_query: Vec<u8>,
        cancel: CancellationToken,
    ) {
        let parsed = match dnsparser::parse_dns_request_lite(&assembled_query) {
            Ok(p) if p.has_question => p,
            _ => return,
        };
        let q = parsed.first_question;
        let cache_key = dnscache::build_key(&q.name, q.q_type, q.class);
        let now = SystemTime::now();

        if let Some(cached) = self.dns_cache.get_ready(&cache_key, Some(&assembled_query), now) {
            self.queue_dns_query_response(session_id, sequence_num, download_compression, download_mtu_bytes, &cached);
            return;
        }

        let inflight_key = basecodec::encode(&cache_key);
        let (entry, is_leader) = self.dns_resolve_inflight.acquire(&inflight_key, std::time::Instant::now());

        if !is_leader {
            if let inflight::WaitOutcome::Resolved(Some(response)) = self.dns_resolve_inflight.wait(&entry, self.cfg.dns_inflight_wait_timeout()).await {
                self.queue_dns_query_response(session_id, sequence_num, download_compression, download_mtu_bytes, &response);
            }
            return;
        }

        let response = self.resolve_dns_upstream(&assembled_query, &cancel).await;
        self.dns_resolve_inflight.resolve(&inflight_key, response.clone());

        if let Some(response) = response {
            self.dns_cache.set_ready(&cache_key, &q.name, q.q_type, q.class, &response, SystemTime::now());
            self.queue_dns_query_response(session_id, sequence_num, download_compression, download_mtu_bytes, &response);
        }
    }

    async fn resolve_dns_upstream(&self, query: &[u8], cancel: &CancellationToken) -> Option<Vec<u8>> {
        let timeout = non_zero_or(self.cfg.dns_upstream_timeout(), Duration::from_secs(4));

        for server_addr in &self.dns_upstream_servers {
            let attempt = async {
                let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
                socket.connect(server_addr).await.ok()?;
                socket.send(query).await.ok()?;
                let mut buf = vec![0u8; 65535];
                let n = tokio::time::timeout(timeout, socket.recv(&mut buf)).await.ok()?.ok()?;
                buf.truncate(n);
                Some(buf)
            };

            tokio::select! {
                _ = cancel.cancelled() => return None,
                result = attempt => {
                    if let Some(response) = result {
                        return Some(response);
                    }
                }
            }
        }
        None
    }

    fn queue_dns_query_response(&self, session_id: u8, sequence_num: u16, compression_type: u8, download_mtu_bytes: usize, response: &[u8]) {
        let chunk_size = download_mtu_bytes.saturating_sub(64).max(64);
        let chunks: Vec<&[u8]> = response.chunks(chunk_size).collect();
        let total_fragments = chunks.len().min(MAX_DNS_RESPONSE_FRAGMENTS).max(1) as u8;

        for (i, chunk) in chunks.iter().take(MAX_DNS_RESPONSE_FRAGMENTS).enumerate() {
            self.queue_main_session_packet(
                session_id,
                vpnproto::Packet {
                    packet_type: enums::PACKET_DNS_QUERY_RES,
                    sequence_num,
                    has_sequence_num: true,
                    fragment_id: i as u8,
                    total_fragments,
                    compression_type,
                    payload: chunk.to_vec(),
                    ..Default::default()
                },
            );
        }
    }
}

fn non_zero_or(d: Duration, fallback: Duration) -> Duration {
    if d.is_zero() {
        fallback
    } else {
        d
    }
}
