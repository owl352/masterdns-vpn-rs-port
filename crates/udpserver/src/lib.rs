//! Port of `internal/udpserver` (the UDP server side of MasterDnsVPN).
//!
//! See `/Users/bebra/.claude/plans/quiet-conjuring-flask.md` (Phase 2 plan)
//! for the full architecture writeup. Summary: every inbound UDP datagram is
//! a DNS query that demands exactly one synchronous DNS-answer reply, built
//! by draining whatever's queued for that session (§ `postsession::serve_queued_or_pong`)
//! — this is *not* a push-based server despite being a long-running daemon.
//!
//! Not implemented this pass (see plan step 9 / README): `udp_fallback.go`'s
//! raw-UDP passthrough feature (`FALLBACK` config, off by default).
//! `dns_tunnel.go`'s tunneled-DNS-resolution service is implemented in
//! `dns_tunnel.rs` in a simplified (sequential-upstream, no hedging) form.

#[cfg(target_os = "linux")]
mod batch_io;
mod datagram;
mod deferred;
mod dns_tunnel;
mod ingress;
mod invalid_cookie;
mod postsession;
mod runtime;
mod session;
mod session_handlers;
mod socks5_upstream;
mod stream;
mod transport;

#[cfg(test)]
mod tests;

pub use runtime::run;
pub use session::MAX_SERVER_SESSION_ID;

use std::sync::atomic::{AtomicU32, AtomicU64};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub(crate) const MTU_PROBE_MODE_RAW: u8 = 0;
pub(crate) const MTU_PROBE_MODE_BASE64: u8 = 1;
pub(crate) const MTU_PROBE_CODE_LENGTH: usize = 4;
pub(crate) const MTU_PROBE_META_LENGTH: usize = MTU_PROBE_CODE_LENGTH + 2;
pub(crate) const MTU_PROBE_UP_MIN_SIZE: usize = 1 + MTU_PROBE_CODE_LENGTH;
pub(crate) const MTU_PROBE_DOWN_MIN_SIZE: usize = MTU_PROBE_UP_MIN_SIZE + 2;
pub(crate) const MTU_PROBE_MIN_DOWN_SIZE: usize = vpnproto::SESSION_ACCEPT_PAYLOAD_SIZE;
pub(crate) const MTU_PROBE_MAX_DOWN_SIZE: usize = 4096;

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
pub(crate) struct DnsFragmentKey {
    pub session_id: u8,
    pub sequence_num: u16,
}

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
pub(crate) struct Socks5FragmentKey {
    pub session_id: u8,
    pub stream_id: u16,
    pub sequence_num: u16,
}

pub struct Server {
    pub cfg: config::ServerConfig,
    pub log: Arc<logger::Logger>,
    pub codec: Arc<security::Codec>,
    domain_matcher: domainmatcher::Matcher,
    pub sessions: session::SessionStore,
    deferred: deferred::DeferredRuntime,
    invalid_cookie_tracker: invalid_cookie::InvalidCookieTracker,
    dns_cache: dnscache::Store,
    dns_resolve_inflight: inflight::Manager<Vec<u8>>,
    dns_upstream_servers: Vec<String>,
    dns_fragments: fragmentstore::Store<DnsFragmentKey>,
    datagram_fragments: fragmentstore::Store<datagram::DatagramFragmentKey>,
    udp_flows: datagram::Flows,
    datagram_seq: std::sync::atomic::AtomicU32,
    socks5_fragments: fragmentstore::Store<Socks5FragmentKey>,
    dns_fragment_timeout: Duration,

    upload_compression_mask: u8,
    download_compression_mask: u8,

    invalid_cookie_window: Duration,
    invalid_cookie_threshold: usize,

    socks_connect_timeout: Duration,
    use_external_socks5: bool,
    external_socks5: socks5_upstream::ExternalSocks5Config,

    #[allow(dead_code)]
    deferred_dropped_packets: AtomicU64,
    pong_nonce: AtomicU32,
    invalid_drop_mode: AtomicU32,

    deferred_inflight: postsession::DeferredInflight,
    /// Set once, immediately after construction (see `Server::new`), so
    /// deferred-work closures can clone their own `Arc<Server>` — mirrors
    /// nothing in Go (plain pointers don't have this chicken-and-egg
    /// problem); it's purely a Rust `Arc` bootstrapping detail.
    self_ref: OnceLock<Arc<Server>>,
}

impl Server {
    pub(crate) fn deferred_inflight(&self) -> &postsession::DeferredInflight {
        &self.deferred_inflight
    }

    pub(crate) fn invalid_cookie_tracker_cleanup(&self, now: std::time::Instant) {
        self.invalid_cookie_tracker.cleanup(now, self.invalid_cookie_window);
    }
}

fn build_compression_mask(values: &[u8]) -> u8 {
    let mut mask: u8 = 1 << compression::TYPE_OFF;
    for &value in values {
        if value > compression::TYPE_ZLIB || !compression::is_type_available(value) {
            continue;
        }
        mask |= 1 << value;
    }
    mask
}

impl Server {
    pub fn new(cfg: config::ServerConfig, log: Arc<logger::Logger>, codec: Arc<security::Codec>) -> Arc<Self> {
        let invalid_cookie_window = non_zero_or(cfg.invalid_cookie_window(), Duration::from_secs(2));
        let dns_fragment_timeout = non_zero_or(cfg.dns_fragment_assembly_timeout(), Duration::from_secs(300));
        let socks_connect_timeout = non_zero_or(cfg.socks_connect_timeout_duration(), Duration::from_secs(8));

        let domain_matcher = domainmatcher::Matcher::new(&cfg.domain, cfg.min_vpn_label_length as usize);

        let sessions = session::SessionStore::new(
            cfg.effective_session_orphan_queue_initial_cap() as usize,
            cfg.effective_stream_queue_initial_capacity() as usize,
            cfg.session_init_reuse_ttl(),
            cfg.recently_closed_stream_ttl(),
            cfg.recently_closed_stream_cap as usize,
        );
        sessions.max_active_sessions.store(cfg.max_allowed_client_active_session as u16, std::sync::atomic::Ordering::Relaxed);
        sessions.max_active_streams.store(cfg.max_allowed_client_active_streams_per_session as u16, std::sync::atomic::Ordering::Relaxed);

        let deferred_workers = cfg.effective_deferred_session_workers().max(1) as usize;
        let deferred_queue_limit = cfg.effective_deferred_session_queue_limit() as usize;
        let session_pending_cap = (deferred_queue_limit / 2).clamp(32, 1024) * deferred_workers.min(4);

        let upload_compression_mask = build_compression_mask(&cfg.supported_upload_compression_types);
        let download_compression_mask = build_compression_mask(&cfg.supported_download_compression_types);

        let external_socks5 = socks5_upstream::ExternalSocks5Config {
            address: format!("{}:{}", cfg.forward_ip, cfg.forward_port),
            auth: cfg.socks5_auth,
            user: cfg.socks5_user.as_bytes().to_vec(),
            pass: cfg.socks5_pass.as_bytes().to_vec(),
        };

        let dns_cache = dnscache::Store::new(
            cfg.effective_dns_cache_max_records() as usize,
            Duration::from_secs_f64(cfg.dns_cache_ttl_seconds.max(0.0)),
            dns_fragment_timeout,
        );

        let server = Arc::new(Server {
            use_external_socks5: cfg.use_external_socks5,
            dns_resolve_inflight: inflight::Manager::new(cfg.dns_inflight_wait_timeout(), Duration::from_secs(15)),
            dns_upstream_servers: cfg.dns_upstream_servers.clone(),
            dns_fragments: fragmentstore::Store::new(cfg.effective_dns_fragment_store_capacity() as usize),
            datagram_fragments: fragmentstore::Store::new(4096),
            udp_flows: datagram::Flows::default(),
            datagram_seq: std::sync::atomic::AtomicU32::new(0),
            socks5_fragments: fragmentstore::Store::new(cfg.effective_socks5_fragment_store_capacity() as usize),
            dns_fragment_timeout,
            upload_compression_mask,
            download_compression_mask,
            invalid_cookie_window,
            invalid_cookie_threshold: cfg.invalid_cookie_error_threshold as usize,
            socks_connect_timeout,
            external_socks5,
            deferred_dropped_packets: AtomicU64::new(0),
            pong_nonce: AtomicU32::new(0),
            invalid_drop_mode: AtomicU32::new(0),
            domain_matcher,
            sessions,
            deferred: deferred::DeferredRuntime::new(session_pending_cap),
            invalid_cookie_tracker: invalid_cookie::InvalidCookieTracker::new(),
            dns_cache,
            deferred_inflight: postsession::DeferredInflight::new(),
            self_ref: OnceLock::new(),
            cfg,
            log,
            codec,
        });

        let _ = server.self_ref.set(server.clone());
        server
    }
}

fn non_zero_or(d: Duration, fallback: Duration) -> Duration {
    if d.is_zero() {
        fallback
    } else {
        d
    }
}

fn session_response_mode_name(mode: u8) -> &'static str {
    if mode == MTU_PROBE_MODE_BASE64 {
        "BASE64"
    } else {
        "RAW (Bytes)"
    }
}

fn parse_mtu_probe_base_encoding(mode: u8) -> Option<bool> {
    match mode {
        MTU_PROBE_MODE_RAW => Some(false),
        MTU_PROBE_MODE_BASE64 => Some(true),
        _ => None,
    }
}
