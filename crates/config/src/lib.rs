//! Port of `internal/config`: TOML (+ JSON / base64-JSON) config loading for
//! the server and client.
//!
//! Field names mirror the `SCREAMING_SNAKE_CASE` keys documented in the Go
//! repo's `server_config.toml.simple` / `client_config.toml.simple` (copied
//! into this repo's root as reference) — `serde(rename_all = "SCREAMING_SNAKE_CASE")`
//! maps each Rust `snake_case` field to its TOML key automatically.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("io error reading {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("json parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid base64 config: {0}")]
    Base64(#[from] base64::DecodeError),
}

/// Mirrors Go's loading pattern (`cfg := defaultServerConfig(); toml.DecodeFile(path, &cfg)`):
/// the container-level `serde(default)` tells serde to fill any field missing
/// from the input with the corresponding field from `ServerConfig::default()`
/// rather than requiring every one of the ~70 fields to be present — so a
/// minimal partial config (like the reference tools' generated configs) loads
/// exactly like it would against the Go binary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", default)]
pub struct ServerConfig {
    pub domain: Vec<String>,
    pub protocol_type: String,
    pub supported_upload_compression_types: Vec<u8>,
    pub supported_download_compression_types: Vec<u8>,

    pub udp_host: String,
    pub udp_port: u16,
    /// `HOST:PORT` for the optional raw-UDP passthrough feature.
    pub fallback: String,

    pub udp_readers: u32,
    pub dns_request_workers: u32,
    pub max_concurrent_requests: u32,
    pub socket_buffer_size: u32,
    pub max_packet_size: u32,
    pub drop_log_interval_seconds: f64,

    pub deferred_session_workers: u32,
    pub deferred_session_queue_limit: u32,

    pub invalid_cookie_window_seconds: f64,
    pub invalid_cookie_error_threshold: u32,

    pub session_timeout_seconds: f64,
    pub session_cleanup_interval_seconds: f64,
    pub closed_session_retention_seconds: f64,
    pub session_init_reuse_ttl_seconds: f64,
    pub recently_closed_stream_ttl_seconds: f64,
    pub recently_closed_stream_cap: u32,
    pub terminal_stream_retention_seconds: f64,

    pub dns_upstream_servers: Vec<String>,
    pub dns_upstream_timeout: f64,
    pub dns_inflight_wait_timeout_seconds: f64,
    pub dns_fragment_assembly_timeout: f64,
    pub dns_cache_max_records: u32,
    pub dns_cache_ttl_seconds: f64,

    pub socks_connect_timeout: f64,
    pub forward_ip: String,
    pub forward_port: u16,
    pub use_external_socks5: bool,
    pub socks5_auth: bool,
    /// Relays client UDP datagrams (voice/video calls, games) when negotiated.
    pub udp_relay_enabled: bool,
    /// Lets relayed UDP reach loopback/private addresses. Testing only.
    pub udp_relay_allow_private: bool,
    pub socks5_user: String,
    pub socks5_pass: String,

    pub data_encryption_method: u8,
    pub encryption_key_file: String,

    /// Minimum length (in DNS-label-safe encoded characters) a query's
    /// leading label chain must have to be considered a VPN frame rather
    /// than junk/scanner traffic.
    pub min_vpn_label_length: u32,

    pub max_packets_per_batch: u32,
    pub packet_block_control_duplication: u32,

    pub stream_setup_ack_ttl_seconds: f64,
    pub stream_result_packet_ttl_seconds: f64,
    pub stream_failure_packet_ttl_seconds: f64,

    pub arq_window_size: usize,
    pub arq_initial_rto_seconds: f64,
    pub arq_max_rto_seconds: f64,
    pub arq_control_initial_rto_seconds: f64,
    pub arq_control_max_rto_seconds: f64,
    pub arq_max_control_retries: u32,
    pub arq_inactivity_timeout_seconds: f64,
    pub arq_data_packet_ttl_seconds: f64,
    pub arq_control_packet_ttl_seconds: f64,
    pub arq_max_data_retries: u32,
    pub arq_data_nack_max_gap: usize,
    pub arq_data_nack_initial_delay_seconds: f64,
    pub arq_data_nack_repeat_seconds: f64,
    pub arq_terminal_drain_timeout_seconds: f64,
    pub arq_terminal_ack_wait_timeout_seconds: f64,

    pub max_allowed_client_active_session: u32,
    pub max_allowed_client_active_streams_per_session: u32,
    pub max_allowed_client_packet_duplication_count: u32,
    pub max_allowed_client_setup_packet_duplication_count: u32,
    pub max_allowed_client_upload_mtu: u32,
    pub max_allowed_client_download_mtu: u32,
    pub max_allowed_client_rx_tx_workers: u32,
    pub min_allowed_client_ping_aggressive_interval_seconds: f64,
    pub max_allowed_client_packets_per_batch: u32,
    pub max_allowed_client_arq_window_size: u32,
    pub max_allowed_client_arq_data_nack_max_gap: u32,
    pub min_allowed_client_compression_min_size: u32,
    pub min_allowed_client_arq_initial_rto_seconds: f64,

    pub log_level: String,
    pub config_version: String,
}

/// Ported field-for-field from Go's `defaultServerConfig()` (`internal/config/server.go`).
impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            protocol_type: "SOCKS5".to_string(),
            udp_host: String::new(),
            udp_port: 53,
            fallback: String::new(),
            udp_readers: 4,
            socket_buffer_size: 8 * 1024 * 1024,
            max_concurrent_requests: 16384,
            dns_request_workers: 8,
            deferred_session_workers: 4,
            deferred_session_queue_limit: 4096,
            max_packet_size: 65535,
            drop_log_interval_seconds: 2.0,
            invalid_cookie_window_seconds: 2.0,
            invalid_cookie_error_threshold: 10,
            session_timeout_seconds: 300.0,
            session_cleanup_interval_seconds: 30.0,
            closed_session_retention_seconds: 600.0,
            session_init_reuse_ttl_seconds: 600.0,
            recently_closed_stream_ttl_seconds: 600.0,
            recently_closed_stream_cap: 2000,
            terminal_stream_retention_seconds: 45.0,
            max_packets_per_batch: 5,
            packet_block_control_duplication: 1,
            dns_upstream_servers: vec!["1.1.1.1:53".to_string(), "1.0.0.1:53".to_string()],
            dns_upstream_timeout: 4.0,
            dns_inflight_wait_timeout_seconds: 15.0,
            socks_connect_timeout: 120.0,
            dns_fragment_assembly_timeout: 300.0,
            stream_setup_ack_ttl_seconds: 400.0,
            stream_result_packet_ttl_seconds: 300.0,
            stream_failure_packet_ttl_seconds: 120.0,
            dns_cache_max_records: 50000,
            dns_cache_ttl_seconds: 300.0,
            use_external_socks5: false,
            socks5_auth: false,
            udp_relay_enabled: true,
            udp_relay_allow_private: false,
            socks5_user: "admin".to_string(),
            socks5_pass: "123456".to_string(),
            forward_ip: String::new(),
            forward_port: 1080,
            domain: Vec::new(),
            min_vpn_label_length: 3,
            supported_upload_compression_types: vec![0, 1, 2, 3],
            supported_download_compression_types: vec![0, 1, 2, 3],
            data_encryption_method: 1,
            encryption_key_file: "encrypt_key.txt".to_string(),
            log_level: "INFO".to_string(),
            arq_window_size: 800,
            arq_initial_rto_seconds: 1.0,
            arq_max_rto_seconds: 5.0,
            arq_control_initial_rto_seconds: 0.5,
            arq_control_max_rto_seconds: 3.0,
            arq_max_control_retries: 400,
            arq_inactivity_timeout_seconds: 1800.0,
            arq_data_packet_ttl_seconds: 2400.0,
            arq_control_packet_ttl_seconds: 1200.0,
            arq_max_data_retries: 1200,
            arq_data_nack_max_gap: 16,
            arq_data_nack_initial_delay_seconds: 0.3,
            arq_data_nack_repeat_seconds: 1.0,
            arq_terminal_drain_timeout_seconds: 120.0,
            arq_terminal_ack_wait_timeout_seconds: 90.0,
            max_allowed_client_active_session: 255,
            max_allowed_client_active_streams_per_session: 2000,
            max_allowed_client_packet_duplication_count: 5,
            max_allowed_client_setup_packet_duplication_count: 6,
            max_allowed_client_upload_mtu: 150,
            max_allowed_client_download_mtu: 4096,
            max_allowed_client_rx_tx_workers: 255,
            min_allowed_client_ping_aggressive_interval_seconds: 0.05,
            max_allowed_client_packets_per_batch: 20,
            max_allowed_client_arq_window_size: 8000,
            max_allowed_client_arq_data_nack_max_gap: 255,
            min_allowed_client_compression_min_size: 120,
            min_allowed_client_arq_initial_rto_seconds: 0.05,
            config_version: String::new(),
        }
    }
}

impl ServerConfig {
    /// Path to the encryption key file, relative to the current working
    /// directory. Go's `runtimepath` resolves this relative to the running
    /// executable instead; that binary-location resolution is a Phase 2
    /// concern (no `cmd-server` runtime exists yet to anchor it to).
    pub fn encryption_key_path(&self) -> PathBuf {
        PathBuf::from(&self.encryption_key_file)
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.udp_host, self.udp_port)
    }

    pub fn drop_log_interval(&self) -> Duration {
        secs(self.drop_log_interval_seconds)
    }
    pub fn invalid_cookie_window(&self) -> Duration {
        secs(self.invalid_cookie_window_seconds)
    }
    pub fn session_timeout(&self) -> Duration {
        secs(self.session_timeout_seconds)
    }
    pub fn session_cleanup_interval(&self) -> Duration {
        secs(self.session_cleanup_interval_seconds)
    }
    pub fn closed_session_retention(&self) -> Duration {
        secs(self.closed_session_retention_seconds)
    }
    pub fn dns_upstream_timeout(&self) -> Duration {
        secs(self.dns_upstream_timeout)
    }
    pub fn dns_inflight_wait_timeout(&self) -> Duration {
        secs(self.dns_inflight_wait_timeout_seconds)
    }
    pub fn socks_connect_timeout_duration(&self) -> Duration {
        secs(self.socks_connect_timeout)
    }
    pub fn dns_fragment_assembly_timeout(&self) -> Duration {
        secs(self.dns_fragment_assembly_timeout)
    }
    pub fn session_init_reuse_ttl(&self) -> Duration {
        secs(self.session_init_reuse_ttl_seconds)
    }
    pub fn recently_closed_stream_ttl(&self) -> Duration {
        secs(self.recently_closed_stream_ttl_seconds)
    }
    pub fn terminal_stream_retention(&self) -> Duration {
        secs(self.terminal_stream_retention_seconds)
    }
    pub fn stream_setup_ack_ttl(&self) -> Duration {
        secs(self.stream_setup_ack_ttl_seconds)
    }
    pub fn stream_result_packet_ttl(&self) -> Duration {
        secs(self.stream_result_packet_ttl_seconds)
    }
    pub fn stream_failure_packet_ttl(&self) -> Duration {
        secs(self.stream_failure_packet_ttl_seconds)
    }

    /// Ported from Go's `ServerConfig.Effective*()` family (`internal/config/server.go`):
    /// runtime-CPU-aware sizing with a user-configured floor. `available_parallelism()`
    /// stands in for Go's `runtime.NumCPU()`.
    fn num_cpus() -> i64 {
        std::thread::available_parallelism().map(|n| n.get() as i64).unwrap_or(1)
    }

    pub fn effective_udp_readers(&self) -> i64 {
        let cpus = Self::num_cpus();
        let mut recommended = (cpus / 2).max(1).min(8);
        if self.protocol_type == "SOCKS5" && cpus >= 4 && recommended < 2 {
            recommended = 2;
        }
        if self.max_concurrent_requests as i64 >= 32768 && cpus >= 4 && recommended < 4 {
            recommended = 4;
        }
        (self.udp_readers as i64).max(recommended).clamp(1, 32)
    }

    pub fn effective_dns_request_workers(&self) -> i64 {
        let cpus = Self::num_cpus();
        let mut recommended = cpus.max(2).min(24);
        if self.protocol_type == "SOCKS5" && cpus >= 4 && recommended < 4 {
            recommended = 4;
        }
        let reader_target = if cpus >= 4 {
            self.effective_udp_readers() * 2
        } else {
            self.effective_udp_readers() + 1
        };
        if recommended < reader_target {
            recommended = reader_target;
        }
        (self.dns_request_workers as i64).max(recommended).clamp(1, 256)
    }

    pub fn effective_deferred_session_workers(&self) -> i64 {
        let cpus = Self::num_cpus();
        let mut recommended = (cpus / 2).max(2).min(16);
        if self.protocol_type == "SOCKS5" && recommended < 4 {
            recommended = 4;
        }
        (self.deferred_session_workers as i64).max(recommended).clamp(0, 256)
    }

    pub fn effective_deferred_session_queue_limit(&self) -> i64 {
        let recommended = (self.effective_deferred_session_workers() * 512)
            .max(self.effective_max_packets_per_batch() * 128)
            .clamp(256, 16384);
        (self.deferred_session_queue_limit as i64).max(recommended).clamp(256, 32768)
    }

    pub fn effective_max_concurrent_requests(&self) -> i64 {
        let recommended = (self.effective_udp_readers() * self.effective_dns_request_workers() * 512).max(4096);
        (self.max_concurrent_requests as i64).max(recommended).clamp(1024, 131072)
    }

    pub fn effective_max_packets_per_batch(&self) -> i64 {
        let recommended = if self.arq_window_size > 3000 {
            14
        } else if self.arq_window_size > 1500 {
            12
        } else if self.arq_window_size > 1024 {
            10
        } else {
            5
        };
        (self.max_packets_per_batch as i64).max(recommended).clamp(1, 64)
    }

    pub fn effective_dns_cache_max_records(&self) -> i64 {
        let recommended = (self.effective_max_concurrent_requests() * 2).max(2000).clamp(2000, 200000);
        (self.dns_cache_max_records as i64).max(recommended).clamp(1, 500000)
    }

    pub fn effective_session_orphan_queue_initial_cap(&self) -> i64 {
        let recommended = self.effective_max_packets_per_batch() * 4
            + self.effective_deferred_session_workers() * 16
            + self.packet_block_control_duplication as i64 * 16;
        recommended.clamp(32, 2048)
    }

    pub fn effective_stream_queue_initial_capacity(&self) -> i64 {
        let mut recommended = (self.arq_window_size as i64 / 8).max(self.effective_max_packets_per_batch() * 8);
        if self.packet_block_control_duplication > 1 {
            recommended += self.packet_block_control_duplication as i64 * 4;
        }
        recommended.clamp(32, 2048)
    }

    pub fn effective_dns_fragment_store_capacity(&self) -> i64 {
        let recommended = self.effective_max_concurrent_requests() / 32 + self.effective_dns_request_workers() * 16;
        recommended.clamp(64, 8192)
    }

    pub fn effective_socks5_fragment_store_capacity(&self) -> i64 {
        let recommended = self.effective_max_concurrent_requests() / 16 + self.effective_deferred_session_workers() * 32;
        recommended.clamp(64, 8192)
    }
}

fn secs(value: f64) -> Duration {
    Duration::from_secs_f64(value.max(0.0))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct ClientConfig {
    pub domains: Vec<String>,
    pub data_encryption_method: u8,
    pub encryption_key: String,
    pub protocol_type: String,

    pub listen_ip: String,
    pub listen_port: u16,

    pub local_dns_enabled: bool,
    pub local_dns_ip: String,
    pub local_dns_port: u16,
    pub local_dns_cache_max_records: u32,
    pub local_dns_cache_ttl_seconds: f64,
    pub local_dns_pending_timeout_seconds: f64,
    pub dns_response_fragment_timeout_seconds: f64,
    pub local_dns_cache_persist_to_file: bool,
    pub local_dns_cache_flush_interval_seconds: f64,

    pub resolver_balancing_strategy: u8,
    pub packet_duplication_count: u32,
    pub setup_packet_duplication_count: u32,
    pub stream_resolver_failover_resend_threshold: u32,
    pub stream_resolver_failover_cooldown: f64,
    pub recheck_inactive_servers_enabled: bool,
    pub auto_disable_timeout_servers: bool,
    pub auto_disable_timeout_window_seconds: f64,

    pub base_encode_data: bool,
    pub upload_compression_type: u8,
    pub download_compression_type: u8,
    pub compression_min_size: u32,

    pub min_upload_mtu: u32,
    pub min_download_mtu: u32,
    pub max_upload_mtu: u32,
    pub max_download_mtu: u32,
    pub auto_remove_low_mtu_servers: bool,
    pub mtu_test_retries: u32,
    pub mtu_test_timeout: f64,
    pub mtu_test_parallelism: u32,
    pub save_mtu_servers_to_file: bool,
    pub mtu_servers_file_name: String,
    pub mtu_servers_file_format: String,
    pub mtu_using_section_separator_text: String,
    pub mtu_removed_server_log_format: String,
    pub mtu_added_server_log_format: String,
    pub mtu_reactive_added_server_log_format: String,

    pub rx_tx_workers: u32,
    pub tunnel_process_workers: u32,
    pub tunnel_packet_timeout_seconds: f64,
    pub dispatcher_idle_poll_interval_seconds: f64,
    pub rx_channel_size: u32,
    pub socks_udp_associate_read_timeout_seconds: f64,
    pub client_terminal_stream_retention_seconds: f64,
    pub client_cancelled_setup_retention_seconds: f64,

    pub session_init_retry_base_seconds: f64,
    pub session_init_retry_step_seconds: f64,
    pub session_init_retry_linear_after: u32,
    pub session_init_retry_max_seconds: f64,
    pub session_init_busy_retry_interval_seconds: f64,
    pub session_init_racing_count: u32,

    pub ping_aggressive_interval_seconds: f64,
    pub ping_lazy_interval_seconds: f64,
    pub ping_cooldown_interval_seconds: f64,
    pub ping_cold_interval_seconds: f64,
    pub ping_warm_threshold_seconds: f64,
    pub ping_cool_threshold_seconds: f64,
    pub ping_cold_threshold_seconds: f64,

    pub max_packets_per_batch: u32,
    pub arq_window_size: usize,
    pub arq_initial_rto_seconds: f64,
    pub arq_max_rto_seconds: f64,
    pub arq_control_initial_rto_seconds: f64,
    pub arq_control_max_rto_seconds: f64,
    pub arq_max_control_retries: u32,
    pub arq_inactivity_timeout_seconds: f64,
    pub arq_data_packet_ttl_seconds: f64,
    pub arq_control_packet_ttl_seconds: f64,
    pub arq_max_data_retries: u32,
    pub arq_data_nack_max_gap: usize,
    pub arq_data_nack_initial_delay_seconds: f64,
    pub arq_data_nack_repeat_seconds: f64,
    pub arq_terminal_drain_timeout_seconds: f64,
    pub arq_terminal_ack_wait_timeout_seconds: f64,

    pub log_level: String,
}

fn read_to_string(path: &Path) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|source| ConfigError::Io { path: path.to_path_buf(), source })
}

pub fn load_server_toml(path: &Path) -> Result<ServerConfig, ConfigError> {
    Ok(toml::from_str(&read_to_string(path)?)?)
}

pub fn load_client_toml(path: &Path) -> Result<ClientConfig, ConfigError> {
    Ok(toml::from_str(&read_to_string(path)?)?)
}

pub fn load_server_json(path: &Path) -> Result<ServerConfig, ConfigError> {
    Ok(serde_json::from_str(&read_to_string(path)?)?)
}

pub fn load_client_json(path: &Path) -> Result<ClientConfig, ConfigError> {
    Ok(serde_json::from_str(&read_to_string(path)?)?)
}

pub fn load_server_json_base64(encoded: &str) -> Result<ServerConfig, ConfigError> {
    let raw = STANDARD.decode(encoded.trim())?;
    Ok(serde_json::from_slice(&raw)?)
}

pub fn load_client_json_base64(encoded: &str) -> Result<ClientConfig, ConfigError> {
    let raw = STANDARD.decode(encoded.trim())?;
    Ok(serde_json::from_slice(&raw)?)
}

/// Parses a `client_resolvers.simple`-style resolver list file: one
/// `ip:port` (or `ip:port#domain-override`) entry per line, blank lines and
/// `#`-prefixed comment lines ignored.
pub fn parse_resolvers_file(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_reference_server_config() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server_config.toml.simple");
        let cfg = load_server_toml(&path).expect("server_config.toml.simple should parse against ServerConfig");
        assert_eq!(cfg.config_version, "12");
        assert_eq!(cfg.udp_port, 53);
    }

    #[test]
    fn loads_minimal_partial_server_config_with_defaults() {
        // Mirrors the minimal config scripts/bench/bench.go generates in the Go
        // repo (~25 of ~70 fields) — proves container-level `serde(default)`
        // fills in the rest from `ServerConfig::default()`, matching Go's
        // `defaultServerConfig()` + partial-TOML-overlay loading pattern.
        let toml_str = r#"
            PROTOCOL_TYPE = "TCP"
            UDP_HOST = "0.0.0.0"
            UDP_PORT = 5300
            DOMAIN = ["a.io"]
            MIN_VPN_LABEL_LENGTH = 1
            DATA_ENCRYPTION_METHOD = 1
            ENCRYPTION_KEY_FILE = "encrypt_key.txt"
            FORWARD_IP = "127.0.0.1"
            FORWARD_PORT = 9000
            LOG_LEVEL = "INFO"
        "#;
        let dir = std::env::temp_dir().join(format!("config-minimal-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("minimal_server_config.toml");
        std::fs::write(&path, toml_str).unwrap();

        let cfg = load_server_toml(&path).expect("minimal partial config should load using defaults");
        assert_eq!(cfg.udp_port, 5300);
        assert_eq!(cfg.forward_ip, "127.0.0.1");
        assert_eq!(cfg.forward_port, 9000);
        // Fields absent from the TOML must fall back to Go's defaults.
        assert_eq!(cfg.udp_readers, 4);
        assert_eq!(cfg.max_concurrent_requests, 16384);
        assert_eq!(cfg.arq_window_size, 800);
        assert_eq!(cfg.socks5_user, "admin");
        assert_eq!(cfg.dns_upstream_servers, vec!["1.1.1.1:53".to_string(), "1.0.0.1:53".to_string()]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parses_real_reference_client_config() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../client_config.toml.simple");
        let cfg = load_client_toml(&path).expect("client_config.toml.simple should parse against ClientConfig");
        assert_eq!(cfg.listen_port, 18000);
        assert_eq!(cfg.log_level, "INFO");
    }

    #[test]
    fn parses_real_reference_resolvers_file() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../client_resolvers.simple");
        let contents = std::fs::read_to_string(path).unwrap();
        let resolvers = parse_resolvers_file(&contents);
        assert!(!resolvers.is_empty());
    }

    #[test]
    fn parses_resolvers_file_skipping_comments_and_blanks() {
        let contents = "\
# a comment
1.1.1.1:53

8.8.8.8:53
  9.9.9.9:53
";
        let parsed = parse_resolvers_file(contents);
        assert_eq!(parsed, vec!["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"]);
    }

    #[test]
    fn json_round_trips_server_config() {
        let cfg = minimal_server_config();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: ServerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn base64_json_round_trips_client_config() {
        let cfg = minimal_client_config();
        let json = serde_json::to_string(&cfg).unwrap();
        let encoded = STANDARD.encode(json);
        let parsed = load_client_json_base64(&encoded).unwrap();
        assert_eq!(parsed, cfg);
    }

    fn minimal_server_config() -> ServerConfig {
        ServerConfig {
            domain: vec!["v.example.com".to_string()],
            protocol_type: "SOCKS5".to_string(),
            supported_upload_compression_types: vec![0, 1, 2, 3],
            supported_download_compression_types: vec![0, 1, 2, 3],
            udp_host: String::new(),
            udp_port: 53,
            fallback: String::new(),
            udp_readers: 6,
            dns_request_workers: 10,
            max_concurrent_requests: 32768,
            socket_buffer_size: 8388608,
            max_packet_size: 65535,
            drop_log_interval_seconds: 2.0,
            deferred_session_workers: 6,
            deferred_session_queue_limit: 8192,
            invalid_cookie_window_seconds: 2.0,
            invalid_cookie_error_threshold: 10,
            session_timeout_seconds: 300.0,
            session_cleanup_interval_seconds: 30.0,
            closed_session_retention_seconds: 600.0,
            session_init_reuse_ttl_seconds: 600.0,
            recently_closed_stream_ttl_seconds: 600.0,
            recently_closed_stream_cap: 2000,
            terminal_stream_retention_seconds: 45.0,
            dns_upstream_servers: vec!["1.1.1.1:53".to_string(), "1.0.0.1:53".to_string()],
            dns_upstream_timeout: 4.0,
            dns_inflight_wait_timeout_seconds: 15.0,
            dns_fragment_assembly_timeout: 300.0,
            dns_cache_max_records: 50000,
            dns_cache_ttl_seconds: 300.0,
            socks_connect_timeout: 60.0,
            forward_ip: String::new(),
            forward_port: 0,
            use_external_socks5: false,
            socks5_auth: false,
            udp_relay_enabled: true,
            udp_relay_allow_private: false,
            socks5_user: "admin".to_string(),
            socks5_pass: "123456".to_string(),
            data_encryption_method: 1,
            encryption_key_file: "encrypt_key.txt".to_string(),
            min_vpn_label_length: 3,
            max_packets_per_batch: 10,
            packet_block_control_duplication: 1,
            stream_setup_ack_ttl_seconds: 400.0,
            stream_result_packet_ttl_seconds: 300.0,
            stream_failure_packet_ttl_seconds: 120.0,
            arq_window_size: 1000,
            arq_initial_rto_seconds: 0.5,
            arq_max_rto_seconds: 3.0,
            arq_control_initial_rto_seconds: 0.5,
            arq_control_max_rto_seconds: 2.0,
            arq_max_control_retries: 126,
            arq_inactivity_timeout_seconds: 1800.0,
            arq_data_packet_ttl_seconds: 2400.0,
            arq_control_packet_ttl_seconds: 1200.0,
            arq_max_data_retries: 126,
            arq_data_nack_max_gap: 32,
            arq_data_nack_initial_delay_seconds: 0.3,
            arq_data_nack_repeat_seconds: 0.8,
            arq_terminal_drain_timeout_seconds: 120.0,
            arq_terminal_ack_wait_timeout_seconds: 90.0,
            max_allowed_client_active_session: 255,
            max_allowed_client_active_streams_per_session: 2000,
            max_allowed_client_packet_duplication_count: 5,
            max_allowed_client_setup_packet_duplication_count: 6,
            max_allowed_client_upload_mtu: 150,
            max_allowed_client_download_mtu: 4096,
            max_allowed_client_rx_tx_workers: 255,
            min_allowed_client_ping_aggressive_interval_seconds: 0.05,
            max_allowed_client_packets_per_batch: 20,
            max_allowed_client_arq_window_size: 8000,
            max_allowed_client_arq_data_nack_max_gap: 255,
            min_allowed_client_compression_min_size: 120,
            min_allowed_client_arq_initial_rto_seconds: 0.05,
            log_level: "INFO".to_string(),
            config_version: "12".to_string(),
        }
    }

    fn minimal_client_config() -> ClientConfig {
        ClientConfig {
            domains: vec!["v.example.com".to_string()],
            data_encryption_method: 1,
            encryption_key: String::new(),
            protocol_type: "SOCKS5".to_string(),
            listen_ip: "127.0.0.1".to_string(),
            listen_port: 18000,
            local_dns_enabled: false,
            local_dns_ip: "127.0.0.1".to_string(),
            local_dns_port: 53,
            local_dns_cache_max_records: 10000,
            local_dns_cache_ttl_seconds: 14400.0,
            local_dns_pending_timeout_seconds: 300.0,
            dns_response_fragment_timeout_seconds: 60.0,
            local_dns_cache_persist_to_file: true,
            local_dns_cache_flush_interval_seconds: 60.0,
            resolver_balancing_strategy: 3,
            packet_duplication_count: 3,
            setup_packet_duplication_count: 4,
            stream_resolver_failover_resend_threshold: 2,
            stream_resolver_failover_cooldown: 2.5,
            recheck_inactive_servers_enabled: true,
            auto_disable_timeout_servers: true,
            auto_disable_timeout_window_seconds: 30.0,
            base_encode_data: false,
            upload_compression_type: 0,
            download_compression_type: 0,
            compression_min_size: 120,
            min_upload_mtu: 38,
            min_download_mtu: 200,
            max_upload_mtu: 150,
            max_download_mtu: 4000,
            auto_remove_low_mtu_servers: true,
            mtu_test_retries: 2,
            mtu_test_timeout: 2.0,
            mtu_test_parallelism: 32,
            save_mtu_servers_to_file: false,
            mtu_servers_file_name: "masterdnsvpn_success_test_{time}.log".to_string(),
            mtu_servers_file_format: "{IP} ({DOMAIN}) - UP: {UP_MTU} DOWN: {DOWN-MTU}".to_string(),
            mtu_using_section_separator_text: String::new(),
            mtu_removed_server_log_format: "Resolver {IP} ({DOMAIN}) removed at {TIME} due to {CAUSE}".to_string(),
            mtu_added_server_log_format: "Resolver {IP} ({DOMAIN}) added back at {TIME} (UP {UP_MTU}, DOWN {DOWN_MTU})".to_string(),
            mtu_reactive_added_server_log_format: "Resolver {IP} ({DOMAIN}) added back at {TIME} after reactive recheck (UP {UP_MTU}, DOWN {DOWN_MTU})".to_string(),
            rx_tx_workers: 4,
            tunnel_process_workers: 6,
            tunnel_packet_timeout_seconds: 10.0,
            dispatcher_idle_poll_interval_seconds: 0.020,
            rx_channel_size: 4096,
            socks_udp_associate_read_timeout_seconds: 30.0,
            client_terminal_stream_retention_seconds: 45.0,
            client_cancelled_setup_retention_seconds: 120.0,
            session_init_retry_base_seconds: 1.0,
            session_init_retry_step_seconds: 1.0,
            session_init_retry_linear_after: 5,
            session_init_retry_max_seconds: 60.0,
            session_init_busy_retry_interval_seconds: 60.0,
            session_init_racing_count: 3,
            ping_aggressive_interval_seconds: 0.100,
            ping_lazy_interval_seconds: 0.750,
            ping_cooldown_interval_seconds: 2.0,
            ping_cold_interval_seconds: 15.0,
            ping_warm_threshold_seconds: 8.0,
            ping_cool_threshold_seconds: 20.0,
            ping_cold_threshold_seconds: 30.0,
            max_packets_per_batch: 8,
            arq_window_size: 1000,
            arq_initial_rto_seconds: 0.5,
            arq_max_rto_seconds: 3.0,
            arq_control_initial_rto_seconds: 0.5,
            arq_control_max_rto_seconds: 2.0,
            arq_max_control_retries: 126,
            arq_inactivity_timeout_seconds: 1800.0,
            arq_data_packet_ttl_seconds: 2400.0,
            arq_control_packet_ttl_seconds: 1200.0,
            arq_max_data_retries: 126,
            arq_data_nack_max_gap: 32,
            arq_data_nack_initial_delay_seconds: 0.1,
            arq_data_nack_repeat_seconds: 0.8,
            arq_terminal_drain_timeout_seconds: 120.0,
            arq_terminal_ack_wait_timeout_seconds: 90.0,
            log_level: "INFO".to_string(),
        }
    }
}
