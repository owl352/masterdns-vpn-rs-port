//! Port of `internal/udpserver/socks5_upstream.go`: outbound dial logic
//! (direct TCP, or via an external SOCKS5 upstream), plus the SSRF host guard.

use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub enum DialError {
    Blocked(String),
    Upstream { packet_type: u8, message: String },
    Io(std::io::Error),
    Cancelled,
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialError::Blocked(host) => write!(f, "blocked socks target: {host}"),
            DialError::Upstream { message, .. } => write!(f, "{message}"),
            DialError::Io(e) => write!(f, "{e}"),
            DialError::Cancelled => write!(f, "dial cancelled"),
        }
    }
}

impl From<std::io::Error> for DialError {
    fn from(e: std::io::Error) -> Self {
        DialError::Io(e)
    }
}

/// Rejects loopback/private/link-local/multicast/CGNAT(100.64/10)/
/// benchmarking(198.18/15)/unspecified targets — an SSRF guard on the server
/// itself, since the target is client-controlled (SOCKS5 mode).
pub fn validate_socks_target_host(host: &str) -> Result<(), DialError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(DialError::Blocked(host.to_string()));
    }

    let lower = trimmed.to_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return Err(DialError::Blocked(host.to_string()));
    }

    let ip: IpAddr = match trimmed.parse() {
        Ok(ip) => ip,
        Err(_) => return Ok(()), // not an IP literal (a domain name) — allowed
    };

    let blocked = match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_multicast()
                || v4.is_link_local()
                || v4.is_unspecified()
                || !is_global_unicast_v4(&v4)
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1])) // CGNAT 100.64/10
                || (v4.octets()[0] == 198 && (v4.octets()[1] == 18 || v4.octets()[1] == 19)) // benchmarking 198.18/15
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_multicast() || v6.is_unicast_link_local() || v6.is_unspecified(),
    };

    if blocked {
        Err(DialError::Blocked(host.to_string()))
    } else {
        Ok(())
    }
}

fn is_global_unicast_v4(ip: &std::net::Ipv4Addr) -> bool {
    !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_broadcast() || ip.is_documentation() || ip.is_unspecified())
}

pub struct ExternalSocks5Config {
    pub address: String,
    pub auth: bool,
    pub user: Vec<u8>,
    pub pass: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub async fn dial_socks_stream_target(
    host: &str,
    port: u16,
    target_payload: &[u8],
    use_external_socks5: bool,
    external: &ExternalSocks5Config,
    connect_timeout: Duration,
    cancel: &CancellationToken,
) -> Result<TcpStream, DialError> {
    validate_socks_target_host(host)?;

    if !use_external_socks5 || target_payload.is_empty() {
        dial_tcp_target(&format!("{host}:{port}"), connect_timeout, cancel).await
    } else {
        dial_external_socks5_target(target_payload, external, connect_timeout, cancel).await
    }
}

pub async fn dial_tcp_target(address: &str, timeout: Duration, cancel: &CancellationToken) -> Result<TcpStream, DialError> {
    tokio::select! {
        _ = cancel.cancelled() => Err(DialError::Cancelled),
        result = tokio::time::timeout(timeout, TcpStream::connect(address)) => {
            match result {
                Ok(Ok(stream)) => Ok(stream),
                Ok(Err(e)) => Err(DialError::Io(e)),
                Err(_elapsed) => Err(DialError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"))),
            }
        }
    }
}

async fn dial_external_socks5_target(
    target_payload: &[u8],
    external: &ExternalSocks5Config,
    connect_timeout: Duration,
    cancel: &CancellationToken,
) -> Result<TcpStream, DialError> {
    let mut conn = dial_tcp_target(&external.address, connect_timeout, cancel).await?;

    let handshake = async {
        write_all_upstream(&mut conn, &external_socks5_greeting(external)).await?;

        let mut greeting = [0u8; 2];
        conn.read_exact(&mut greeting).await.map_err(upstream_unavailable)?;
        if greeting[0] != 0x05 {
            return Err(DialError::Upstream {
                packet_type: enums::PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
                message: "upstream proxy is not a valid SOCKS5 server".to_string(),
            });
        }
        handle_external_socks5_auth(&mut conn, greeting[1], external).await?;

        let mut request = Vec::with_capacity(3 + target_payload.len());
        request.extend_from_slice(&[0x05, 0x01, 0x00]);
        request.extend_from_slice(target_payload);
        write_all_upstream(&mut conn, &request).await?;

        let mut header = [0u8; 4];
        conn.read_exact(&mut header).await.map_err(upstream_unavailable)?;
        if header[0] != 0x05 {
            return Err(DialError::Upstream {
                packet_type: enums::PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
                message: "invalid external SOCKS5 connect response".to_string(),
            });
        }
        if header[1] != 0x00 {
            return Err(DialError::Upstream {
                packet_type: socks5_reply_packet_type(header[1]),
                message: format!("external SOCKS5 failed to connect to target: code {}", header[1]),
            });
        }
        discard_socks5_bound_address(&mut conn, header[3]).await?;
        Ok(())
    };

    tokio::select! {
        _ = cancel.cancelled() => {
            let _ = conn.shutdown().await;
            Err(DialError::Cancelled)
        }
        result = tokio::time::timeout(connect_timeout, handshake) => {
            match result {
                Ok(Ok(())) => Ok(conn),
                Ok(Err(e)) => Err(e),
                Err(_elapsed) => Err(DialError::Upstream {
                    packet_type: enums::PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
                    message: "external SOCKS5 handshake timed out".to_string(),
                }),
            }
        }
    }
}

fn upstream_unavailable(e: std::io::Error) -> DialError {
    DialError::Upstream { packet_type: enums::PACKET_SOCKS5_UPSTREAM_UNAVAILABLE, message: e.to_string() }
}

fn external_socks5_greeting(external: &ExternalSocks5Config) -> [u8; 3] {
    if external.auth {
        [0x05, 0x01, 0x02]
    } else {
        [0x05, 0x01, 0x00]
    }
}

async fn handle_external_socks5_auth(conn: &mut TcpStream, method: u8, external: &ExternalSocks5Config) -> Result<(), DialError> {
    if !external.auth {
        if method == 0x00 {
            return Ok(());
        }
        return Err(DialError::Upstream {
            packet_type: enums::PACKET_SOCKS5_AUTH_FAILED,
            message: "external SOCKS5 requires unsupported authentication method".to_string(),
        });
    }

    if method != 0x02 {
        return Err(DialError::Upstream {
            packet_type: enums::PACKET_SOCKS5_AUTH_FAILED,
            message: "external SOCKS5 authentication method mismatch".to_string(),
        });
    }

    let mut request = Vec::with_capacity(3 + external.user.len() + external.pass.len());
    request.push(0x01);
    request.push(external.user.len() as u8);
    request.extend_from_slice(&external.user);
    request.push(external.pass.len() as u8);
    request.extend_from_slice(&external.pass);

    write_all_upstream(conn, &request).await.map_err(|_| DialError::Upstream {
        packet_type: enums::PACKET_SOCKS5_AUTH_FAILED,
        message: "failed to send external SOCKS5 auth".to_string(),
    })?;

    let mut response = [0u8; 2];
    conn.read_exact(&mut response).await.map_err(|_| DialError::Upstream {
        packet_type: enums::PACKET_SOCKS5_AUTH_FAILED,
        message: "failed to read external SOCKS5 auth response".to_string(),
    })?;
    if response[1] != 0x00 {
        return Err(DialError::Upstream {
            packet_type: enums::PACKET_SOCKS5_AUTH_FAILED,
            message: "external SOCKS5 authentication failed".to_string(),
        });
    }
    Ok(())
}

async fn discard_socks5_bound_address(conn: &mut TcpStream, atyp: u8) -> Result<(), DialError> {
    let length = match atyp {
        0x01 => 4 + 2,
        0x03 => {
            let mut dlen = [0u8; 1];
            conn.read_exact(&mut dlen).await.map_err(upstream_unavailable)?;
            dlen[0] as usize + 2
        }
        0x04 => 16 + 2,
        _ => {
            return Err(DialError::Upstream {
                packet_type: enums::PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
                message: "unsupported SOCKS5 bound address type".to_string(),
            })
        }
    };
    if length == 0 {
        return Ok(());
    }
    let mut buffer = vec![0u8; length];
    conn.read_exact(&mut buffer).await.map_err(upstream_unavailable)?;
    Ok(())
}

fn socks5_reply_packet_type(reply: u8) -> u8 {
    match reply {
        0x02 => enums::PACKET_SOCKS5_RULESET_DENIED,
        0x03 => enums::PACKET_SOCKS5_NETWORK_UNREACHABLE,
        0x04 => enums::PACKET_SOCKS5_HOST_UNREACHABLE,
        0x05 => enums::PACKET_SOCKS5_CONNECTION_REFUSED,
        0x06 => enums::PACKET_SOCKS5_TTL_EXPIRED,
        0x07 => enums::PACKET_SOCKS5_COMMAND_UNSUPPORTED,
        0x08 => enums::PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
        _ => enums::PACKET_SOCKS5_CONNECT_FAIL,
    }
}

async fn write_all_upstream(conn: &mut TcpStream, payload: &[u8]) -> Result<(), DialError> {
    conn.write_all(payload).await.map_err(upstream_unavailable)
}

/// Maps a [`DialError`] to the appropriate `PACKET_SOCKS5_*`/`PACKET_STREAM_*`
/// failure packet type for the caller to send back to the client.
pub fn map_socks_connect_error(err: &DialError) -> u8 {
    match err {
        DialError::Blocked(_) => enums::PACKET_SOCKS5_RULESET_DENIED,
        DialError::Upstream { packet_type, .. } => *packet_type,
        DialError::Io(e) => match e.kind() {
            std::io::ErrorKind::TimedOut => enums::PACKET_SOCKS5_TTL_EXPIRED,
            std::io::ErrorKind::ConnectionRefused => enums::PACKET_SOCKS5_CONNECTION_REFUSED,
            _ => enums::PACKET_SOCKS5_NETWORK_UNREACHABLE,
        },
        DialError::Cancelled => enums::PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_private_and_loopback() {
        assert!(validate_socks_target_host("127.0.0.1").is_err());
        assert!(validate_socks_target_host("10.0.0.5").is_err());
        assert!(validate_socks_target_host("192.168.1.1").is_err());
        assert!(validate_socks_target_host("169.254.1.1").is_err());
        assert!(validate_socks_target_host("localhost").is_err());
        assert!(validate_socks_target_host("foo.localhost").is_err());
        assert!(validate_socks_target_host("100.64.0.1").is_err());
        assert!(validate_socks_target_host("198.18.0.1").is_err());
    }

    #[test]
    fn allows_public_ip_and_domain() {
        assert!(validate_socks_target_host("8.8.8.8").is_ok());
        assert!(validate_socks_target_host("example.com").is_ok());
    }
}
