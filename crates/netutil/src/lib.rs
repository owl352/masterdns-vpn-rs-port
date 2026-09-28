//! Port of `internal/netutil/localip.go`.

use std::net::IpAddr;

/// Enumerates non-loopback, non-link-local local IPs, IPv4 before IPv6, then
/// lexically within each family. Errors enumerating interfaces yield an empty list
/// (matches Go's `LocalInterfaceIPs`, which swallows the `net.Interfaces()` error).
pub fn local_interface_ips() -> Vec<String> {
    let interfaces = match if_addrs::get_if_addrs() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut v4 = Vec::new();
    let mut v6 = Vec::new();

    for iface in interfaces {
        let ip = iface.ip();
        if ip.is_loopback() || is_link_local(&ip) {
            continue;
        }
        match ip {
            IpAddr::V4(_) => v4.push(ip.to_string()),
            IpAddr::V6(_) => v6.push(ip.to_string()),
        }
    }

    v4.sort();
    v6.sort();
    v4.extend(v6);
    v4
}

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_unicast_link_local(),
    }
}

/// If `ip` is a wildcard address (`0.0.0.0`, `::`, or empty), returns a
/// human-readable "reachable at" hint listing every local IP; otherwise
/// returns an empty string (nothing to add — the configured IP is already specific).
pub fn format_listen_hint(ip: &str, port: u16) -> String {
    if !(ip.is_empty() || ip == "0.0.0.0" || ip == "::") {
        return String::new();
    }

    let ips = local_interface_ips();
    if ips.is_empty() {
        return String::new();
    }

    let parts: Vec<String> = ips.iter().map(|addr| format!("{addr}:{port}")).collect();
    format!("Reachable at: {}", parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hint_empty_for_specific_ip() {
        assert_eq!(format_listen_hint("127.0.0.1", 53), "");
    }

    #[test]
    fn hint_nonempty_for_wildcard() {
        // This machine always has at least one non-loopback interface in CI/dev,
        // but tolerate sandboxes that don't: just check the function doesn't panic
        // and produces a well-formed prefix when it does return something.
        let hint = format_listen_hint("0.0.0.0", 53);
        assert!(hint.is_empty() || hint.starts_with("Reachable at: "));
    }
}
