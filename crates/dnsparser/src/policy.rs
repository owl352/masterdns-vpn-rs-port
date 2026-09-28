//! Port of `internal/dnsparser/policy.go`.

pub fn is_supported_tunnel_dns_query(q_type: u16, q_class: u16) -> bool {
    if q_class != enums::DNSQ_CLASS_IN {
        return false;
    }

    matches!(
        q_type,
        enums::DNS_RECORD_TYPE_A
            | enums::DNS_RECORD_TYPE_AAAA
            | enums::DNS_RECORD_TYPE_CNAME
            | enums::DNS_RECORD_TYPE_MX
            | enums::DNS_RECORD_TYPE_NS
            | enums::DNS_RECORD_TYPE_PTR
            | enums::DNS_RECORD_TYPE_SRV
            | enums::DNS_RECORD_TYPE_SVCB
            | enums::DNS_RECORD_TYPE_CAA
            | enums::DNS_RECORD_TYPE_NAPTR
            | enums::DNS_RECORD_TYPE_SOA
            | enums::DNS_RECORD_TYPE_HTTPS
            | enums::DNS_RECORD_TYPE_TLSA
    )
}
