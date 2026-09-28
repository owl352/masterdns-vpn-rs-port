//! Port of the `DNSRecordTypeName` half of `internal/enums/dns_names.go`.

use crate::dns::*;

pub fn dns_record_type_name(q_type: u16) -> String {
    match q_type {
        DNS_RECORD_TYPE_A => "A".to_string(),
        DNS_RECORD_TYPE_AAAA => "AAAA".to_string(),
        DNS_RECORD_TYPE_CNAME => "CNAME".to_string(),
        DNS_RECORD_TYPE_MX => "MX".to_string(),
        DNS_RECORD_TYPE_NS => "NS".to_string(),
        DNS_RECORD_TYPE_PTR => "PTR".to_string(),
        DNS_RECORD_TYPE_SRV => "SRV".to_string(),
        DNS_RECORD_TYPE_SVCB => "SVCB".to_string(),
        DNS_RECORD_TYPE_CAA => "CAA".to_string(),
        DNS_RECORD_TYPE_NAPTR => "NAPTR".to_string(),
        DNS_RECORD_TYPE_SOA => "SOA".to_string(),
        DNS_RECORD_TYPE_TXT => "TXT".to_string(),
        DNS_RECORD_TYPE_HTTPS => "HTTPS".to_string(),
        other => format!("TYPE{other}"),
    }
}
