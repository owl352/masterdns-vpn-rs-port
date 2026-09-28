//! Port of `internal/domainmatcher`: matches an incoming DNS question against
//! configured tunnel domains via a reverse-label suffix trie, and classifies
//! the routing decision.

use dnsparser::{LitePacket, Question};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    FormatError,
    NoData,
    Process,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decision {
    pub action: Option<Action>,
    pub reason: &'static str,
    pub question: Question,
    pub request_name: String,
    pub base_domain: String,
    pub labels: String,
    pub question_type: u16,
}

#[derive(Default)]
struct DomainNode {
    children: HashMap<String, DomainNode>,
    domain: Option<String>,
}

pub struct Matcher {
    allowed_domains: Vec<String>,
    root: Option<DomainNode>,
    min_label_length: usize,
}

impl Matcher {
    pub fn new(domains: &[String], min_label_length: usize) -> Self {
        let normalized = normalize_domains(domains);
        let min_label_length = if min_label_length < 1 { 3 } else { min_label_length };
        let root = build_domain_trie(&normalized);

        Matcher { allowed_domains: normalized, root, min_label_length }
    }

    pub fn domains(&self) -> &[String] {
        &self.allowed_domains
    }

    pub fn matches(&self, parsed: &LitePacket) -> Decision {
        if !parsed.has_question {
            return Decision { action: Some(Action::FormatError), reason: "missing-question", ..Default::default() };
        }

        let q0 = parsed.first_question.clone();
        let request_name = normalize_parsed_domain(&q0.name);
        if request_name.is_empty() || request_name == "." {
            return Decision { action: Some(Action::FormatError), reason: "empty-qname", ..Default::default() };
        }

        let found = find_allowed_domain(&request_name, self.root.as_ref());
        let (base_domain, labels) = match found {
            None => {
                return Decision {
                    action: Some(Action::NoData),
                    reason: "unauthorized-domain",
                    question_type: q0.q_type,
                    question: q0,
                    request_name,
                    ..Default::default()
                };
            }
            Some(v) => v,
        };

        if q0.q_type != enums::DNS_RECORD_TYPE_TXT {
            return Decision {
                action: Some(Action::NoData),
                reason: "unsupported-qtype",
                question_type: q0.q_type,
                question: q0,
                request_name,
                base_domain,
                ..Default::default()
            };
        }

        if labels.is_empty() {
            return Decision {
                action: Some(Action::NoData),
                reason: "missing-vpn-labels",
                question_type: q0.q_type,
                question: q0,
                request_name,
                base_domain,
                ..Default::default()
            };
        }

        if labels.len() < self.min_label_length {
            return Decision {
                action: Some(Action::NoData),
                reason: "labels-too-short",
                question_type: q0.q_type,
                question: q0,
                request_name,
                base_domain,
                labels,
            };
        }

        Decision {
            action: Some(Action::Process),
            reason: "matched-vpn-domain",
            question_type: q0.q_type,
            question: q0,
            request_name,
            base_domain,
            labels,
        }
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().to_lowercase().trim_end_matches('.').to_string()
}

fn normalize_parsed_domain(domain: &str) -> String {
    domain.strip_suffix('.').unwrap_or(domain).to_string()
}

fn normalize_domains(domains: &[String]) -> Vec<String> {
    let mut unique = std::collections::HashSet::new();
    for domain in domains {
        let normalized = normalize_domain(domain);
        if normalized.is_empty() || normalized == "." {
            continue;
        }
        unique.insert(normalized);
    }

    let mut normalized: Vec<String> = unique.into_iter().collect();
    normalized.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    normalized
}

fn build_domain_trie(domains: &[String]) -> Option<DomainNode> {
    if domains.is_empty() {
        return None;
    }

    let mut root = DomainNode::default();
    for domain in domains {
        let mut node = &mut root;
        let bytes = domain.as_bytes();
        let mut offset = bytes.len();
        loop {
            let start = bytes[..offset].iter().rposition(|&b| b == b'.');
            let label_start = start.map(|s| s + 1).unwrap_or(0);
            let label = &domain[label_start..offset];
            node = node.children.entry(label.to_string()).or_default();
            match start {
                None => break,
                Some(s) => offset = s,
            }
        }
        node.domain = Some(domain.clone());
    }
    Some(root)
}

fn find_allowed_domain(request_name: &str, root: Option<&DomainNode>) -> Option<(String, String)> {
    let root = root?;
    if request_name.is_empty() {
        return None;
    }

    let mut node = root;
    let bytes = request_name.as_bytes();
    let mut offset = bytes.len();
    let mut matched_pos: Option<usize> = None;
    let mut base_domain = String::new();

    loop {
        let start = bytes[..offset].iter().rposition(|&b| b == b'.');
        let label_start = start.map(|s| s + 1).unwrap_or(0);
        let label = &request_name[label_start..offset];
        let child = match node.children.get(label) {
            Some(c) => c,
            None => break,
        };
        node = child;
        if let Some(domain) = &node.domain {
            base_domain = domain.clone();
            matched_pos = Some(label_start);
        }
        match start {
            None => break,
            Some(s) => offset = s,
        }
    }

    let matched_pos = matched_pos?;
    if matched_pos == 0 {
        return Some((base_domain, String::new()));
    }

    let raw_labels = &request_name[..matched_pos - 1];
    let labels = if raw_labels.contains('.') { strip_label_dots(raw_labels) } else { raw_labels.to_string() };
    Some((base_domain, labels))
}

fn strip_label_dots(labels: &str) -> String {
    labels.chars().filter(|&c| c != '.').collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnsparser::{Header, Question};

    fn matcher() -> Matcher {
        Matcher::new(&["v.example.com".to_string()], 3)
    }

    fn packet_for(name: &str, q_type: u16) -> LitePacket {
        let question = Question { name: name.to_string(), q_type, class: enums::DNSQ_CLASS_IN };
        LitePacket {
            header: Header::default(),
            questions: vec![question.clone()],
            first_question: question,
            has_question: true,
            question_end_offset: 12,
        }
    }

    #[test]
    fn matches_vpn_labels() {
        let m = matcher();
        let decision = m.matches(&packet_for("abcdefgh.v.example.com", enums::DNS_RECORD_TYPE_TXT));
        assert_eq!(decision.action, Some(Action::Process));
        assert_eq!(decision.base_domain, "v.example.com");
        assert_eq!(decision.labels, "abcdefgh");
    }

    #[test]
    fn multi_label_prefix_gets_dots_stripped() {
        let m = matcher();
        let decision = m.matches(&packet_for("aaa.bbb.ccc.v.example.com", enums::DNS_RECORD_TYPE_TXT));
        assert_eq!(decision.action, Some(Action::Process));
        assert_eq!(decision.labels, "aaabbbccc");
    }

    #[test]
    fn unauthorized_domain_rejected() {
        let m = matcher();
        let decision = m.matches(&packet_for("abcdefgh.evil.com", enums::DNS_RECORD_TYPE_TXT));
        assert_eq!(decision.action, Some(Action::NoData));
        assert_eq!(decision.reason, "unauthorized-domain");
    }

    #[test]
    fn wrong_qtype_rejected() {
        let m = matcher();
        let decision = m.matches(&packet_for("abcdefgh.v.example.com", enums::DNS_RECORD_TYPE_A));
        assert_eq!(decision.reason, "unsupported-qtype");
    }

    #[test]
    fn bare_domain_has_no_labels() {
        let m = matcher();
        let decision = m.matches(&packet_for("v.example.com", enums::DNS_RECORD_TYPE_TXT));
        assert_eq!(decision.reason, "missing-vpn-labels");
    }

    #[test]
    fn labels_too_short_rejected() {
        let m = matcher();
        let decision = m.matches(&packet_for("ab.v.example.com", enums::DNS_RECORD_TYPE_TXT));
        assert_eq!(decision.reason, "labels-too-short");
    }

    #[test]
    fn missing_question_is_format_error() {
        let m = matcher();
        let empty = LitePacket::default();
        let decision = m.matches(&empty);
        assert_eq!(decision.action, Some(Action::FormatError));
        assert_eq!(decision.reason, "missing-question");
    }
}
