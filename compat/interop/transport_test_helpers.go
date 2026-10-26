package main

import (
	"fmt"
	"strings"
	"time"
)

func parseResolverRTTs(value string) ([]time.Duration, error) {
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	if len(parts) > 8 {
		return nil, fmt.Errorf("at most 8 resolver lanes are supported")
	}
	lanes := make([]time.Duration, 0, len(parts))
	for _, part := range parts {
		rtt, err := time.ParseDuration(strings.TrimSpace(part))
		if err != nil || rtt < 0 {
			return nil, fmt.Errorf("invalid resolver RTT %q", part)
		}
		lanes = append(lanes, rtt)
	}
	return lanes, nil
}

func transportEvidence(logs []string, expected string) (activated, envelopes int, err error) {
	for _, log := range logs {
		if strings.Contains(log, "Transport extension v1 activated") {
			activated++
		}
		if strings.Contains(log, "Transport extension v1 envelope received") {
			envelopes++
		}
	}
	switch expected {
	case "auto":
	case "legacy":
		if activated != 0 || envelopes != 0 {
			err = fmt.Errorf("expected legacy transport, observed activation=%d envelope peers=%d", activated, envelopes)
		}
	case "extended":
		if activated != len(logs) || envelopes == 0 {
			err = fmt.Errorf("extended transport not exercised by all peers: activation=%d/%d envelope peers=%d", activated, len(logs), envelopes)
		}
	default:
		err = fmt.Errorf("invalid transport expectation %q", expected)
	}
	return
}

func (p *udpProxy) snapshot() LaneResult {
	return LaneResult{
		RTTMs:       float64(p.impair.RTT) / float64(time.Millisecond),
		Queries:     p.upstream.Load(),
		Replies:     p.replies.Load(),
		QueryBytes:  p.queryBytes.Load(),
		ReplyBytes:  p.replyBytes.Load(),
		QueryDrops:  p.queryDrops.Load(),
		ReplyDrops:  p.replyDrops.Load(),
		DNSFailures: p.dnsFailures.Load(),
	}
}

func laneDelta(before, after LaneResult) LaneResult {
	return LaneResult{
		RTTMs:       after.RTTMs,
		Queries:     after.Queries - before.Queries,
		Replies:     after.Replies - before.Replies,
		QueryBytes:  after.QueryBytes - before.QueryBytes,
		ReplyBytes:  after.ReplyBytes - before.ReplyBytes,
		QueryDrops:  after.QueryDrops - before.QueryDrops,
		ReplyDrops:  after.ReplyDrops - before.ReplyDrops,
		DNSFailures: after.DNSFailures - before.DNSFailures,
	}
}
