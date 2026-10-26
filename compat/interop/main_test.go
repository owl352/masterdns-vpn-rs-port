package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDeliveryPercentilesIncludeIdleSeconds(t *testing.T) {
	m := &deliveryMeter{buckets: []int64{125000, 0, 375000, 900000}, longest: 200 * time.Millisecond}
	var r Result
	m.finish(&r)
	if r.DownloadP10Mbps != 0 || r.DownloadMedianMbps != 1 || r.LongestDeliveryGapMs != 200 {
		t.Fatalf("unexpected delivery metrics: %+v", r)
	}
	if len(r.DownloadSamplesMbps) != 4 {
		t.Fatal("raw samples must retain the final partial second")
	}
}

func TestSustainedSourceReportsIndependentDigest(t *testing.T) {
	source, reader := net.Pipe()
	target := newTargets()
	target.sourceDuration = 5 * time.Millisecond
	go target.serve("download", source)
	var received bytes.Buffer
	if _, err := io.Copy(&received, reader); err != nil {
		t.Fatal(err)
	}
	got := sha256.Sum256(received.Bytes())
	sent := <-target.sinkDigests
	if sent.n == 0 || sent.n != int64(received.Len()) || sent.sum != hex.EncodeToString(got[:]) {
		t.Fatalf("source and receiver disagree: %+v, bytes=%d", sent, received.Len())
	}
	var expected bytes.Buffer
	if err := writeStream(&expected, 1, received.Len()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected.Bytes(), received.Bytes()) {
		t.Fatal("continuous source must retain deterministic RNG across chunks")
	}
}

func TestProxyCopiesDelayedPacketsAndStopsAfterClose(t *testing.T) {
	p := &udpProxy{impair: Impair{RTT: 20 * time.Millisecond}}
	// Avoid using the RNG in this test's no-jitter/no-loss path.
	p.rng = rand.New(rand.NewSource(7))
	out := make(chan []byte, 1)
	data := []byte("original")
	p.deliver(func(b []byte) { out <- b }, data)
	copy(data, "modified")
	select {
	case got := <-out:
		if string(got) != "original" {
			t.Fatalf("delayed packet aliased receive buffer: %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("delayed packet missing")
	}
	p.closed.Store(true)
	p.deliver(func(b []byte) { out <- b }, data)
	select {
	case <-out:
		t.Fatal("closed proxy delivered another packet")
	case <-time.After(30 * time.Millisecond):
	}
}

func TestStressScenariosAreExplicitAndRoutineGateStaysBounded(t *testing.T) {
	all := allScenarios()
	routine, err := pick(all, "all")
	if err != nil || len(routine) != 9 {
		t.Fatalf("routine scenarios: %d, %v", len(routine), err)
	}
	stress, err := pick(all, "stress")
	if err != nil || len(stress) != 3 {
		t.Fatalf("stress scenarios: %d, %v", len(stress), err)
	}
	if stress[0].Streams != 8 || stress[0].Bytes != int(8*1024*1024**scale) {
		t.Fatal("large duplex regression size changed")
	}
}

func TestPerStreamProgressRetainsFailedTransferBytes(t *testing.T) {
	meter := &deliveryMeter{}
	stream := &streamMeter{seed: 7, last: time.Now().Add(-100 * time.Millisecond)}
	stream.Write([]byte("abc"))
	meter.recordStream(stream)
	var result Result
	meter.finish(&result)
	if len(result.StreamProgress) != 1 || result.StreamProgress[0].Bytes != 3 || result.StreamProgress[0].FirstByteMs < 90 {
		t.Fatalf("missing partial transfer progress: %+v", result)
	}
}

func TestGapMetricsDoNotCountSetupOrSuccessfulCompletionWait(t *testing.T) {
	now := time.Now()
	meter := &deliveryMeter{start: now.Add(-time.Second), last: now.Add(-time.Second)}
	meter.Write([]byte("a"))
	if meter.first < 900*time.Millisecond || meter.longest != 0 {
		t.Fatal("setup must be separate from delivery gaps")
	}
	stream := &streamMeter{seed: 1, bytes: 10, last: now.Add(-time.Second), longest: 20 * time.Millisecond, complete: true}
	meter.recordStream(stream)
	if meter.streams[0].LongestGapMs != 20 {
		t.Fatal("a completed stream must not count post-delivery wait as a gap")
	}
}

func TestResolverLaneParsing(t *testing.T) {
	lanes, err := parseResolverRTTs("0, 50ms, 200ms")
	if err != nil || len(lanes) != 3 || lanes[2] != 200*time.Millisecond {
		t.Fatalf("unexpected resolver lanes: %v, %v", lanes, err)
	}
	for _, value := range []string{"-1ms", "1ms,", "bad", strings.Repeat("1ms,", 8) + "1ms"} {
		if _, err := parseResolverRTTs(value); err == nil {
			t.Fatalf("accepted invalid lane setting %q", value)
		}
	}
}

func TestTransportEvidenceRequiresActualEnvelopeAndEveryPeer(t *testing.T) {
	active := "Transport extension v1 activated"
	envelope := "Transport extension v1 envelope received"
	if _, _, err := transportEvidence([]string{active, active}, "extended"); err == nil {
		t.Fatal("activation without data cannot prove extended transport")
	}
	if _, _, err := transportEvidence([]string{active + envelope, ""}, "extended"); err == nil {
		t.Fatal("missing peer activation cannot prove extended transport")
	}
	if activated, peers, err := transportEvidence([]string{active + envelope, active}, "extended"); err != nil || activated != 2 || peers != 1 {
		t.Fatalf("valid extended evidence rejected: %d %d %v", activated, peers, err)
	}
	if _, _, err := transportEvidence([]string{"legacy", envelope}, "legacy"); err == nil {
		t.Fatal("legacy gate ignored extended data")
	}
	if _, _, err := transportEvidence([]string{"legacy", "legacy"}, "legacy"); err != nil {
		t.Fatal(err)
	}
}

func TestDirectionalLossAndLaneDelta(t *testing.T) {
	proxy := &udpProxy{impair: Impair{QueryDrop: 1}, rng: rand.New(rand.NewSource(1))}
	before := proxy.snapshot()
	sent := 0
	proxy.deliver(func([]byte) { sent++ }, []byte("query"))
	proxy.deliverDirection(func([]byte) { sent++ }, []byte("reply"), true)
	delta := laneDelta(before, proxy.snapshot())
	if sent != 1 || delta.Queries != 1 || delta.Replies != 1 || delta.QueryDrops != 1 || delta.ReplyDrops != 0 || delta.QueryBytes != 5 || delta.ReplyBytes != 5 {
		t.Fatalf("directional loss mixed query/reply statistics: %+v, sent=%d", delta, sent)
	}
}

func TestHeldRepliesDelayOnlySelectedOrdinal(t *testing.T) {
	proxy := &udpProxy{impair: Impair{HoldReplyEvery: 2, HoldReplyFor: 20 * time.Millisecond}, rng: rand.New(rand.NewSource(1))}
	immediate := 0
	proxy.deliverDirection(func([]byte) { immediate++ }, []byte("first"), true)
	if immediate != 1 {
		t.Fatal("first reply should not be held")
	}
	start := time.Now()
	delivered := make(chan time.Duration, 1)
	proxy.deliverDirection(func([]byte) { delivered <- time.Since(start) }, []byte("held"), true)
	select {
	case elapsed := <-delivered:
		if elapsed < proxy.impair.HoldReplyFor {
			t.Fatalf("held reply arrived too early: %s", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("held reply never arrived")
	}
	proxy.deliverDirection(func([]byte) { immediate++ }, []byte("third"), true)
	if immediate != 2 {
		t.Fatal("third reply should not be held")
	}
}

func TestInjectedQueryAndReplyCopiesAreCountedSeparately(t *testing.T) {
	proxy := &udpProxy{impair: Impair{Dup: 1}, rng: rand.New(rand.NewSource(1))}
	sent := 0
	proxy.deliver(func([]byte) { sent++ }, []byte("query"))
	proxy.deliverDirection(func([]byte) { sent++ }, []byte("reply"), true)
	if sent != 4 || proxy.queryCopies.Load() != 1 || proxy.replyCopies.Load() != 1 {
		t.Fatal("proxy duplication accounting mixed directions")
	}
}

func TestDNSFailureInjectionStartsOnlyAfterHandshakeAndPreservesIDs(t *testing.T) {
	p := &udpProxy{impair: Impair{RcodeEvery: 2}}
	packet := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, 'a', 0}
	now := time.Unix(100, 0)
	if got := p.injectDNSFailure(packet, now); !bytes.Equal(got, packet) || p.dnsFailures.Load() != 0 {
		t.Fatal("handshake was impaired")
	}
	p.faultStarted.Store(now.UnixNano())
	if got := p.injectDNSFailure(packet, now); !bytes.Equal(got, packet) {
		t.Fatal("first traffic reply unexpectedly failed")
	}
	failed := p.injectDNSFailure(packet, now)
	if len(failed) != 12 || failed[0] != packet[0] || failed[1] != packet[1] || failed[3]&15 != 5 || packet[3]&15 != 0 {
		t.Fatalf("invalid error reply: %x", failed)
	}
	for _, n := range failed[4:] {
		if n != 0 {
			t.Fatal("error reply retained record counts")
		}
	}
	if p.snapshot().DNSFailures != 1 {
		t.Fatal("injection evidence was not counted")
	}
}

func TestDNSFailureBurstHasFiniteRecoveryInterval(t *testing.T) {
	p := &udpProxy{impair: Impair{RcodeBurstEvery: time.Second, RcodeBurstFor: 50 * time.Millisecond}}
	start := time.Unix(100, 0)
	p.faultStarted.Store(start.UnixNano())
	packet := []byte{0, 1, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0}
	if p.injectDNSFailure(packet, start.Add(20*time.Millisecond))[3]&15 != 5 {
		t.Fatal("burst was not injected")
	}
	if !bytes.Equal(p.injectDNSFailure(packet, start.Add(100*time.Millisecond)), packet) {
		t.Fatal("finite burst did not recover")
	}
}
