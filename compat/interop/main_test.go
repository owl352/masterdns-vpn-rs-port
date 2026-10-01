package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/rand"
	"net"
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

func TestInjectedQueryAndReplyCopiesAreCountedSeparately(t *testing.T) {
	proxy := &udpProxy{impair: Impair{Dup: 1}, rng: rand.New(rand.NewSource(1))}
	sent := 0
	proxy.deliver(func([]byte) { sent++ }, []byte("query"))
	proxy.deliverDirection(func([]byte) { sent++ }, []byte("reply"), true)
	if sent != 4 || proxy.queryCopies.Load() != 1 || proxy.replyCopies.Load() != 1 {
		t.Fatal("proxy duplication accounting mixed directions")
	}
}
