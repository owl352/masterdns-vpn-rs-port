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
