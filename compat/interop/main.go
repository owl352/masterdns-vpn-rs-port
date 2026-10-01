// Interop runner: drives the real Go client against a server binary (the Rust
// port, or the Go server as a reference) and checks that data arrives intact.
//
// Every scenario verifies SHA-256 of all bytes moved, and that the server
// exits on SIGTERM afterwards (a stuck server means a deadlock). Scenarios can
// run through an impairment proxy that drops, duplicates and reorders UDP
// datagrams. The "load" scenarios report server CPU and memory per query.
//
//	go run . -server-bin <path> -client-bin <path> [-scenarios all] [-json out.json]
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const tunnelDomain = "t.compat.test"

type Impair struct {
	Drop, Dup, Reorder      float64
	ReorderDelay            time.Duration
	RTT, Jitter             time.Duration
	BurstEvery, BurstLength time.Duration
}

type Scenario struct {
	Run     int // log directory suffix when repeating
	Name    string
	Mode    string // "TCP" or "SOCKS5"
	Work    string // "upload", "download", "echo"
	Method  int    // DATA_ENCRYPTION_METHOD
	Clients int    // client processes = sessions
	Streams int    // concurrent streams per client (echo only)
	Bytes   int    // bytes per stream and direction
	Impair  *Impair
	Load    bool // report CPU/memory per query
}

type Result struct {
	Scenario             string    `json:"scenario"`
	Pass                 bool      `json:"pass"`
	Error                string    `json:"error,omitempty"`
	Seconds              float64   `json:"seconds"`
	MiBps                float64   `json:"mib_s"`
	CleanShutdown        bool      `json:"clean_shutdown"`
	ServerCPU            float64   `json:"server_cpu_s,omitempty"`
	ServerRSSKB          int       `json:"server_rss_kb,omitempty"`
	Queries              int64     `json:"queries,omitempty"`
	CPUPerQueryUs        float64   `json:"cpu_per_query_us,omitempty"`
	LogErrors            int       `json:"server_log_errors"`
	DownloadP10Mbps      float64   `json:"download_p10_mbps,omitempty"`
	DownloadMedianMbps   float64   `json:"download_median_mbps,omitempty"`
	LongestDeliveryGapMs float64   `json:"longest_delivery_gap_ms,omitempty"`
	DownloadSamplesMbps  []float64 `json:"download_samples_mbps,omitempty"`
}

var (
	sustained   = flag.Duration("sustained", 0, "generate continuous download traffic for this duration instead of fixed bytes")
	repeat      = flag.Int("repeat", 1, "repeat selected scenarios with fresh server/client sessions")
	serverBin   = flag.String("server-bin", "", "server binary under test (Rust port or Go reference)")
	clientBin   = flag.String("client-bin", "", "Go client binary")
	scenarios   = flag.String("scenarios", "all", "comma-separated scenario names, 'all', 'quick' or 'load'")
	workDir     = flag.String("work", "", "directory for configs and logs (default: temp)")
	socksHost   = flag.String("socks-host", "", "hostname the SOCKS5 tests connect to; must resolve to this machine and not be an IP literal (default: <LocalHostName>.local or $COMPAT_SOCKS_HOST)")
	jsonOut     = flag.String("json", "", "write results as JSON to this file")
	scale       = flag.Float64("scale", 1, "multiply transfer sizes")
	timeoutSec  = flag.Int("timeout", 180, "per-scenario timeout in seconds")
	logLevel    = flag.String("log-level", "INFO", "LOG_LEVEL for the server and clients")
	pathRTT     = flag.Duration("path-rtt", 0, "simulated RTT, each direction gets half")
	pathJitter  = flag.Duration("path-jitter", 0, "additional random one-way delay")
	pathLoss    = flag.Float64("path-loss", 0, "independent datagram loss probability")
	burstEvery  = flag.Duration("burst-every", 0, "period between simulated loss bursts")
	burstLength = flag.Duration("burst-length", 0, "duration of simulated loss bursts")
	allowSkip   = flag.Bool("allow-skip", false, "do not count scenarios skipped for lack of a SOCKS host as failures")
)

func allScenarios() []Scenario {
	mib := func(n float64) int { return int(n * 1024 * 1024 * *scale) }
	lossy := &Impair{Drop: 0.03, Dup: 0.02, Reorder: 0.05, ReorderDelay: 15 * time.Millisecond}
	return []Scenario{
		{Name: "tcp-upload", Mode: "TCP", Work: "upload", Method: 1, Clients: 1, Streams: 1, Bytes: mib(8)},
		{Name: "tcp-download", Mode: "TCP", Work: "download", Method: 1, Clients: 1, Streams: 1, Bytes: mib(32)},
		{Name: "tcp-download-aes", Mode: "TCP", Work: "download", Method: 5, Clients: 1, Streams: 1, Bytes: mib(8)},
		{Name: "socks-echo-multi", Mode: "SOCKS5", Work: "echo", Method: 2, Clients: 1, Streams: 8, Bytes: mib(1)},
		{Name: "tcp-upload-lossy", Mode: "TCP", Work: "upload", Method: 1, Clients: 1, Streams: 1, Bytes: mib(2), Impair: lossy},
		{Name: "tcp-download-lossy", Mode: "TCP", Work: "download", Method: 1, Clients: 1, Streams: 1, Bytes: mib(4), Impair: lossy},
		{Name: "socks-echo-lossy", Mode: "SOCKS5", Work: "echo", Method: 1, Clients: 1, Streams: 4, Bytes: mib(0.5), Impair: lossy},
		{Name: "load-sessions", Mode: "SOCKS5", Work: "echo", Method: 1, Clients: 8, Streams: 4, Bytes: mib(0.5), Impair: &Impair{}, Load: true},
		{Name: "load-streams", Mode: "SOCKS5", Work: "echo", Method: 1, Clients: 1, Streams: 64, Bytes: mib(0.125), Impair: &Impair{}, Load: true},
	}
}

func pick(all []Scenario, sel string) ([]Scenario, error) {
	switch sel {
	case "all":
		return all, nil
	case "quick":
		sel = "tcp-upload,tcp-download,socks-echo-multi,tcp-download-lossy"
	case "load":
		sel = "load-sessions,load-streams"
	}
	var out []Scenario
	for _, name := range strings.Split(sel, ",") {
		found := false
		for _, s := range all {
			if s.Name == strings.TrimSpace(name) {
				out = append(out, s)
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown scenario %q", name)
		}
	}
	return out, nil
}

func main() {
	flag.Parse()
	if *serverBin == "" || *clientBin == "" {
		fmt.Fprintln(os.Stderr, "need -server-bin and -client-bin")
		os.Exit(2)
	}
	if *repeat < 1 || *sustained < 0 || *pathRTT < 0 || *pathJitter < 0 || *pathLoss < 0 || *pathLoss > 1 || *burstLength < 0 || *burstEvery < 0 || (*burstLength > 0 && (*burstEvery == 0 || *burstLength >= *burstEvery)) {
		fmt.Fprintln(os.Stderr, "invalid repeat, duration, loss or burst settings")
		os.Exit(2)
	}
	selected, err := pick(allScenarios(), *scenarios)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *workDir == "" {
		d, _ := os.MkdirTemp("", "compat-interop-")
		*workDir = d
	}
	host, hostIP := resolveSocksHost()

	var results []Result
	failed := 0
	for iteration := 0; iteration < *repeat; iteration++ {
		for _, sc := range selected {
			sc.Run = iteration + 1
			if sc.Mode == "SOCKS5" && host == "" {
				results = append(results, Result{Scenario: sc.Name, Error: "skipped: no -socks-host that resolves to this machine"})
				if *allowSkip {
					fmt.Printf("%-20s SKIP (no SOCKS host)\n", sc.Name)
				} else {
					fmt.Printf("%-20s FAIL (skipped: no SOCKS host; pass -socks-host or -allow-skip)\n", sc.Name)
					failed++
				}
				continue
			}
			bindIP := "127.0.0.1"
			if sc.Mode == "SOCKS5" {
				bindIP = hostIP
			}
			r := runScenario(sc, host, bindIP)
			results = append(results, r)
			status := "PASS"
			if !r.Pass {
				status = "FAIL"
				failed++
			}
			extra := ""
			if sc.Load {
				extra = fmt.Sprintf("  server cpu %.2fs  rss %d KB  queries %d  %.1f µs/query", r.ServerCPU, r.ServerRSSKB, r.Queries, r.CPUPerQueryUs)
			}
			fmt.Printf("%-20s %s  %6.2fs  %7.2f MiB/s  shutdown=%v  log-errors=%d%s\n", sc.Name, status, r.Seconds, r.MiBps, r.CleanShutdown, r.LogErrors, extra)
			if r.Error != "" {
				fmt.Printf("%20s   %s\n", "", r.Error)
			}
		}
	}
	if *jsonOut != "" {
		data, _ := json.MarshalIndent(results, "", "  ")
		_ = os.WriteFile(*jsonOut, append(data, '\n'), 0o644)
	}
	fmt.Printf("\n%d scenarios, %d failed. Logs: %s\n", len(results), failed, *workDir)
	if failed > 0 {
		os.Exit(1)
	}
}

// resolveSocksHost picks a hostname (not an IP literal: the server refuses
// those for loopback/private targets) that resolves to this machine, and the
// address it resolves to, which the SOCKS echo target then listens on.
// Loopback is preferred; a local interface address works too, e.g. when
// "<LocalHostName>.local" resolves to the LAN address.
func resolveSocksHost() (string, string) {
	candidates := []string{*socksHost, os.Getenv("COMPAT_SOCKS_HOST")}
	if out, err := exec.Command("scutil", "--get", "LocalHostName").Output(); err == nil {
		candidates = append(candidates, strings.TrimSpace(string(out))+".local")
	}
	candidates = append(candidates, "compat-target.test")
	for _, h := range candidates {
		if h == "" || net.ParseIP(h) != nil {
			continue
		}
		addrs, err := net.LookupHost(h)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil && ip.IsLoopback() {
				return h, ip.String()
			}
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil && isLocalAddress(ip) {
				return h, ip.String()
			}
		}
	}
	return "", ""
}

func isLocalAddress(ip net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// ---- scenario execution ----

func runScenario(sc Scenario, host, bindIP string) (res Result) {
	res.Scenario = sc.Name
	dir := filepath.Join(*workDir, sc.Name)
	if *repeat > 1 {
		dir = filepath.Join(dir, fmt.Sprintf("run-%02d", sc.Run))
	}
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		res.Error = "work dir: " + err.Error()
		return
	}

	targets := newTargets()
	targets.sourceBytes = sc.Bytes
	targets.sourceDuration = *sustained
	defer targets.close()
	targetPort, err := targets.listen(sc.Work, bindIP)
	if err != nil {
		res.Error = err.Error()
		return
	}

	serverPort := freeUDPPort()
	srvDir := filepath.Join(dir, "server")
	_ = os.MkdirAll(srvDir, 0o755)
	writeServerConfig(srvDir, sc, serverPort, targetPort)
	server, err := startProc(*serverBin, srvDir, filepath.Join(dir, "server.log"))
	if err != nil {
		res.Error = "start server: " + err.Error()
		return
	}
	defer func() {
		res.CleanShutdown = server.stop()
		res.LogErrors = countLogErrors(server.log.String())
		if res.Pass && !res.CleanShutdown {
			res.Pass = false
			res.Error = "server did not exit within 5s of SIGTERM (possible deadlock)"
		}
	}()
	key, err := waitKey(filepath.Join(srvDir, "encrypt_key.txt"))
	if err != nil {
		res.Error = err.Error() + "\n" + tail(server.log.String(), 800)
		return
	}

	resolverPort := serverPort
	var proxy *udpProxy
	if sc.Impair != nil || *pathRTT > 0 || *pathJitter > 0 || *pathLoss > 0 || *burstEvery > 0 {
		impairment := Impair{}
		if sc.Impair != nil {
			impairment = *sc.Impair
		}
		proxy, err = newUDPProxy(serverPort, impairment)
		if err != nil {
			res.Error = "proxy: " + err.Error()
			return
		}
		defer proxy.close()
		resolverPort = proxy.port
	}

	var clients []*proc
	var listenPorts []int
	for i := 0; i < sc.Clients; i++ {
		cDir := filepath.Join(dir, fmt.Sprintf("client-%d", i))
		_ = os.MkdirAll(cDir, 0o755)
		port := freeTCPPort()
		writeClientConfig(cDir, sc, key, port, resolverPort)
		c, err := startProc(*clientBin, cDir, filepath.Join(dir, fmt.Sprintf("client-%d.log", i)))
		if err != nil {
			res.Error = "start client: " + err.Error()
			return
		}
		defer c.stop()
		clients = append(clients, c)
		listenPorts = append(listenPorts, port)
	}
	for i, c := range clients {
		if err := waitFor(c.log, "Proxy server is listening", 60*time.Second); err != nil {
			res.Error = fmt.Sprintf("client-%d not ready: %v\n%s", i, err, tail(c.log.String(), 1500))
			return
		}
	}

	cpuBefore, _ := procCPUSeconds(server.cmd.Process.Pid)
	var queriesBefore int64
	if proxy != nil {
		queriesBefore = proxy.upstream.Load()
	}

	start := time.Now()
	meter := &deliveryMeter{start: time.Now(), last: time.Now()}
	moved, err := runWork(sc, targets, listenPorts, host, targetPort, meter)
	meter.finish(&res)
	res.Seconds = time.Since(start).Seconds()
	if err != nil {
		res.Error = err.Error()
		return
	}
	res.MiBps = float64(moved) / (1024 * 1024) / res.Seconds

	if sc.Load {
		cpuAfter, _ := procCPUSeconds(server.cmd.Process.Pid)
		res.ServerCPU = cpuAfter - cpuBefore
		res.ServerRSSKB, _ = procRSSKB(server.cmd.Process.Pid)
		if proxy != nil {
			res.Queries = proxy.upstream.Load() - queriesBefore
			if res.Queries > 0 {
				res.CPUPerQueryUs = res.ServerCPU * 1e6 / float64(res.Queries)
			}
		}
	}
	res.Pass = true
	return
}

func runWork(sc Scenario, t *targets, listenPorts []int, host string, targetPort int, meter *deliveryMeter) (int64, error) {
	deadline := time.Now().Add(time.Duration(*timeoutSec) * time.Second)
	switch sc.Work {
	case "upload":
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPorts[0]), 10*time.Second)
		if err != nil {
			return 0, err
		}
		defer conn.Close()
		_ = conn.SetDeadline(deadline)
		want := sha256.New()
		if err := writeStream(io.MultiWriter(conn, want), 1, sc.Bytes); err != nil {
			return 0, fmt.Errorf("upload write: %w", err)
		}
		_ = conn.(*net.TCPConn).CloseWrite()
		select {
		case got := <-t.sinkDigests:
			if got.n != int64(sc.Bytes) || got.sum != hex.EncodeToString(want.Sum(nil)) {
				return 0, fmt.Errorf("upload corrupted: target got %d bytes sha %s", got.n, got.sum)
			}
		case <-time.After(time.Until(deadline)):
			return 0, errors.New("upload: target never saw EOF")
		}
		return int64(sc.Bytes), nil

	case "download":
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPorts[0]), 10*time.Second)
		if err != nil {
			return 0, err
		}
		defer conn.Close()
		_ = conn.SetDeadline(deadline)
		got := sha256.New()
		n, err := io.Copy(io.MultiWriter(got, meter), conn)
		if err != nil {
			return 0, fmt.Errorf("download read after %d bytes: %w", n, err)
		}
		want := sha256.New()
		expected := int64(sc.Bytes)
		if *sustained > 0 {
			select {
			case sent := <-t.sinkDigests:
				expected = sent.n
				if sent.sum != hex.EncodeToString(got.Sum(nil)) {
					return n, errors.New("sustained download corrupted")
				}
			case <-time.After(time.Until(deadline)):
				return n, errors.New("sustained source digest unavailable")
			}
		}
		_ = writeStream(want, 1, int(expected))
		if n != expected || n == 0 || !bytes.Equal(got.Sum(nil), want.Sum(nil)) {
			return 0, fmt.Errorf("download corrupted: got %d of %d bytes", n, sc.Bytes)
		}
		return n, nil

	case "echo":
		var wg sync.WaitGroup
		var moved atomic.Int64
		errs := make(chan error, len(listenPorts)*sc.Streams)
		for ci, port := range listenPorts {
			for s := 0; s < sc.Streams; s++ {
				wg.Add(1)
				go func(port, seed int) {
					defer wg.Done()
					n, err := socksEcho(port, host, targetPort, seed, sc.Bytes, deadline, meter)
					moved.Add(n)
					if err != nil {
						errs <- fmt.Errorf("stream seed %d: %w", seed, err)
					}
				}(port, ci*1000+s+1)
			}
		}
		wg.Wait()
		close(errs)
		if err, ok := <-errs; ok {
			return moved.Load(), fmt.Errorf("%v (and %d more stream errors)", err, len(errs))
		}
		return moved.Load(), nil
	}
	return 0, fmt.Errorf("unknown work %q", sc.Work)
}

// socksEcho opens a SOCKS5 stream through the client, sends a seeded stream
// and checks it comes back unchanged. Returns bytes moved in both directions.
func socksEcho(port int, host string, targetPort, seed, size int, deadline time.Time, meter *deliveryMeter) (int64, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 10*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	if err := socksConnect(conn, host, targetPort); err != nil {
		return 0, err
	}
	want := sha256.New()
	writeErr := make(chan error, 1)
	go func() {
		err := writeStream(io.MultiWriter(conn, want), seed, size)
		if err == nil {
			err = conn.(*net.TCPConn).CloseWrite()
		}
		writeErr <- err
	}()
	got := sha256.New()
	n, err := io.CopyN(io.MultiWriter(got, meter), conn, int64(size))
	if err != nil {
		return n, fmt.Errorf("echo read after %d of %d bytes: %w", n, size, err)
	}
	if err := <-writeErr; err != nil {
		return n, fmt.Errorf("echo write: %w", err)
	}
	if !bytes.Equal(got.Sum(nil), want.Sum(nil)) {
		return n, errors.New("echo data corrupted")
	}
	return 2 * n, nil
}

func socksConnect(conn net.Conn, host string, port int) error {
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	var hello [2]byte
	if _, err := io.ReadFull(conn, hello[:]); err != nil {
		return fmt.Errorf("socks hello: %w", err)
	}
	if hello[1] != 0 {
		return fmt.Errorf("socks auth method %d refused", hello[1])
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fmt.Errorf("socks reply: %w", err)
	}
	if head[1] != 0 {
		return fmt.Errorf("socks CONNECT to %s:%d failed with reply code %d", host, port, head[1])
	}
	skip := map[byte]int{1: 4 + 2, 4: 16 + 2}[head[3]]
	if head[3] == 3 {
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return err
		}
		skip = int(l[0]) + 2
	}
	_, err := io.CopyN(io.Discard, conn, int64(skip))
	return err
}

// writeStream writes size deterministic bytes derived from seed.
func writeStream(w io.Writer, seed, size int) error {
	r := rand.New(rand.NewSource(int64(seed)))
	buf := make([]byte, 32*1024)
	for size > 0 {
		n := min(size, len(buf))
		r.Read(buf[:n])
		if _, err := w.Write(buf[:n]); err != nil {
			return err
		}
		size -= n
	}
	return nil
}

// ---- upstream targets the server dials ----

type digest struct {
	n   int64
	sum string
}

type targets struct {
	ln             net.Listener
	sinkDigests    chan digest
	sourceBytes    int
	sourceDuration time.Duration
}

func newTargets() *targets { return &targets{sinkDigests: make(chan digest, 16)} }

func (t *targets) listen(work, bindIP string) (int, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(bindIP, "0"))
	if err != nil {
		return 0, err
	}
	t.ln = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go t.serve(work, c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func (t *targets) serve(work string, c net.Conn) {
	defer c.Close()
	switch work {
	case "upload":
		h := sha256.New()
		n, _ := io.Copy(h, c)
		t.sinkDigests <- digest{n: n, sum: hex.EncodeToString(h.Sum(nil))}
	case "download":
		if t.sourceDuration == 0 {
			_ = writeStream(c, 1, t.sourceBytes)
			return
		}
		_ = c.SetWriteDeadline(time.Now().Add(t.sourceDuration + 30*time.Second))
		h := sha256.New()
		writer := io.MultiWriter(c, h)
		var sent int64
		defer func() { t.sinkDigests <- digest{n: sent, sum: hex.EncodeToString(h.Sum(nil))} }()
		rng := rand.New(rand.NewSource(1))
		buf := make([]byte, 32*1024)
		until := time.Now().Add(t.sourceDuration)
		for time.Now().Before(until) {
			rng.Read(buf)
			n, err := writer.Write(buf)
			sent += int64(n)
			if err != nil {
				return
			}
		}
	case "echo":
		_, _ = io.Copy(c, c)
	}
}

func (t *targets) close() {
	if t.ln != nil {
		_ = t.ln.Close()
	}
}

// ---- UDP impairment proxy ----

type udpProxy struct {
	port     int
	conn     *net.UDPConn
	server   *net.UDPAddr
	impair   Impair
	mu       sync.Mutex
	peers    map[string]*net.UDPConn
	upstream atomic.Int64 // client->server datagrams forwarded (= queries)
	closed   atomic.Bool
	rng      *rand.Rand
	rngMu    sync.Mutex
	started  time.Time
}

func newUDPProxy(serverPort int, impair Impair) (*udpProxy, error) {
	impair.RTT += *pathRTT
	impair.Jitter += *pathJitter
	impair.Drop = max(impair.Drop, *pathLoss)
	impair.BurstEvery, impair.BurstLength = *burstEvery, *burstLength
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadBuffer(8 << 20)
	_ = conn.SetWriteBuffer(8 << 20)
	p := &udpProxy{started: time.Now(), port: conn.LocalAddr().(*net.UDPAddr).Port, conn: conn, server: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: serverPort}, impair: impair, peers: map[string]*net.UDPConn{}, rng: rand.New(rand.NewSource(7))}
	go p.clientLoop()
	return p, nil
}

func (p *udpProxy) roll() float64 {
	p.rngMu.Lock()
	defer p.rngMu.Unlock()
	return p.rng.Float64()
}

// deliver applies drop/duplicate/reorder to one datagram.
func (p *udpProxy) deliver(send func([]byte), pkt []byte) {
	if p.closed.Load() {
		return
	}
	if p.impair.BurstEvery > 0 && time.Since(p.started)%p.impair.BurstEvery < p.impair.BurstLength {
		return
	}
	if p.impair.Drop > 0 && p.roll() < p.impair.Drop {
		return
	}
	copies := 1
	if p.impair.Dup > 0 && p.roll() < p.impair.Dup {
		copies = 2
	}
	for i := 0; i < copies; i++ {
		delay := p.impair.RTT/2 + time.Duration(p.roll()*float64(p.impair.Jitter))
		if p.impair.Reorder > 0 && p.roll() < p.impair.Reorder {
			delay += p.impair.ReorderDelay
		}
		if delay > 0 {
			data := append([]byte(nil), pkt...)
			time.AfterFunc(delay, func() {
				if !p.closed.Load() {
					send(data)
				}
			})
		} else {
			send(pkt)
		}
	}
}

func (p *udpProxy) clientLoop() {
	buf := make([]byte, 65535)
	for {
		n, from, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		up := p.upstreamFor(from)
		if up == nil {
			continue
		}
		p.upstream.Add(1)
		p.deliver(func(b []byte) { _, _ = up.Write(b) }, buf[:n])
	}
}

func (p *udpProxy) upstreamFor(client *net.UDPAddr) *net.UDPConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := client.String()
	if c, ok := p.peers[key]; ok {
		return c
	}
	c, err := net.DialUDP("udp", nil, p.server)
	if err != nil {
		return nil
	}
	_ = c.SetReadBuffer(8 << 20)
	p.peers[key] = c
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			p.deliver(func(b []byte) { _, _ = p.conn.WriteToUDP(b, client) }, buf[:n])
		}
	}()
	return c
}

func (p *udpProxy) close() {
	p.closed.Store(true)
	_ = p.conn.Close()
	p.mu.Lock()
	for _, c := range p.peers {
		_ = c.Close()
	}
	p.mu.Unlock()
}

// ---- processes and configs ----

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
	f  *os.File
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f != nil {
		_, _ = s.f.Write(p)
	}
	if s.b.Len() < 4<<20 {
		s.b.Write(p)
	}
	return len(p), nil
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type proc struct {
	cmd  *exec.Cmd
	log  *safeBuf
	done chan struct{}
}

func startProc(bin, dir, logPath string) (*proc, error) {
	f, _ := os.Create(logPath)
	log := &safeBuf{f: f}
	cmd := exec.Command(bin, "--config", filepath.Join(dir, "config.toml"))
	cmd.Dir = dir
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &proc{cmd: cmd, log: log, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(p.done) }()
	return p, nil
}

// stop sends SIGTERM and reports whether the process exited within 5s.
func (p *proc) stop() bool {
	select {
	case <-p.done:
		return true
	default:
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
		return true
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
		return false
	}
}

func waitKey(path string) (string, error) {
	for i := 0; i < 150; i++ {
		if b, err := os.ReadFile(path); err == nil && len(bytes.TrimSpace(b)) > 0 {
			return string(bytes.TrimSpace(b)), nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", errors.New("server never wrote its encryption key")
}

func waitFor(b *safeBuf, pattern string, timeout time.Duration) error {
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		if strings.Contains(b.String(), pattern) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %q", pattern)
}

func countLogErrors(log string) int {
	n := 0
	sc := bufio.NewScanner(strings.NewReader(log))
	for sc.Scan() {
		l := sc.Text()
		if strings.Contains(l, "[ERROR]") || strings.Contains(l, "panicked") || strings.Contains(l, "panic:") {
			n++
		}
	}
	return n
}

func tail(s string, n int) string {
	if len(s) > n {
		return "..." + s[len(s)-n:]
	}
	return s
}

func freeUDPPort() int {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		panic(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func freeTCPPort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func writeServerConfig(dir string, sc Scenario, udpPort, forwardPort int) {
	cfg := fmt.Sprintf(`PROTOCOL_TYPE = %q
UDP_HOST = "127.0.0.1"
UDP_PORT = %d
DOMAIN = [%q]
MIN_VPN_LABEL_LENGTH = 1
DATA_ENCRYPTION_METHOD = %d
ENCRYPTION_KEY_FILE = "encrypt_key.txt"
FORWARD_IP = "127.0.0.1"
FORWARD_PORT = %d
USE_EXTERNAL_SOCKS5 = false
LOG_LEVEL = %q
MAX_PACKETS_PER_BATCH = 5
ARQ_WINDOW_SIZE = 4096
ARQ_INITIAL_RTO_SECONDS = 0.25
ARQ_MAX_RTO_SECONDS = 1.0
ARQ_CONTROL_INITIAL_RTO_SECONDS = 0.25
ARQ_CONTROL_MAX_RTO_SECONDS = 1.0
SUPPORTED_UPLOAD_COMPRESSION_TYPES = [0, 1, 2, 3]
SUPPORTED_DOWNLOAD_COMPRESSION_TYPES = [0, 1, 2, 3]
SOCKET_BUFFER_SIZE = 8388608
MAX_PACKET_SIZE = 65535
`, sc.Mode, udpPort, tunnelDomain, sc.Method, forwardPort, *logLevel)
	_ = os.WriteFile(filepath.Join(dir, "config.toml"), []byte(cfg), 0o644)
}

func writeClientConfig(dir string, sc Scenario, key string, listenPort, resolverPort int) {
	mtuRetries := 0
	if sc.Impair != nil && sc.Impair.Drop > 0 {
		mtuRetries = 4
	}
	cfg := fmt.Sprintf(`PROTOCOL_TYPE = %q
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = %d
DOMAINS = [%q]
ENCRYPTION_KEY = %q
DATA_ENCRYPTION_METHOD = %d
RESOLVER_BALANCING_STRATEGY = 1
PACKET_DUPLICATION_COUNT = 1
SETUP_PACKET_DUPLICATION_COUNT = 1
MIN_UPLOAD_MTU = 100
MIN_DOWNLOAD_MTU = 1000
MAX_UPLOAD_MTU = 142
MAX_DOWNLOAD_MTU = 4000
MTU_TEST_RETRIES = %d
MTU_TEST_TIMEOUT = 1.0
MTU_TEST_PARALLELISM = 1
AUTO_REMOVE_LOW_MTU_SERVERS = false
RECHECK_INACTIVE_SERVERS_ENABLED = false
AUTO_DISABLE_TIMEOUT_SERVERS = false
ARQ_WINDOW_SIZE = 4096
ARQ_INITIAL_RTO_SECONDS = 0.25
ARQ_MAX_RTO_SECONDS = 1.0
ARQ_CONTROL_INITIAL_RTO_SECONDS = 0.25
ARQ_CONTROL_MAX_RTO_SECONDS = 1.0
DISPATCHER_IDLE_POLL_INTERVAL_SECONDS = 0.002
PING_AGGRESSIVE_INTERVAL_SECONDS = 0.05
UPLOAD_COMPRESSION_TYPE = 0
DOWNLOAD_COMPRESSION_TYPE = 0
SOCKS5_AUTH = false
LOCAL_DNS_ENABLED = false
LOG_LEVEL = %q
`, sc.Mode, listenPort, tunnelDomain, key, sc.Method, mtuRetries, *logLevel)
	_ = os.WriteFile(filepath.Join(dir, "config.toml"), []byte(cfg), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte(fmt.Sprintf("127.0.0.1:%d\n", resolverPort)), 0o644)
}

// ---- process accounting (ps works on macOS and Linux) ----

func procCPUSeconds(pid int) (float64, error) {
	if stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		// Fields after the ")" that ends the command name; utime and stime
		// are fields 14 and 15, in clock ticks (USER_HZ, 100 on Linux).
		f := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:]))
		if len(f) > 12 {
			utime, _ := strconv.ParseFloat(f[11], 64)
			stime, _ := strconv.ParseFloat(f[12], 64)
			return (utime + stime) / 100, nil
		}
	}
	out, err := exec.Command("ps", "-o", "time=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, err
	}
	return parsePSTime(strings.TrimSpace(string(out)))
}

// parsePSTime parses [[DD-]HH:]MM:SS[.ss].
func parsePSTime(s string) (float64, error) {
	days := 0.0
	if i := strings.Index(s, "-"); i >= 0 {
		d, _ := strconv.ParseFloat(s[:i], 64)
		days, s = d, s[i+1:]
	}
	parts := strings.Split(s, ":")
	total := 0.0
	for _, p := range parts {
		v, err := strconv.ParseFloat(p, 64)
		if err != nil {
			return 0, err
		}
		total = total*60 + v
	}
	return total + days*86400, nil
}

func procRSSKB(pid int) (int, error) {
	if status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				return strconv.Atoi(strings.Fields(line)[1])
			}
		}
	}
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}

// deliveryMeter measures application-delivered bytes, including idle seconds.
// Kept in the test runner; the server hot path has no instrumentation cost.
type deliveryMeter struct {
	mu          sync.Mutex
	start, last time.Time
	longest     time.Duration
	buckets     []int64
}

func (m *deliveryMeter) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if gap := now.Sub(m.last); gap > m.longest {
		m.longest = gap
	}
	m.last = now
	second := int(now.Sub(m.start) / time.Second)
	for len(m.buckets) <= second {
		m.buckets = append(m.buckets, 0)
	}
	m.buckets[second] += int64(len(b))
	return len(b), nil
}
func (m *deliveryMeter) finish(r *Result) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.LongestDeliveryGapMs = float64(m.longest) / float64(time.Millisecond)
	// Exclude the partial final second from percentiles, but retain its raw sample.
	for _, b := range m.buckets {
		r.DownloadSamplesMbps = append(r.DownloadSamplesMbps, float64(b)*8/1e6)
	}
	if len(m.buckets) < 2 {
		return
	}
	values := append([]float64(nil), r.DownloadSamplesMbps[:len(m.buckets)-1]...)
	sort.Float64s(values)
	r.DownloadP10Mbps = values[(len(values)-1)/10]
	r.DownloadMedianMbps = values[len(values)/2]
}
