// qps floods a DNS server with queries and reports how many replies per
// second it gets back, to measure the server's packet-rate ceiling.
//
// Each connection keeps -inflight queries outstanding and sends a new one per
// reply (or after -timeout for a lost one). Queries ask for random labels
// under -zone, so the server does real parsing and answering work without a
// tunnel session. With -pid, it also reports the server's CPU per query
// (Linux /proc only).
//
//	go run . -addr 127.0.0.1:5300 -zone t.compat.test -conns 8 -inflight 64 -duration 5s
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	addr     = flag.String("addr", "127.0.0.1:5300", "server UDP address")
	zone     = flag.String("zone", "t.compat.test", "zone the queries fall under")
	conns    = flag.Int("conns", 8, "UDP sockets (distinct source ports)")
	inflight = flag.Int("inflight", 64, "outstanding queries per socket")
	duration = flag.Duration("duration", 5*time.Second, "measurement time (after 1s warm-up)")
	timeout  = flag.Duration("timeout", 200*time.Millisecond, "resend a slot after this long without a reply")
	pid      = flag.Int("pid", 0, "server pid, to report CPU per query from /proc")
)

func query(id uint16, r *rand.Rand) []byte {
	b := make([]byte, 12, 96)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(b[4:], 1)      // QDCOUNT
	label := make([]byte, 16)
	for i := range label {
		label[i] = "abcdefghijklmnopqrstuvwxyz0123456789"[r.Intn(36)]
	}
	b = append(b, byte(len(label)))
	b = append(b, label...)
	for _, part := range strings.Split(*zone, ".") {
		b = append(b, byte(len(part)))
		b = append(b, part...)
	}
	b = append(b, 0, 0, 16, 0, 1) // root, TXT, IN
	return b
}

func cpuSeconds(p int) float64 {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", p))
	if err != nil {
		return -1
	}
	s := string(stat)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	u, _ := strconv.ParseFloat(f[11], 64)
	k, _ := strconv.ParseFloat(f[12], 64)
	return (u + k) / 100
}

func main() {
	flag.Parse()
	server, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		panic(err)
	}
	var replies atomic.Int64
	var measuring atomic.Bool
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for c := 0; c < *conns; c++ {
		conn, err := net.DialUDP("udp", nil, server)
		if err != nil {
			panic(err)
		}
		_ = conn.SetReadBuffer(4 << 20)
		wg.Add(1)
		go func(conn *net.UDPConn, seed int64) {
			defer wg.Done()
			defer conn.Close()
			r := rand.New(rand.NewSource(seed))
			var nextID uint16
			send := func() {
				nextID++
				_, _ = conn.Write(query(nextID, r))
			}
			for i := 0; i < *inflight; i++ {
				send()
			}
			buf := make([]byte, 4096)
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = conn.SetReadDeadline(time.Now().Add(*timeout))
				if _, err := conn.Read(buf); err != nil {
					send() // a reply was lost or slow: refill the slot
					continue
				}
				if measuring.Load() {
					replies.Add(1)
				}
				send()
			}
		}(conn, int64(c+1))
	}
	time.Sleep(time.Second)
	cpu0 := cpuSeconds(*pid)
	measuring.Store(true)
	start := time.Now()
	time.Sleep(*duration)
	measuring.Store(false)
	elapsed := time.Since(start).Seconds()
	cpu1 := cpuSeconds(*pid)
	close(stop)
	wg.Wait()

	n := replies.Load()
	fmt.Printf("replies/s %9.0f", float64(n)/elapsed)
	if *pid > 0 && cpu0 >= 0 && n > 0 {
		fmt.Printf("   server cpu %.2f cores   %.2f µs/query", (cpu1-cpu0)/elapsed, (cpu1-cpu0)*1e6/float64(n))
	}
	fmt.Println()
}
