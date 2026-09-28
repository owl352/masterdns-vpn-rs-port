# Compatibility suite

Guards wire compatibility between this Rust port and the original Go
MasterDnsVPN while the server's internals are restructured. Every change to
protocol, ARQ or server code should pass it.

```sh
compat/run.sh              # Rust tests, both wire directions, quick interop
compat/run.sh all          # every interop scenario
compat/run.sh all --linux  # also on Linux in Docker
```

It expects the Go checkout at `../MasterDnsVPN`; set `GO_REPO` otherwise.

## What it checks

**Wire fixtures, Go to Rust.** `compat/fixtures/go-wire.json` holds bytes
produced by the Go code: every packet type's frame, packed ACK blocks,
SESSION_ACCEPT with and without the policy block, base36 and raw base64,
ciphertexts for all six encryption methods, zstd/lz4/zlib payloads, queries
as the Go client builds them and responses as the Go server builds them.
`crates/wirecompat/tests/go_fixtures.rs` checks the Rust code against them;
queries go through the same steps the server's ingress uses.

**Wire fixtures, Rust to Go.** `wirecompat-dump` writes the same kinds of
cases built by the Rust code, including responses with full-length query
names in the new single-record TXT layout. `compat/wirefix.sh check` parses
them with the Go client's own functions.

**Interop.** `compat/interop` runs the real Go client against the server:
TCP upload and download, AES and ChaCha20, SOCKS5 with several concurrent
streams, the same through a proxy that drops 3%, duplicates 2% and reorders
5% of datagrams, and two load runs (8 sessions × 4 streams; 64 streams in
one session). Every byte is checked by SHA-256, and the server must exit
within 5 s of SIGTERM, which catches deadlocks.

`-server-bin` also accepts the Go server, which is how the runner itself was
validated and how the baselines below were taken.

## Regenerating the Go fixtures

`compat/wirefix.sh gen` rebuilds `go-wire.json` from the Go checkout. Run it
when the Go protocol code changes. The generator is compiled into the Go
module with `go build -overlay`, so nothing is written into the Go
repository. Ciphertexts use random nonces, so a regenerated file always
differs in those lines.

## Reading load results

Throughput in the load scenarios is noisy because the client processes share
the CPU with the server; the same build can vary by 2×. Compare
`cpu_per_query_us` and `server_rss_kb` instead, and on Linux.

Linux (Docker, 8 CPUs), CPU per query / RSS:

| Scenario | Go server | Rust, Phase 0 | Rust, after Phase 4 |
|---|---|---|---|
| load-sessions (8 × 4) | 11.0–12.4 µs / 318–460 MB | 8.2–8.6 µs / 26–29 MB | 6.0–7.1 µs / 26–28 MB |
| load-streams (1 × 64) | 11.6–14.3 µs / 144–216 MB | 22.4–50.5 µs / 17–19 MB | 9.1–10.5 µs / 24–27 MB |

At Phase 0 the Rust server also sent 1.4–1.9× more queries than Go for the
same 64-stream transfer: every query looked up each stream through the
session's `streams` lock, and the contended atomics took ~80% of its CPU.
Phase 4 (a cached snapshot of active streams) removed that; it now sends
about the same number of queries as Go.

## Packet-rate test

`compat/qps` floods a server with DNS queries (random labels under the tunnel
zone, so each one is parsed and answered without a session) and reports
replies per second, plus server CPU per query with `-pid` on Linux:

```sh
cd compat/qps && go run . -addr 127.0.0.1:5300 -zone t.compat.test -conns 8 -inflight 64 -pid <server pid>
```

Linux (Docker, 8 CPUs), 8 sockets × 64 queries in flight:

| Server | Replies/s | CPU per query |
|---|---|---|
| Go | 427–436k | 4.3 µs |
| Rust, one datagram per syscall (Phase 4) | 1.08–1.17M | 2.8–3.1 µs |
| Rust, `recvmmsg`/`sendmmsg` (Phase 2) | 1.49–1.57M | 1.7 µs |

## Known issue: very fast long uploads can stall

Data sequence numbers are 16 bits. When an upload runs at tens of thousands
of packets per second (loopback, 10+ MiB/s), 32,768 packets pass within one
client retransmission timeout, so a retransmission whose ACK was lost can no
longer be told apart from data that is ahead of the window. The server
re-ACKs retransmissions that are provably old (further ahead than any sender
can be), which cut the stall rate of the 8 MiB `tcp-upload` on Linux from
about 75% to about 20%, but some remain ambiguous: the stream then waits for
the client's drain timeout (120 s). The Go server has the same logic and is
only spared by being slower. Real tunnels over resolvers run at hundreds to a
few thousand packets per second, where 32,768 packets take 10+ seconds. A
real fix needs wider sequence numbers, i.e. a negotiated protocol extension.

## SOCKS5 test target

The server refuses loopback and private IP literals as SOCKS5 targets, so the
SOCKS scenarios connect to a hostname that resolves to 127.0.0.1:
`<LocalHostName>.local` on macOS, `compat-target.test` in the Linux
container (added with `--add-host`), or `-socks-host` / `$COMPAT_SOCKS_HOST`.
