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

## Latest recovery-efficiency evaluation

See [recovery efficiency results](recovery-efficiency-results.md) for bounded
ACK work, timer coalescing, intentional duplication accounting, mixed-path
comparisons and remaining pause/runtime validation limits. Raw results are in
`recovery-efficiency-results.json`.

The runner accepts test-only `-client-dup`, `-client-setup-dup`, `-batch`,
`-window`, `-download-mtu`, `-compression`, `-rto` and `-max-rto` flags.
`-slow-rtt` / `-slow-share` assign reproducible slow groups by DNS id, applying
the same group to request and response. These approximate mixed delays, not
independent public resolver caches. Default routine settings are unchanged.
No user configuration files are modified.

Current `first_delivery_ms` / per-stream `first_byte_ms` separate setup from
mid-transfer gaps. Failed/incomplete streams retain their final read wait;
successful streams do not count post-delivery upload-completion wait as a gap.
Older result files use the previous accounting, as documented in their reports.

## Sustained path and integrity tests

See [the software stall recovery results](stall-recovery-results.md) for the
confirmed duplex-stall cause, fixes and final passing stress gates. Raw outcomes
are in `stall-recovery-results.json`. The [earlier stability evaluation](download-stability-results.md)
preserves the initial measurements, rejected experiments and failed gates.

The interop runner can simulate RTT, jitter, loss and short loss bursts without
changing the real client's code or any user configuration. It generates its
own throwaway test configurations, as with the original scenarios.

```sh
cd compat/interop
go build -o /tmp/interop .
/tmp/interop -server-bin <server> -client-bin <unchanged-go-client> \
  -scenarios tcp-download -sustained 60s -timeout 100 \
  -path-rtt 200ms -path-jitter 30ms -path-loss 0.01 \
  -repeat 3 -work /tmp/path-run -json /tmp/path-run.json

# Short repeated outages, optional in the same command:
# -burst-every 10s -burst-length 100ms

# 15 independent 40 MiB uploads (tcp-upload is 8 MiB before scaling):
/tmp/interop -server-bin <server> -client-bin <unchanged-go-client> \
  -scenarios tcp-upload -scale 5 -repeat 15 -timeout 90 \
  -work /tmp/upload-integrity -json /tmp/upload-integrity.json
```

`-sustained` controls continuous **download source generation**, not total
scenario duration: connection setup and draining in-flight bytes add time.
The source reports an independent byte count and SHA-256; the receiver also
checks the deterministic byte stream. Repeat logs use separate `run-NN`
directories. Timeouts and corruptions are failures, never successful speed
samples.

JSON includes application-delivered per-second Mbps, p10 and median goodput
(including idle seconds, excluding the final partial second from percentiles),
and the longest observed gap between application deliveries. First-byte latency is reported separately from mid-transfer gaps. These are not resolver throughput, DNS response-type
counts, or per-stream p95 pause statistics. Run alternatives sequentially and
alternate their order; concurrent performance runs contaminate comparisons.
The delay proxy uses a deterministic random seed, but thread scheduling and
packet order mean it does not produce an identical loss trace across runs.
`-path-jitter` adds a uniformly distributed extra delay to each direction;
it approximates mixed path delays, not several independently balanced resolvers.

## Stall recovery stress gate

The ordinary `all` selector remains the nine routine scenarios. Use `stress`
for the expensive regression cases, or select them individually:

```sh
/tmp/interop -server-bin <server> -client-bin <unchanged-go-client> \
  -scenarios stress-duplex,stress-upload-eof -repeat 15 -timeout 90 \
  -work /tmp/stall-stress -json /tmp/stall-stress.json
/tmp/interop -server-bin <server> -client-bin <unchanged-go-client> \
  -scenarios stress-download -repeat 3 -timeout 90
```

- `stress-duplex`: eight simultaneous SOCKS streams, 8 MiB per direction per
  stream, including upload half-close.
- `stress-upload-eof`: 40 MiB upload verified at the upstream target, including
  delivery of EOF.
- `stress-download`: 256 MiB download, verified independently.

Duplex JSON includes `stream_progress`: delivered bytes and longest delivery
pause per stream, retaining partial progress on failure. The final read wait
is included, so a stalled stream's timeout is visible rather than hidden by
successful activity on other streams. These gaps include setup and are not
pure ARQ RTT measurements.

For a local diagnostic run only, `MASTERDNS_STALL_DIAGNOSTICS=1` enables
metadata snapshots every two seconds per stream. They contain sequence/buffer
counts, retry state and close/write flags, never payloads or keys. Diagnostics
are off by default and require no configuration-file edits. Use a retained,
immutable copy of each benchmark binary: rebuilding a binary while a runner
starts fresh processes can mix variants and invalidates the comparison.

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
SOCKS scenarios connect to a hostname instead: `-socks-host` /
`$COMPAT_SOCKS_HOST`, else `<LocalHostName>.local` on macOS, else
`compat-target.test` (added with `--add-host` in the Linux container). The
name must resolve to this machine: loopback is preferred, a local interface
address also works (the echo target then listens on that address for the
duration of the scenario, reachable from the local network). If no such name
is found, the SOCKS scenarios fail rather than being silently skipped; pass
`-allow-skip` to the runner to accept that.
