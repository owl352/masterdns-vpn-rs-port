# MasterDnsVPN (Rust rewrite)

A Rust port of [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN) — a
DNS-tunnel VPN designed to keep working under extreme censorship, tunneling
TCP/SOCKS traffic through DNS queries across multiple public resolvers with a
custom lightweight wire protocol, its own reliable-transport (ARQ) layer,
pluggable compression and encryption, multi-resolver balancing, and adaptive
MTU discovery.

**Phase 1 (protocol crates) and Phase 2 (the UDP server) are done.** The
server (`masterdnsvpn-server`) is a real, working binary — session handshake,
stream forwarding (both plain-TCP and SOCKS5 modes), and tunneled DNS
resolution all work end-to-end (see the test in
`crates/udpserver/src/tests.rs` that dials a real TCP listener and forwards
bytes through it). There is **no client yet** — `cmd-client` is still a stub;
that's Phase 3. You can't use this end-to-end without a client (the Go client
can't talk to this server — different wire encoding for the transport
internals even though the DNS-facing protocol matches).

## Status

| Crate | Ports (from Go `internal/…`) | State |
|---|---|---|
| `crates/enums` | `enums` | Done |
| `crates/basecodec` | `basecodec` | Done, byte-for-byte tested against known vectors |
| `crates/compression` | `compression` | Done — zstd/lz4/zlib + decompression-bomb guard |
| `crates/security` | `security` | Done — NONE/XOR/ChaCha20/AES-128/192/256-GCM |
| `crates/config` | `config` | Done — TOML/JSON(+base64) loading + the `Effective*()` sizing/defaulting logic, parses the real `*.toml.simple` files below |
| `crates/dnsparser` | `dnsparser` | Done — wire parse/build, TXT chunking, VPN-frame extraction |
| `crates/vpnproto` | `vpnproto` | Done — packet framing, session-accept handshake, control-block packing |
| `crates/arq` | `arq` | Done — full reliable-transport state machine (see design note below) |
| `crates/netutil`, `logger`, `socksproto`, `mlq`, `fragmentstore`, `inflight`, `domainmatcher`, `dnscache` | matching `internal/*` | Done — small support packages the server depends on |
| `crates/udpserver` + `cmd-server` | `internal/udpserver`, `cmd/server` | Done — see below for what's simplified vs. Go |
| `cmd-client` | `cmd/client`, `internal/client` | **Not started** — stub binary only (Phase 3) |

### What's simplified in the server vs. Go (all documented in-code where they live)

- **`udp_fallback.go`** (optional raw-UDP passthrough behind the `FALLBACK` config, off by default) — **not ported**.
- **`dns_tunnel.go`** (tunneled DNS-resolution-as-a-service, `PACKET_DNS_QUERY_REQ`) — ported with sequential-upstream resolution instead of Go's hedged-parallel-query strategy (same result when the first upstream is healthy; slower fallback when it isn't).
- **Deferred session runtime**: replaced Go's pinned-worker-pool + bounded-channel design with a per-`{session,stream}` `tokio::sync::Mutex` lane + `CancellationToken` tree (session → lane), matching Go's ordering and cancellation guarantees without reimplementing a worker pool tokio doesn't need. See `crates/udpserver/src/deferred.rs`.
- **No object pooling** (Go's several `sync.Pool`s for buffers/TX-packet structs) — relies on the Rust allocator.
- **No RCU-style active-stream snapshot caching** — recomputed on demand; likewise no heap-based throttled-log eviction (a plain rate-limited counter instead).
- **Stream cleanup** relies solely on the periodic sweep (`session_cleanup_loop`) rather than *also* wiring an immediate on-close callback from a background ARQ timeout — bounded extra latency (default sweep interval 30s) before a purely idle-timed-out stream's slot frees up.
- Worker replies via whichever `SO_REUSEPORT` socket a datagram arrived on, rather than Go's fixed `conns[0]` — functionally equivalent.

### `arq` design note

Go's `ARQ` keeps almost all of its logic as plain non-blocking methods behind
a single mutex, with four goroutines blocking on I/O, timers, or channels.
This port mirrors that, except that inbound data is processed inline by
`receive_data` instead of in an rx loop, so its ACK can ride the reply to the
same query. That leaves three loops in `crates/arq/src/loops.rs` (io, write,
retransmit); everything else is a synchronous `&self` method using
`std::sync::Mutex`. The server crate (`udpserver`) follows the same split:
nearly everything is a synchronous method, since a reply must be built
within the same UDP datagram's handling, and only the serve and cleanup loops
plus deferred dial/DNS-resolve work are real `async fn`s.

## Building

```sh
cargo build --workspace
cargo test --workspace
```

Every crate carries unit tests; `crates/config` parses the real
`server_config.toml.simple`/`client_config.toml.simple` files in this repo's
root, `crates/arq` has end-to-end tests against a real in-memory duplex
connection, and `crates/udpserver` has end-to-end tests that play the client
role with the already-shipped protocol crates directly — including one that
does a full SESSION_INIT→SESSION_ACCEPT handshake, a STREAM_SYN, a real
deferred TCP dial to a `tokio::net::TcpListener`, and confirms bytes sent as
`STREAM_DATA` arrive on the dialed socket.

## Running the server

```sh
cargo run -p masterdnsvpn-server -- -config server_config.toml
```

Flags: `-config <path>` (or a bare positional path), `-json <path>`,
`-json_base64 <string>`, `-log <path>`, `-genkey` (print a fresh encryption
key and exit), `-version`, `-help`.

## Reference files

`server_config.toml.simple`, `client_config.toml.simple`, and
`client_resolvers.simple` are copied verbatim from the Go repo — they're the
spec for every config field and are parsed directly by `crates/config`'s test
suite.

## License

MIT — see `LICENSE` (same license as the original Go project).
