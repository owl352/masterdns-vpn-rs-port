# Software stall recovery — 2026-10-01

Branch: `stall-recovery`, based on `download-stability` at `b4e70c2`.
Original Go client and Go checkout unchanged; no user configuration edits,
wire changes, pushes or deployment.

## Confirmed cause of the large duplex stall

The previous large duplex gate failed three out of three times at 90 seconds.
The retained baseline also failed. The problematic rule was in
`run_gap_recovery_watchdog`: recovery required the entire stream to be idle
for `data_nack_repeat_interval`. Continued ACK/control traffic updated
`last_activity`, indefinitely suppressing NACKs for an unresolved receive hole.

An isolated variant restored **only that suppression rule**, keeping the other
fixes. Its eight-stream duplex transfer timed out at 90 seconds. Opt-in
snapshots showed affected streams with 8,192 packets buffered behind a missing
sequence, no writer progress, no outbound backlog and `nack_pending=0`.
Examples included receive sequence positions 22,812, 31,228 and 39,915.
This distinguishes the stalled receive direction from an upstream write block,
missing downstream query or a pending EOF handshake.

The fixed watchdog uses the existing per-hole initial delay and repeat
cooldown; unrelated activity no longer suppresses recovery. A first 15-run
series after the initial receive/EOF fixes passed all large duplex transfers
in approximately 10–15 seconds and all 15 large EOF uploads.

## Software defects fixed

| Defect | Fix and regression evidence |
|---|---|
| Active traffic suppresses receive-hole recovery | Recover independently of general stream activity. Deterministic test failed before the fix; isolated large-duplex rollback reproduced the 90-second timeout. |
| Watchdog requests future, unobserved sequences | Restrict NACK candidates to holes preceding actually buffered data. Before the fix, receiving sequence 1 caused requests for 0,2,3,4,5,6,7 rather than only 0. Wrap and enqueue-failure cooldown tests included. |
| EOF shuts down a writer behind a receive hole | Require the receive buffer to be drained, not merely lacking a contiguous prefix. Test delivers exact `helloworld` after a delayed missing first packet, then EOF. |
| Checked-out writer consumes shutdown request without shutdown | Obtain writer ownership first; mark shutdown complete only after success. Cancellation/timeout do not restore a closed writer. Ownership and stuck-shutdown tests included. |
| Graceful finalization clears unacknowledged outbound data | Require the send buffer to be drained before finalizing remote EOF. Deterministic test failed before the fix. |
| Successful writes do not reset the timeout/transient budget | Count consecutive failures, reset on byte progress. An intermittently backpressured writer previously stalled/failed; now delivers all bytes. |
| Initial tracked control enqueue calls the queue while holding the ARQ lock | Reserve tracking first and enqueue outside the state lock, allowing synchronous/concurrent dequeue and ACK. Failed enqueue remains retryable without a false RTT sample. |
| Control retry overwrites a concurrent dequeue | Reserve before enqueue, invalidate retransmission RTT samples, roll back only the still-owned reservation on failure. The deterministic concurrent-dequeue test failed before the fix. ACKed or stale controls are retired from the server queue. |

Additional exact-delivery tests cover two complete 16-bit sequence wraps,
duplicate packets, wrapping receive holes, failed NACK enqueue and cooldown,
control ACK/retry races, cancellation and stale control-queue cleanup.
These tests do not prove that arbitrary ancient identical packets can always
be distinguished within the unchanged 16-bit wire protocol.

## Local commits

- `799d6d0`: receive-hole, writer/EOF and control transmission fixes with regressions.
- `3b5545c`: named stress cases, per-stream failure progress, opt-in bounded metadata snapshots.
- `e519505`: stress documentation and server control-queue cleanup test.

Diagnostics are disabled by default. `MASTERDNS_STALL_DIAGNOSTICS=1` enables
one metadata snapshot per stream every two seconds. No payloads or encryption
keys are logged. Large tests are explicit (`-scenarios stress`); the ordinary
`all` selector remains the nine routine scenarios.

## Verification notes

One intermediate validation series was intentionally stopped because a
comparison build reused its mutable binary path. It is excluded from final
acceptance. Final repetitions use an immutable copy of the shipping binary;
the isolated watchdog variant uses a separate immutable file.

Test source uses only generated, disposable test configuration. Simulated
path settings are not the user's real mixed-resolver configuration. Integrity
stress and cross-platform checks may overlap; their throughput numbers are
not a controlled performance benchmark or evidence of stable 50 Mbit/s.

## Final verification

| Gate | Outcome |
|---|---|
| Offline workspace tests | Passed, including 44 ARQ tests and 16 UDP server tests |
| Go runner tests with race detector | Passed |
| Rust-to-Go wire checks | 118/118 passed |
| Go-to-Rust wire fixtures | Passed |
| macOS routine Go-client scenarios | 9/9 passed |
| Final Linux routine Go-client scenarios | 9/9 passed |
| Pinned final large duplex, 8 × 8 MiB per direction | 15/15 passed; 11.33–14.36s, median 12.61s |
| Pinned final 40 MiB EOF uploads | 15/15 passed; 3.56–5.64s, median 3.67s |
| Pinned final 256 MiB downloads | 3/3 passed |
| Final Linux stress repeats | 9/9 passed: 3 duplex, 3 EOF uploads, 3 large downloads |
| Final diagnostic-enabled large duplex | Passed, 13.76s |
| Isolated rollback of watchdog fix | Expected failure at 90s; retained as cause evidence, not a shipping-gate failure |

Every successful end-to-end transfer verified SHA-256 and clean server
shutdown. Final shipping stress/path gates reported no hash corruption or
transfer timeout. The earlier failed and interrupted series remain historical
evidence; the isolated expected failure is retained in the raw results.

### Impaired-path integrity

Each RTT row includes one continuously generated 60-second download and one
eight-stream duplex scenario (1 MiB per direction per stream). Conditions:
3% independent datagram loss, 0–30ms extra one-way jitter, and an additional
100ms outage every 10 seconds. Setup and drain extend elapsed download time.

| RTT | Download | Duplex | Download average Mbps | Duplex aggregate Mbps |
|---|---|---|---:|---:|
| 100ms | Passed | Passed | 2.66 | 26.48 |
| 200ms | Passed | Passed | 2.23 | 26.41 |
| 300ms | Passed | Passed | 2.28 | 16.00 |

These validate recovery and byte integrity, not comparative bandwidth gains.
The duplex scenarios are fixed-size, **not 60-second continuous multi-stream
measurements**. The routine lossy cases additionally cover packet duplication
and reordering. No claim of stable 40–50 Mbit/s is supported by these synthetic
path runs.

### What remains outside this validation

- Resolver outages/loss cannot be prevented by the server. Recovery is bounded;
  a permanently unreachable peer terminates through the existing retry/reset
  limits, covered by a deterministic expired-data/reset-wait test.
- Arbitrarily delayed identical packets after 16-bit sequence reuse remain
  ambiguous in the legacy wire protocol. The fixes do not extend that protocol.
- Exact production multi-resolver traces, exhaustive scheduling interleavings,
  per-stream p95 statistics, continuous multi-stream download benchmarks and
  a controlled standalone QPS comparison were not run. Passing this matrix is
  evidence, not proof that no other latent defect exists.
- Integrity and cross-platform runs overlapped, so their timing/CPU numbers
  should not be treated as a controlled throughput regression study.
- Release server is built locally; nothing has been deployed or pushed.

Raw outcomes are preserved in `stall-recovery-results.json`; earlier baseline
failures remain in `download-stability-results.{md,json}`. Tests use the original
90-second large-transfer deadlines, not increased timeout allowances.


Built macOS release binary: `target/release/masterdnsvpn-server`.
SHA-256: `517d0482edc45f0a8c1f81f9061a4cf0051945726aeb4143dbf6f762734fa0bc`.
It matches the immutable binary used for the final pinned tests. Linux builds
were separately verified in Docker. `bd260a5` adds the unreachable-peer cleanup
regression without changing shipping server behaviour.
