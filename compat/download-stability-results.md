# Download stability evaluation — 2026-10-01

Branch: `download-stability`. Local VCS only; no pushes or deployment. The Go
client/repository and user configuration files were not modified.

## Retained changes

| Commit | Change | Validation |
|---|---|---|
| `39a39c4` | Sustained impairment/repeat harness, independent source hashes, application delivery metrics | Go tests and race detector passed |
| `68807da` | Measure RTT below timeout floor; clamp resulting RTO | Estimator bounds and repeated samples tested |
| `2bca151` | Shared retry reservation/rollback; distinct-ACK reorder-aware early recovery; learned timeout bounds and guarded precise deadlines | ARQ tests cover duplicate/retransmitted ACKs, wrap, jitter, tail loss, burst budgets, queue failure, concurrent dequeue/ACK, stale jobs, cooldown and startup |
| `09b4c2a` | Bounded fresh-data/ACK fairness with essential-control front protection | Deterministic queue/stream tests passed |

The early-recovery signal requires four distinct later, sample-eligible ACKs
and elapsed RTT/jitter grace. Duplicate ACKs do not add evidence. Queued retries
coalesce, invalidate RTT samples, and start send age at dequeue. Retry work is
bounded per scheduler tick. Already-outstanding packets benefit from a newly
learned timeout; precise deadlines do not activate before the first valid RTT
sample. The configured RTO minimum and maximum are preserved.

## Sustained simulated-path results

Each path uses a 60-second continuously generated download, an unchanged Go
client, 1% independent datagram loss, and 0–30ms extra delay in each direction.
Handshake/setup and draining extend total elapsed time. The runner negotiates
4000-byte download MTU and an initial 250ms RTO; these **test-only settings do
not reproduce the user's 905-byte MTU/multi-resolver configuration**.

| Path | Baseline average Mbps | Corrected candidate average Mbps | Baseline p10 Mbps | Candidate p10 Mbps |
|---|---:|---:|---:|---:|
| 100ms RTT, one corrected run | 5.07 | 5.34 | 3.84 | 4.19 |
| 200ms RTT, final paired run | 5.06 | 4.95 | 3.90 | 3.68 |
| 300ms RTT, two repeated runs | 4.81 / 5.01 | 5.49 / 5.49 | 3.07 / 3.42 | 3.30 / 3.52 |

All these transfers passed hash verification. The 200ms run does not demonstrate
an improvement. Overall gains are path-dependent and sample counts are small;
these are not a promise of higher VM speed or sustained 40–50 Mbit/s.

A candidate-only 200ms test with an additional 100ms outage every 10 seconds
passed: 3.63 Mbps average, 1.57 Mbps p10, longest application delivery gap
1099ms. No matching burst-loss baseline was run, so this establishes integrity,
not comparative improvement.

### Rejected initial timing implementation

The initial candidate fell to 2.50–2.77 Mbps at 300ms while repeated baseline
runs delivered 4.81–5.01 Mbps. Isolating RTT estimation, early recovery and fairness
individually did not eliminate it. Fixing initial deadline behaviour and applying
learned RTO bounds to existing packets removed the repeatable collapse. Before
that correction, a 250ms exact deadline could retransmit before an ACK arrived
on the 300ms path; Karn exclusion then blocked RTT learning.

### Bounded poll-wait experiment: not shipped

A nonblocking 5ms waiting prototype used session-ready notifications, a global
512-poll cap, per-session 16-poll cap, cancellation guards, session identity
checks, and readiness rechecks after notification registration. Wakeup, expiry,
overflow and cancellation tests passed. Immediate Linux replies retained batch
sending; deferred replies used individual sends.

One paired 100ms test measured 4.92 → 5.35 Mbps download and 40.91 → 41.18 Mbps
aggregate duplex, with no delivery-gap improvement (download 365 → 366ms;
duplex 267 → 271ms). That is insufficient evidence to retain its additional
latency, tasks and state. The prototype was removed from the shipping tree;
local artifacts remain under `/tmp/download-stability-bench/deferred-*`.

## Compatibility and integrity gates

- Final `cargo test --workspace --offline`: passed.
- Final `compat/run.sh all`: all nine scenarios ran and passed; no skips.
- Rust wire output parsed by Go: all 118 cases passed. Go-to-Rust fixtures passed.
- Final `compat/linux.sh all rust`: all nine scenarios ran and passed; no skips.
- Go impairment-harness tests with `-race`: passed.
- Final 15 independent 40 MiB uploads: 15/15 passed, including SHA-256 and clean
  shutdown. Baseline comparison also passed 15/15.
- An earlier corrected-candidate upload series passed 14/15: one timeout at 45s
  waiting for upstream EOF. No hash mismatch was reported. This failure is not
  erased by the later successful series and its cause is not established.
- Extended transfers: 3/3 independently hashed 256 MiB downloads passed;
  0/3 eight-stream duplex scenarios (8 MiB per stream per direction) completed
  within 90 seconds. All three reported read timeouts, not hash mismatches,
  and clean server shutdown. One matching retained-baseline extended duplex
  scenario also timed out at 90 seconds (four streams reported read errors),
  demonstrating that the failure can occur without these changes; this does
  not establish its cause or excuse the candidate failures. A no-fairness
  candidate variant also timed out at 90 seconds, so disabling that feature
  alone did not resolve the stall. This blocks a clean all-gates-passed claim.

The final Linux packet-path CPU measurements were 8.0µs/query for
`load-sessions` and 11.8µs/query for `load-streams`, with approximately 38MB and
28MB RSS. These are individual interop samples, not a dedicated QPS regression
gate. No final standalone QPS comparison was performed.

## Remaining limits and incomplete acceptance

This work is **not fully validated for deployment** while the extended duplex
stall remains unresolved. An earlier long-upload timeout also remains relevant.
The 16-bit sequence space and ACK/pull coupling have not changed. Resolver
capacity and client polling still bound downstream throughput.

The new test runner records average/per-second delivered bytes, p10/median
throughput and longest delivery gap. It does not yet record DNS response-type
mix, recovery timing, per-stream p95 gaps, or independent multi-resolver lanes.
Multi-stream duplex was tested, but no 60–120-second multi-stream download-only
measurement was added. These approved-plan acceptance items remain incomplete.
No measured evidence supports a claim of stable 50 Mbit/s on the user's path.
