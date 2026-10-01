# Recovery efficiency — 2026-10-01

Branch: `recovery-efficiency`, based on `stall-recovery` at `e92608e`.
Core commit: `d13b8a0`. Benchmark/accounting commit: `fb69d7d`.
No Go client/checkout, desktop source or user configuration changes; no
protocol/header changes, pushes or deployment. Duplication setting 2 is preserved.

## What prompted this work

The desktop capture `2026-10-01T18-44-47-466Z` showed 5,177 queries/s, 99%
answered, 1,164 RESEND arrivals/s, 56% duplicate/old **ARQ-classified data
arrivals**, and reorder gaps up to 808. The configured query duplication is 2;
the effective observed wire/build ratio was 1.25. Intentional duplication,
resolver caching/delivery and ARQ recovery can all contribute to duplicate
arrivals. These counts do not establish the number of avoidable server retries.
Incoming payload counters include duplicates and are not application goodput.
The bundled CPU profile is from the Mac client, not the Linux server.

## Retained changes

- **Bounded ACK evidence:** eligible ACKs append to a 16-entry history instead
  of scanning the whole send buffer. Only distinct, actually dispatched,
  Karn-eligible ACKs count. Sequence/creation and dispatch-time checks preserve
  wrapping/send-epoch safety; eviction may conservatively fall back to timeout.
- **Coalesced ACK-timer wakeups:** adding a later entry to an already armed
  re-ACK/fast-ACK FIFO no longer wakes recovery for every upload packet.
- **One recovery scan:** the scheduler reuses an advisory next-deadline cache
  rather than rescanning all send items just to choose its next sleep. Active
  initialized senders recheck at bounded 50ms intervals; stale cached deadlines
  can cause an extra wake, never authorize a stale resend.
- **Mixed-path repair grace:** eight time-based RTT-tail buckets cover roughly
  two seconds. Valid samples update both ordinary SRTT/variation and this
  bounded tail envelope. A burst of fast ACKs cannot immediately erase a
  recently observed slow path. Configured RTO bounds and Karn exclusion remain.
- **Shared repair cooldown:** a NACK just after a repair is retained as pending
  evidence instead of immediately causing another resend. ACK/close cancels it;
  queued repairs coalesce and deferred NACKs retain timer/timeout fallback.
- **Opt-in recovery accounting:** snapshots distinguish requested, queued,
  dequeued and coalesced retries by cause. Arrays are ordered
  `[timeout, early recovery, explicit NACK]`. Dequeue counters are ARQ dispatch
  transitions, not a guarantee of successful UDP delivery. Diagnostics remain
  disabled by default and never log payloads or keys.

The confirmed receive-hole watchdog, writer/EOF, retry reservation and control
cleanup fixes remain intact. No return to whole-stream idle-gated gap recovery.

## Direct CPU evidence

Same-host release-mode ACK benchmark, 20 rounds per send-buffer size:

| Outstanding entries | Before, ns/ACK | After, ns/ACK |
|---|---:|---:|
| 300 | 168.9 | 78.2 |
| 1,000 | 605.1 | 91.4 |
| 8,000 | 3,448.5 | 82.3 |

This isolates ACK retirement/evidence work and manually populates the send
buffer. It is **not a measurement of whole-server CPU, a production workload,
or a claim of a 6–42× server speedup**. Default workspace tests ignore this
benchmark; it was executed explicitly in release mode.

## Native Linux comparisons

The Docker engine is ARM64. Linux tests used native ARM64 servers and the
unchanged Go CLI; the delivered binary is separately Zig-built x86-64.
The baseline server was the retained cached pre-efficiency Linux build; the
candidate was built with Zig. Build-toolchain differences are a possible
confound in these end-to-end numbers. The direct ACK benchmark above used the
same host toolchain for before/after.

Two alternating baseline/final pairs used duplication 2, setup duplication 2,
batch 1, window 1,000, maximum download MTU 1,000, compression 1, initial/max RTO
1/5 seconds, fast/slow DNS-ID groups at 50/250ms RTT (20% slow) and 1% loss.
Downloads used 60 seconds of continuously generated source data; setup and
draining add elapsed time. Duplex used eight streams, 1 MiB per direction each.

| Metric | Baseline runs | Candidate runs |
|---|---|---|
| Download application goodput, Mbps | 1.31 / 1.41 | 1.56 / 1.74 |
| Download CPU/query, µs | 167.5 / 166.9 | 154.9 / 158.4 |
| Download p10, Mbps | 0.94 / 1.03 | 1.17 / 1.31 |
| Duplex aggregate goodput, Mbps | 10.14 / 9.96 | 9.97 / 11.18 |
| Duplex CPU/query, µs | 19.4 / 19.8 | 16.6 / 16.2 |

Download median goodput improved about 21%; normalized CPU/query fell about
6% for download and 16% for duplex in these small samples. Total CPU duration
need not fall when more useful data is transferred. CPU/query includes
background timer/recovery work divided by observed queries, not just request
handler cost. No actual VM server profile was captured.

### Pause accounting and limits

The first comparisons included connection setup in aggregate longest gaps,
and per-stream gaps could include waiting for successful upload completion
after all expected download bytes arrived. The runner now separates first-byte
latency from gaps between actual deliveries; final waits are retained only for
failed/incomplete streams. This changed metrics, not tunnel behaviour.

Three additional alternating duplex pairs with corrected accounting:

| Metric | Baseline | Candidate |
|---|---|---|
| Goodput, Mbps | 12.39 / 11.90 / 9.86 | 10.03 / 11.37 / 11.73 |
| CPU/query, µs | 17.7 / 18.0 / 20.2 | 15.5 / 16.6 / 13.2 |
| Longest mid-transfer aggregate gap, ms | 221.9 / 277.2 / 402.9 | 266.5 / 281.6 / 675.5 |

Median gaps were similar, but the candidate had a larger pause outlier and
slightly lower median goodput in this series. These samples **do not establish
an all-metrics/no-regression win**, improved latency, or optimal recovery policy
for every resolver mix. The strict universal pause non-regression acceptance
criterion remains unproven. This is a validated-integrity, reduced-work
candidate for the user's VM test, not a promise of uniformly higher speed.

Removing the RTT-tail component in an isolated experiment produced download
goodput of 1.34 / 1.26 Mbps and did not demonstrate an overall improvement.
That variant was not retained. Its original pause metrics still included setup,
so they cannot be compared directly to the corrected gap series.

A final diagnostic snapshot in the 1% mixed-path test recorded 8,138 original
ARQ dequeues, 107 early repair dequeues and 61 NACK repair dequeues, with no
RTO repair dequeues at that snapshot. This is about 2% repairs/original dequeues
for that experiment; **it is not a before/after comparison of the user's 56%
classified-arrival waste and excludes work after the snapshot**.

## Integrity and compatibility

- Offline workspace: passed (48 ARQ tests; one explicitly run benchmark ignored
  during the ordinary gate). Existing stall regressions remain green.
- Go runner with race detector: passed, including gap and duplicate accounting.
- Rust output parsed by Go: 118/118 passed; Go-to-Rust fixtures passed.
- macOS routine interop: 9/9 passed.
- Native ARM64 Linux routine interop: 9/9 passed.
- Final duplication-2/batch-1/profile stress: 15/15 eight-stream duplex transfers
  (8 MiB per direction per stream), 15/15 40 MiB EOF uploads, 3/3 256 MiB downloads.
  All checked SHA-256 and clean shutdown, with original 90-second deadlines.
- Additional duplication-2 mixed 50/250ms tests with 3% loss, proxy duplication,
  reordering and 100ms outages every 10 seconds: download and duplex both passed.
- No corruption or transfer timeout reported in the final candidate gates.

Test-only flags affect disposable generated configurations, not user files.
The proxy separates intentionally injected query and reply copies. The original
Go CLI lacks the desktop's patched per-resolver pacing/adaptive NACK behaviour,
and slow DNS-ID groups are not independent public resolver caches. These tests
therefore do not exactly reproduce the real client/path.

## Delivered Linux binary

Built using `cargo zigbuild --locked --release --target
x86_64-unknown-linux-gnu.2.28 -p masterdnsvpn-server`, with existing full LTO and
one codegen unit, portable CPU settings, no `target-cpu=native` from the Mac.

Path: `target/x86_64-unknown-linux-gnu/release/masterdnsvpn-server`

SHA-256: `297f562185631a7babad89738ca3ae7edcf7d400b576cadc37f81d32c4ff029c`

Cross-build and ELF architecture verification succeeded. The x86-64 runtime
smoke check did **not** complete: fetching the appropriate runtime image failed,
and a subsequent image fetch was blocked by permissions. The cached ARM64
image could not run the dynamically linked x86-64 binary because it lacked
`/lib64/ld-linux-x86-64.so.2`. Native ARM64 Linux tests validate the same source,
not execution of this exact x86-64 artifact. The user's VM remains its runtime
and production-performance check. No deployment or push was performed.

Raw results: `recovery-efficiency-results.json`. Prior failure/cause reports
remain in `stall-recovery-results.{md,json}` and `download-stability-results.*`.
