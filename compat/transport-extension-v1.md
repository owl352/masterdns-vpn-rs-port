# Transport extension v1 — implementation contract

All integers are unsigned big-endian. Existing framing, session/cookie checks, encryption and legacy packet types are unchanged. SESSION_INIT remains exactly 10 bytes. Extension mode is immutable after activation; all legacy peers retain legacy mode.

## Types
- 0x38 TRANSPORT_CAPS request (SELECT or COMMIT)
- 0x39 TRANSPORT_CAPS_ACK response (SELECTED or COMMITTED)
- 0x3A STREAM_FEEDBACK: streamless, compression-capable standalone feedback
- 0x3B STREAM_ENVELOPE: stream + sequence + fragment header extensions, compression header supported but outer compression OFF when inner payload is already prepared

Add names, flag/priority/identity classification in both implementations. 0x13 packed controls retain their old 7-byte layout. The envelope's inner data kind is only legacy DATA (0x0F) or RESEND (0x12); envelope nesting is forbidden.

## Offer and activation
Append an offer only after the unchanged normal 20-byte SESSION_ACCEPT payload, and only if the final encoded response fits the tested path budget:

`magic[4]="MDX1" | length:u16=14 | version:u8=1 | features:u8=7 | nonce:u64 | feedbackBudget:u16 | serialSpan:u16`

Features: bit0 selective feedback, bit1 data envelope, bit2 explicit repair ranges. The initial v1 implementation requires the complete feature profile 7: select 7 only when all three bits are offered and supported, otherwise stay legacy. Subset SELECTs and SELECTs containing unknown/unoffered bits are rejected without activation. Unknown offer bits are ignored, never selected. feedbackBudget is the maximum cleartext standalone feedback payload that fits both directions after the existing wire/crypto/base encoding; serialSpan is at most 16,384 and bounded by both endpoints' effective receive capacity (twice their clamped ARQ window). The existing outstanding send-buffer count limit is unchanged; negotiation must not halve the receive/reorder buffer merely by equating serial span with send-window count. Minimum feedback budget is 14 bytes (version/count + one record + one range). Too-small paths use legacy mode before activation.

Caps payload (exactly 15 bytes):
`version:u8=1 | op:u8 | features:u8 | nonce:u64 | feedbackBudget:u16 | serialSpan:u16`

Ops: SELECT=1, SELECTED=2, COMMIT=3, COMMITTED=4.

OFFER -> SELECT -> SELECTED -> COMMIT. Server SELECT prepares RX but keeps legacy TX; COMMIT or the first valid extended request commits the selected mode. Duplicate requests replay identical decisions. Client prepares decoding before SELECT, emits extended data only after SELECTED, and retries COMMIT. Timeout before commit freezes legacy; never silently downgrade after commit. Queue initial stream starts until the client has received COMMITTED; merely enqueueing COMMIT is not sufficient, because a legacy-header SYN can overtake it across resolver lanes. A missing COMMITTED reply is retried without falling back after COMMIT. A legacy stream started while prepared freezes legacy and prevents a late activation. Bind nonce/features/budgets to the session and clear on replacement. An old server provides no offer, so a new client sends no new packet type. An old client never selects, so a new server never sends extended packets. Do not reuse stream IDs within an activated session; renew safely on exhaustion.

## Feedback payload
`version:u8=1 | recordCount:u8 | records...`

Each record:
`streamID:u16 | ackNext:u32 | sackCount:u8 | repairCount:u8 | sackRanges... | repairRanges...`

Each range: `offset:u16 | length:u16` (length > 0), relative to ackNext.

At most 8 SACK ranges and 8 repair ranges per record, at most 16 records, total bytes <= negotiated feedbackBudget. SACK ranges have offset >= 1, are ordered and disjoint, and describe positively stored data. Repair ranges may start at offset 0 and must describe observed holes whose initial/repeat recovery deadline elapsed. Ranges of each kind must be canonical, nonoverlapping, within serialSpan and checked against u32 overflow; SACK and repair ranges must not intersect. Validate the whole payload, including exact consumption, before applying any records. Missing SACK ranges are NOT repair requests. Pages may omit/rotate ranges to fit; a valid empty-range record advances cumulative ACK.

ackNext is a separate contiguous-stored logical cursor, NOT the application writer cursor. ACK only retained data. Validate feedback against dispatched logical generations, never queued/unsent data or future sequences. Maintain bounded selectively-ACKed ledger tombstones until cumulative advancement. Duplicate/stale feedback is idempotent. Explicit repair ranges reuse retry cooldown/reservation logic. Per-entry cleanup preserves RTT/Karn, queue removal, EOF/drain and backpressure semantics.

## Envelope payload
`version:u8=1 | innerKind:u8 | innerCompression:u8 | logicalSeq:u32 | feedbackLen:u16 | dataLen:u16 | feedbackBytes... | dataBytes...`

Fixed overhead is 11 bytes. feedbackLen may be zero. Nonzero feedbackBytes are a complete feedback payload. dataBytes are the selected original DATA/RESEND payload, with its original compression code. The outer sequence must equal low16(logicalSeq); stream/fragment metadata is retained in the outer header. Validate kind, compression, logical epoch, lengths and feedback before applying anything. Inflate the original data exactly once before normal ARQ delivery; preserve retransmission identity. Empty application DATA is permitted only where the existing transport permits it. Outer encryption is applied once through existing framing. No nested codecs or application metadata leakage.

Every extended data unit carries logicalSeq, including the no-feedback fallback. Assign logical sequence to the same unit tracked by existing ARQ/retransmission, not to a DNS duplicate. Keep active span below u16 half-space and stop/drain before u32 reuse. Legacy untagged data ACK/NACK cannot acknowledge/retry extended generations; legacy setup/close control ACKs retain existing handling.

## Negotiated EOF boundary

For an active transport-v1 data stream only, existing `PACKET_STREAM_CLOSE_READ` carries exactly four payload bytes: `endExclusiveLogicalSeq:u32`. Its existing control header sequence and matching `CLOSE_READ_ACK` behavior are unchanged. The logical endpoint is captured under the ARQ lock and preserved by control retries. Legacy sessions and control stream 0 keep the original empty close payload.

Validate the EOF body/session/stream and bound it to the receiver's current logical span before changing any state. Duplicate EOF with the same endpoint is idempotent; conflicting endpoints are invalid. The endpoint proves missing data below it exists, but is not itself a data sequence. Register only holes `[storedAck,end)`, reject new data at/after a known endpoint, keep bounded repair pulls alive for unresolved terminal holes, and finalize application-writer EOF only after its logical cursor reaches the endpoint. An empty receive buffer or expired data-demand lease is not sufficient to finish a stream with known missing terminal bytes. Reset/aborted writers retain their existing reset behavior.

## Scheduling and budgets
Coalesce ACK state with bounded delayed/re-ACK timers and generation tickets. Claim data/feedback non-destructively, build and check full encoded size, then commit; failed encoding/write keeps recovery possible. Reserve the minimum envelope/feedback cost in negotiated effective chunk sizing, not config. Rich feedback that will not fit remains dirty for standalone feedback; never rely on compression to create room. Maintain demand-driven DNS polling independently of ACK count. Control-only feedback is useful tunnel credit, but malformed/unnegotiated envelopes are not. Raw DNS counters and logical inner-data counters remain distinct.

## Required gates
Shared Go/Rust vectors; malformed/oversized records; no activation for legacy peers; lost/reordered SELECT/SELECTED/COMMIT; low-MTU fallback; prior-epoch feedback; queued-unsent ACK immunity; >824-packet gaps; bounded repair work and re-ACK; compression/encryption/fragmentation; integrity and EOF/duplex under independent delayed resolver lanes. Runtime interop must assert extended mode was exercised, not just that fallback transferred bytes.
