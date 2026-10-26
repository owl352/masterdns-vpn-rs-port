//! Port of `internal/arq`: a QUIC-inspired reliable transport overlay
//! designed to run over DNS/UDP. See `internal/arq/arq.go` in the original Go
//! source for the reference implementation this crate ports.
//!
//! Design note: Go's `ARQ` keeps almost all of its logic as plain
//! non-blocking methods under a single mutex, with four background
//! goroutines blocking on I/O, timers, or channels. This port mirrors that
//! except for Go's rx goroutine: inbound data is processed inline by
//! `receive_data` (so its ACK can ride the reply to the same query), leaving
//! three loops in [`loops`]. Everything else is a synchronous `&self` method
//! on [`Arq`], using `std::sync::Mutex`.

/// Largest ARQ window any peer uses: the Go client and server both clamp
/// `ARQ_WINDOW_SIZE` to 8000, and [`Arq::new`] clamps to the same value. A
/// sender is therefore never more than this many sequence numbers ahead of
/// what the receiver has delivered.
pub const MAX_WINDOW_SIZE: usize = 8000;

mod arq;
mod close;
mod control;
mod data;
mod diagnostics;
mod retransmit;
mod state;
mod terminal;
mod types;
mod util;

mod loops;

#[cfg(test)]
mod tests;

pub use arq::Arq;
pub use types::{ArqLogger, CloseOptions, Config, DummyLogger, PacketEnqueuer, StreamState};

mod transport;
pub use transport::{FeedbackClaim, LogicalFeedbackStatus, LogicalRange};
