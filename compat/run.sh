#!/usr/bin/env bash
# Phase 0 compatibility suite, in one command.
#
#   compat/run.sh [scenarios] [--linux]
#
#   scenarios   interop scenarios: quick (default), all, load, or a comma list
#   --linux     also run the same scenarios on Linux in Docker (compat/linux.sh)
#
# Needs: cargo, go, and the Go MasterDnsVPN checkout at $GO_REPO
# (default ../MasterDnsVPN next to this repository).
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
export GO_REPO=$(cd "${GO_REPO:-$ROOT/../MasterDnsVPN}" && pwd)
SCENARIOS=quick
LINUX=0
for arg in "$@"; do
  case "$arg" in
    --linux) LINUX=1 ;;
    *) SCENARIOS=$arg ;;
  esac
done
WORK=$(mktemp -d "${TMPDIR:-/tmp}/masterdns-compat.XXXXXX")
echo "work dir: $WORK"

step() { printf '\n== %s\n' "$*"; }

step "1/4 Rust tests (includes Go wire fixtures -> Rust)"
(cd "$ROOT" && cargo test --workspace -q 2>&1 | grep -E 'test result|FAILED|panicked|error' | sort | uniq -c)
(cd "$ROOT" && cargo test --workspace -q >/dev/null 2>&1) || { echo "Rust tests failed"; exit 1; }

step "2/4 Rust wire output -> parsed by the Go client's code"
(cd "$ROOT" && cargo run -q -p wirecompat --bin wirecompat-dump -- "$WORK/rust-wire.json" >/dev/null)
"$HERE/wirefix.sh" check "$WORK/rust-wire.json"

step "3/4 building release server, Go client and interop runner"
(cd "$ROOT" && cargo build --release -q -p masterdnsvpn-server)
(cd "$GO_REPO" && go build -o "$WORK/go-client" ./cmd/client)
(cd "$HERE/interop" && go build -o "$WORK/interop-runner" .)

step "4/4 interop: Go client -> Rust server ($SCENARIOS)"
"$WORK/interop-runner" -server-bin "$ROOT/target/release/masterdnsvpn-server" -client-bin "$WORK/go-client" \
  -scenarios "$SCENARIOS" -work "$WORK/interop-logs" -json "$WORK/interop.json"

if [ "$LINUX" = 1 ]; then
  step "linux: same scenarios in Docker"
  "$HERE/linux.sh" "$SCENARIOS" rust
fi

printf '\nAll compatibility checks passed.\n'
