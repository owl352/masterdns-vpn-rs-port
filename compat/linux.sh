#!/usr/bin/env bash
# Runs the interop suite on Linux inside Docker (the production OS).
#
#   compat/linux.sh [scenarios] [rust|go|both]      default: quick rust
#
# Builds Linux binaries in the official rust/golang images (cached in the
# Docker volume "masterdns-compat-cache"), then runs compat/interop in a plain
# Debian container. Sources are mounted read-only.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
GO_REPO=$(cd "${GO_REPO:-$ROOT/../MasterDnsVPN}" && pwd)
SCENARIOS=${1:-quick}
SERVERS=${2:-rust}
VOL=masterdns-compat-cache

docker volume create "$VOL" >/dev/null

echo "== building Rust server (linux)"
docker run --rm -v "$ROOT":/src:ro -v "$VOL":/cache -e CARGO_TARGET_DIR=/cache/target -e CARGO_HOME=/cache/cargo -w /src rust:1-bookworm \
  bash -c 'cargo build --release -q -p masterdnsvpn-server && mkdir -p /cache/bin && cp /cache/target/release/masterdnsvpn-server /cache/bin/rust-server'

echo "== building Go client, Go server and interop runner (linux)"
docker run --rm -v "$GO_REPO":/gosrc:ro -v "$HERE/interop":/interop:ro -v "$VOL":/cache -e GOFLAGS=-buildvcs=false -e GOPATH=/cache/gopath -e GOCACHE=/cache/gocache golang:1-bookworm \
  bash -c 'mkdir -p /cache/bin && cd /gosrc && go build -o /cache/bin/go-client ./cmd/client && go build -o /cache/bin/go-server ./cmd/server && cd /interop && go build -o /cache/bin/interop .'

run() {
  local server=$1
  echo "== interop on linux: $server server, scenarios: $SCENARIOS"
  docker run --rm --add-host compat-target.test:127.0.0.1 -v "$VOL":/cache debian:bookworm-slim \
    /cache/bin/interop -server-bin "/cache/bin/$server-server" -client-bin /cache/bin/go-client -scenarios "$SCENARIOS" -work "/tmp/interop-$server"
}

case "$SERVERS" in
  rust) run rust ;;
  go) run go ;;
  both) run go; run rust ;;
  *) echo "servers must be rust, go or both" >&2; exit 2 ;;
esac
