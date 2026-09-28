#!/usr/bin/env bash
# Builds compat/wirefix/main.go inside the Go module via `go build -overlay`
# (no files are written into the Go repository) and runs it.
#
#   compat/wirefix.sh gen   [out.json]   default: compat/fixtures/go-wire.json
#   compat/wirefix.sh check <in.json>
#
# GO_REPO points at the Go MasterDnsVPN checkout (default: ../MasterDnsVPN
# next to this repository).
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
GO_REPO=$(cd "${GO_REPO:-$ROOT/../MasterDnsVPN}" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/overlay.json" <<EOF
{"Replace": {"$GO_REPO/cmd/wirefix_compat_overlay/main.go": "$HERE/wirefix/main.go"}}
EOF
(cd "$GO_REPO" && go build -overlay "$WORK/overlay.json" -o "$WORK/wirefix" ./cmd/wirefix_compat_overlay)

mode=${1:-gen}
case "$mode" in
  gen) "$WORK/wirefix" gen "${2:-$HERE/fixtures/go-wire.json}" ;;
  check) "$WORK/wirefix" check "$2" ;;
  *) echo "usage: $0 gen [out.json] | check <in.json>" >&2; exit 2 ;;
esac
