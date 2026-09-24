#!/usr/bin/env bash
# Scans gnark's std/ library at a given version and writes the JSON report.
#
#   scripts/canary-gnark-std.sh VERSION OUTPUT.json
#
# VERSION is a gnark module version (v0.16.3) or a ref such as master. The
# scan runs in a throwaway module that requires only gnark, so the result
# does not depend on this repository's dependency graph. Paths in the report
# are relative to the gnark module root. GNARK_SAFETY names the analyzer
# binary; by default it is built from this checkout.
set -euo pipefail

version="${1:?usage: canary-gnark-std.sh VERSION OUTPUT.json}"
output="${2:?usage: canary-gnark-std.sh VERSION OUTPUT.json}"
if ! [[ "$version" =~ ^[0-9A-Za-z._+-]+$ ]]; then
  echo "canary: invalid version '$version'" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="$(cd "$(dirname "$output")" && pwd)/$(basename "$output")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

analyzer="${GNARK_SAFETY:-}"
if [ -z "$analyzer" ]; then
  analyzer="$work/gnark-safety"
  (cd "$root" && go build -o "$analyzer" ./cmd/gnark-safety)
fi

cd "$work"
go mod init canary >/dev/null 2>&1
go get "github.com/consensys/gnark/std/...@$version" >/dev/null
gnark_dir="$(go list -m -f '{{.Dir}}' github.com/consensys/gnark)"
resolved="$(go list -m -f '{{.Version}}' github.com/consensys/gnark)"
echo "canary: scanning github.com/consensys/gnark/std/... at $resolved" >&2

"$analyzer" scan --format json --fail-on none --relative-to "$gnark_dir" \
  --max-hints 100000 --timeout 10m github.com/consensys/gnark/std/... > "$output"
