#!/usr/bin/env bash
# Builds release archives of gnark-safety and a checksum file.
#
#   scripts/build-release.sh vX.Y.Z OUTPUT_DIR
#
# Builds are reproducible for a given Go toolchain: -trimpath, no cgo, no VCS
# stamping (the version comes from the tag), and archives with fixed
# timestamps, ownership, and entry order. SOURCE_DATE_EPOCH sets the archive
# timestamps (default: the HEAD commit time). PLATFORMS overrides the
# space-separated GOOS/GOARCH list.
set -euo pipefail

version="${1:?usage: build-release.sh vX.Y.Z OUTPUT_DIR}"
out="${2:?usage: build-release.sh vX.Y.Z OUTPUT_DIR}"
if ! [[ "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))(\.((0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)))*)?(\+([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?$ ]]; then
  echo "build-release: version must look like vX.Y.Z, got '$version'" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
epoch="${SOURCE_DATE_EPOCH:-$(git -C "$root" show -s --format=%ct HEAD)}"
platforms="${PLATFORMS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64}"
ldflags="-s -w -X github.com/auditinfra-io/gnark-safety/internal/version.override=$version"

mkdir -p "$out"
out="$(cd "$out" && pwd)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

archives=()
for platform in $platforms; do
  goos="${platform%/*}"
  goarch="${platform#*/}"
  name="gnark-safety_${version#v}_${goos}_${goarch}"
  exe="gnark-safety"
  if [ "$goos" = windows ]; then
    exe="gnark-safety.exe"
  fi
  mkdir -p "$stage/$name"
  (cd "$root" && CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$stage/$name/$exe" ./cmd/gnark-safety)
  cp "$root/LICENSE" "$root/README.md" "$root/CHANGELOG.md" "$stage/$name/"
  find "$stage/$name" -exec touch -h -d "@$epoch" {} +
  if [ "$goos" = windows ]; then
    archive="$name.zip"
    rm -f "$out/$archive"
    (cd "$stage" && find "$name" -type f | LC_ALL=C sort | TZ=UTC zip -q -X -@ "$out/$archive")
  else
    archive="$name.tar.gz"
    tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -C "$stage" -cf - "$name" | gzip -n -9 > "$out/$archive"
  fi
  archives+=("$archive")
done

(cd "$out" && sha256sum "${archives[@]}" > gnark-safety-binaries.sha256)
echo "build-release: wrote ${#archives[@]} archive(s) and gnark-safety-binaries.sha256 to $out"
