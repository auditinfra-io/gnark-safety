#!/usr/bin/env bash
# Refuses to release a tag that CHANGELOG.md does not describe.
#
#   scripts/release-preflight.sh vX.Y.Z [CHANGELOG]
#
# The tag must be a semantic version, and the changelog must contain a
# non-empty "## [X.Y.Z]" section, so every published release says what
# changed. The version itself comes from the tag at build time, so there is
# no manifest to fall out of step with it.
set -euo pipefail

tag="${1:?usage: release-preflight.sh vX.Y.Z [CHANGELOG]}"
changelog="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/CHANGELOG.md}"

if ! [[ "$tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?)$ ]]; then
  echo "release-preflight: tag must look like vX.Y.Z, got '$tag'" >&2
  exit 1
fi
version="${BASH_REMATCH[1]}"

# Print the body of the version's section: lines after its heading up to the
# next "## " heading, ignoring blank lines.
body="$(awk -v heading="## [$version]" '
  index($0, heading) == 1 { inside = 1; next }
  inside && /^## / { exit }
  inside && NF { print }
' "$changelog")"

if [ -z "$body" ]; then
  echo "release-preflight: $changelog has no non-empty '## [$version]' section; move the Unreleased notes under it before tagging $tag" >&2
  exit 1
fi
echo "release-preflight: $tag is described in $(basename "$changelog")"
