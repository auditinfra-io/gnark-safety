#!/usr/bin/env bash
# Installs gnark-safety for the GitHub Action and puts it on PATH for later
# steps. With VERSION set it installs that release; otherwise it builds the
# checkout of the action itself, so the analyzer always matches the ref named
# in `uses:`. Inputs arrive only through the environment.
set -euo pipefail

bin_dir="${RUNNER_TEMP:-$(mktemp -d)}/gnark-safety-bin"
mkdir -p "$bin_dir"

if [ -n "${VERSION:-}" ]; then
  if ! [[ "$VERSION" =~ ^(v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?|latest)$ ]]; then
    echo "::error title=gnark-safety::version must be a release such as v0.2.0, or latest"
    exit 2
  fi
  GOBIN="$bin_dir" go install "github.com/auditinfra-io/gnark-safety/cmd/gnark-safety@$VERSION"
else
  action_path="${GITHUB_ACTION_PATH:?GITHUB_ACTION_PATH is not set}"
  ldflags=""
  # Stamp the ref from `uses:` only when it is a plain ref name, so it cannot
  # smuggle extra linker flags.
  if [[ "${ACTION_REF:-}" =~ ^[0-9A-Za-z._/-]+$ ]]; then
    ldflags="-X github.com/auditinfra-io/gnark-safety/internal/version.override=$ACTION_REF"
  fi
  (cd "$action_path" && go build -trimpath -ldflags "$ldflags" -o "$bin_dir/gnark-safety" ./cmd/gnark-safety)
fi

if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$bin_dir" >> "$GITHUB_PATH"
fi
"$bin_dir/gnark-safety" --version
