#!/usr/bin/env bash
# Runs one gnark-safety scan for the GitHub Action. It writes SARIF and
# records the exit status as step outputs; the action's later steps upload the
# SARIF and enforce the gate. Inputs arrive only through the environment.
#
# Exit status: 0 when the scan completed (whether or not it found anything at
# the gate), and the analyzer's status (2) when it could not scan, so a broken
# scan never reads as a clean one.
set -euo pipefail

gnark_safety="${GNARK_SAFETY:-gnark-safety}"
: "${SARIF_FILE:?SARIF_FILE is not set}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is not set}"

fail() {
  echo "::error title=gnark-safety::$1"
  exit 2
}

args=(scan --fail-on "${FAIL_ON:-high}" --field "${FIELD:-unknown}" --sarif-output "$SARIF_FILE")
if [ -n "${REPO_ROOT:-}" ]; then
  args+=(--relative-to "$REPO_ROOT")
fi
for pair in "include-tests:${INCLUDE_TESTS:-false}:--include-tests" \
            "include-examples:${INCLUDE_EXAMPLES:-false}:--include-examples" \
            "allow-empty:${ALLOW_EMPTY:-false}:--allow-empty"; do
  IFS=: read -r name value flag <<< "$pair"
  case "$value" in
    true) args+=("$flag") ;;
    false) ;;
    *) fail "$name must be true or false, got '$value'" ;;
  esac
done

# Split the patterns on any whitespace, including newlines from a YAML block.
patterns=()
read -r -d '' -a patterns <<< "${SCAN_PATH:-./...}" || true
if [ "${#patterns[@]}" -eq 0 ]; then
  fail "path must name at least one Go package pattern"
fi
for pattern in "${patterns[@]}"; do
  case "$pattern" in
    -*) fail "path entries must be package patterns, not flags: '$pattern'" ;;
  esac
done

rm -f "$SARIF_FILE"
set +e
"$gnark_safety" "${args[@]}" "${patterns[@]}"
status=$?
set -e

case "$status" in
  0|1)
    {
      echo "sarif-file=$SARIF_FILE"
      echo "exit-code=$status"
    } >> "$GITHUB_OUTPUT"
    ;;
  *)
    echo "exit-code=$status" >> "$GITHUB_OUTPUT"
    echo "::error title=gnark-safety::the scan did not complete (exit $status); see the log above"
    exit "$status"
    ;;
esac
