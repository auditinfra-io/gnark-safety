# Reproduction evidence

This directory retains concise output from the documented run. Regenerate it
from the repository root with `GOTOOLCHAIN=go1.25.7 go run ./cmd/reproduce`.
The command runs the complete suite first and fails instead of publishing
evidence if a required semantic behavior regresses.

- `results.json` records environment, versions, commands, exit codes, semantic outcomes, and SHA-256 hashes for every Go source file plus `go.mod` and `go.sum`.
- `test-output.txt` is the raw verbose output of the full Go test command.

The source hashes bind the run to exact inputs without creating the circularity of embedding a commit ID in evidence committed by that same commit. The output file SHA-256 is recorded only as an integrity convenience. It does
not prove that the code is sound, that a third party reproduced it, or that the
result generalizes beyond this fixture.
