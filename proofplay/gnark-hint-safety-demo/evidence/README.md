# Reproduction evidence

This directory retains concise output from the documented run. It is evidence
of one local execution, not a proof of correctness or a reproducible-build
attestation.

- `results.json` records environment, versions, commands, exit codes, and the
  semantic outcomes asserted by named tests.
- `test-output.txt` is the raw verbose output of the full Go test command.

The output file SHA-256 is recorded only as an integrity convenience. It does
not prove that the code is sound, that a third party reproduced it, or that the
result generalizes beyond this fixture.
