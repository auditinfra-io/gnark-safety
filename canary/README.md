# Canary: gnark's own std/ library

`gnark-safety` is only useful if it stays quiet on correct code. The canary
scans gnark's standard library, the largest body of carefully reviewed gnark
circuit code, and every finding it produces is read and classified here.

```bash
scripts/canary-gnark-std.sh v0.16.3 /tmp/std.json
go run ./internal/canary/check -snapshot canary/gnark-std-v0.16.3.json -report /tmp/std.json
```

The script scans `github.com/consensys/gnark/std/...` in a throwaway module
that requires only gnark, with paths relative to the gnark module root. The
check fails if the scan has a finding the snapshot does not classify, or the
snapshot lists one the scan no longer produces. CI runs both pinned versions
on every change (the `canary` job), and a weekly workflow scans gnark's
`master` branch against the latest snapshot, ignoring line numbers.

## Classifications

| Classification | Meaning |
|---|---|
| `intended` | The rule describes the code correctly, and the code's own documented design accounts for it. |
| `false-positive` | The rule is wrong here. The note names the guard the rule is missing. A high false positive is not recorded: the rule is fixed instead (a test enforces this). |
| `true-positive` | A real defect in gnark. |

**Never commit an unreleased defect in gnark.** A true positive is recorded
here only after gnark's maintainers have been told privately (see gnark's
`SECURITY.md`) and have cleared publication. Until then keep it out of this
repository entirely, including commit messages: a push is public and
permanent.

## Results

| gnark | Packages | Files | Findings | High | Classification |
|---|---:|---:|---:|---:|---|
| v0.15.0 | 68 | 207 | 2 | 0 | 2 intended |
| v0.16.3 | 70 | 223 | 2 | 0 | 2 intended |

Both releases produce the same two findings: `GNARK_BITS_OMIT_MODULUS_CHECK` in
`MarshalG1` for BLS12-377 and Grumpkin, which skip the modulus check unless the
caller passes `algopts.WithCanonicalBitRepresentation()`, as gnark documents.
`TestReleaseMatrix` pins that delta.

The canary has already changed the rules. The first scan of v0.16.3 reported
172 `GNARK_HINT_OUTPUT_UNUSED` false positives: outputs passed on as
sub-slices or stored into struct fields were counted as unused. It also
produced two high false positives from new rules before release: a Go
comparison guarding an API-misuse error in `hash.go`, and `MiMC.State`
flushing itself through its own `Sum`. All three were fixed in the rules, with
fixtures, rather than recorded here.
