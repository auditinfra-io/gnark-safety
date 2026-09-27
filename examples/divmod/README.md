# A reproducible gnark hint-safety demonstration

A small, synthetic educational fixture showing that a gnark **hint computes a
witness value but does not prove that the value has the intended meaning**. It
is not a report of a gnark vulnerability. The two circuits differ by one
semantic check, making the consequence visible both to the constraint solver
and to a real Groth16 verifier. It is also the regression fixture for
`gnark-safety`'s `GNARK_HINT_RELATION_INCOMPLETE` rule.

## Intended arithmetic

For public unsigned integers `n` (dividend) and `d` (divisor), the private hint
outputs `q` (quotient) and `r` (remainder). The intended relation is:

```text
n = q*d + r,  d > 0,  0 <= r < d
```

All four values are constrained to 8 bits (`0..255`). Consequently the largest
right-hand side allowed by those individual ranges is
`255*255+255 = 65,280`, vastly smaller than the BN254 scalar-field modulus.
Thus field wraparound cannot masquerade as the integer equality used here.

`VulnerableCircuit` checks the 8-bit ranges, nonzero divisor, and reconstruction
but intentionally omits `r < d`. Both hint outputs still participate in
constraints. `CorrectedCircuit` is otherwise identical and adds the missing
bounded comparison. Both call the shared helper `constrainDivision`, whose
`enforceCanonicalRemainder` parameter selects the path.

For `n=17,d=5`, honest advice is `q=3,r=2`. The adversarial test replacement
returns `q=2,r=7`: it still reconstructs 17, but 7 is not a valid remainder for
divisor 5. gnark's supported `solver.OverrideHint` option replaces only this
fixture's quotient/remainder hint. It models prover-controlled witness advice;
it does not alter verification, bypass gnark, or propose an attack on gnark.

An honest hint implementation is useful for constructing a witness, but it does
not make the constraint system sound. A proof establishes only the encoded
constraints, so every semantic property of hint outputs must be constrained.

## Reproduce

Prerequisites are Git and a Go installation capable of Go's toolchain
auto-selection (the default, `GOTOOLCHAIN=auto`). This repository's `go.mod`
requires Go 1.26.0 and names `toolchain go1.27.1`, so the commands below run
with Go 1.27.1 unless your `go` is newer. The module pins gnark v0.16.3 (whose
own `go.mod` requires Go 1.25.7) and gnark-crypto v0.21.0. `go.sum` records
module-content checksums; it does not select dependency versions.

From the repository root:

```bash
go mod download
go test -count=1 -v ./examples/divmod
```

Regenerate the machine-readable environment, source hashes, and retained test
output for the whole repository with:

```bash
go run ./cmd/reproduce
```

To run just the solver matrix or real-proof checks:

```bash
go test -count=1 -v -run TestRequiredHintSafetyMatrix ./examples/divmod
go test -count=1 -v -run TestGroth16 ./examples/divmod
```

The differential suite exhaustively checks the hint against the ordinary-Go
8-bit division specification, then checks a smaller valid/adversarial corpus
against R1CS and sparse R1CS on BN254 and BLS12-381. The proof matrix generates
and verifies corrected-circuit proofs with Groth16 and PLONK on both curves:

```bash
go test -count=1 -v -run 'TestHintMatchesSpecificationExhaustively|TestCorrectedCircuitMatchesSpecificationMatrix' ./examples/divmod
go test -count=1 -v -run TestCorrectedProofBackendCurveMatrix ./examples/divmod
```

PLONK setup in the proof matrix uses gnark's explicitly test-only `unsafekzg`
SRS generator. It must not be copied as production trusted-setup guidance.

`hint_inventory_test.go` keeps a registry of every `NewHint` call in this
package and fails if one lacks an adversarial mutation suite.

## Observed outcomes

Observed on Linux/x86_64; see [`evidence/`](../../evidence/README.md) for the
retained run.

| Case | Hint output | Observed result |
|---|---|---|
| Vulnerable, valid | `q=3,r=2` | solver accepts |
| Corrected, valid | `q=3,r=2` | solver accepts |
| Vulnerable, invalid | `q=2,r=7` | solver accepts; Groth16 proof verifies |
| Corrected, same invalid | `q=2,r=7` | solver rejects; Groth16 proving fails |
| Exact division, `n<d`, and representative 8-bit boundaries | honest | both circuits accept |
| Vulnerable, zero divisor | adversarial `q=0,r=17` returned successfully | rejects on an unsatisfied constraint |

The quotient and remainder are internal witness values: this demonstrates that a
proof built from a noncanonical quotient/remainder witness verifies against an
underspecified circuit, not a false public quotient claim or an exploitable
application.

The vulnerable and corrected circuits are compiled and set up separately. No
claim is made that a proof or key from one circuit works with the other.

## Scope and limits

One deliberately incomplete relation does not establish a general method for
finding underconstrained circuits or measure any scanner's accuracy. It also
does not exhaust gnark hint risks, curves, backends, or comparison gadgets. See
[`docs/upstream-comparison.md`](../../docs/upstream-comparison.md) for what
gnark already documents and tests, and the narrower value this paired fixture
adds.
