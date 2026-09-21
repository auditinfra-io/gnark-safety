# gnark hint-safety demo

A small, synthetic educational fixture showing that a gnark **hint computes a
witness value but does not prove that the value has the intended meaning**. It
is not a report of a gnark vulnerability. The two circuits differ by one
semantic check, making the consequence visible both to the constraint solver
and to a real Groth16 verifier.

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
bounded comparison.

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
auto-selection. The module pins gnark v0.16.3, whose `go.mod` requires Go
1.25.7, and transitively pins gnark-crypto v0.21.0 in `go.sum`.

From the repository root:

```bash
cd proofplay/gnark-hint-safety-demo
GOTOOLCHAIN=go1.25.7 go mod download
GOTOOLCHAIN=go1.25.7 go test -count=1 -v ./...
```

To run just the solver matrix or real-proof checks:

```bash
GOTOOLCHAIN=go1.25.7 go test -count=1 -v -run TestRequiredHintSafetyMatrix
GOTOOLCHAIN=go1.25.7 go test -count=1 -v -run TestGroth16
```

## Observed outcomes

Observed on 2026-09-21 on Linux/x86_64; see [`evidence/`](evidence/README.md).

| Case | Hint output | Observed result |
|---|---|---|
| Vulnerable, valid | `q=3,r=2` | solver accepts |
| Corrected, valid | `q=3,r=2` | solver accepts |
| Vulnerable, invalid | `q=2,r=7` | solver accepts; Groth16 proof verifies |
| Corrected, same invalid | `q=2,r=7` | solver rejects; Groth16 proving fails |
| Exact division, `n<d`, and representative 8-bit boundaries | honest | both circuits accept |
| Zero divisor | no valid quotient/remainder | both circuits reject |

The vulnerable and corrected circuits are compiled and set up separately. No
claim is made that a proof or key from one circuit works with the other.

## Scope and limits

This demonstration isolates public educational code under the repository's
existing `proofplay` experimental area. It includes no scanner detector,
proprietary invariant pack, customer finding, or general-purpose analysis.

One deliberately incomplete relation does not establish a general method for
finding underconstrained circuits or measure any scanner's accuracy. It also
does not exhaust gnark hint risks, curves, backends, or comparison gadgets. See
[`docs/upstream-comparison.md`](docs/upstream-comparison.md) for what gnark
already documents and tests, and the narrower value this paired fixture adds.
