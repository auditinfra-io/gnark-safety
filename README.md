# A reproducible gnark hint-safety demonstration

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
1.25.7, and explicitly requires gnark-crypto v0.21.0 in `go.mod`. `go.sum` records module-content checksums; it does not select
dependency versions.

From the repository root:

```bash
git clone https://github.com/auditinfra-io/gnark-safety.git
cd gnark-safety
GOTOOLCHAIN=go1.25.7 go mod download
GOTOOLCHAIN=go1.25.7 go test -count=1 -v ./...
```

Regenerate the machine-readable environment, source hashes, and retained test
output with:

```bash
GOTOOLCHAIN=go1.25.7 go run ./cmd/reproduce
```

To run just the solver matrix or real-proof checks:

```bash
GOTOOLCHAIN=go1.25.7 go test -count=1 -v -run TestRequiredHintSafetyMatrix
GOTOOLCHAIN=go1.25.7 go test -count=1 -v -run TestGroth16
```

## Hint-call inventory CLI

`gnark-hint-scan` is a small source inventory tool. Build it and scan this
module from the repository root with:

```bash
GOTOOLCHAIN=go1.25.7 go build -o ./gnark-hint-scan ./cmd/gnark-hint-scan
./gnark-hint-scan scan ./...
./gnark-hint-scan scan --format json ./...
```

The text inventory for the demonstration includes its single source call site
(both circuits share this helper):

```text
circuits.go:20:35: github.com/auditinfra-io/gnark-safety: constrainDivision (hint=github.com/auditinfra-io/gnark-safety.QuotientRemainderHint, outputs=2, inputs=2)
Inventory only: constraint completeness and circuit soundness were not analyzed.
```

The scanner examines every function and method in the requested non-test Go
packages, including helpers. It identifies direct calls to gnark's resolved
`frontend.Compiler.NewHint` method, so import aliases work and unrelated
methods with that name are ignored. Dependencies are loaded for type resolution
but are not themselves reported unless a requested package pattern includes
them. Package loading invokes the Go toolchain and may resolve dependencies.

This release does not analyze call-graph reachability, trace constraints,
detect missing constraints, establish circuit soundness, or execute circuit or
hint code. A dynamically selected hint function, a non-constant output count,
or variadic input expansion is explicitly shown as `unknown`. JSON output uses
the versioned `1.0` schema and includes `hints`, `diagnostics`, and
`limitations`.

## Observed outcomes

Observed on 2026-09-21 on Linux/x86_64; see [`evidence/`](evidence/README.md).

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

This standalone repository contains the public educational demonstration and
the narrow hint-call inventory CLI described above. It includes no constraint
scanner detector, proprietary invariant pack, customer finding, or
general-purpose safety analysis.

One deliberately incomplete relation does not establish a general method for
finding underconstrained circuits or measure any scanner's accuracy. It also
does not exhaust gnark hint risks, curves, backends, or comparison gadgets. See
[`docs/upstream-comparison.md`](docs/upstream-comparison.md) for what gnark
already documents and tests, and the narrower value this paired fixture adds.
