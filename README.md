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

The differential suite exhaustively checks the hint against the ordinary-Go
8-bit division specification, then checks a smaller valid/adversarial corpus
against R1CS and sparse R1CS on BN254 and BLS12-381. The proof matrix generates
and verifies corrected-circuit proofs with Groth16 and PLONK on both curves:

```bash
GOTOOLCHAIN=go1.25.7 go test -count=1 -v -run 'TestHintMatchesSpecificationExhaustively|TestCorrectedCircuitMatchesSpecificationMatrix'
GOTOOLCHAIN=go1.25.7 go test -count=1 -v -run TestCorrectedProofBackendCurveMatrix
```

PLONK setup in the proof matrix uses gnark's explicitly test-only `unsafekzg`
SRS generator. It must not be copied as production trusted-setup guidance.

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
`frontend.Compiler.NewHint` method and the deprecated `frontend.API.NewHint`
shortcut, so import aliases and embedded APIs work and unrelated methods with
that name are ignored. Dependencies are loaded for type resolution
but are not themselves reported unless a requested package pattern includes
them. Package loading invokes the Go toolchain and may resolve dependencies.

This release does not analyze call-graph reachability, trace constraints,
detect missing constraints, establish circuit soundness, or execute circuit or
hint code. A dynamically selected hint function, a non-constant output count,
or variadic input expansion is explicitly shown as `unknown`. JSON output uses
the versioned `1.0` schema and includes `hints`, `diagnostics`, and
`limitations`.

## Experimental safety analyzer

`gnark-safety` is the type-aware successor to the inventory command. Its
rules, generated from the registry in `internal/rules`:

<!-- BEGIN GENERATED RULE TABLE -->
| Rule | Severity | Class | What it means |
|---|---|---|---|
| [`GNARK_HINT_RELATION_INCOMPLETE`](https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md#gnark_hint_relation_incomplete) | high | unbound witness | A two-output hint is reconstructed as `n = q*d + r`, but no unconditional `r < d` bound makes the quotient and remainder unique, so the prover can supply a noncanonical pair that still satisfies the circuit. |
| [`GNARK_HINT_OUTPUT_UNUSED`](https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md#gnark_hint_output_unused) | medium | unbound witness | A hint output is extracted from the returned slice but never referenced again. An unused prover-computed value often means a forgotten constraint, but it can also be intentional padding, so the rule asks for review. |
<!-- END GENERATED RULE TABLE -->

Run the scanner and read a rule's full explanation with:

```bash
GOTOOLCHAIN=go1.25.7 go run ./cmd/gnark-safety scan --fail-on none ./...
GOTOOLCHAIN=go1.25.7 go run ./cmd/gnark-safety scan --format json --fail-on none ./...
GOTOOLCHAIN=go1.25.7 go run ./cmd/gnark-safety scan --format sarif --output results.sarif --fail-on none ./...
GOTOOLCHAIN=go1.25.7 go run ./cmd/gnark-safety explain GNARK_HINT_RELATION_INCOMPLETE
GOTOOLCHAIN=go1.25.7 go run ./cmd/gnark-safety explain GNARK_HINT_OUTPUT_UNUSED
```

Scans default to a two-minute timeout, 10,000 hint call sites, and 16 MiB of
rendered output. Override these with `--timeout`, `--max-hints`, and
`--max-output-bytes`. These are defense-in-depth limits, not a sandbox; follow
[`docs/untrusted-scanning.md`](docs/untrusted-scanning.md) before analyzing a
repository outside your trust boundary.

Use `--field bn254` or `--field bls12-381` when the compilation field is known.
The analyzer will compare a recognized bounded reconstruction maximum with that
scalar-field modulus. The default `--field unknown` makes no field-safety claim.

The default `--fail-on high` policy exits 1 for a finding at high severity or
above; `--fail-on` accepts `critical`, `high`, `medium`, `low`, `info`, or
`none` for report-only runs. Invalid configuration and package-loading
failures exit 2. So does a scan in which no package imports gnark, because a
mistyped pattern must not read as a clean pass; pass `--allow-empty` when no
circuits are expected. Every run prints a one-line summary to stderr with the
finding counts, how many packages were scanned, and the gate verdict.

`_test.go` files are excluded unless `--include-tests` is passed. Findings in
`example/`, `examples/`, or `_examples/` directories are downgraded to low,
recording the original severity, unless `--include-examples` is passed:
example code is simplified on purpose, but it is also copied into production,
so it is reported rather than hidden. The JSON report retains the hint inventory and
adds stable findings. Schema 2.0 uses a critical/high/medium/low/info severity
scale, records the tool name and version, and keeps independent per-output
participation, range, relation, canonicality, and field-safety assessments;
unsupported conclusions remain explicitly `unknown`. SARIF 2.1.0 output carries
per-rule help links and GitHub `security-severity` scores for code-scanning
import. `gnark-safety --version` prints the build version.

This is deliberately not a claim of full circuit soundness. The initial rule
follows only one level of direct local helper calls and reports unsupported
constructs in the top-level `limitations` field. See
[`docs/architecture.md`](docs/architecture.md) and [`docs/rules.md`](docs/rules.md).

## Security and audit research

[`docs/security-roadmap.md`](docs/security-roadmap.md) maps themes from gnark's
published audits and security guidance to concrete next steps for this project.
The highest-value follow-ups are adversarial-hint mutation testing, explicit
field/range reasoning, interprocedural analysis, and differential tests against
ordinary Go specifications. This is a research roadmap, not an assertion that
an upstream audit finding affects this fixture.

[`docs/o1js-scan-parity-plan.md`](docs/o1js-scan-parity-plan.md) is the plan
for turning this repository into the gnark counterpart of
[o1js-scan](https://github.com/auditinfra-io/o1js-scan): packaging, CI
integration, a broader rule catalog, and public calibration.

Please report a suspected vulnerability privately as described in
[`SECURITY.md`](SECURITY.md). Dependency updates are monitored through
Dependabot and CI runs vulnerability, race, static-analysis, and fuzz checks.
Tagged releases additionally publish an SPDX SBOM, SARIF, source hashes,
toolchain metadata, and retained test output; see
[`docs/releases.md`](docs/releases.md) for reproduction and signature guidance.

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

This standalone repository contains the public educational demonstration, the
hint-call inventory CLI, and one deliberately narrow experimental detector. It
includes no proprietary invariant pack, customer finding, or general-purpose
safety analysis.

One deliberately incomplete relation does not establish a general method for
finding underconstrained circuits or measure any scanner's accuracy. It also
does not exhaust gnark hint risks, curves, backends, or comparison gadgets. See
[`docs/upstream-comparison.md`](docs/upstream-comparison.md) for what gnark
already documents and tests, and the narrower value this paired fixture adds.
