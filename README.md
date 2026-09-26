# gnark-safety

A static analyzer for **soundness bugs in [gnark](https://github.com/Consensys/gnark)
circuits**: prover-controlled values that the circuit never binds to the
meaning the developer intended.

gnark hints compute witness values outside the circuit. The proof then
establishes only the constraints the circuit encodes, so every property of a
hint output that matters (its range, its relation to the inputs, its
uniqueness) has to be constrained explicitly. `gnark-safety` loads your Go
packages with full type information and reports hint outputs whose
constraints are missing or incomplete. It is the gnark counterpart of
[o1js-scan](https://github.com/auditinfra-io/o1js-scan), which covers o1js and
Noir.

## Install

```bash
go install github.com/auditinfra-io/gnark-safety/cmd/gnark-safety@latest
```

Go 1.25.7 or newer is required to build. `go.mod` also pins `toolchain
go1.27.1`: three published Go standard-library vulnerabilities reachable
through `gnark-safety-vet` are present in Go 1.25.7 and fixed only in later
releases (see [`CHANGELOG.md`](CHANGELOG.md)), so with Go's default
toolchain management (`GOTOOLCHAIN=auto`) `go install` fetches and builds
with 1.27.1 automatically, even when your local Go already satisfies the
1.25.7 floor. With `GOTOOLCHAIN=local` (common in CI), that automatic fetch
does not happen: an older local Go builds as-is if it is at least 1.25.7 —
without the fix — or install fails outright with `go.mod requires go >=
1.25.7` if it is older still; pin Go 1.27.1 or newer directly in a
`GOTOOLCHAIN=local` environment to get the same fix. The analyzer
type-checks the packages you scan, so they must build, and their module
dependencies must be downloadable or already in the module cache. It must
also be built with a Go release at least as new as the `go` command on your
`PATH`, because it type-checks that release's standard library: `go install`
guarantees this, and a prebuilt binary reports the mismatch and how to fix
it.

Tagged releases also publish reproducible prebuilt archives for Linux, macOS,
and Windows (amd64 and arm64), with a checksum list in the release evidence;
see [`docs/releases.md`](docs/releases.md). CI can use the
[GitHub Action](#github-action) instead.

## Example

[`examples/divmod`](examples/divmod) contains two circuits that share one
quotient/remainder helper. `VulnerableCircuit` omits the `r < d` bound, and
`CorrectedCircuit` enforces it. The scanner reports the call that disables the
bound and stays quiet about the corrected one:

```console
$ gnark-safety scan --include-examples ./examples/divmod
examples/divmod/circuits.go:44:26: high [GNARK_HINT_RELATION_INCOMPLETE] This call passes enforceCanonicalRemainder=false to constrainDivision, which then skips the canonical remainder bound r < d on its hint outputs.

1 finding(s).
gnark-safety: 1 finding(s) [1 high] in 1 file(s); scanned 1 package(s), 1 importing gnark; _test.go files excluded — fails (--fail-on high)
$ echo $?
1
```

Without the bound, a prover can supply `q=2, r=7` for `n=17, d=5`. That
witness still satisfies `n = q*d + r`, and a Groth16 proof built from it
verifies. The example's tests demonstrate this with gnark's
`solver.OverrideHint`.

`--include-examples` is needed here only because the demo lives under
`examples/`. By default the scanner downgrades example code to low so that a
repository's own samples cannot fail its build:

```console
$ gnark-safety scan ./examples/divmod
examples/divmod/circuits.go:44:26: low [GNARK_HINT_RELATION_INCOMPLETE] This call passes enforceCanonicalRemainder=false to constrainDivision, which then skips the canonical remainder bound r < d on its hint outputs.

1 finding(s).
gnark-safety: 1 finding(s) [1 low] in 1 file(s); scanned 1 package(s), 1 importing gnark; 1 downgraded as example code; _test.go files excluded — passes (--fail-on high)
$ echo $?
0
```

## Usage

```bash
gnark-safety scan ./...                                  # text report; exit 1 on high or critical
gnark-safety scan --format json ./...                    # machine-readable report (schema 2.0)
gnark-safety scan --format sarif --output gnark-safety.sarif ./...   # GitHub code scanning
gnark-safety scan --sarif-output gnark-safety.sarif ./...  # readable log plus SARIF in one pass
gnark-safety scan --fail-on medium ./circuits/...        # gate at a different severity
gnark-safety scan --field bn254 ./...                    # compare bounds with a known scalar field
gnark-safety inventory ./...                             # list every hint call site
gnark-safety explain                                     # list rules
gnark-safety explain GNARK_HINT_RELATION_INCOMPLETE      # explain one rule
gnark-safety --version
```

Arguments are Go package patterns, resolved from the current directory.
Reported paths are relative to the current directory; `--relative-to DIR`
makes them relative to `DIR` instead. Use the repository root when the module
lives in a subdirectory, so SARIF locations resolve in code scanning.

**Exit codes.** `0` means the scan passed. `1` means a finding at or above
`--fail-on` (default `high`; accepts `critical`, `high`, `medium`, `low`,
`info`, or `none`). `2` means a usage error, a scan in which **no package
imports gnark**, or a scan in which **a requested package failed to load or
type-check**. Neither may read as a clean pass: a mistyped pattern or a moved
package would otherwise turn CI green, and a package the analyzer could not
read could hold the findings. Packages that do load are still analyzed and
reported, and each one skipped is named in a warning and in the report's
`coverage.skipped`. Pass `--allow-empty` when no circuits are expected, and
`--allow-partial` to accept a scan with skipped packages (a package that only
builds for `GOOS=js`, say). Findings at the gate take precedence and exit
`1`. Every run prints a one-line summary to stderr with the finding counts,
what was scanned, and the gate verdict.

**Test and example code.** `_test.go` files are excluded unless
`--include-tests` is passed. Findings in example directories (`example/`,
`examples/`, `_examples/`, and names such as `example_native/`) are downgraded
to low, with the original severity recorded, unless `--include-examples` is
passed. Example code is simplified on purpose, but it is also copied into
production, so it is reported rather than hidden. Findings in test-support
directories (`test/`, `tests/`, `testutil/`, `testutils/`, `testing/`,
`testhelpers/`, `e2e/`), which hold dummy circuits and harnesses outside
`_test.go` files, are downgraded the same way unless `--include-test-support`
is passed.

**Output.** The JSON report records:

- the tool version and scan coverage;
- stable findings with evidence;
- a per-hint inventory with independent participation, range, relation,
  canonicality, and field-safety assessments.

Unsupported conclusions stay explicitly `unknown`. SARIF 2.1.0 output carries
per-rule help links, GitHub `security-severity` scores, and suppressions.

**Fields.** Use `--field bn254` or `--field bls12-381` when the compilation
field is known. The analyzer then compares a recognized bounded reconstruction
maximum with that scalar-field modulus. The default `--field unknown` makes no
field-safety claim.

**Resource limits.** Scans default to a two-minute timeout, 10,000 hint call
sites, and 16 MiB of rendered output. Override these with `--timeout`,
`--max-hints`, and `--max-output-bytes`. These are defense-in-depth limits,
not a sandbox; follow [`docs/untrusted-scanning.md`](docs/untrusted-scanning.md)
before analyzing a repository outside your trust boundary.

## GitHub Action

The action builds the analyzer and scans once. It uploads SARIF to code
scanning, so findings appear as pull-request annotations and under
**Security → Code scanning**, and then fails the job if a finding reaches
`fail-on`:

```yaml
# .github/workflows/gnark-safety.yml
name: gnark-safety
on: [push, pull_request]

permissions:
  contents: read
  security-events: write # needed to upload SARIF

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: auditinfra-io/gnark-safety@main # pin a release tag or commit SHA
        with:
          path: ./...
          fail-on: high
```

| Input | Default | Meaning |
|---|---|---|
| `path` | `./...` | Go package patterns, separated by whitespace, resolved from `working-directory`. |
| `working-directory` | `.` | Directory containing the module's `go.mod`. Reported paths stay relative to the repository root, so code scanning can place them. |
| `fail-on` | `high` | Lowest severity that fails the job: `critical`, `high`, `medium`, `low`, `info`, or `none`. |
| `upload-sarif` | `true` | Upload SARIF to code scanning. Needs `security-events: write`; private repositories also need code scanning enabled. |
| `sarif-category` | `gnark-safety` | Code scanning category, to keep several scans of one repository apart. |
| `include-tests` | `false` | Also analyze `_test.go` files. |
| `include-examples` | `false` | Keep the original severity of findings in example directories. |
| `include-test-support` | `false` | Keep the original severity of findings in test-support directories. |
| `allow-empty` | `false` | Pass even when no scanned package imports gnark. |
| `allow-partial` | `false` | Pass even when some requested packages failed to load and were not analyzed. |
| `field` | `unknown` | Scalar field for bound checks: `unknown`, `bn254`, or `bls12-381`. |
| `version` | empty | Release to `go install`, such as `v0.2.0`. Empty builds the analyzer from the action at the ref in `uses:`. |
| `go-version` | `stable` | Go version for `actions/setup-go`. The analyzer is built and run with it, so it must be at least your module's `go` version (1.25.7); with the default `GOTOOLCHAIN=auto` the build then fetches the pinned `toolchain` version (1.27.1) automatically. Empty uses the Go already on `PATH`. |

The action's outputs are `sarif-file` and `exit-code`. An upload runs whenever
the scan completed, including when it failed the gate, so the findings that
failed the job are visible. A scan that could not run fails the job without
uploading anything, so a broken scan never reads as a clean one.

Inputs reach the action's scripts only through environment variables, and
`path` entries that look like flags are rejected. The analyzer loads and
type-checks the scanned packages, so the job needs network access to your
module dependencies, or a warmed module cache.

### pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/auditinfra-io/gnark-safety
    rev: main # pin a release tag or commit SHA
    hooks:
      - id: gnark-safety
```

The hook runs `gnark-safety scan --fail-on high ./...` from the repository
root when Go files change. Overriding `args` replaces all of them, so start
with `scan`, for example `args: [scan, --fail-on, medium, ./circuits/...]`.

### go vet

`gnark-safety-vet` runs the same rules as a `go vet` tool. It is useful where
`go vet` is already wired into editors or scripts:

```bash
go install github.com/auditinfra-io/gnark-safety/cmd/gnark-safety-vet@latest
go vet -vettool="$(command -v gnark-safety-vet)" ./...
```

`go vet` type-checks each package together with its tests and prints findings
as `file:line:col: severity [RULE] message`. It has no severity gate, SARIF,
example downgrading, or coverage summary; use `gnark-safety scan` for those. A
test keeps both reporting the same findings at the same positions.

### Suppressing a reviewed finding

Put a directive on the flagged line or on the line above it. A rule ID and a
reason are required:

```go
//gnark-safety:ignore GNARK_HINT_RELATION_INCOMPLETE the caller constrains r < d
out, err := api.Compiler().NewHint(quotientRemainder, 2, n, d)
```

Suppressed findings move to the report's `suppressed` list, never fail the
gate, and appear in SARIF with an `inSource` suppression, so code scanning
keeps the audit trail. A directive with no reason, an unknown rule, or a space
after `//` suppresses nothing and prints a warning. So does a directive that
no longer matches any finding.

## Rules

Generated from the registry in [`internal/rules`](internal/rules/rules.go).
Full descriptions are in [`docs/rules.md`](docs/rules.md).

<!-- BEGIN GENERATED RULE TABLE -->
| Rule | Severity | Class | What it means |
|---|---|---|---|
| [`GNARK_HINT_RELATION_INCOMPLETE`](https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md#gnark_hint_relation_incomplete) | high | unbound witness | A two-output hint is reconstructed as `n = q*d + r`, but no unconditional `r < d` bound makes the quotient and remainder unique, so the prover can supply a noncanonical pair that still satisfies the circuit. |
| [`GNARK_HINT_OUTPUT_UNUSED`](https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md#gnark_hint_output_unused) | medium | unbound witness | A hint output is extracted from the returned slice but never referenced again. An unused prover-computed value often means a forgotten constraint, but it can also be intentional padding, so the rule asks for review. |
| [`GNARK_TAG_VISIBILITY_AS_NAME`](https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md#gnark_tag_visibility_as_name) | high / info | unbound witness | A struct tag such as `gnark:"public"` names the witness element `public` instead of setting its visibility, so the field stays secret: a value the verifier meant to fix becomes one the prover chooses. |
| [`GNARK_GO_EQUALITY_ON_VARIABLE`](https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md#gnark_go_equality_on_variable) | high | non-load-bearing predicate | Go `==`, `!=`, or `switch` on a `frontend.Variable` compares the value the variable holds while the circuit is being compiled, a constraint expression rather than the witness, so the branch it guards is not a constraint. |
| [`GNARK_DISCARDED_PREDICATE`](https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md#gnark_discarded_predicate) | high | non-load-bearing predicate | The result of a gnark predicate (`IsZero`, `Cmp`, a bounded comparator's `IsLess`/`IsLessEq`, a recursive verifier's `IsValidProof`, or a hash `Sum`) is discarded, so the check it computes constrains nothing. |
| [`GNARK_VACUOUS_ASSERT`](https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md#gnark_vacuous_assert) | high / medium | non-load-bearing predicate | An assertion that holds by construction, such as `api.AssertIsEqual(x, x)` or an assertion over constants only, adds no restriction while reading like a check. |
| [`GNARK_BITS_UNCONSTRAINED`](https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md#gnark_bits_unconstrained) | high / medium | unbound witness | A `bits` decomposition opts out of digit constraints (`WithUnconstrainedOutputs` or `WithUnconstrainedInputs`) and nothing in the function constrains the digits, so the prover can choose non-boolean digits that still sum to the value. |
| [`GNARK_BITS_OMIT_MODULUS_CHECK`](https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md#gnark_bits_omit_modulus_check) | medium | unbound witness | `bits.OmitModulusCheck()` skips the comparison against the field modulus, so a full-width decomposition of `a` can also be one of `a + r`: the bits are not unique. |
| [`GNARK_COMPARATOR_NONDETERMINISTIC`](https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md#gnark_comparator_nondeterministic) | medium | unbound witness | `cmp.NewBoundedComparator(api, bound, true)` allows nondeterministic behavior: when the operands differ by more than the bound, the constraint system can have several solutions, so comparison results are prover-selectable. |
| [`GNARK_IGNORE_UNCONSTRAINED_INPUTS`](https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md#gnark_ignore_unconstrained_inputs) | medium | configuration | `frontend.IgnoreUnconstrainedInputs()` disables gnark's compile-time error for inputs that no constraint uses, a check gnark's documentation says should stay on in production. |
| [`GNARK_UNSAFE_SETUP`](https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md#gnark_unsafe_setup) | medium / low | configuration | Production code imports gnark's test-only `unsafekzg` SRS (medium), or runs a single-party `groth16.Setup` in a `main` package (low), so whoever ran setup could forge proofs. |
<!-- END GENERATED RULE TABLE -->

`GNARK_HINT_RELATION_INCOMPLETE` matches one specific reconstruction shape,
not "hint outputs are unconstrained" in general; see its "Where it stops"
entry in [`docs/rules.md`](docs/rules.md#gnark_hint_relation_incomplete) for
exactly which shapes it does and does not cover, including which gaps stay
quiet and which can instead produce a false positive.

Every rule is checked in four ways:

- **Corpus.** Its true positives and false-positive guards are pinned line by
  line in an annotated corpus (`internal/analyzer/testdata/corpus`).
- **Metamorphic suite.** It must give the same verdicts after
  spelling-only rewrites: import aliases, parentheses, swapped operands.
- **Canary.** It runs against gnark's own `std/` library, where every finding
  is read and classified ([`canary/`](canary/README.md)). On gnark v0.15.0 and
  v0.16.3 the result is two medium findings, both intended, and no high ones.
- **Executable witness (high rules).** Each high rule has a test
  (`internal/witness`) in which the reported circuit accepts a semantically
  invalid witness and the corrected circuit rejects it.

[`docs/o1js-scan-parity-plan.md`](docs/o1js-scan-parity-plan.md) lays out the
next rules: hint outputs that reach no constraint, `DivUnchecked` by a
possibly-zero divisor, inverses guarded by `Select`, validation that exists
only in hint code, unverified recursive proofs, unpinned verifying keys, and
unbound Merkle roots.

## Where this tool stops

- **A clean run is not an audit.** It means no shape these rules recognize
  matched, not that the circuit is sound.
- **A finding is a lead, not a verdict.** Every rule documents what it does
  not match; see "Where it stops" in [`docs/rules.md`](docs/rules.md).
- **Analysis is type-aware but shallow.** Hint calls are resolved by type
  (`Compiler.NewHint` and the deprecated `API.NewHint`, including import
  aliases and embedded APIs). Bounds are followed through one level of
  package-local helpers, and bounds guarded by a bool parameter are resolved
  at constant call sites. Deeper call graphs, reflection, generated code, and
  dynamically selected hints are reported in each report's `limitations`
  rather than guessed.

For a protocol holding real value, treat this as a first pass and budget for a
full circuit review.

## Repository layout

| Path | Contents |
|---|---|
| `cmd/gnark-safety` | The CLI. |
| `cmd/gnark-safety-vet`, `internal/vet` | The `go vet -vettool` binary and its `go/analysis` adapter. |
| `internal/analyzer`, `internal/rules`, `internal/output` | Analysis, the rule registry, and text/JSON/SARIF rendering. |
| `action.yml`, `.pre-commit-hooks.yaml`, `scripts/` | The GitHub Action, the pre-commit hook, and the release scripts. `internal/contract` tests all of them. |
| `pkg/report` | The public, versioned report schema. |
| [`examples/divmod`](examples/divmod) | The educational vulnerable/corrected pair, with solver, differential, adversarial-hint, and Groth16/PLONK proof tests. |
| `cmd/reproduce`, `cmd/release-evidence`, [`evidence/`](evidence/README.md) | Reproducible evidence and signed-release bundles; see [`docs/releases.md`](docs/releases.md). |
| `cmd/gnark-hint-scan` | Deprecated; use `gnark-safety inventory`. |

Run the full suite with `GOTOOLCHAIN=go1.25.7 go test -count=1 ./...`.
After changing a rule's metadata, run `go generate ./internal/rules` to
regenerate the rule tables. A test fails until you do.

## Security and research

- [`docs/security-roadmap.md`](docs/security-roadmap.md) maps themes from
  gnark's published audits to this project's analysis and testing.
- [`docs/o1js-scan-parity-plan.md`](docs/o1js-scan-parity-plan.md) is the
  roadmap toward parity with o1js-scan in packaging, CI integration, rule
  breadth, and public calibration.
- Report a suspected vulnerability privately as described in
  [`SECURITY.md`](SECURITY.md).
- Tagged releases publish an SPDX SBOM, SARIF, source hashes, toolchain
  metadata, and retained test output.

## License

MIT. See [`LICENSE`](LICENSE).
