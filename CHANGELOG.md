# Changelog

All notable changes to gnark-safety are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-09-27

The same code as 0.1.0. The v0.1.0 tag was cut before this file had a
0.1.0 section, so the release workflow stopped at its preflight check and
published no binaries or evidence. 0.1.1 is the first release with them.

## [0.1.0] - 2026-09-27

The first tagged release.

### Fixed

- **`GNARK_HINT_RELATION_INCOMPLETE` accepted bounds that do not bound the
  remainder.** Challenge circuits, solved with adversarial witnesses, showed
  two shapes the rule treated as safe that accept noncanonical witnesses
  (see [`docs/relation-rule-review.md`](docs/relation-rule-review.md)):
  - a bounded comparator's `AssertIsLess(r, d)` without a range check of
    `r`. The comparator compares signed values, so `r = p - 3` (-3) passed
    for 17 ÷ 5 with `q = 4`. It now counts only with a range check of `r`,
    and is otherwise reported with that explanation;
  - `api.AssertIsLessOrEqual(r, api.Sub(d, 1))` without `d != 0`. With
    `d = 0`, `d - 1` is the largest field element, so every `r` and every
    `q` passed. It now counts only with `AssertIsDifferent(d, 0)` or a known
    nonzero `d`, and is otherwise reported at medium confidence.

  Negative constant bounds, which gnark encodes near the field modulus, no
  longer count. Nor does a compile-time value the circuit does not see:
  package-level `int` arithmetic that overflows (a divisor of
  `big62*4 + 5` is 5 at run time, not 2^64 + 5, and the rule accepted
  `r <= 100` for it), or a constant at or above the field modulus, which
  the field reduces. Without `--field`, constants must be below 2^240. The comparator's `AssertIsLessEq(r, api.Sub(d, 1))`, the
  same constraint as `AssertIsLess(r, d)`, is now recognized instead of
  reported. Five fixtures that pinned the unsound shapes as safe now include
  the missing check, and the unsound shapes are kept as reported cases.
- **`GNARK_HINT_RELATION_INCOMPLETE` stated every finding as certain.** The
  message said the bound "is not constrained" when the rule had only failed
  to recognize one, at high confidence even when the remainder was returned
  to a caller, passed to a helper deeper than it looks, compared in a
  region that may not run, or used in a computation it does not follow.
  Such findings now say "Not confirmed:" and why, list up to three such
  uses in the evidence, and have medium confidence. The rule's registered
  confidence is medium. Its summary no longer claims that `r < d` alone
  makes the quotient and remainder unique; without a range check of `q`,
  `q*d + r` can exceed the field modulus. The rule still does not report
  that case, and the `field_safety` invariant now names the values with no
  recognized range check.
- **Reports did not say what a result means.** A scan with no findings
  printed only "No findings.", and a partial scan said so only on stderr, so
  a report saved with `--output` looked complete and clean. The text report
  now says that no findings is not evidence of soundness, that a finding is
  a lead rather than a confirmed vulnerability, and, for a partial scan,
  which packages were not analyzed. The JSON report's `limitations` say the
  same. The stderr summary also counts hint calls and how many are in the
  quotient/remainder shape that `GNARK_HINT_RELATION_INCOMPLETE` checks, so
  a quiet scan of code the rule cannot read is visible. Exit codes are
  unchanged.
- **Precision on application code.** A first scan of 11 public gnark
  application repositories (12 modules, 486 packages) reported 6 high and 10
  medium findings, none of them bugs. Reading each one led to these fixes,
  every one pinned by corpus cases in both directions. Afterwards the same
  repositories yield no high findings outside test-support code, except one
  that is correct in principle: a range check that one configuration of the
  code skips.
  - `GNARK_HINT_RELATION_INCOMPLETE` accepts bounds whose value proves
    `r < d` when `d` is known at compile time:
    - a constant bound (`AssertIsLessOrEqual(r, lanes-1)`);
    - a range check of `r`;
    - range-checked limbs `r = hi*2^b + lo`, including the check that forces
      `lo` to zero when `hi` is all ones, which is how emulated KoalaBear,
      BabyBear, and Goldilocks code proves `r < p`.

    `d` may be a constant, `math.Pow(2, k)`, or an unexported package-level
    `*big.Int` built from a constant that nothing in the package changes.
    Range checks count in every branch of an `if`/`else`. Constraints inside
    an `if err == nil` block whose other path returns that error now count as
    unconditional.
  - `GNARK_VACUOUS_ASSERT` reports a constant-only assertion only when it
    always holds. Assertions that always fail (`AssertIsEqual(1, 0)`, used to
    abort compilation) and length checks over fixed-size arrays
    (`AssertIsEqual(len(a), len(b))`) are no longer reported.
  - `GNARK_GO_EQUALITY_ON_VARIABLE` no longer reports comparisons of local
    variables or slices that only ever hold Go constants, such as a padding
    mask. A slice that receives a witness value, directly or through an alias
    sharing its elements, is still reported.
- **One package that failed to load aborted the whole scan**, hiding every
  finding in the packages that did load. The CLI now analyzes the packages
  that load, names each skipped package in a warning and in the report's
  `coverage.skipped`, and exits 2 unless `--allow-partial` is passed.
  Findings at the gate still exit 1.
- **CI and release builds used Go 1.25.7, whose standard library has three
  vulnerabilities reachable from this repository**: GO-2026-4601 and
  GO-2026-6218 in `net/url`, and GO-2026-4602 in `os`, fixed in Go 1.25.8
  and 1.25.13. They are reachable from `gnark-safety-vet` through
  `unitchecker`; `gnark-safety` and the other commands do not reach them.
  `govulncheck` in CI would have failed on them. `go.mod` now names `toolchain go1.27.1`, which CI's
  analysis, fuzz, and canary jobs and the release workflow install. (The
  minimum is now 1.26.0; see the next entry.) CI's staticcheck moves from v0.6.1, which cannot read Go
  1.27 export data, to v0.8.1. govulncheck moves from v1.1.4 to v1.8.0: the
  old release builds on x/tools v0.29, which predates Go 1.26, and on Go 1.27
  it crashed intermittently while building SSA. v1.8.0 reports the same
  advisories.
- **The documented minimum Go version was wrong.** Updating
  `golang.org/x/tools` to v0.50.0 raised `go.mod`'s `go` line to 1.26.0
  (x/tools, x/mod, x/sync, and x/sys all require it), but the README, the
  release notes, and the example's instructions still said 1.25.7, and the
  README's test command, `GOTOOLCHAIN=go1.25.7 go test ./...`, failed with
  `go.mod requires go >= 1.26.0`. The CI matrix's "1.25.7" leg would have
  failed the same way at its first `go` command, because `actions/setup-go`
  exports `GOTOOLCHAIN=local`. The leg now names 1.26.0, and the documentation
  states 1.26.0. The README also said the Action's build "fetches the pinned
  toolchain version (1.27.1) automatically"; under setup-go's
  `GOTOOLCHAIN=local` it builds with exactly the `go-version` input.
- **A `gnark-safety` binary failed with unexplained type errors when the
  `go` command on `PATH` was newer than the Go it was built with** (after a
  Go upgrade, say), even on code written for older Go: the analyzer
  type-checks that command's standard library. The error now names both versions and says how to rebuild, and
  release binaries are built with the newest stable Go (see
  [`docs/releases.md`](docs/releases.md)).
- The `actions/setup-go` pin labelled `v6.0.0` named the commit before that
  release (identical code). It now names the v6.0.0 commit, so the label is
  true and Dependabot can update it.
- **`GNARK_HINT_OUTPUT_UNUSED` reported 172 false positives on gnark's own
  `std/` library.** It counted only constant-index reads as uses. Outputs
  passed on as a sub-slice (`assignE12(e, out[:12])`), copied, read by a
  dynamic index, or stored into struct fields (`w.C0.B0.A0 = hint[0]`) were
  all reported as unused, contradicting the rule's documented limit that
  such uses stay unknown. Any reference to the output slice other than a
  constant-index read now makes the result unknown (no finding). Only an
  assignment to a variable declared in the same function is treated as an
  alias; a store into a field, a slice, or a package variable counts as a
  use. Found by the new gnark `std/` canary.
- **Circuits that call the deprecated `api.NewHint` were invisible.** The
  analyzer and `gnark-hint-scan` matched only `frontend.Compiler.NewHint`, but
  gnark v0.16.3 still exports the deprecated `frontend.API.NewHint` shortcut.
  A circuit that used it and omitted `r < d` scanned as zero hints and zero
  findings. Both forms are now recognized, including method expressions and
  APIs promoted through embedding. If you scanned code that uses `api.NewHint`
  before this change, scan it again.
- **The module did not build.** `go.mod` pinned `golang.org/x/tools v0.34.0`,
  but gnark v0.16.3 requires v0.48.0, and `go.sum` lacked the selected
  version. Every package importing `go/packages` failed with a missing
  `go.sum` entry.
- **A shared helper was reported instead of the vulnerable caller.** When an
  `r < d` bound in an unexported function is guarded by a bool parameter, the
  finding now moves to each package-local call that passes the disabling
  constant, and calls that enable the bound are quiet. Exported functions and
  methods keep the finding at the hint, because callers in other packages or
  through interfaces can pass any value. The demo now reports
  `(*VulnerableCircuit).Define` and not `(*CorrectedCircuit).Define`.

### Added

- `--include-test-support` and the `include-test-support` Action input.
  Findings in test-support directories (`test/`, `tests/`, `testutil/`,
  `testutils/`, `testing/`, `testhelpers/`, `e2e/`) are downgraded to low
  like example code, and are counted in `coverage.test_support_downgraded`.
- `--allow-partial` and the `allow-partial` Action input (see Fixed).
- **Nine new rules (Wave 1).** Each is resolved by type against gnark v0.16.3:
  - `GNARK_TAG_VISIBILITY_AS_NAME`: `gnark:"public"` names the field instead
    of making it public;
  - `GNARK_GO_EQUALITY_ON_VARIABLE`: Go `==`/`switch` on a `frontend.Variable`
    deciding which constraints are emitted;
  - `GNARK_DISCARDED_PREDICATE`: dropped `IsZero`, `Cmp`, comparator,
    `IsValidProof`, or hash `Sum` results;
  - `GNARK_VACUOUS_ASSERT`: self-comparisons and constant-only assertions;
  - `GNARK_BITS_UNCONSTRAINED`: bit decompositions whose digits nothing
    constrains;
  - `GNARK_BITS_OMIT_MODULUS_CHECK`;
  - `GNARK_COMPARATOR_NONDETERMINISTIC`;
  - `GNARK_IGNORE_UNCONSTRAINED_INPUTS`;
  - `GNARK_UNSAFE_SETUP`: `unsafekzg` outside tests, and single-party
    `groth16.Setup` in `main`.
- **Annotated corpus** (`internal/analyzer/testdata/corpus`). `// want`
  annotations pin every true positive and false-positive guard, checked in
  both directions.
- **Executable witnesses** (`internal/witness`). Every high rule has a test in
  which the reported circuit accepts a semantically invalid witness (through
  the solver or a Groth16 proof) and the corrected one rejects it. A test
  fails for any high rule without one.
- **Metamorphic suite.** Reprinting, aliasing imports, parenthesizing
  arguments, and swapping commutative operands must not change any verdict.
  A committed manifest tracks known gaps; none exist today.
- **gnark `std/` canary** (`scripts/canary-gnark-std.sh`, `canary/`). The
  canary scans v0.15.0 and v0.16.3 on every change and `master` weekly. Every
  finding is classified in a committed snapshot, and a release-matrix test
  pins the delta between releases.
- **GitHub Action** (`action.yml`). It builds the analyzer at the ref in
  `uses:` (or installs a named release), scans once, uploads SARIF to code
  scanning whenever the scan completed, and fails the job at `fail-on`. A scan
  that cannot run fails the job without uploading. Inputs reach its scripts
  only through the environment; see the README for inputs and outputs. It
  sets up the latest stable Go by default (`go-version`), because the
  analyzer must be at least as new as the Go of the module it scans.
- **pre-commit hook** (`.pre-commit-hooks.yaml`, id `gnark-safety`).
- **Release binaries.** Tagged releases attach reproducible archives for
  Linux, macOS, and Windows on amd64 and arm64
  (`scripts/build-release.sh`), with their checksums inside the evidence
  bundle. A preflight refuses tags without a `CHANGELOG.md` section.
- **`gnark-safety-vet`** runs the rules under `go vet -vettool`, through a
  `go/analysis` adapter that a parity test keeps in step with the CLI.
- `--sarif-output FILE` writes SARIF in the same pass as the primary output.
- `--relative-to DIR` reports paths relative to `DIR`, such as the repository
  root, so SARIF from a module in a subdirectory maps in code scanning.
- Rule registry (`internal/rules`) as the single source of truth for rule
  metadata. `explain`, SARIF rule metadata, and the rule tables in `README.md`
  and `docs/rules.md` are rendered from it (`go generate ./internal/rules`),
  and tests fail when docs or emitted rules drift from it.
- `gnark-safety --version`, derived from build information, so `go install
  ...@vX.Y.Z` binaries report their release.
- `--fail-on` accepts `critical`, `high`, `medium`, `low`, `info`, or `none`.
- A one-line stderr summary on every scan: finding counts by severity,
  packages scanned, how many import gnark, downgrades, suppressions, and the
  gate verdict.
- **An empty scan is not a pass.** A scan in which no package imports gnark
  exits 2; `--allow-empty` opts out.
- `--include-tests` analyzes `_test.go` files (excluded by default).
- Findings in `example/`, `examples/`, and `_examples/` directories are
  downgraded to low with the original severity recorded;
  `--include-examples` keeps the original severity.
- `//gnark-safety:ignore RULE_ID reason` suppressions. Suppressed findings
  stay in the report's `suppressed` list and in SARIF as `inSource`
  suppressions. Malformed, misspelled, or stale directives produce warnings.
- `gnark-safety inventory` lists every hint call site (text or JSON). A
  parity test keeps it identical to `gnark-hint-scan`.
- SARIF rules list title, summary, help text, `helpUri`, precision, tags, and
  GitHub `security-severity`. Results carry `ruleIndex`, and the invocation
  records scan coverage and warnings.
- README console transcripts are executed by a test.

### Changed

- Example directories include names that start with `example_`, `examples_`,
  `example-`, or `examples-`, such as `example_native_aggregation/`.
- **Report schema 2.0.** Severities are `critical`, `high`, `medium`, `low`,
  and `info`; schema 1.x `review` becomes `medium`. The report adds `tool`
  (name and version), `coverage`, `suppressed`, and per-finding
  `original_severity` and `suppression`.
- SARIF `driver.version` is the tool version rather than the report schema
  version.
- The educational demonstration moved from the repository root to
  `examples/divmod` (package `divmod`), and the README now leads with the
  scanner.

### Deprecated

- `gnark-hint-scan`: use `gnark-safety inventory`. The command prints a
  deprecation notice and will be removed in a future release.
