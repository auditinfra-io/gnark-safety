# Changelog

All notable changes to gnark-safety are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **CI and release builds used Go 1.25.7, whose standard library has three
  vulnerabilities reachable from this repository**: GO-2026-4601 and
  GO-2026-6218 in `net/url`, and GO-2026-4602 in `os`, fixed in Go 1.25.8
  and 1.25.13. They are reachable from `gnark-safety-vet` through
  `unitchecker`; `gnark-safety` and the other commands do not reach them.
  `govulncheck` in CI would have failed on them. `go.mod` now names `toolchain go1.27.1`, which CI's
  analysis, fuzz, and canary jobs and the release workflow install; the
  minimum Go version for `go install` stays 1.25.7, and the test matrix
  still runs on it. CI's staticcheck moves from v0.6.1, which cannot read Go
  1.27 export data, to v0.8.1.
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
