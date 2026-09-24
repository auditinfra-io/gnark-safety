# Changelog

All notable changes to gnark-safety are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

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
  `r < d` bound is guarded by a bool parameter, the finding now moves to each
  package-local call that passes the disabling constant, and calls that
  enable the bound are quiet. The demo now reports
  `(*VulnerableCircuit).Define` and not `(*CorrectedCircuit).Define`.

### Added

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
