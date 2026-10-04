# gnark-safety

`gnark-safety` reads the Go source of [gnark](https://github.com/Consensys/gnark)
circuits and reports a small set of specific patterns that often mean a
circuit accepts values it should reject. It is a static analyzer: it never
runs your circuit, and it knows only the patterns its rules describe.

Its main target is gnark *hints*. A hint computes a value outside the circuit,
such as a quotient and remainder, and a proof establishes only the constraints
the circuit states about that value. If a property the developer relied on is
never constrained, a dishonest prover can supply a different value that still
passes. `gnark-safety` loads your packages with full Go type information,
reports hint outputs whose constraints look incomplete, and checks ten other
patterns listed under [Rules](#rules). It is the gnark counterpart of
[o1js-scan](https://github.com/auditinfra-io/o1js-scan) (o1js / Noir); see
also [vk-guard](https://github.com/auditinfra-io/vk-guard) (verification-key
regression).

See it run: [`docs/walkthrough.md`](docs/walkthrough.md).

## Status

- **Experimental.** The project is pre-1.0; its first release is v0.1.0.
  Rules, messages, and the report schema may change. Nothing here has been
  independently audited.
- **AI-assisted.** Much of the code, tests, and documentation was written
  with AI assistance (Anthropic's Claude, through Claude Code); those commits
  carry `Co-Authored-By` trailers. Review the tool's findings, and its
  documentation's claims, as you would those of any unaudited tool.
- **Narrow.** Each rule matches specific source shapes. A clean scan is not
  an audit, and a finding is a lead to review, not a confirmed
  vulnerability. See [What a result does not tell you](#what-a-result-does-not-tell-you).

## Install

Requirements:

- **Go 1.26.0 or newer** to build. That is the `go` line in `go.mod`, which
  `golang.org/x/tools` v0.50.0 and its `golang.org/x/*` dependencies require.
  `go.mod` also names `toolchain go1.27.1`, because three published Go
  standard-library vulnerabilities reachable through `gnark-safety-vet` are
  fixed only in later releases (see [`CHANGELOG.md`](CHANGELOG.md)). Under
  Go's default `GOTOOLCHAIN=auto`, an older `go` command downloads and builds
  with Go 1.27.1. Under `GOTOOLCHAIN=local`, common in CI, Go 1.26.0 through
  1.27.0 builds without that fix and anything older fails with
  `go.mod requires go >= 1.26.0`, so pin Go 1.27.1 or newer there.
- **Packages that build.** The analyzer type-checks the packages you scan,
  so their module dependencies must be downloadable or already in the module
  cache.
- **A binary at least as new as your `go` command.** The analyzer
  type-checks the standard library of the `go` command on your `PATH`, so it
  must be built with that Go release or a newer one. `go install pkg@version`
  does not ensure this on its own: it picks its toolchain from
  gnark-safety's `go.mod` and your local Go, not from the module you will
  scan. Run the install below from the directory that holds your `go.mod`;
  `go env GOVERSION` there names the toolchain your module selects. A
  mismatched binary says how to rebuild.

```bash
GOTOOLCHAIN="$(go env GOVERSION)" go install github.com/auditinfra-io/gnark-safety/cmd/gnark-safety@latest
gnark-safety --version
```

`@latest` installs the newest tagged release, and `--version` prints its
tag. To use a particular checkout instead, run `go build -o gnark-safety
./cmd/gnark-safety` in it; `--version` then prints a pseudo-version such as
`v0.0.0-20260927122302-f6cf9fd8d1db` whose last part names the commit, with
`+dirty` if the tree has uncommitted changes. (`go run` reports only
`devel`.) Releases from v0.1.1 on also publish prebuilt archives for Linux,
macOS, and Windows on the
[releases page](https://github.com/auditinfra-io/gnark-safety/releases); see
[`docs/releases.md`](docs/releases.md). CI can use the
[GitHub Action](#github-action) instead.

## Scan your circuits

From the directory that holds your `go.mod`:

```bash
gnark-safety scan ./...
```

Arguments are Go package patterns. Findings go to stdout and a one-line
summary to stderr. The exit code is `0` when the scan passed, `1` when a
finding reached `--fail-on` (default `high`), and `2` when the scan could not
give a complete answer: a usage error, no scanned package imports gnark, or
a requested package failed to load. [Usage](#usage) has the details and the
flags.

The summary states what was analyzed, including how many hint calls were
found and how many are in the quotient/remainder shape that the first rule
checks. If that second number is 0, the first rule had nothing to check in
your code, whatever else the scan reports.

## A synthetic finding, and how to read it

[`examples/divmod`](examples/divmod) is a small circuit that is incomplete on
purpose. Scanned from this repository's root:

```console
$ gnark-safety scan --include-examples ./examples/divmod
examples/divmod/circuits.go:44:26: high [GNARK_HINT_RELATION_INCOMPLETE] This call passes enforceCanonicalRemainder=false to constrainDivision, which then skips the canonical remainder bound r < d on its hint outputs.

1 finding(s). Each is a lead for review, not a confirmed vulnerability; `gnark-safety explain <rule>` says what a rule checks and where it stops.
gnark-safety: 1 finding(s) [1 high] in 1 file(s); scanned 1 package(s), 1 importing gnark; 1 hint call(s), 1 in the quotient/remainder shape; _test.go files excluded — fails (--fail-on high)
$ echo $?
1
```

(`--include-examples` keeps the finding at its original severity; by default
findings under `examples/` are lowered to `low`, as shown under
[Usage](#usage).)

How to read it:

- **Where.** Line 44 is the call in `(*VulnerableCircuit).Define` that
  passes `false` to the shared helper `constrainDivision`. The helper asks a
  hint for a quotient `q` and a remainder `r`, checks `n = q*d + r` and 8-bit
  ranges, and checks `r < d` only when its last argument is `true`. The rule
  reports the caller that turns the check off, not the helper.
- **What.** `high` is the severity, which decides the exit code, and
  `GNARK_HINT_RELATION_INCOMPLETE` is the rule. `gnark-safety explain
  GNARK_HINT_RELATION_INCOMPLETE` describes it and where it stops. With
  `--format json`, the finding also has a confidence (`high` here, because
  the remainder reaches no code the rule does not read) and its evidence.
- **Why it matters.** Without `r < d`, both `q=3, r=2` and `q=2, r=7`
  satisfy `17 = q*5 + r`. For this example that is shown, not just
  predicted: the example's tests have gnark's solver accept `q=2, r=7`, and
  a Groth16 proof built from it verifies.
- **What to check in your own code.** Whether the hint is really meant as
  division with a remainder in `[0, d)`; whether `r` is bounded somewhere the
  rule does not look, such as a caller or a helper two calls deep; and,
  separately, whether `q`, `d`, and `n` are range-checked so that `q*d + r`
  cannot wrap around the field, which this rule does not check.
  [`docs/understanding-the-first-detector.md`](docs/understanding-the-first-detector.md)
  explains all of this without assuming a computer-science background.
- **Fixing or accepting it.** `CorrectedCircuit` in the same file is the
  fix: it range-checks `r` and asserts `r < d` with a bounded comparator. If
  you have reviewed a finding and it is not a problem, suppress it with a
  reason; see [Suppressing a reviewed finding](#suppressing-a-reviewed-finding).

## What a result does not tell you

- **A clean run is not an audit.** No findings means that no pattern these
  rules recognize matched, not that the circuit is sound. Most soundness bugs
  match no rule here.
- **A finding is a lead, not a verdict.** The analyzer matches source
  shapes; it does not run the circuit or know what a hint is meant to
  compute. When a finding depends on code it does not read, its message says
  "Not confirmed:" and why, and its confidence is `medium`. Each rule's
  "Where it stops" entry in [`docs/rules.md`](docs/rules.md) lists what the
  rule misses and where it can be wrong.
- **Analysis is type-aware but shallow.** Hint calls are resolved by type
  (`Compiler.NewHint` and the deprecated `API.NewHint`, including import
  aliases and embedded APIs). Bounds are followed through one level of
  package-local helpers, and bounds guarded by a bool parameter are resolved
  at constant call sites. Deeper call graphs, callers, reflection, generated
  code, and dynamically selected hints are listed in each report's
  `limitations` rather than guessed.
- **Code that does not load is not analyzed.** The scan then exits 2 and
  names the packages it skipped, in the report and on stderr, unless you
  pass `--allow-partial`.

For a protocol holding real value, treat this as a first pass and budget for
a full circuit review.

## Reporting a security issue

Do not open a public issue for a suspected vulnerability, in this tool or in
gnark. Use **Report a vulnerability** under this repository's **Security**
tab to open a private advisory. [`SECURITY.md`](SECURITY.md) lists what to
include and what is in scope. A suspected vulnerability in gnark itself
belongs with gnark's maintainers, under
[gnark's security policy](https://github.com/Consensys/gnark/blob/cfc7b2f907cc4212ec152077e022c6d0b4805759/SECURITY.md).

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

Without `--include-examples`, the demo's finding is downgraded to low, so a
repository's own samples cannot fail its build:

```console
$ gnark-safety scan ./examples/divmod
examples/divmod/circuits.go:44:26: low [GNARK_HINT_RELATION_INCOMPLETE] This call passes enforceCanonicalRemainder=false to constrainDivision, which then skips the canonical remainder bound r < d on its hint outputs.

1 finding(s). Each is a lead for review, not a confirmed vulnerability; `gnark-safety explain <rule>` says what a rule checks and where it stops.
gnark-safety: 1 finding(s) [1 low] in 1 file(s); scanned 1 package(s), 1 importing gnark; 1 hint call(s), 1 in the quotient/remainder shape; 1 downgraded as example code; _test.go files excluded — passes (--fail-on high)
$ echo $?
0
```

**Output.** The JSON report records:

- the tool version and scan coverage;
- stable findings with a severity, a confidence (`medium` when the rule could
  not read everything its verdict depends on), evidence, and limitations;
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
| `go-version` | `stable` | Go version for `actions/setup-go`. The analyzer is built and run with it, so it must be at least your module's `go` version and this module's (1.26.0). `setup-go` exports `GOTOOLCHAIN=local`, so no other toolchain is downloaded. Empty uses the Go already on `PATH`. |

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

### AI coding assistants (MCP)

`gnark-safety-mcp` serves the same analysis to AI coding assistants over the
[Model Context Protocol](https://modelcontextprotocol.io), so an assistant
can check a circuit while you write it. It is a separate binary, like
`gnark-safety-vet`; the CLI does not include it. It speaks only stdio: your
assistant's client starts it on your machine, and it uploads nothing. Like
any build, loading packages may download their module dependencies through
your configured `GOPROXY`.

```bash
GOTOOLCHAIN="$(go env GOVERSION)" go install github.com/auditinfra-io/gnark-safety/cmd/gnark-safety-mcp@latest
```

Register it with Claude Code from your module's directory (`--scope project`
writes `.mcp.json` to share it with the repository; the default, `local`,
keeps it to you):

```bash
claude mcp add --transport stdio gnark-safety -- gnark-safety-mcp --root "$(pwd)"
```

Clients that read an `mcpServers` file, such as `.mcp.json` for Claude Code
or `.cursor/mcp.json` for Cursor, take the same command:

```json
{
  "mcpServers": {
    "gnark-safety": {
      "command": "gnark-safety-mcp",
      "args": ["--root", "/path/to/your/module"]
    }
  }
}
```

It offers four tools: `scan` (the CLI's `scan`, with `fail_on`, `field`, and
the three `include_*` options), `inventory`, `list_rules`, and
`explain_rule`. A scan result states what was analyzed, the rules that ran,
the field setting, and the report's limitations, and each tool description
carries the caveat from [What a result does not tell you](#what-a-result-does-not-tell-you).

- **Fail-closed.** A scan in which no package imports gnark is an error
  (`no_gnark_packages`), and so is one in which a requested package fails to
  load or type-check (`packages_failed_to_load`, naming each package). There
  is no `--allow-empty` or `--allow-partial` here: an assistant cannot accept
  a weaker scan and report it as clean. Use the CLI for that.
- **Pinned loading environment.** Every `go` command the server runs uses
  `GOTOOLCHAIN=local`, so a scanned module's `go` or `toolchain` line can
  never select, download, or run another toolchain. `GOFLAGS`, the go env
  file, `go.work`, and cgo are off; only the cache and module-fetch settings
  (`GOPATH`, `GOMODCACHE`, `GOCACHE`, `GOPROXY`, `GOPRIVATE`, `GONOPROXY`,
  `GONOSUMDB`, `GOSUMDB`) are taken from your configuration at startup. The
  `go` on the server's `PATH` must therefore satisfy your module's `go` line;
  set `PATH` in the client configuration if it does not.
- **Below `--root` only.** Patterns must be relative and start with `./`,
  and `--root` must contain the module's `go.mod`. A pattern, a local
  `replace` in `go.mod`, or a symlink anywhere in the module or in a local
  replacement that resolves outside `--root` is refused
  (`path_outside_root`).
- **Read-only, bounded.** The tools write, modify, and execute nothing in
  your source tree; like any build, the `go` command fills the module and
  build caches. `--timeout`
  (2m), `--max-hints` (10000), and `--max-output-bytes` (16777216) have the
  CLI's defaults and are set only on the command line. A result cut to fit
  the output limit says so in `truncated`. Scans run one at a time.

None of this makes it safe to scan a hostile repository on a developer
machine: the Go toolchain still parses its code and fetches its
dependencies. Follow [`docs/untrusted-scanning.md`](docs/untrusted-scanning.md)
for code outside your trust boundary.

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
| [`GNARK_HINT_RELATION_INCOMPLETE`](https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md#gnark_hint_relation_incomplete) | high | unbound witness | A two-output hint is reconstructed as `n = q*d + r`, but no unconditional bound `0 <= r < d` was recognized, so a prover may be able to supply another quotient and remainder that satisfy the same equation. |
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

## How the rules are tested

- **Annotated corpus.** Each rule's true positives and false-positive guards
  are pinned line by line, in both directions, in
  `internal/analyzer/testdata/corpus`. The cases are synthetic: shapes
  written to exercise the rules, some modeled on application code.
- **Metamorphic suite.** Each rule must give the same verdicts after
  spelling-only rewrites: import aliases, parentheses, swapped operands.
- **Canary.** The rules run against gnark's own `std/` library at v0.15.0
  and v0.16.3, and every finding is read and classified
  ([`canary/`](canary/README.md)): two medium findings, both intended, and no
  high ones. `std/` contains no hint in the quotient/remainder shape, so the
  canary says nothing about `GNARK_HINT_RELATION_INCOMPLETE`.
- **Executable witnesses.** For each high rule, a test (in `internal/witness`,
  and in `examples/divmod` for the first rule) builds a small synthetic
  circuit that the rule reports, shows by solving it that it accepts a
  witness violating its intended property, and shows that a corrected
  circuit rejects that witness. This shows that the pattern can be a real
  bug. It does not show that every finding of the rule is exploitable.
- **Challenge cases.** The first rule's assumptions are tested against
  circuits whose correct outcome was worked out from their constraints,
  including cases where it is wrong; see
  [`docs/relation-rule-review.md`](docs/relation-rule-review.md).
- **Retained evidence.** [`evidence/`](evidence/README.md) keeps the verbose
  output of one full test run, bound to SHA-256 hashes of the sources it ran
  on. It records that run on the machine that produced it; it is not an
  independent reproduction, and it no longer describes the code once those
  hashes stop matching.
- **CI.** `.github/workflows/test.yml` is set up to check formatting, run
  `go vet`, the full suite on Go 1.26.0 and the current stable Go,
  staticcheck, govulncheck, a fuzz target, the Action, and the canary. Check
  the workflow run for the commit you use rather than assuming it passed.

None of this measures precision or recall on real application code. The
calibration against public gnark applications described in
[`CHANGELOG.md`](CHANGELOG.md) kept its per-finding results out of the
repository, so it cannot be reproduced from here.

[`docs/o1js-scan-parity-plan.md`](docs/o1js-scan-parity-plan.md) lays out the
next rules: hint outputs that reach no constraint, `DivUnchecked` by a
possibly-zero divisor, inverses guarded by `Select`, validation that exists
only in hint code, unverified recursive proofs, unpinned verifying keys, and
unbound Merkle roots.

## Repository layout

| Path | Contents |
|---|---|
| `cmd/gnark-safety` | The CLI. |
| `cmd/gnark-safety-vet`, `internal/vet` | The `go vet -vettool` binary and its `go/analysis` adapter. |
| `cmd/gnark-safety-mcp` | The local MCP server for AI coding assistants (stdio only). |
| `internal/analyzer`, `internal/rules`, `internal/output` | Analysis, the rule registry, and text/JSON/SARIF rendering. |
| `action.yml`, `.pre-commit-hooks.yaml`, `scripts/` | The GitHub Action, the pre-commit hook, and the release scripts. `internal/contract` tests all of them. |
| `pkg/report` | The public, versioned report schema. |
| [`examples/divmod`](examples/divmod) | The educational vulnerable/corrected pair, with solver, differential, adversarial-hint, and Groth16/PLONK proof tests. |
| `cmd/reproduce`, `cmd/release-evidence`, [`evidence/`](evidence/README.md) | Retained test evidence, and the release-evidence bundle, which is checksummed but not signed; see [`docs/releases.md`](docs/releases.md). |
| `cmd/gnark-hint-scan` | Deprecated; use `gnark-safety inventory`. |

Run the full suite with `go test -count=1 ./...` (Go 1.27.1 under the
default `GOTOOLCHAIN=auto`), or with `GOTOOLCHAIN=go1.26.0` to test the
minimum.
After changing a rule's metadata, run `go generate ./internal/rules` to
regenerate the rule tables. A test fails until you do.

## Security and research

- [`docs/security-roadmap.md`](docs/security-roadmap.md) maps themes from
  gnark's published audits to this project's analysis and testing.
- [`docs/o1js-scan-parity-plan.md`](docs/o1js-scan-parity-plan.md) is the
  roadmap toward parity with o1js-scan in packaging, CI integration, rule
  breadth, and public calibration.
- The release workflow is set up to attach an SPDX SBOM, SARIF, source
  hashes, toolchain metadata, and retained test output to each tagged
  release, from v0.1.1 on.

## License

MIT. See [`LICENSE`](LICENSE).
