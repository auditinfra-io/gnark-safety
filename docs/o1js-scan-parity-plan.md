# Plan: make gnark-safety the gnark counterpart of o1js-scan

Status: proposal, 2026-09-24. Reference points: gnark-safety `d339b3e` (main),
[o1js-scan](https://github.com/auditinfra-io/o1js-scan) `403fdf6` (0.20.0 plus
unreleased changes), gnark v0.16.3. Every gnark API named below was checked
against the v0.16.3 module source; file references are relative to that module.

## 1. Summary

o1js-scan is a **product**: a scanner you install in one command, drop into CI
with a GitHub Action, and trust because its rule catalog, false-positive guards,
and calibration against real ecosystem code are public and tested. gnark-safety
is currently an **educational fixture plus a two-rule research analyzer**. Its
engineering foundations are stronger than o1js-scan's in several places: type
resolution, per-output invariant evidence, executable adversarial witnesses,
differential and proof-backend matrices, and signed-release evidence. What it
lacks is the product layer, rule breadth, and calibration discipline.

The plan keeps gnark-safety's architecture and adopts o1js-scan's operating
model. It does not copy o1js-scan's lexical frontend, because Go ships a parser
and type checker, and type resolution removes the import-alias and name-matching
failure modes that o1js-scan spends much of its effort guarding against.

Two defects need fixing first:

1. **The build was broken on `main`.** `go.mod` pinned `golang.org/x/tools
   v0.34.0`, but gnark v0.16.3 and gnark-crypto v0.21.0 require v0.48.0.
   Minimal version selection picks v0.48.0, which had no `go.sum` entry, so
   every package importing `go/packages` failed to build. The `quality` workflow
   is red on `main` and on both open Dependabot PRs. **Fixed on this branch**
   with `go mod tidy`; `go vet` and the full test suite pass afterwards.
2. **Deprecated `api.NewHint` calls are invisible to the analyzer.** The
   analyzer matches only `frontend.Compiler.NewHint`, but gnark v0.16.3 still
   exposes the deprecated `frontend.API.NewHint` shortcut (`frontend/api.go:146-148`).
   A probe circuit that uses `api.NewHint`, has the exact missing-`r < d` bug,
   and also carries a `gnark:"public"` tag typo produced **0 hints and 0
   findings** (exit 0). This is the same class of silent gap as o1js-scan's
   `extends TokenContract` miss (fixed in its 0.20.0). It is the first item of
   Phase 1.

## 2. What o1js-scan does, feature by feature

| Capability | o1js-scan | gnark-safety today |
|---|---|---|
| Install | `pip`/`pipx`/`npm`, versioned 0.20.0 | `go run` from a checkout; no tool version |
| CI integration | Composite GitHub Action: SARIF upload, severity gate, env-passed inputs, one argument array for report and gate | None |
| Rules | 29 (18 o1js, 11 Noir), each with documented false-positive guards and limits | 2: `GNARK_HINT_RELATION_INCOMPLETE` (high), `GNARK_HINT_OUTPUT_UNUSED` (review) |
| Rule metadata | Single registry, which renders the README tables, `docs/rules.md`, and SARIF metadata; tests fail on drift | Hard-coded `RuleHelp` switch plus hand-written prose |
| Severity | critical/high/medium/low/info; `--fail-on` at any level; `--strict` | high/review; `--fail-on high\|none` |
| Scan hygiene | Test code excluded; example code downgraded to LOW; an empty scan exits 2 unless `--allow-empty`; a stderr summary always states coverage | Tests are excluded implicitly by `go/packages`. No example policy, so the repo's own demo fails its default gate. A package set with no gnark code reports "No findings." and exits 0 |
| Suppression | `o1js-scan-disable-line` / `-next-line` directives, optionally per rule | None |
| SARIF | Registry-driven rule metadata, `helpUri`, `security-severity`, tool version, skip counts under `invocation.properties` | Rule description is copied from the first finding's message; `driver.version` is the schema version |
| Library API | `analyze_file`, `analyze_project` | `internal/analyzer`, which other modules cannot import; only `pkg/report` is public |
| Test corpus | 56 `tp_*`/`fp_*` fixtures with recall annotations | One relation testdata package plus the inventory fixtures |
| Robustness tests | Metamorphic (formatting-neutral rewrites with a committed known-fragile manifest), snapshot, executed README transcripts, docs consistency, action contract | Unit and CLI tests; fuzzing of the hint |
| Calibration | Weekly upstream canaries; release matrix across framework versions; held-out benchmarks with labels frozen in git before scanning; recall study against a published audit (Veridise) | Audit reports cited qualitatively in `docs/security-roadmap.md` |
| Project hygiene | CHANGELOG, CONTRIBUTING (including a disclosure embargo rule), false-positive issue template, privacy guide, release preflight that checks version = tag | SECURITY.md; release evidence workflow |

gnark-safety strengths to keep; o1js-scan has none of these:

- **Type-resolved matching** through `go/packages` and `go/types`.
- **Independent per-output invariants** (participation, range, relation,
  canonicality, field safety), where `unknown` is kept distinct from `missing`.
- **Executable ground truth.** `solver.OverrideHint` mutation suites,
  differential tests against an ordinary-Go specification, and a
  Groth16/PLONK × BN254/BLS12-381 proof matrix.
- **Release evidence**: SBOM, SARIF, source hashes, toolchain metadata,
  retained test output.
- **Scanner resource ceilings** and an untrusted-input scanning guide.
- **CI analysis**: staticcheck, govulncheck, race tests, fuzzing, and SHA-pinned
  actions.

## 3. Design decisions

**D1. Keep type-aware analysis; build rules on `golang.org/x/tools/go/analysis`.**
Each rule becomes an `*analysis.Analyzer`. That brings four things almost for
free:

- `analysistest` fixtures with `// want "GNARK_…"` annotations, the Go-native
  equivalent of o1js-scan's `tp_`/`fp_` corpus;
- `go vet -vettool` and `multichecker` binaries;
- `buildssa` for def-use and phi-node dataflow in Wave 2;
- a later golangci-lint module plugin.

`go/analysis/checker` (present in x/tools v0.48.0) can drive the analyzers
programmatically, so the `gnark-safety` CLI and the versioned `pkg/report`
schema remain the product front door. The trade-off stays documented: analysis
needs a package that compiles and dependencies that resolve. Load failures
already exit 2 and must keep doing so.

**D2. One rule registry.** Add `internal/rules/registry.go` with ID, title,
severity spread, taxonomy class, description, limitations, and gnark API
evidence. A `go generate` step renders the README rule table, `docs/rules.md`,
`explain` text, and SARIF rule metadata. A test fails when any rendering drifts
or when an emitted rule ID is missing from the registry, in either direction.
Rule IDs are never renamed; retired IDs remain as documented aliases.

**D3. Severity model.** Adopt critical/high/medium/low/info. Map the current
`review` severity to `medium`. Map severities to SARIF `level` and
`security-severity` using o1js-scan's buckets. This changes the JSON contract,
so ship it as report schema 2.0 with a migration note. The project is pre-1.0;
dual-emitting both schemas is not worth the complexity.

**D4. Repository layout.** Move the educational circuits and their tests into
`examples/divmod/`. Split `VulnerableCircuit` and `CorrectedCircuit` so a scan
of each reproduces the headline transcript (vulnerable: HIGH, exit 1;
corrected: clean, exit 0). The root package then stops failing the tool's own
gate. `gnark-hint-scan` becomes `gnark-safety inventory` and the old binary is
kept for one release with a deprecation notice. The analyzer moves to an
importable `pkg/` path to provide a library API.

**D5. Scan hygiene, adapted to Go conventions:**

- **Tests:** `_test.go` files are excluded by default; `--include-tests` sets
  `packages.Config.Tests`. `testdata/` and `_`-prefixed directories are already
  ignored by `./...`.
- **Examples:** findings under `example/`, `examples/`, or `_examples/` are
  downgraded to low with a note. `--include-examples` restores the original
  severity.
- **Empty scan:** exit 2 when no loaded package imports
  `github.com/consensys/gnark/frontend`, unless `--allow-empty` is passed.
- **Summary line:** always written to stderr, for example `N finding(s) [1
  high] in X of Y circuit package(s); Z Define method(s); K suppressed —
  fails (--fail-on high)`.

**D6. Suppressions.** Accept `//gnark-safety:ignore RULE_ID reason`, following
the `//lint:ignore` directive convention, on the flagged line or the line above
it. A reason is required. Emit suppressed results as SARIF `suppressions` of
kind `inSource`, rather than dropping them, so code scanning keeps an audit
trail. o1js-scan drops suppressed findings entirely, so this is an improvement.

**D7. Distribution.**

- `go install github.com/auditinfra-io/gnark-safety/cmd/gnark-safety@vX.Y.Z`
  becomes the primary install.
- GoReleaser binaries with checksums are folded into the existing
  release-evidence bundle.
- A root `action.yml` composite action mirrors o1js-scan's contract:
  - inputs: `path`, `version`, `fail-on`, `upload-sarif`, `include-tests`,
    `include-examples`, and `field`;
  - inputs pass through `env`, never through `${{ }}` interpolation into
    scripts;
  - the report and the gate are built from one argument array;
  - the reporting pass runs at `--fail-on none`, and the gate runs as a
    separate step.

  The action also has to run `actions/setup-go` and `go mod download` for the
  target module, and its README section must state that network access is
  needed.
- A pre-commit recipe.

**D8. Version identity.** Read the version from `debug.ReadBuildInfo`, with an
ldflags override for release binaries. Add a `--version` flag. SARIF
`driver.version` becomes the tool version, with `informationUri` and per-rule
`helpUri` anchors into `docs/rules.md`. A release preflight fails when the tag
and the embedded version disagree.

## 4. Rule catalog roadmap

Rules are grouped by the taxonomy in o1js-scan's
`docs/missing-constraint-taxonomy.md`:

- **unbound witness**
- **non-load-bearing predicate**
- **unverified proof edge**
- **unpinned commitment**
- **configuration**, meaning a proof-system or compile setting that
  weakens soundness

The o1js-scan analog is listed so behavior and false-positive guards can be
ported deliberately.

### Wave 1: type-level, high precision, no dataflow

| Proposed ID | Class | Severity | Detection | gnark v0.16.3 evidence | o1js-scan analog |
|---|---|---|---|---|---|
| `GNARK_TAG_VISIBILITY_AS_NAME` | unbound witness | high (`public`) / info (`secret`) | Struct tag `gnark:"public"` without the leading comma. `parseTag` takes `public` as the witness *name*, so the field defaults to secret: a value the verifier meant to fix becomes prover-chosen | `frontend/schema/tags.go:98-101`, `walk.go:195-215` | `NOIR_UNCONSTRAINED_PUBLIC_INPUT` (dual) |
| `GNARK_GO_EQUALITY_ON_VARIABLE` | non-load-bearing predicate | high | Go `==`/`!=`/`switch` with a `frontend.Variable` operand in circuit code. `Variable` is `any`, so this compares Go interface values at compile time, never the witness. Guard: comparisons with `nil` | `frontend/variable.go:13` | `O1JS_CONDITIONAL_ASSERT` |
| `GNARK_DISCARDED_PREDICATE` | non-load-bearing predicate | high | Bare-statement or `_ =` result of `IsZero`, `Cmp`, `cmp` `IsLess`/`IsLessEq`, recursion `IsValidProof`, or hasher `Sum`. Go already rejects unused locals, so only these forms remain | `frontend/api.go:102-109`; `std/recursion/groth16/verifier.go:531` | `O1JS_UNASSERTED_BOOL`, `NOIR_UNUSED_CHECK_RESULT` |
| `GNARK_VACUOUS_ASSERT` | non-load-bearing predicate | high (self-comparison) / medium (constants) | `AssertIsEqual(x, x)`, `AssertIsLessOrEqual(x, x)`, or assertions whose operands are all constants | `frontend/api.go` | `O1JS_VACUOUS_ASSERT` |
| `GNARK_BITS_UNCONSTRAINED` | unbound witness | high / medium | `bits.WithUnconstrainedOutputs()` whose digits never reach a boolean or digit constraint; `bits.WithUnconstrainedInputs()` on digits with no boolean evidence | `std/math/bits/conversion.go:80-100` | `O1JS_UNCONSTRAINED_PROVABLE_WITNESS` |
| `GNARK_BITS_OMIT_MODULUS_CHECK` | unbound witness | medium | `bits.OmitModulusCheck()`: full-width decompositions become non-unique (`a` versus `a+r`) | `std/math/bits/conversion.go:103-118` | `MissingRangeCheck` |
| `GNARK_COMPARATOR_NONDETERMINISTIC` | unbound witness | medium; high without operand range evidence | `cmp.NewBoundedComparator(api, bound, true)`: past the bound, the constraint system "may have multiple solutions" | `std/math/cmp/bounded.go:42-71` | none |
| `GNARK_IGNORE_UNCONSTRAINED_INPUTS` | configuration | medium | `frontend.IgnoreUnconstrainedInputs()` in non-test code disables gnark's own unconstrained-input compile error ("should not be used in production") | `frontend/compile.go:208-221` | `O1JS_WEAK_PERMISSIONS` |
| `GNARK_UNSAFE_SETUP` | configuration | medium | A non-test import of `test/unsafekzg` (a test-only SRS). Single-party `groth16.Setup` in a `main` package is reported at low | `test/unsafekzg` | `O1JS_WEAK_PERMISSIONS` |

### Wave 2: intraprocedural dataflow (SSA)

| Proposed ID | Class | Severity | Detection | Evidence | Analog |
|---|---|---|---|---|---|
| `GNARK_HINT_OUTPUT_UNCONSTRAINED` (supersedes `GNARK_HINT_OUTPUT_UNUSED`) | unbound witness | high native / medium emulated | A hint output never reaches an assertion sink (`Assert*`, `ToBinary`, `rangecheck` `Check`, comparator asserts). Covers `Compiler.NewHint`, deprecated `API.NewHint`, and `emulated.Field.NewHint*`/`NewHintGeneric`. Emulated outputs get limb range checks but no relation, hence the lower severity. This computes the `participation` invariant in general | `frontend/api.go:146-148`, `frontend/builder.go:59`, `std/math/emulated/field_hint.go:84,113,142,450` | `NOIR_UNCONSTRAINED_WITNESS` |
| `GNARK_HINT_RELATION_INCOMPLETE` (existing) | unbound witness | high | Keep the rule. Add call-site specialization of helper summaries on constant arguments, so `constrainDivision(…, false)` is reported at the vulnerable caller and not at the shared helper | `circuits.go` | — |
| `GNARK_DIV_UNCHECKED_ZERO` | unbound witness | medium | `api.DivUnchecked(a, b)` with no nonzero evidence for `b` (`AssertIsDifferent(b, 0)`, or `b` known to be a nonzero constant) | `frontend/api.go:41-53`: "undetermined" when `b == 0` | none |
| `GNARK_GUARDED_INVERSE` | liveness | medium | `Inverse`/`Div` of `x` inside a `Select` guarded by `IsZero(x)`. Both branches are evaluated, and the constraint is unsatisfiable at zero | `frontend/api.go:55-61, 92-94` | `O1JS_GUARDED_INVERSE` (Veridise V-O1J-VUL-060) |
| `GNARK_LOGIC_IN_HINT` | non-load-bearing predicate | low / medium | A `solver.Hint` body rejects inputs (returns an error) on a predicate that the circuit never asserts. Only the honest prover runs that check. Start with zero checks mapped to `AssertIsDifferent(x, 0)` | `hints.go` (the repo's own hint) | `O1JS_LOGIC_OUTSIDE_PROOF` |

### Wave 3: gnark std semantic edges (interprocedural; calibrate before shipping)

| Proposed ID | Class | Severity | Detection | Evidence | Analog |
|---|---|---|---|---|---|
| `GNARK_RECURSION_PROOF_UNVERIFIED` | unverified proof edge | high | A circuit field of type recursion `Proof[…]` with no reachable `AssertProof`/`AssertSameProofs`/`AssertDifferentProofs`, or an `IsValidProof` result that is never asserted | `std/recursion/groth16/verifier.go:521,531`; `std/recursion/plonk/verifier.go:928,943,976` | `O1JS_UNVERIFIED_PROOF` |
| `GNARK_RECURSION_VK_UNPINNED` | unpinned commitment | high / medium | A `VerifyingKey` supplied as a witness rather than fixed (`ValueOfVerifyingKeyFixed`, `gnark:"-"`) and not bound to a public commitment, so the prover picks the circuit being verified | `groth16/verifier.go:140,292`; `plonk/verifier.go:233-270` | `O1JS_STALE_MERKLE_ROOT` |
| `GNARK_MERKLE_ROOT_UNBOUND` | unpinned commitment | high | `merkle.MerkleProof.VerifyProof` checks against `mp.RootHash`, but `RootHash` is a secret witness that is never tied to a public input or constant | `std/accumulator/merkle/verify.go:41-44, 78-95` | `O1JS_STALE_MERKLE_ROOT` |
| `GNARK_HASHER_REUSED` | correctness | low | A `hash.FieldHasher` used for a second `Sum` without `Reset` | `std/hash` | none |

Research only; no rule until a precise shape exists:

- Fiat–Shamir completeness of `frontend.Committer.Commit` inputs.
- Emulated-field reduction assumptions (`Reduce` versus strict reduction).
- Integer underflow through `api.Sub` without range evidence (a ZKSecurity
  std-audit theme).

Not applicable to gnark, recorded so nobody ports it by mistake:

- **Witness-indexed arrays** (`NOIR_UNCONSTRAINED_ARRAY_INDEX`). Go cannot index
  a slice with a `frontend.Variable`; selection goes through
  `selector`/`logderivlookup`, which constrain the index.
- **Mina account rules** (preconditions, permissions, sender).
- **Unused public inputs.** gnark already refuses to compile these unless
  `IgnoreUnconstrainedInputs` is set, which `GNARK_IGNORE_UNCONSTRAINED_INPUTS`
  covers.

**Rule acceptance criteria**, stricter than o1js-scan's. Every rule ships with:

- a registry entry;
- at least one `analysistest` true-positive fixture and one false-positive
  guard fixture;
- metamorphic coverage;
- a canary run with every new finding classified;
- for high rules, an **executable witness**: a solver test using
  `OverrideHint` (or a crafted assignment) that shows the true-positive fixture
  accepts a semantically invalid witness and the corrected fixture rejects it.
  No other scanner in this family can offer this.

## 5. Testing and calibration program

1. **Corpus.** Add `internal/…/testdata/src/<rule>/{tp,fp}_*.go` driven by
   `analysistest`, reusing o1js-scan's naming so cross-project comparisons stay
   readable.
2. **Metamorphic suite.** Apply semantics-preserving rewrites:
   - an import alias;
   - a method value (`nh := api.Compiler().NewHint`);
   - extraction into a local or a helper;
   - swapped commutative operands;
   - an added parenthesis;
   - `gofmt -r` rewrites.

   The reported `(rule, severity, function)` set must not change. Commit an
   `ENFORCED` list and a `KNOWN_FRAGILE` manifest; a new gap and an unrecorded
   fix both fail the test.
3. **Snapshot and documentation tests.**
   - Golden JSON and SARIF output.
   - A test that executes every README console transcript and compares the
     output.
   - Rule tables checked against the registry.
   - Action inputs checked against `action.yml`.
4. **Upstream canaries** (weekly and `workflow_dispatch`, uploaded as
   artifacts, each with a classified finding budget):
   - gnark's own `std/` at the pinned release and at HEAD; the expectation is 0
     unclassified high findings in non-test code;
   - public gnark applications, **selected by `go.mod` dependency on
     `github.com/consensys/gnark`**, not by grepping for APIs the analyzer
     keys on. o1js-scan's v2 corpus found the `TokenContract` blind spot only
     after it stopped selecting by the analyzer's own match string.
5. **Release matrix.** Scan gnark `std/` at v0.15.0 and v0.16.3. Snapshot the
   findings and pin the delta in a fixture test. The v0.12.0–v0.16.3 range
   covers the deprecation of `API.NewHint`.
6. **Held-out benchmark.** Label vulnerable/fixed commit pairs from public gnark
   circuit fixes in a `manifest.json` commit that contains no results. Results
   land in a child commit. Record predicted false positives in advance.
7. **Audit recall.** gnark ships five audit reports in `audits/`:
   - Kudelski, 2022-10;
   - Sigma Prime KZG, 2024-05;
   - zkSecurity std, 2024-05;
   - Least Authority arithmetic/GKR, 2024-09;
   - Least Authority Linea zkEVM, 2024-11.

   State the scope before measuring. Most of these findings are
   library-internal, and only application-shaped findings count toward recall.
   Record null results rather than discarding them, as o1js-scan's
   `research/veridise-recall` does.

## 6. Documentation and community

- **README rewrite**, leading with `go install`, a vulnerable/fixed console
  transcript, and the rule table. Move the educational narrative to
  `examples/divmod/README.md`. Add "Known limitations" and "Where this tool
  stops" sections.
- **CONTRIBUTING.md**, including:
  - how to add a rule;
  - the rule that documentation is tested;
  - release steps;
  - **the third-party disclosure embargo**, which the canaries make necessary:
    a finding in someone else's project stays out of this repository,
    including commit messages, until its maintainers clear publication.
- **CHANGELOG.md** in Keep a Changelog format.
- **Issue templates** for false positives and missed detections.
- **`docs/privacy.md`**: local-only analysis, and how to build synthetic
  reproducers.
- **Taxonomy doc:** link to o1js-scan's taxonomy and map each gnark rule to its
  class, rather than duplicating the essay.

## 7. Phases and exit criteria

**Phase 0: unbreak and re-baseline** (partly done on this branch)

- [x] `go mod tidy`: x/tools v0.48.0 and the missing `go.sum` entries. vet and
  tests pass.
- [ ] Regenerate `evidence/`: 5 of its 9 hashed files, including `go.mod` and
  `go.sum`, no longer match. Add a CI check so stale evidence fails the build
  instead of drifting.
- [ ] Rebase or close Dependabot PRs #7 and #8 once `main` is green.

**Phase 1 (v0.1.0): productize what exists**

- Match `frontend.API.NewHint`, and add the probe circuit above as a regression
  fixture. Resolve hint calls through method values and interface embedding by
  type rather than by receiver name.
- D2 registry, D3 severities and schema 2.0, D4 layout, D5 hygiene, D6
  suppressions, D8 version identity, and the SARIF upgrade.
- Call-site specialization so the flagship pair reports vulnerable → HIGH,
  exit 1, and corrected → clean, exit 0.
- **Exit criteria:** both headline transcripts are executed by a test; a
  self-scan passes at the default gate; the registry-drift test is green.

**Phase 2 (v0.2.0): distribution**

- `action.yml` with a contract test, GoReleaser binaries in the evidence bundle,
  a pre-commit recipe, and a documented `go vet -vettool` path.
- **Exit criteria:** a sample repository's workflow uploads SARIF and gates on
  high, and the action contract test runs in CI.

**Phase 3 (v0.3.0): Wave 1 rules and canary infrastructure**

- Nine rules, the corpus, and the metamorphic suite; the gnark `std/` canary
  and release matrix.
- **Exit criteria:** every Wave 1 finding on gnark `std/` is classified, with 0
  unclassified high findings, and every high rule has an executable witness.

**Phase 4 (v0.4–0.6): Wave 2 and Wave 3 rules and calibration**

- SSA dataflow, generalized invariants, std semantic rules, the application
  canary corpus, the held-out benchmark, and the audit-recall study.
- **Exit criteria:** a published calibration document with classified budgets,
  and a held-out result committed after its frozen labels.

The phases are ordered so calibration infrastructure (Phase 3) lands before the
bulk of the rules. The o1js-scan record shows the corpus finds the blind spots.

## 8. Decisions for the owner

1. **License.** gnark-safety is MIT. o1js-scan and gnark are Apache-2.0.
   Aligning with Apache-2.0 simplifies reuse of gnark examples in fixtures.
2. **Name.** Recommendation: keep `gnark-safety` (existing links and history)
   rather than rename to `gnark-scan`. A `gnark-scan` alias binary is cheap if
   symmetry matters.
3. **Schema 2.0 in Phase 1**, versus additive severities under 1.x.
   Recommendation: 2.0 now, while pre-1.0.
4. **Headline.** Whether to demote the educational demo to `examples/`.
   Recommendation: yes, because a scanner's README should lead with the scanner.
5. **Deeper-analysis pointer.** Whether to include an
   `audit-engine-cli` pointer as o1js-scan does.
