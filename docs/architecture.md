# Analyzer architecture

The experimental analyzer is split at stable data boundaries:

1. `internal/analyzer` loads requested roots with `go/packages`, uses type
   information (through `internal/gnarkapi`) to distinguish gnark's
   `frontend.Compiler.NewHint` and deprecated `frontend.API.NewHint` from
   unrelated methods, extracts hint metadata, and applies the initial
   conservative syntax rule.
2. `internal/rules` is the rule registry: IDs, titles, severity spreads,
   taxonomy classes, descriptions, and limitations. `explain`, SARIF rule
   metadata, and the generated sections of `README.md` and `docs/rules.md`
   are rendered from it, and tests fail when the docs or the emitted rules
   drift from it.
3. `pkg/report` is the public, versioned report model. Unknown hint metadata is
   represented explicitly by the `unknown` list rather than guessed. Schema
   2.0 records the tool identity, a five-level severity scale, and per-output
   invariant assessments; `unknown` is distinct from `missing` so unsupported
   analysis never claims a missing constraint.
4. `internal/output` renders the same report as text, JSON, or SARIF 2.1.0.
5. `cmd/gnark-safety` owns argument validation, output destinations, and the
   deterministic exit policy.

The current pass follows one level of direct, package-local helper calls for
recognized bounds. When a bound is guarded by a bool parameter, it also
resolves that parameter at every package-local call site with a constant
argument and reports the calls that disable the bound (see
`internal/analyzer/specialize.go`). It does not model reflection, generated code, external or
recursive helpers, complex aliases, or dynamic hint selection. These limits
are emitted in every report. Later dataflow and deeper call-graph passes can
consume the report model without changing the command-line schema.

`ScanContext` carries cancellation through `go/packages` and the AST walk and
applies a hint-call ceiling. The CLI adds a wall-clock deadline and renders into
a size-limited buffer before writing output. These controls bound application
behavior cooperatively; only an external sandbox can impose hard process,
memory, filesystem, and network limits on the Go subprocess.

For a recognized quotient/remainder reconstruction, the analyzer evaluates
participation, range, relation, canonicality, and field safety independently.
It records direct constraint evidence and calculates the maximum bounded
reconstruction value. Field safety remains `unknown` because the compilation
field is chosen by the caller outside `Define`; consumers must not reinterpret
that status as either safe or vulnerable. A CLI field selection supplies the
modulus explicitly and enables the comparison without guessing from imports or
hint provenance.

Hint identities are provenance evidence, not a trust decision. The analyzer
does not maintain a “known-good” hint allowlist because gnark hint results are
advice regardless of which function computes them; circuit constraints, not
the implementation name, establish the proved relation.
