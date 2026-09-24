# Analyzer architecture

The experimental analyzer is split at stable data boundaries:

1. `internal/analyzer` loads requested roots with `go/packages`, uses type
   information to distinguish gnark's `frontend.Compiler.NewHint` from
   unrelated methods, extracts hint metadata, and applies the initial
   conservative syntax rule.
2. `pkg/report` is the public, versioned report model. Unknown hint metadata is
   represented explicitly by the `unknown` list rather than guessed. Schema
   1.1 also records per-output invariant assessments; `unknown` is distinct
   from `missing` so unsupported analysis never claims a missing constraint.
3. `internal/output` renders the same report as text, JSON, or SARIF 2.1.0.
4. `cmd/gnark-safety` owns argument validation, output destinations, and the
   deterministic exit policy.

The current pass follows one level of direct, package-local helper calls for
recognized bounds. It does not model reflection, generated code, external or
recursive helpers, complex aliases, or dynamic hint selection. These limits
are emitted in every report. Later dataflow and deeper call-graph passes can
consume the report model without changing the command-line schema.

For a recognized quotient/remainder reconstruction, the analyzer evaluates
participation, range, relation, canonicality, and field safety independently.
It records direct constraint evidence and calculates the maximum bounded
reconstruction value. Field safety remains `unknown` because the compilation
field is chosen by the caller outside `Define`; consumers must not reinterpret
that status as either safe or vulnerable.
