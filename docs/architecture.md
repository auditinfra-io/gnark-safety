# Analyzer architecture

The experimental analyzer is split at stable data boundaries:

1. `internal/analyzer` loads requested roots with `go/packages`, uses type
   information to distinguish gnark's `frontend.Compiler.NewHint` from
   unrelated methods, extracts hint metadata, and applies the initial
   conservative syntax rule.
2. `pkg/report` is the public, versioned report model. Unknown hint metadata is
   represented explicitly by the `unknown` list rather than guessed.
3. `internal/output` renders the same report as text, JSON, or SARIF 2.1.0.
4. `cmd/gnark-safety` owns argument validation, output destinations, and the
   deterministic exit policy.

The current pass is intra-function. It does not model reflection, generated
code, opaque helpers, complex aliases, or dynamic hint selection. These limits
are emitted in every report. Later dataflow and call-graph passes can consume
the report model without changing the command-line schema.
