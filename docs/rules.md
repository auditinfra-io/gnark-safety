# Rules

Every rule `gnark-safety` can emit. The summary table and the per-rule
reference below are generated from the registry in
[`internal/rules`](../internal/rules/rules.go) by `go generate
./internal/rules`; edit the registry, not the generated blocks. SARIF
`helpUri` values link to the rule headings on this page.

A quiet scan means no shape these rules recognize matched. It is not
evidence that a circuit is sound.

## Summary

<!-- BEGIN GENERATED RULE TABLE -->
| Rule | Severity | Class | What it means |
|---|---|---|---|
| [`GNARK_HINT_RELATION_INCOMPLETE`](https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md#gnark_hint_relation_incomplete) | high | unbound witness | A two-output hint is reconstructed as `n = q*d + r`, but no unconditional `r < d` bound makes the quotient and remainder unique, so the prover can supply a noncanonical pair that still satisfies the circuit. |
| [`GNARK_HINT_OUTPUT_UNUSED`](https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md#gnark_hint_output_unused) | medium | unbound witness | A hint output is extracted from the returned slice but never referenced again. An unused prover-computed value often means a forgotten constraint, but it can also be intentional padding, so the rule asks for review. |
<!-- END GENERATED RULE TABLE -->

## Rule reference

<!-- BEGIN GENERATED RULE REFERENCE -->
### GNARK_HINT_RELATION_INCOMPLETE

**Incomplete hint relation**: severity high; confidence high; class unbound witness.

A two-output hint is reconstructed as `n = q*d + r`, but no unconditional `r < d` bound makes the quotient and remainder unique, so the prover can supply a noncanonical pair that still satisfies the circuit.

Identifies a direct, type-resolved two-output `NewHint` call (`Compiler.NewHint` or the deprecated `API.NewHint`) when one `AssertIsEqual` contains the typed `Add(Mul(q, d), r)` reconstruction but the function has no unconditional, type-resolved `AssertIsLess(r, d)` or equivalent `AssertIsLessOrEqual(r, api.Sub(d, 1))`. Indexed outputs may use literals, named constants, constant expressions, or local aliases. Comparisons with the wrong operand order or a different bound do not count as coverage. A comparison inside an `if`/`else`, loop, switch, select, or function literal, or after a successful early return, is not universal coverage because that region may not execute. The finding points to the hint call and records the hint identity, the observed reconstruction, and the missing canonical bound as evidence. When the bound runs only under `if p` (or `!p`, or in the `else` branch) for a bool parameter `p` that the function never reassigns, and every use of the function in its package is a direct call with a constant for `p`, the finding moves to each call that disables the bound, and calls that enable it are not reported. A shared helper therefore reports the vulnerable caller rather than the helper.

*Where it stops:* One level of unconditional, direct, package-local helper calls is summarized. Deeper, recursive, external, or dynamically dispatched helpers, other aliasing, and alternative comparison gadgets remain unknown. Algebraically neutral wrappers such as `Sub(x, 0)` are not simplified. Call-site specialization needs every use of the function to be a direct call in the same package with a constant guard; an escaping function value, a runtime argument, a method expression, or callers in other packages keep the finding at the hint. A quiet result is not evidence of soundness.

### GNARK_HINT_OUTPUT_UNUSED

**Unused hint output**: severity medium; confidence high; class unbound witness.

A hint output is extracted from the returned slice but never referenced again. An unused prover-computed value often means a forgotten constraint, but it can also be intentional padding, so the rule asks for review.

Reports a statically indexed hint output that is extracted from the slice returned by `NewHint` but never subsequently referenced, either directly or through its local alias. Every hint output is prover-controlled advice; one that reaches no constraint contributes nothing the verifier can rely on.

*Where it stops:* Only statically indexed outputs and their local aliases are tracked. Dynamic indexes, outputs passed through slices or struct fields, and complex aliasing remain unknown.
<!-- END GENERATED RULE REFERENCE -->

## Suppressing a reviewed finding

Write `//gnark-safety:ignore RULE_ID[,RULE_ID...] reason` on the flagged line
or on the line directly above it. Following Go's directive convention there
is no space after `//`. The reason is required and is recorded as the SARIF
suppression justification.

The directive never hides anything by accident:

- a finding it matches moves to the report's `suppressed` list, does not count
  toward `--fail-on`, and is emitted in SARIF with an `inSource` suppression;
- a directive with no reason, an unknown rule ID, or a space after `//`
  suppresses nothing and produces a warning;
- a directive that matches no finding produces a warning, so stale
  suppressions surface after the code they covered changes.

## Severity scale

Report schema 2.0 uses five levels. The CLI gate (`--fail-on`) and SARIF
output derive from the same values:

| Severity | SARIF level | GitHub `security-severity` |
|---|---|---|
| `critical` | `error` | 9.5 |
| `high` | `error` | 8.0 |
| `medium` | `warning` | 5.0 |
| `low` | `note` | 3.0 |
| `info` | `note` | 1.0 |

Schema 1.x used `high` and `review`. `review` became `medium`.

## Per-output invariant assessments

Every hint in the JSON report carries an `invariants` array. Each output
receives separate `participation`, `range`, `relation`, `canonicality`, and
`field_safety` assessments. Status is one of `satisfied`, `missing`, or
`unknown`; only `missing` means the analyzer recognized the applicable shape
and established that the required direct constraint was absent.

For the quotient/remainder shape, an unconditional constant-width `ToBinary`
provides range evidence, the reconstruction provides participation/relation
evidence, and an unconditional `r < d` provides canonicality evidence. The
analyzer calculates the bounded maximum of `q*d+r`, but reports field safety as
unknown because the circuit's compilation field is not selected inside the
analyzed function. Passing `--field bn254` or `--field bls12-381` compares that
maximum with the selected scalar-field modulus and reports field safety as
`satisfied` or `missing`. This does not change the missing-canonicality finding:
field non-wraparound and uniqueness of integer quotient/remainder are separate
properties.

The reconstruction matcher deliberately requires the normalized
`Add(Mul(q,d),r)` shape, with commutative operand order. Algebraically neutral
wrappers such as `Sub(x,0)` or `Mul(1,x)` remain unsupported instead of being
simplified speculatively.
