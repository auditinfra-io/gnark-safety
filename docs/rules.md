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

## Rule reference

<!-- BEGIN GENERATED RULE REFERENCE -->
### GNARK_HINT_RELATION_INCOMPLETE

**Incomplete hint relation**: severity high; confidence high; class unbound witness.

A two-output hint is reconstructed as `n = q*d + r`, but no unconditional `r < d` bound makes the quotient and remainder unique, so the prover can supply a noncanonical pair that still satisfies the circuit.

Identifies a direct, type-resolved two-output `NewHint` call (`Compiler.NewHint` or the deprecated `API.NewHint`) when one `AssertIsEqual` contains the typed `Add(Mul(q, d), r)` reconstruction but the function has no unconditional, type-resolved `AssertIsLess(r, d)` or equivalent `AssertIsLessOrEqual(r, api.Sub(d, 1))`. Indexed outputs may use literals, named constants, constant expressions, or local aliases. Comparisons with the wrong operand order or a different bound do not count as coverage. When `d` is known at compile time (a constant, `math.Pow(2, k)`, or an unexported package-level `*big.Int` built from a constant that nothing in the package changes), a bound is also accepted when its value proves `r < d`: a constant bound such as `AssertIsLessOrEqual(r, lanes-1)`, a range check of `r` (`api.ToBinary` or a range checker's `Check`), or range-checked limbs that `r` is rebuilt from, `r = hi*2^b + lo`, including the check that forces `lo` to zero when `hi` is all ones (how emulated KoalaBear, BabyBear, and Goldilocks code proves `r < p`). A range check counts when it runs unconditionally or in every branch of an `if`/`else`. A comparison inside an `if`/`else`, loop, switch, select, or function literal, or after a successful early return, is not universal coverage because that region may not execute; the exception is an `if err == nil` block whose other path immediately returns that error, since a failing function yields no constraint system. The finding points to the hint call and records the hint identity, the observed reconstruction, and the missing canonical bound as evidence. When the bound runs only under `if p` (or `!p`, or in the `else` branch) for a bool parameter `p` that the function never reassigns, the function is unexported and not a method, and every use of it in its package is a direct call with a constant for `p`, the finding moves to each call that disables the bound, and calls that enable it are not reported. A shared helper therefore reports the vulnerable caller rather than the helper.

*Where it stops:* One level of unconditional, direct, package-local helper calls is summarized. Deeper, recursive, external, or dynamically dispatched helpers, other aliasing, and alternative comparison gadgets remain unknown. A range check in a switch, or deferred to a later batch (a commit-based range checker's collected checks), is not seen. Value-based evidence assumes a pairing-friendly scalar field and ignores reconstructions wider than 240 bits. An `if err == nil` block counts as unconditional on the assumption that callers propagate the error. Algebraically neutral wrappers such as `Sub(x, 0)` are not simplified. Call-site specialization applies only to unexported plain functions whose every use is a direct call in the same package with a constant guard; exported functions, methods, escaping function values, and runtime arguments keep the finding at the hint. A quiet result is not evidence of soundness.

### GNARK_HINT_OUTPUT_UNUSED

**Unused hint output**: severity medium; confidence high; class unbound witness.

A hint output is extracted from the returned slice but never referenced again. An unused prover-computed value often means a forgotten constraint, but it can also be intentional padding, so the rule asks for review.

Reports a statically indexed hint output that is extracted from the slice returned by `NewHint` but never subsequently referenced, either directly or through its local alias. Every hint output is prover-controlled advice; one that reaches no constraint contributes nothing the verifier can rely on.

*Where it stops:* Only statically indexed outputs and their local aliases are tracked. Dynamic indexes, outputs passed through slices or struct fields, and complex aliasing remain unknown.

### GNARK_TAG_VISIBILITY_AS_NAME

**Visibility written as a witness name**: severity high / info; confidence high; class unbound witness.

A struct tag such as `gnark:"public"` names the witness element `public` instead of setting its visibility, so the field stays secret: a value the verifier meant to fix becomes one the prover chooses.

gnark parses `gnark:"name,options"` like `encoding/json`: the text before the first comma is the witness name and visibility is an option after it. `gnark:"public"` therefore names the element "public" and leaves it at the default visibility, secret, so it is absent from the public witness and the verifier cannot pin it. The fix is `gnark:",public"`. High for `public`. The same mistake with `secret` is reported as info, because the field is secret either way and only the name is surprising. Evidence: gnark v0.16.3 `frontend/schema/tags.go` `parseTag` and `walk.go`.

*Where it stops:* Only tags whose name part is exactly `public` or `secret` are matched. Visibility inherited from a parent struct is not evaluated.

### GNARK_GO_EQUALITY_ON_VARIABLE

**Go comparison of a circuit variable**: severity high; confidence high; class non-load-bearing predicate.

Go `==`, `!=`, or `switch` on a `frontend.Variable` compares the value the variable holds while the circuit is being compiled, a constraint expression rather than the witness, so the branch it guards is not a constraint.

`frontend.Variable` is `any`. During `frontend.Compile` it holds a linear expression, not the prover's value, so `if c.Flag == 1 { api.AssertIsEqual(...) }` is decided once at compile time (the comparison is false) and the guarded constraint is never emitted. Express conditions in the circuit instead, for example with `api.IsZero`, `api.Select`, or `api.Mul(flag, ...)`. Comparisons with `nil`, fields tagged `gnark:"-"` (which hold Go constants at compile time), and local variables or slices that only ever hold Go constants (a padding mask built with `make` and constant stores, never passed on whole) are not reported. Evidence: gnark v0.16.3 `frontend/variable.go`.

*Where it stops:* Only direct comparisons and switch tags are matched; a Variable converted to another type first, or compared through a helper, is not.

### GNARK_DISCARDED_PREDICATE

**Discarded predicate**: severity high; confidence high; class non-load-bearing predicate.

The result of a gnark predicate (`IsZero`, `Cmp`, a bounded comparator's `IsLess`/`IsLessEq`, a recursive verifier's `IsValidProof`, or a hash `Sum`) is discarded, so the check it computes constrains nothing.

Predicates return a variable; they do not assert anything. A call used as a statement, or assigned only to `_`, computes a value the circuit never uses, so the line reads as a check that does not exist. Assert the result (`api.AssertIsEqual(api.IsZero(x), 1)`), use the assertion form, or feed it into later constraints. Go already rejects unused local variables, so these are the forms that compile. Evidence: gnark v0.16.3 `frontend/api.go` (`IsZero`, `Cmp`), `std/math/cmp/bounded.go`, `std/recursion/groth16/verifier.go` (`IsValidProof`), and `std/hash/hash.go`.

*Where it stops:* A result stored and then never read, or discarded through a helper, is not matched.

### GNARK_VACUOUS_ASSERT

**Vacuous assertion**: severity high / medium; confidence high; class non-load-bearing predicate.

An assertion that holds by construction, such as `api.AssertIsEqual(x, x)` or an assertion over constants only, adds no restriction while reading like a check.

High when both sides are the same expression (`AssertIsEqual(x, x)`, `AssertIsLessOrEqual(x, x)`, or a bounded comparator's `AssertIsLessEq(x, x)`); that is almost always a typo for a real check, such as `(computed, expected)` written as `(expected, expected)`. Medium when every operand is a constant and the assertion always holds (`AssertIsEqual(1, 1)`, `AssertIsBoolean(1)`), which is more often a placeholder. Constant assertions that always fail (`AssertIsEqual(1, 0)`) abort compilation on purpose, and ones over `len` or `cap` check the shape of fixed-size arrays, so neither is reported. Unsatisfiable forms such as `AssertIsDifferent(x, x)` are liveness bugs, not vacuous ones, and are not reported.

*Where it stops:* Expressions are compared structurally: the same variable, field path, or constant index. Algebraically equal but differently written operands are not matched.

### GNARK_BITS_UNCONSTRAINED

**Unconstrained bit decomposition**: severity high / medium; confidence medium; class unbound witness.

A `bits` decomposition opts out of digit constraints (`WithUnconstrainedOutputs` or `WithUnconstrainedInputs`) and nothing in the function constrains the digits, so the prover can choose non-boolean digits that still sum to the value.

`bits.ToBinary(api, v, bits.WithUnconstrainedOutputs())` constrains only the weighted sum of the digits; the digits themselves are hint outputs. High when those digits are used in the function but never constrained (`AssertIsBoolean`, `AssertIsCrumb`, `bits.AssertIsTrit`, `api.FromBinary`, or `bits.FromBinary` without the option). Medium for `FromBinary`/`FromBase` with `WithUnconstrainedInputs` whose digits are prover advice (hint outputs or an unconstrained decomposition) with no such constraint. Digits passed to another function, returned, or stored elsewhere may be constrained there, so they are not reported. Evidence: gnark v0.16.3 `std/math/bits/conversion.go`.

*Where it stops:* Options passed through a slice (`opts...`) are not resolved. Constraints in called functions are not followed, so any hand-off silences the rule.

### GNARK_BITS_OMIT_MODULUS_CHECK

**Bit decomposition without modulus check**: severity medium; confidence high; class unbound witness.

`bits.OmitModulusCheck()` skips the comparison against the field modulus, so a full-width decomposition of `a` can also be one of `a + r`: the bits are not unique.

When the number of digits equals the field's bit length, both `a` and `a + r` (for modulus `r`) can have valid decompositions, and gnark's modulus check is what excludes the second. Omitting it is safe only when the decomposition is checked for uniqueness elsewhere or uniqueness does not matter; state which in a suppression. Evidence: gnark v0.16.3 `std/math/bits/conversion.go` `OmitModulusCheck`.

*Where it stops:* The rule does not check the digit count; a decomposition narrower than the field is unique regardless.

### GNARK_COMPARATOR_NONDETERMINISTIC

**Nondeterministic bounded comparator**: severity medium; confidence high; class unbound witness.

`cmp.NewBoundedComparator(api, bound, true)` allows nondeterministic behavior: when the operands differ by more than the bound, the constraint system can have several solutions, so comparison results are prover-selectable.

The third argument `allowNonDeterministicBehaviour` trades soundness outside the bound for fewer constraints. It is sound only when range checks elsewhere guarantee `|a - b| <= bound` for every comparison. Prefer `false`, which makes out-of-bound inputs fail to prove or return a deterministic result. Evidence: gnark v0.16.3 `std/math/cmp/bounded.go`.

*Where it stops:* Only a literal constant `true` is matched. Whether the operands are range-checked is not analyzed.

### GNARK_IGNORE_UNCONSTRAINED_INPUTS

**Unconstrained-input check disabled**: severity medium; confidence high; class configuration.

`frontend.IgnoreUnconstrainedInputs()` disables gnark's compile-time error for inputs that no constraint uses, a check gnark's documentation says should stay on in production.

By default `frontend.Compile` fails when a public or secret input appears in no constraint, which catches inputs the circuit forgot to bind. The option turns that error off. Test code is excluded by default. Evidence: gnark v0.16.3 `frontend/compile.go`.

*Where it stops:* Options assembled dynamically (`opts...`) are not resolved.

### GNARK_UNSAFE_SETUP

**Unsafe setup outside tests**: severity medium / low; confidence high; class configuration.

Production code imports gnark's test-only `unsafekzg` SRS (medium), or runs a single-party `groth16.Setup` in a `main` package (low), so whoever ran setup could forge proofs.

`test/unsafekzg` generates KZG parameters from locally known randomness; it exists for tests. A `groth16.Setup` run by one party leaves that party able to forge proofs unless the output comes from a multi-party ceremony. Both are reported only outside `_test.go` files: the import at its import line, and `groth16.Setup` only in a `main` package, where it most likely produces deployable keys.

*Where it stops:* Whether the resulting keys are actually deployed cannot be seen from source. Key generation in library packages is not reported.
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
