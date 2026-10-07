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
| [`GNARK_RECURSION_WITNESS_UNVERIFIED`](https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md#gnark_recursion_witness_unverified) | high | unverified proof edge | A circuit's `Define` uses the public inputs of a `std/recursion` witness, but no in-circuit verification takes that witness, so the prover can supply any values for them. |
<!-- END GENERATED RULE TABLE -->

## Rule reference

<!-- BEGIN GENERATED RULE REFERENCE -->
### GNARK_HINT_RELATION_INCOMPLETE

**Incomplete hint relation**: severity high; confidence medium; class unbound witness.

A two-output hint is reconstructed as `n = q*d + r`, but no unconditional bound `0 <= r < d` was recognized, so a prover may be able to supply another quotient and remainder that satisfy the same equation.

Identifies a direct, type-resolved two-output `NewHint` call (`Compiler.NewHint` or the deprecated `API.NewHint`) when one `AssertIsEqual` contains the typed `Add(Mul(q, d), r)` reconstruction, with output 0 as `q` and output 1 as `r`, and assumes the hint means Euclidean division: `0 <= r < d`. It then looks, in the same function, for an unconditional bound that proves that in gnark's field arithmetic. A bounded comparator's `AssertIsLess(r, d)` or `AssertIsLessEq(r, api.Sub(d, 1))` (the same constraint) counts only together with a range check of `r`, because the comparator compares signed values and a field element near the modulus encodes a negative `r`. `api.AssertIsLessOrEqual(r, api.Sub(d, 1))` counts only together with `api.AssertIsDifferent(d, 0)` or a known nonzero `d`, because when `d = 0`, `d - 1` is the largest field element. Indexed outputs may use literals, named constants, constant expressions, or local aliases. Comparisons with the wrong operand order or a different bound do not count. When `d` is known at compile time (a constant, `math.Pow(2, k)`, or an unexported package-level `*big.Int` built from a constant that nothing in the package changes) and the circuit sees that same number, a bound is also accepted when its value proves `r < d`. The circuit sees the same number only if Go computes it without overflow in its type and it is below the field modulus, which the rule checks against `--field` or, without it, by requiring constants below 2^240; a larger constant wraps around the field. Such bounds are: a non-negative constant bound such as `AssertIsLessOrEqual(r, lanes-1)`, a range check of `r` (`api.ToBinary` or a range checker's `Check`), or range-checked limbs that `r` is rebuilt from, `r = hi*2^b + lo`, including the check that forces `lo` to zero when `hi` is all ones (how emulated KoalaBear, BabyBear, and Goldilocks code proves `r < p`). A range check counts when it runs unconditionally or in every branch of an `if`/`else`. A comparison inside an `if`/`else`, loop, switch, select, or function literal, or after a successful early return, is not universal coverage because that region may not execute; the exception is an `if err == nil` block whose other path immediately returns that error, since a failing function yields no constraint system. The finding points to the hint call and records the hint identity, the observed reconstruction, and the bound that was not recognized. Its confidence is high only when, within the function, `r` reaches no constraint or code the rule does not read; when `r` is returned, passed to a helper, used in another computation, or compared in a region that may not run, the message says so after "Not confirmed:", the evidence lists up to three such uses, and the confidence is medium. A bound of `r <= d-1` without a recognized `d != 0` is always medium, because `d` may be kept nonzero outside the function. When the bound runs only under `if p` (or `!p`, or in the `else` branch) for a bool parameter `p` that the function never reassigns, the function is unexported and not a method, and every use of it in its package is a direct call with a constant for `p`, the finding moves to each call that disables the bound, and calls that enable it are not reported. A shared helper therefore reports the vulnerable caller rather than the helper.

*Where it stops:* The rule checks one property, the remainder bound. It does not report a quotient without a range check, although then `q*d + r` can exceed the field modulus and `q = (n - r)/d` computed in the field satisfies the reconstruction for every `r` in `[0, d)`, so `r < d` alone does not make `q` and `r` unique; the JSON report's `field_safety` invariant names the values with no recognized range check. The rule matches only a two-output hint; a different output count, including one that cannot be determined statically, is not analyzed by this rule at all. Within a two-output hint, only the literal `AssertIsEqual(n, Add(Mul(q, d), r))` shape (operand and Add/Mul order may vary), written as one nested expression, is recognized as the reconstruction; the same relation split across intermediate local variables, with the outputs in the other order, or built any other way, is not, and is then not checked for a bound either. These stay quiet: no finding, on a hint that may have no bound at all. The rule does not know what the hint computes. A hint with another remainder convention, such as a signed digit in `[-8, 8)`, shares the reconstruction shape, and requiring `r < d` there would reject honest witnesses; such a finding is medium confidence when `r` also reaches a computation the rule does not follow. One level of unconditional, direct, package-local helper calls is summarized; a bound placed two or more helper calls away, in a caller, or in a helper declared in a different package is invisible to this analysis, and the rule reports the hint anyway, so such a finding can be a false positive. Only `AssertIsDifferent(d, 0)` in the function or in the helper that bounds `r` counts as proof that `d != 0`. Any arithmetic argument for canonicality other than those in the description is not recognized and fails the same way. A range check in a switch, or deferred to a later batch (a commit-based range checker's collected checks), is not seen. Without `--field`, value-based evidence (constants below 2^240) and the range check of `r` that a comparator needs (at most 240 bits) assume a pairing-friendly scalar field such as BN254 or BLS12-381; on a small field such as BabyBear they are not sufficient. Limb reconstructions wider than 240 bits are ignored. An `if err == nil` block counts as unconditional on the assumption that callers propagate the error. Algebraically neutral wrappers such as `Sub(x, 0)` are not simplified. Call-site specialization applies only to unexported plain functions whose every use is a direct call in the same package with a constant guard; exported functions, methods, escaping function values, and runtime arguments keep the finding at the hint. A quiet result is not evidence of soundness, and a reported one is not a confirmed vulnerability until the shapes above are ruled out; see docs/relation-rule-review.md.

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

### GNARK_RECURSION_WITNESS_UNVERIFIED

**Recursive proof witness used without verification**: severity high; confidence medium; class unverified proof edge.

A circuit's `Define` uses the public inputs of a `std/recursion` witness, but no in-circuit verification takes that witness, so the prover can supply any values for them.

gnark verifies a proof inside a circuit with a `Verifier` from `std/recursion/groth16` or `std/recursion/plonk`: `AssertProof(vk, proof, witness)` asserts that the proof holds for the witness, plonk's `AssertSameProofs` and `AssertDifferentProofs` assert several proofs at once, groth16's `IsValidProof` returns a variable that is 1 only for a valid proof, and plonk's `PrepareVerification` returns KZG openings to verify in a later batch. A `Witness` holds the inner proof's public inputs in its `Public` field. Those values mean what the inner circuit proved only once a proof over that witness is verified; otherwise they are free inputs. The rule looks at each `Define(frontend.API) error` method that no package code outside its own body refers to: the circuit entry point that gnark compiles, which no caller can verify for. It reports the first read of a witness's `Public` (directly, through an embedded witness, or through a type defined over `Witness`; not under `len` or `cap`, in a `range` that takes no values, or as an assignment target) when no verification in `Define` takes that witness, whether `Define` verifies nothing or verifies only other witnesses. A witness is matched by its field path from the receiver, so a `[]Witness` passed to a batch method covers each element, a literal of witnesses (also through a local holding it) covers each one it lists, a witness rebuilt as a literal from another witness's `Public` counts as that witness, and a local defined once from a field path, or a `range` variable over one, stands for that path when it is never reassigned (a `range` with `=` included) or addressed (calling a pointer method on it included). An `IsValidProof` call whose result is thrown away (as a statement, deferred, or bound to `_`) is not a verification; `GNARK_DISCARDED_PREDICATE` reports the plain statement and `_ =` forms of the call itself. gnark's compiler already rejects a circuit with an input that no constraint uses unless `frontend.IgnoreUnconstrainedInputs()` is set, which catches a proof that is left entirely unused; this rule names the cause at the read, and also covers circuits that touch the proof or witness without verifying it. Evidence: the gnark v0.16.3 package documentation of `std/recursion/groth16` and `std/recursion/plonk` (`Verifier`, `Witness`) and of `frontend.IgnoreUnconstrainedInputs`.

*Where it stops:* Only reads made in an entry-point `Define` count: public inputs read in a helper are not seen. A `Define` that other package code refers to (typically another circuit calling it as a sub-circuit, but any reference outside its own body counts) is skipped, and its reads are not seen from a caller either; composition across packages, or only through an interface such as `frontend.Circuit`, is not recognized, so such a sub-circuit is analyzed as an entry point and can be a false positive. Verification is looked for in `Define` and, one level deep, in package-local functions and methods (generic ones included) that `Define` passes the witness, its public inputs (the slice, part of it, its elements, or a local holding them), or the receiver; a method value bound to a value holding the witness counts as handing it to that method wherever it appears, called or not. A helper that contains any verification silences the rule for the whole method, whichever witness it verifies, and a verification two or more calls away is missed and reported as absent. Public inputs handed to code in another package are not followed, so verification there is reported as absent. The rule stays quiet for the whole method when the witness itself reaches code it does not follow: another package (the standard library excepted, which cannot verify), a function value (a function literal included), or an interface value (assigned, converted, appended, sent on a channel, placed in a literal, or returned by a package-local helper), including a sub-circuit run through `frontend.Circuit`, whether or not that code verifies; and when a verification's witness argument is not a field path from the receiver, a literal of them, or a local standing for one (for example a call result, or a local copy that is later modified). A read through such a value is reported only when `Define` verifies nothing at all. Indexes and slice bounds are ignored, so verifying `c.Witnesses[0]` or `c.Witnesses[:1]` covers a read of `c.Witnesses[1]`. Matching ignores statement order: a witness whose `Public` elements `Define` overwrites, or a field it reassigns, still counts as verified wherever it is read. A verification counts wherever it appears in `Define`: under a Go condition, after an early return, in a loop, in a function literal, or in unreachable code, although it may not run while the circuit compiles. A kept `IsValidProof` result counts as enforced: whether it reaches an assertion, rather than a `Select` or a return value, is not followed. `PrepareVerification` counts as verification even if its openings are never batch-verified. Whether the verifying key is fixed and the intended one, and whether `SwitchVerificationKey` selects only trusted keys, is not checked.
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
`unknown`. `missing` means the analyzer recognized the applicable shape and
found no recognized form of the required constraint within what it analyzes,
the function and one level of package-local helpers. It is not proof that no
such constraint exists elsewhere.

For the quotient/remainder shape, an unconditional constant-width `ToBinary`
provides range evidence, the reconstruction provides participation/relation
evidence, and an unconditional `r < d` whose preconditions are recognized (a
range check of `r` for a bounded comparator, `d != 0` for `r <= d-1`)
provides canonicality evidence. A `satisfied` canonicality means only that:
`q` and `r` are unique only if `q*d + r` also cannot exceed the field modulus,
which is the separate `field_safety` assessment. The
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
