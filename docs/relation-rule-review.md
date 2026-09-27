# Review of GNARK_HINT_RELATION_INCOMPLETE

This is a technical review of the first rule. It records what the rule does,
what it assumes, and where it stops, and then tests each assumption against
circuits whose correct outcome was worked out from their constraints rather
than from the scanner's output. For a plain-language introduction, read
[`understanding-the-first-detector.md`](understanding-the-first-detector.md)
first.

The assessment below describes the rule as of commit `f6cf9fd`, before this
review changed it.

## What the rule recognizes

All of this is in `internal/analyzer`:

1. `inspectFile` finds calls that resolve by type to gnark's
   `Compiler.NewHint` or the deprecated `API.NewHint`, and whose output count
   is the constant 2.
2. `analyzeRelation` finds the variable the outputs are assigned to, and
   local aliases of constant-index reads (`q, r := out[0], out[1]`). It then
   looks for one `api.AssertIsEqual(n, ...)` whose other side is exactly
   `Add(Mul(out[0], d), out[1])`, in any operand order
   (`reconstructionDivisor`, `plainRelationSide`). Output 0 is always taken
   as the quotient `q` and output 1 as the remainder `r`. The other `Mul`
   operand is the divisor `d`.
3. `boundWithin` then looks, in the same function, for a remainder bound
   that runs on every path (`conditionallyExecuted` rules out `if`/`else`,
   loops, `switch`, `select`, closures, and code after a successful early
   return):
   - a bounded comparator's `AssertIsLess(r, d)` from `std/math/cmp`
     (`isComparatorCall`, `sameValue`);
   - `api.AssertIsLessOrEqual(r, api.Sub(d, 1))` (`oneLessThan`);
   - when `d` has a compile-time value, a constant bound below it, a range
     check of `r` (`rangeBits`), or range-checked limbs that `r` is rebuilt
     from (`remainderMaximum`, `limbSum`, `topLimbForcesZero`);
   - either of the first two inside a package-local helper called
     unconditionally (`helperProvidesBound`);
   - any of these inside an `if err == nil` block whose other path returns
     the error (`successGuards`).
4. If there is no such bound, `relationFindings` reports the hint call. If
   the bound runs only under a bool parameter that every package-local
   caller passes as a constant (`findGuard`, `resolveGuardSites`), the
   finding moves to the calls that disable it.

## What it assumes

The rule assumes that the hint means **Euclidean division over the
integers**: for inputs `n` and `d > 0`, `q = floor(n / d)` and
`r = n - q*d`, so `0 <= r < d`. Under that assumption the reconstruction
`n = q*d + r` together with `0 <= r < d` pins `q` and `r` to one pair, as
long as the arithmetic does not wrap around the field modulus.

gnark circuits do not compute over the integers. Every value is an element
of a prime field, and `n = q*d + r` holds modulo the field's prime `p`.
Three more facts therefore matter, and the rule does not check any of them:

- **The comparison's own preconditions.** `std/math/cmp`'s
  `BoundedComparator` compares *signed* values: its documentation says the
  operands "can be any signed integers, as long as their absolute difference
  respects the specified bound". `AssertIsLess(r, d)` is implemented as a
  range check of `d - 1 - r`, so `r = p - 3` (the field's encoding of `-3`)
  satisfies `r < 5`. Only a range check of `r` rules that out.
- **A nonzero divisor.** `api.AssertIsLessOrEqual` compares the canonical
  values in `[0, p)`. When `d = 0`, `d - 1` is `p - 1`, and `r <= p - 1`
  holds for every `r`. So `r <= d - 1` is the same as `r < d` only when
  `d >= 1` is established separately.
- **No wraparound.** Even with `0 <= r < d`, if `q` is not bounded, then
  `q = (n - r) / d` computed in the field satisfies the reconstruction for
  every `r` in `[0, d)`. Uniqueness needs `q*d + r < p`, which in practice
  means range checks on `q` (and on `d` and `n`). The JSON report's
  `field_safety` invariant tracks this, but no finding does.

## What it can establish

Within the function that calls the hint, plus one level of package-local
helpers, the rule can establish whether one of the bound shapes above is
present and runs on every path. That is all. A reported finding means "no
recognized bound", and a quiet result means "a recognized bound shape is
present, or the reconstruction shape was not recognized at all".

## Where the analysis stops

- Hints with any output count other than 2, and reconstructions written any
  other way (split across variables, or with outputs in the other order),
  are not analyzed: the rule stays quiet.
- Bounds in callers, in helpers more than one call away, or in other
  packages are not seen: the rule reports a finding that may be a false
  positive.
- The rule does not know what the hint computes. It cannot tell Euclidean
  division from another convention that happens to share the reconstruction
  shape.

## When a reported pattern may be intentional

- The bound is applied by the caller, for example when a helper returns
  `q, r` and every caller checks `r < d`.
- The hint implements a different convention on purpose, such as a signed
  or centered remainder, where negative `r` is correct and `r < d` would
  reject honest witnesses.
- The divisor is guaranteed nonzero outside the circuit, for example a
  public input that the verifier checks.
- The code is deliberately incomplete, as in `examples/divmod`.

## Challenge cases

Each case is an executable test in
[`internal/witness/relation_challenge_test.go`](../internal/witness/relation_challenge_test.go).
`TestRelationChallengeConstraints` compiles each circuit for BN254, solves
it with an honest hint and with adversarial advice substituted through
`solver.OverrideHint`, and checks whether the witness is accepted or
rejected. A rejection only counts when the substituted hint ran to
completion and the error is an unsatisfied constraint, so a compilation,
hint, or setup failure cannot pass for one. `TestRelationChallengeScanner`
checks what the rule reports on the same code.

"Constraints" is what solving established. The intended property is
Euclidean division of 8-bit values unless the case says otherwise.

| # | Case | Constraints | Rule at `f6cf9fd` | Rule now |
|---|---|---|---|---|
| 1 | `examples/divmod`: no `r < d` | accept `q=2, r=7` for 17 ÷ 5 (unsound); the corrected circuit rejects it | high, at the caller that passes `false` | unchanged |
| 2 | Valid correction: range checks and a comparator's `r < d` | reject `q=2, r=7`, `r = −3`, and `d = 0`; accept honest witnesses | quiet | quiet |
| 3a | Equivalent: comparator `AssertIsLessEq(r, d−1)` | same as case 2 (it is the same constraint) | **high: false positive** | quiet |
| 3b | Equivalent: `api.AssertIsLessOrEqual(r, d−1)` with `d ≠ 0` | same as case 2 | quiet | quiet |
| 4a | Bound in a helper one call away | reject `q=2, r=7` | quiet | quiet |
| 4b | Bound two helper calls away | reject `q=2, r=7` (sound) | high, unqualified: false positive | high, medium confidence, "r is passed to checkRemainder" |
| 4c | Bound applied by the caller of the helper that holds the hint | reject `q=2, r=7` (sound) | high, unqualified: false positive | high, medium confidence, "r is returned to the caller" |
| 5 | Bound under `if c.Strict`, a compile-time setting | accept `q=2, r=7` when compiled without `Strict`; reject with it | high, unqualified | high, medium confidence, "a comparison of r ... may not run" |
| 6 | `api.AssertIsLessOrEqual(r, d−1)` without `d ≠ 0` | accept `d = 0` with `q` = 0, 9, or 255 (unsound) | **quiet: false negative** | high, medium confidence, names `d = 0` |
| 7a | Comparator `r < d` without a range check of `r` | accept `q=4, r=p−3` (that is, −3) for 17 ÷ 5 (unsound) | **quiet: false negative** | high, high confidence, "no range check of r" |
| 7b | `0 <= r < d` enforced, but no range check of `q` | accept `r=0, q=17·5⁻¹ mod p` (unsound) | quiet | quiet (known limitation); `field_safety` now names `q` |
| 8 | Signed-digit hint, `r` in `[−8, 8)`, enforced by `ToBinary(r+8, 4)` | accept honest witnesses including negative `r`; reject the Euclidean `q=1, r=9` for 25. Adding `r <= 15` rejects the honest `q=2, r=−7` | high, unqualified: false positive by intent | high, medium confidence, "r is used in api.Add" |

## Corrections made

- A bounded comparator's bound on `r` now counts only with a recognized
  range check of `r` (case 7a). The fixtures `safe` in
  `testdata/relation`, `testdata/deprecated`, and `testdata/testonly`, and
  the bound helpers in `testdata/specialize`, were labelled safe but had no
  range check. Solving that shared shape accepted `r = −3`. They now include
  the range check, and the old shape is kept as the reported case
  `comparatorWithoutRangeCheck`.
- `api.AssertIsLessOrEqual(r, api.Sub(d, 1))` now counts only with
  `AssertIsDifferent(d, 0)` or a known nonzero `d` (case 6). The
  `lessOrEqualSafe` fixtures gained the assertion, and the old shape is
  kept as `lessOrEqualZeroDivisor`.
- A negative constant bound no longer counts: gnark encodes `-1` as `p − 1`.
- The comparator's `AssertIsLessEq(r, api.Sub(d, 1))` is recognized
  (case 3a).
- Findings no longer say the bound "is not constrained". They say no bound
  was recognized. When `r` reaches code the rule does not read, they add
  "Not confirmed:" with the first such use, list up to three in the
  evidence, and use medium confidence (cases 4b, 4c, 5, 8). The rule's
  registered confidence is now medium.
- The rule summary no longer claims that `r < d` alone makes the quotient
  and remainder unique (case 7b). The `canonicality` invariant says the same
  thing, and `field_safety` names the values that have no recognized range
  check.

## What is still not covered

- **Case 7b stays quiet.** Reporting a quotient without a range check would
  be a new check with its own false-positive profile. The repository has no
  corpus of real code for this rule to measure it on (gnark's `std/` has no
  reconstruction the rule recognizes). It is left to the `field_safety`
  invariant and documented in the rule's limitations.
- **Callers and deeper helpers are still not analyzed.** Cases 4b and 4c
  remain findings. They are now marked as unconfirmed rather than removed.
- **Intent is still assumed.** The rule cannot know that a hint is not
  Euclidean division. Case 8 is flagged because `r` feeds a computation the
  rule does not follow, not because the rule understands signed digits.
- **Some writings are not recognized.** Equivalent forms beyond those listed
  (for example `api.Cmp(r, d) == -1`, or a bound through a local copy of
  `d`) are still false positives.
