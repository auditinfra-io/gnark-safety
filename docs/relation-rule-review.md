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

The next commit adds executable challenge cases for each assumption above,
the case table, and the corrections they led to.
