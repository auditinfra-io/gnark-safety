# Understanding the first detector

This guide explains `GNARK_HINT_RELATION_INCOMPLETE`, the first rule in
`gnark-safety`, for readers without a computer-science background. It covers
what the rule looks for, why that matters, how the code finds it, and why it
can be wrong. The [technical review](relation-rule-review.md) has the details
and the tests behind each claim.

## Witness values and constraints

A zero-knowledge circuit is a list of checks. Someone, the **prover**, wants
to convince someone else, the **verifier**, that they know numbers that pass
every check, without showing those numbers.

- The numbers are the **witness**. Some are public (the verifier sees them);
  the rest stay private.
- The checks are the **constraints**, such as "this number times that number
  equals a third number".

The verifier learns one thing: every constraint holds for the prover's
numbers. It learns nothing about how those numbers were chosen. A property
that no constraint checks is never verified, however obvious it seemed to the
circuit's author.

In gnark, circuits are written in Go. A **hint** is ordinary Go code that
computes witness values the circuit needs, such as the result of a division
that is awkward to express as checks. An honest prover runs the hint. A
dishonest prover can put any numbers in its place. So a hint's outputs are
suggestions: the circuit has to check everything that matters about them.

## Two answers to 17 ÷ 5

Dividing 17 by 5 gives a **quotient** `q` and a **remainder** `r`, with

```text
17 = q × 5 + r
```

The answer from school is `q = 3`, `r = 2`, because `3 × 5 + 2 = 17`. But
`q = 2`, `r = 7` also works: `2 × 5 + 7 = 10 + 7 = 17`. So do `q = 1, r = 12`
and `q = 0, r = 17`. The equation alone has many solutions.

What makes `3, 2` the right answer is one more rule: the remainder must be
smaller than the divisor, `0 <= r < 5`. With that rule there is exactly one
answer. Without it, there are several.

## Why the remainder bound matters

Suppose a circuit asks a hint to divide `n` by `d`, and then checks only
`n = q × d + r`. An honest prover supplies `q = 3, r = 2` for 17 ÷ 5. A
dishonest prover can supply `q = 2, r = 7`, every constraint still holds, and
the proof verifies. If anything later relies on `q` or `r`, for instance as
the number of full rounds of something, or as an index into a table, the
dishonest prover now controls it.

This repository's [`examples/divmod`](../examples/divmod) shows exactly this.
`VulnerableCircuit` checks the equation but not `r < d`; its tests show that
gnark accepts `q = 2, r = 7` and that a real proof built from it verifies.
`CorrectedCircuit` adds the bound and rejects the same numbers.

Two more details matter, because circuits do not use ordinary numbers. They
use "clock arithmetic" on a very large clock, a prime number `p` about 77
digits long: after `p - 1` comes `0` again. So:

- **"Negative" numbers are really huge numbers.** `-3` is stored as `p - 3`.
  gnark's cheap comparison tool, the *bounded comparator*, treats huge numbers
  as negative, so it agrees that `p - 3` is less than 5. Only a separate
  **range check**, a check that `r` is small, such as "fits in 8 bits",
  rules that out.
- **Subtracting from zero wraps around.** If `d` is 0, then `d - 1` is
  `p - 1`, the largest number on the clock, and "`r` is at most `d - 1`"
  holds for every `r`. So "`r <= d - 1`" means "`r < d`" only when `d` is known
  not to be 0.

There is a third detail that this rule does **not** check: if `q` is not
range-checked, the equation can hold only "around the clock". For example,
`q` can be the clock number that, multiplied by 5, lands on 17. Then even
`0 <= r < d` does not pin down the answer.

## How this detector recognizes the code

The rule is in `internal/analyzer`. In order:

1. **Find the hint.** `inspectFile` looks for calls to gnark's `NewHint`,
   using Go's type information rather than the text, so renamed imports do
   not hide them. This rule considers only hints with exactly two outputs.
2. **Find the equation.** `analyzeRelation` looks for a check of the form
   `AssertIsEqual(n, Add(Mul(q, d), r))`, where `q` is the hint's first
   output and `r` its second, in any order of the `Add` and `Mul` operands
   (`reconstructionDivisor`). The other factor is taken to be the divisor
   `d`.
3. **Look for the bound.** `boundWithin` searches the same function for a
   check that proves `0 <= r < d` on every path. `remainderComparison`
   decides whether a comparison counts. A bounded comparator's
   `AssertIsLess(r, d)` counts only if `r` is also range-checked
   (`remainderRanged`), and `AssertIsLessOrEqual(r, d - 1)` counts only if
   `d != 0` is asserted (`divisorNonzero`). When `d` is a fixed number, a
   range check of `r` below it also counts (`remainderMaximum`).
   `helperProvidesBound` looks one function call deep, and
   `conditionallyExecuted` rejects checks inside an `if`, a loop, or after an
   early `return`, because they might not run.
4. **Report.** If no bound is found, `relationFindings` reports the hint. If
   the bound is switched off by a `true`/`false` argument, `findGuard` and
   `resolveGuardSites` move the report to the exact call that passes the
   switch-off value; that is why the divmod example reports line 44.
5. **Say how sure it is.** `remainderQualifiers` lists every other place `r`
   goes that the rule cannot follow: returned to a caller, passed to another
   function, used in another calculation, or checked inside an `if`. If there
   are any, the message adds "Not confirmed:" and the first one, and the
   confidence drops from `high` to `medium`.

## Why it can be wrong

**It can report code that is fine (false positives).**

- The bound is somewhere the rule does not look: in the function that
  called this one, or two function calls deep.
- The bound is written in a way the rule does not recognize, for example
  `api.Cmp(r, d)` checked against `-1`.
- The hint does not mean ordinary division. A "signed digit" hint
  deliberately produces remainders between -8 and 7; demanding `r < d` there
  would break correct proofs.

The "Not confirmed:" note and `medium` confidence flag many of these cases,
but not all.

**It can miss real bugs (false negatives).**

- The equation is written differently, for example split across several
  lines of variables, or with the outputs in the other order. The rule then
  does not recognize the division at all and stays silent.
- The hint has a number of outputs other than two.
- `r < d` is checked, but `q` is not range-checked, so the equation holds
  only around the clock (see above). The rule stays silent. The JSON report's
  `field_safety` entry names the values with no range check.
- The circuit has some other problem entirely. Most bugs have no rule here.

So a finding is a question to answer ("where is the remainder bound?"), not
a verdict. A clean scan is not a guarantee.

## Check your understanding

1. **A circuit checks `n = q × d + r` and that `r` is less than 256. For
   `n = 17, d = 5`, name a dishonest answer it accepts.**

   *Answer:* `q = 2, r = 7` (or `q = 1, r = 12`, or `q = 0, r = 17`). All
   reconstruct 17 and have `r` below 256, but none has `r < 5`. A range
   check keeps `r` small; it proves `r < d` only when `d` is a fixed number
   larger than every value the range check allows (here, 256 or more).

2. **A circuit bounds the remainder with `AssertIsLessOrEqual(r, d - 1)`,
   and a prover submits `d = 0`. What goes wrong, and what one check fixes
   it?**

   *Answer:* `d - 1` wraps around to the largest number on the clock, so
   every `r` passes. With `d = 0` the equation says `n = r`, and `q` can be
   anything. Asserting `d != 0` (`api.AssertIsDifferent(d, 0)`) fixes it,
   and the rule now accepts this bound only when that check is present or
   `d` is a fixed nonzero number.

3. **The scanner reports a finding that says "Not confirmed: r is returned
   to the caller". What should you check before calling it a bug?**

   *Answer:* Look at every function that calls this one and receives `r`.
   If each of them range-checks `r` and checks `r < d` before using it, the
   finding is a false positive: the rule does not look into callers. If any
   caller uses `r` without that check, the bug is real at that caller.
