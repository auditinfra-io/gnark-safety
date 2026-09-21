# Upstream comparison

Research was performed against gnark **v0.16.3**, commit
[`cfc7b2f907cc4212ec152077e022c6d0b4805759`](https://github.com/Consensys/gnark/tree/cfc7b2f907cc4212ec152077e022c6d0b4805759).
URLs below are commit-pinned so that later API changes do not silently change
the basis of this fixture.

## What already exists

- gnark's [`solver.Hint` documentation](https://github.com/Consensys/gnark/blob/cfc7b2f907cc4212ec152077e022c6d0b4805759/constraint/solver/hint.go#L11-L94)
  explicitly says hint results are unconstrained by default and the circuit
  developer must add the necessary constraints. Its factorization example also
  explains that a constraint can be true while remaining semantically too weak.
- [`solver.OverrideHint`](https://github.com/Consensys/gnark/blob/cfc7b2f907cc4212ec152077e022c6d0b4805759/constraint/solver/options.go#L42-L48)
  is the supported solver option used here to replace the function associated
  with exactly one hint ID.
- The regression tests for
  [issue 836](https://github.com/Consensys/gnark/blob/cfc7b2f907cc4212ec152077e022c6d0b4805759/internal/regression_tests/issue_836_test.go#L80-L171)
  already substitute a malicious internal `nBits` hint to ensure comparison
  gadgets reject problematic decompositions. Other focused tests similarly use
  `OverrideHint`, including an
  [emulated-field test](https://github.com/Consensys/gnark/blob/cfc7b2f907cc4212ec152077e022c6d0b4805759/std/math/emulated/smallfield_test.go#L601-L616)
  and a
  [G2 preimage test](https://github.com/Consensys/gnark/blob/cfc7b2f907cc4212ec152077e022c6d0b4805759/std/algebra/emulated/sw_bn254/g2_test.go#L329-L341).
- gnark has a complete
  [hint plus Groth16 example](https://github.com/Consensys/gnark/blob/cfc7b2f907cc4212ec152077e022c6d0b4805759/std/math/emulated/field_hint_example_test.go#L24-L110)
  that constrains the hint result and passes enabled hints into proving.

These sources already establish both the safety rule and the replacement API.
This repository does not claim either as new.

## What this fixture adds

The contribution is presentation and paired regression value rather than a new
library technique:

1. one small quotient/remainder relation with an explicit developer-facing
   specification;
2. vulnerable and corrected circuits that differ only in `r < d`;
3. the same public inputs and the same replacement output in both negative
   cases;
4. an ordinary-Go check showing that the replacement really violates the stated
   property;
5. both solver-level outcomes and end-to-end Groth16/BN254 proof outcomes; and
6. fixed integer bounds with an explicit no-wraparound argument.

Unlike the upstream issue-836 regression, this intentionally shows a user
circuit that *accepts* semantically bad advice before the missing constraint is
added. Unlike the upstream hint example, it places the incomplete and complete
versions side by side and retains reproducibility evidence.

## Remaining uncertainty

Maintainers may reasonably prefer this as documentation rather than an upstream
regression test: gnark already documents that hints are unconstrained and tests
malicious replacements in real gadgets. The synthetic vulnerable half does not
pin a gnark defect. The best next step is therefore a documentation/example
contribution, subject to maintainer interest; further investigation should come
before proposing it as a library regression test.
