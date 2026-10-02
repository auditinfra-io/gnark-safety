# Walkthrough: one bug, one scan

This page shows `gnark-safety` reporting one bug and staying quiet on its
fix, using the vulnerable/corrected pair in
[`examples/divmod`](../examples/divmod). You do not need to install anything
to read it. Every console block is a real terminal session pasted verbatim,
run from a fresh clone of this repository at commit `439f94f` with Go 1.27.1
on Linux/amd64. A later commit prints a different `--version`, and later
releases may word their output differently.

## What the tool looks for

A gnark circuit can ask a *hint* to compute a value outside the circuit, such
as a quotient and a remainder. The prover runs the hint, so the prover
decides what comes back, and a proof shows only that those values satisfy
the constraints the circuit states. If a property the developer relied on is
never constrained, the prover can return a different value and the proof
still verifies. `gnark-safety` reads a circuit's Go source, without running
it, and reports a small set of specific code shapes in which a
prover-controlled value is left unbound like that.

## The bug

[`examples/divmod/circuits.go`](../examples/divmod/circuits.go) asks a hint
to divide `n` by `d`. The shared helper `constrainDivision` checks the result
like this (an excerpt; `// ...` marks lines left out):

```go
qr, err := api.Compiler().NewHint(QuotientRemainderHint, 2, n, d)
// ...
q, r := qr[0], qr[1]
// ... 8-bit range checks on n, d, q, and r
api.AssertIsDifferent(d, 0)
api.AssertIsEqual(n, api.Add(api.Mul(q, d), r))

if enforceCanonicalRemainder {
	// Since r and d are in [0,255], |r-d| <= 255.
	cmp.NewBoundedComparator(api, big.NewInt(255), false).AssertIsLess(r, d)
}
```

`VulnerableCircuit` calls it with that last check turned off:

```go
func (c *VulnerableCircuit) Define(api frontend.API) error {
	return constrainDivision(api, c.N, c.D, false) // deliberately omits r < d
}
```

The missing constraint is the remainder bound `r < d`. Without it, for
`n = 17, d = 5` the honest hint returns `q = 3, r = 2`, but the noncanonical
pair `q = 2, r = 7` also satisfies `17 = 2*5 + 7` and every 8-bit check, so a
prover can supply it and the circuit accepts. (The 8-bit checks keep
`q*d + r` far below the field modulus, so the remainder bound is the only
thing missing.)

## Running the scanner

Clone the repository and build the scanner from it:

```console
$ git clone https://github.com/auditinfra-io/gnark-safety.git
Cloning into 'gnark-safety'...
$ cd gnark-safety
$ go install ./cmd/gnark-safety
$ echo $?
0
$ gnark-safety --version
gnark-safety v0.1.2-0.20260927165010-439f94f51a84
```

`go install` printed nothing because the modules were already in the local
module cache. On a first run, Go prints `go: downloading ...` lines first,
and may download the Go 1.27.1 toolchain that `go.mod` names. The binary
goes to `$(go env GOPATH)/bin`, which needs to be on your `PATH`.

This builds from the clone rather than with the README's
`go install github.com/auditinfra-io/gnark-safety/cmd/gnark-safety@latest`.
Inside the clone, the `toolchain go1.27.1` line in `go.mod` makes `go` run
as Go 1.27.1, and the scanner has to be built with a Go at least as new as
that. With a local Go older than 1.27.1 (seen with 1.24.7 and 1.26.8),
installing with `@latest` from outside the clone built v0.1.1 with go1.26.8,
and scanning `./examples/divmod` with that binary exited 2, ending with:

> gnark-safety was built with go1.26.8, but the go command is go1.27.1: a type checker older than the go command cannot load its standard library. Rebuild gnark-safety with go1.27 or newer, for example with go install github.com/auditinfra-io/gnark-safety/cmd/gnark-safety@<version>.

That was v0.1.1. Since v0.1.2 the README's install line pins the toolchain
(`GOTOOLCHAIN="$(go env GOVERSION)"`, run from the module you will scan), and
the message names the same fix.

Scan the example, keeping the finding at its original severity:

```console
$ gnark-safety scan --include-examples ./examples/divmod
examples/divmod/circuits.go:44:26: high [GNARK_HINT_RELATION_INCOMPLETE] This call passes enforceCanonicalRemainder=false to constrainDivision, which then skips the canonical remainder bound r < d on its hint outputs.

1 finding(s). Each is a lead for review, not a confirmed vulnerability; `gnark-safety explain <rule>` says what a rule checks and where it stops.
gnark-safety: 1 finding(s) [1 high] in 1 file(s); scanned 1 package(s), 1 importing gnark; 1 hint call(s), 1 in the quotient/remainder shape; _test.go files excluded — fails (--fail-on high)
$ echo $?
1
```

Reading it:

- **Where.** `circuits.go:44:26` is the call in `VulnerableCircuit.Define`
  that passes `false`. The hint call itself is at line 20, inside the
  helper; the rule reports the caller that turns the bound off.
- **What.** `high` is the severity and `GNARK_HINT_RELATION_INCOMPLETE` the
  rule. The message names the helper, the parameter, and the bound it skips.
- **Summary.** The last line is written to stderr. `1 in the
  quotient/remainder shape` means the rule had a hint to check. The default
  gate is `--fail-on high`, so the scan fails and exits 1.

The same scan without `--include-examples`:

```console
$ gnark-safety scan ./examples/divmod
examples/divmod/circuits.go:44:26: low [GNARK_HINT_RELATION_INCOMPLETE] This call passes enforceCanonicalRemainder=false to constrainDivision, which then skips the canonical remainder bound r < d on its hint outputs.

1 finding(s). Each is a lead for review, not a confirmed vulnerability; `gnark-safety explain <rule>` says what a rule checks and where it stops.
gnark-safety: 1 finding(s) [1 low] in 1 file(s); scanned 1 package(s), 1 importing gnark; 1 hint call(s), 1 in the quotient/remainder shape; 1 downgraded as example code; _test.go files excluded — passes (--fail-on high)
$ echo $?
0
```

It is the same finding, lowered to `low` because it is under `examples/`, so
the scan passes and exits 0. By default, findings in example directories are
downgraded so that a repository's own sample code cannot fail its build.
They are still printed, and the summary counts them (`1 downgraded as
example code`).

The rule's own explanation, including where it stops:

<details>
<summary>Output of <code>gnark-safety explain GNARK_HINT_RELATION_INCOMPLETE</code></summary>

```console
$ gnark-safety explain GNARK_HINT_RELATION_INCOMPLETE
GNARK_HINT_RELATION_INCOMPLETE: Incomplete hint relation
Severity: high. Confidence: medium. Class: unbound witness.

A two-output hint is reconstructed as `n = q*d + r`, but no unconditional bound `0 <= r < d` was recognized, so a prover may be able to supply another quotient and remainder that satisfy the same equation.

Identifies a direct, type-resolved two-output `NewHint` call (`Compiler.NewHint` or the deprecated `API.NewHint`) when one `AssertIsEqual` contains the typed `Add(Mul(q, d), r)` reconstruction, with output 0 as `q` and output 1 as `r`, and assumes the hint means Euclidean division: `0 <= r < d`. It then looks, in the same function, for an unconditional bound that proves that in gnark's field arithmetic. A bounded comparator's `AssertIsLess(r, d)` or `AssertIsLessEq(r, api.Sub(d, 1))` (the same constraint) counts only together with a range check of `r`, because the comparator compares signed values and a field element near the modulus encodes a negative `r`. `api.AssertIsLessOrEqual(r, api.Sub(d, 1))` counts only together with `api.AssertIsDifferent(d, 0)` or a known nonzero `d`, because when `d = 0`, `d - 1` is the largest field element. Indexed outputs may use literals, named constants, constant expressions, or local aliases. Comparisons with the wrong operand order or a different bound do not count. When `d` is known at compile time (a constant, `math.Pow(2, k)`, or an unexported package-level `*big.Int` built from a constant that nothing in the package changes) and the circuit sees that same number, a bound is also accepted when its value proves `r < d`. The circuit sees the same number only if Go computes it without overflow in its type and it is below the field modulus, which the rule checks against `--field` or, without it, by requiring constants below 2^240; a larger constant wraps around the field. Such bounds are: a non-negative constant bound such as `AssertIsLessOrEqual(r, lanes-1)`, a range check of `r` (`api.ToBinary` or a range checker's `Check`), or range-checked limbs that `r` is rebuilt from, `r = hi*2^b + lo`, including the check that forces `lo` to zero when `hi` is all ones (how emulated KoalaBear, BabyBear, and Goldilocks code proves `r < p`). A range check counts when it runs unconditionally or in every branch of an `if`/`else`. A comparison inside an `if`/`else`, loop, switch, select, or function literal, or after a successful early return, is not universal coverage because that region may not execute; the exception is an `if err == nil` block whose other path immediately returns that error, since a failing function yields no constraint system. The finding points to the hint call and records the hint identity, the observed reconstruction, and the bound that was not recognized. Its confidence is high only when, within the function, `r` reaches no constraint or code the rule does not read; when `r` is returned, passed to a helper, used in another computation, or compared in a region that may not run, the message says so after "Not confirmed:", the evidence lists up to three such uses, and the confidence is medium. A bound of `r <= d-1` without a recognized `d != 0` is always medium, because `d` may be kept nonzero outside the function. When the bound runs only under `if p` (or `!p`, or in the `else` branch) for a bool parameter `p` that the function never reassigns, the function is unexported and not a method, and every use of it in its package is a direct call with a constant for `p`, the finding moves to each call that disables the bound, and calls that enable it are not reported. A shared helper therefore reports the vulnerable caller rather than the helper.

Where it stops: The rule checks one property, the remainder bound. It does not report a quotient without a range check, although then `q*d + r` can exceed the field modulus and `q = (n - r)/d` computed in the field satisfies the reconstruction for every `r` in `[0, d)`, so `r < d` alone does not make `q` and `r` unique; the JSON report's `field_safety` invariant names the values with no recognized range check. The rule matches only a two-output hint; a different output count, including one that cannot be determined statically, is not analyzed by this rule at all. Within a two-output hint, only the literal `AssertIsEqual(n, Add(Mul(q, d), r))` shape (operand and Add/Mul order may vary), written as one nested expression, is recognized as the reconstruction; the same relation split across intermediate local variables, with the outputs in the other order, or built any other way, is not, and is then not checked for a bound either. These stay quiet: no finding, on a hint that may have no bound at all. The rule does not know what the hint computes. A hint with another remainder convention, such as a signed digit in `[-8, 8)`, shares the reconstruction shape, and requiring `r < d` there would reject honest witnesses; such a finding is medium confidence when `r` also reaches a computation the rule does not follow. One level of unconditional, direct, package-local helper calls is summarized; a bound placed two or more helper calls away, in a caller, or in a helper declared in a different package is invisible to this analysis, and the rule reports the hint anyway, so such a finding can be a false positive. Only `AssertIsDifferent(d, 0)` in the function or in the helper that bounds `r` counts as proof that `d != 0`. Any arithmetic argument for canonicality other than those in the description is not recognized and fails the same way. A range check in a switch, or deferred to a later batch (a commit-based range checker's collected checks), is not seen. Without `--field`, value-based evidence (constants below 2^240) and the range check of `r` that a comparator needs (at most 240 bits) assume a pairing-friendly scalar field such as BN254 or BLS12-381; on a small field such as BabyBear they are not sufficient. Limb reconstructions wider than 240 bits are ignored. An `if err == nil` block counts as unconditional on the assumption that callers propagate the error. Algebraically neutral wrappers such as `Sub(x, 0)` are not simplified. Call-site specialization applies only to unexported plain functions whose every use is a direct call in the same package with a constant guard; exported functions, methods, escaping function values, and runtime arguments keep the finding at the hint. A quiet result is not evidence of soundness, and a reported one is not a confirmed vulnerability until the shapes above are ruled out; see docs/relation-rule-review.md.

Reference: https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md#gnark_hint_relation_incomplete
$ echo $?
0
```

</details>

## The corrected version

`CorrectedCircuit`, in the same file, calls the same helper with the bound
turned on:

```go
func (c *CorrectedCircuit) Define(api frontend.API) error {
	return constrainDivision(api, c.N, c.D, true)
}
```

With `true`, the helper asserts `r < d` with a bounded comparator, and `r` is
already range-checked to 8 bits, which that comparator needs.

The scans above already cover it. `./examples/divmod` is one package holding
both circuits, and the only finding is at line 44. Line 54, the call in
`CorrectedCircuit.Define`, is not reported. Both circuits go through the
same single hint call (the summary counts `1 hint call(s)`), so the rule is
not reacting to the hint alone: it resolved the `enforceCanonicalRemainder`
argument at each call site and reported only the call that passes `false`.
A rule that flagged both circuits would be flagging the hint, not the
missing bound. This is why each rule's test corpus pins false-positive
guards alongside its true positives (see
[How the rules are tested](../README.md#how-the-rules-are-tested)).

The scanner's split matches how the two circuits behave when solved. The
example's own test gives both circuits the forged `q = 2, r = 7` for
`n = 17, d = 5` through gnark's solver:

```console
$ go test -count=1 -v -run TestRequiredHintSafetyMatrix ./examples/divmod
=== RUN   TestRequiredHintSafetyMatrix
=== RUN   TestRequiredHintSafetyMatrix/A_vulnerable_accepts_valid_output
=== RUN   TestRequiredHintSafetyMatrix/B_corrected_accepts_valid_output
=== RUN   TestRequiredHintSafetyMatrix/C_vulnerable_accepts_invalid_output
=== RUN   TestRequiredHintSafetyMatrix/D_corrected_rejects_identical_invalid_output
--- PASS: TestRequiredHintSafetyMatrix (0.00s)
    --- PASS: TestRequiredHintSafetyMatrix/A_vulnerable_accepts_valid_output (0.00s)
    --- PASS: TestRequiredHintSafetyMatrix/B_corrected_accepts_valid_output (0.00s)
    --- PASS: TestRequiredHintSafetyMatrix/C_vulnerable_accepts_invalid_output (0.00s)
    --- PASS: TestRequiredHintSafetyMatrix/D_corrected_rejects_identical_invalid_output (0.00s)
PASS
ok  	github.com/auditinfra-io/gnark-safety/examples/divmod	0.007s
$ echo $?
0
```

Subtest C passes because the vulnerable circuit accepts the forged pair, and
D passes because the corrected circuit rejects it with an unsatisfied
constraint. That result comes from solving the circuits, not from the
scanner, which only reads source.
[`examples/divmod/README.md`](../examples/divmod/README.md) lists the
example's other tests, including Groth16 proving with the forged
witness.

## What a clean run does and doesn't mean

No finding on `CorrectedCircuit` means no shape these rules recognize
matched there, not that the circuit is sound. The same holds for your own
code: a quiet scan is not an audit, and most soundness bugs match no rule
here. This rule checks one property, the remainder bound, in one
reconstruction shape. The same relation written another way, or a quotient
with no range check, stays quiet; the "Where it stops" part of the `explain`
output above lists these cases. In the other direction, a finding is a lead
to review, not a confirmed vulnerability.

## Next

- [`docs/rules.md`](rules.md) lists every rule, what it matches, and where
  it stops.
- The [README](../README.md#install) covers installing, the GitHub Action,
  pre-commit, `go vet`, flags, and exit codes.
