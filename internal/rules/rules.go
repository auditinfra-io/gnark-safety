// Package rules is the single source of truth for rule metadata.
//
// The analyzer emits the IDs declared here. `gnark-safety explain`, SARIF
// rule metadata, and the generated sections of README.md and docs/rules.md
// are all rendered from this registry, so documentation cannot drift from
// what the tool reports. After changing a Spec, run:
//
//	go generate ./internal/rules
//
// TestGeneratedDocsUpToDate fails until the committed docs match.
package rules

import (
	"strings"

	"github.com/auditinfra-io/gnark-safety/pkg/report"
)

//go:generate go run ./gendocs -root ../..

// Rule IDs are stable: once released they are never renamed or reused.
const (
	HintRelationIncomplete    = "GNARK_HINT_RELATION_INCOMPLETE"
	HintOutputUnused          = "GNARK_HINT_OUTPUT_UNUSED"
	TagVisibilityAsName       = "GNARK_TAG_VISIBILITY_AS_NAME"
	GoEqualityOnVariable      = "GNARK_GO_EQUALITY_ON_VARIABLE"
	DiscardedPredicate        = "GNARK_DISCARDED_PREDICATE"
	VacuousAssert             = "GNARK_VACUOUS_ASSERT"
	BitsUnconstrained         = "GNARK_BITS_UNCONSTRAINED"
	BitsOmitModulusCheck      = "GNARK_BITS_OMIT_MODULUS_CHECK"
	ComparatorNondeterminism  = "GNARK_COMPARATOR_NONDETERMINISTIC"
	IgnoreUnconstrainedInputs = "GNARK_IGNORE_UNCONSTRAINED_INPUTS"
	UnsafeSetup               = "GNARK_UNSAFE_SETUP"
	RecursionUnverified       = "GNARK_RECURSION_WITNESS_UNVERIFIED"
)

// Taxonomy classes follow o1js-scan's missing-constraint taxonomy, with
// configuration added for proof-system and compile settings.
const (
	ClassUnboundWitness     = "unbound witness"
	ClassNonLoadBearing     = "non-load-bearing predicate"
	ClassUnverifiedProof    = "unverified proof edge"
	ClassUnpinnedCommitment = "unpinned commitment"
	ClassConfiguration      = "configuration"
)

// Classes lists every taxonomy class a rule may declare.
var Classes = []string{ClassUnboundWitness, ClassNonLoadBearing, ClassUnverifiedProof, ClassUnpinnedCommitment, ClassConfiguration}

// DocURL is the published rule reference; SARIF helpUri values anchor into it.
const DocURL = "https://github.com/auditinfra-io/gnark-safety/blob/main/docs/rules.md"

// Spec is the immutable metadata for one rule.
type Spec struct {
	ID    string
	Title string
	Class string
	// Severities is every severity the rule can emit, most severe first. The
	// first entry is the default and sets the SARIF security-severity.
	Severities []report.Severity
	Confidence string
	// Summary is one or two sentences for tables and SARIF fullDescription.
	Summary string
	// Description is the full explanation shown by `explain` and in
	// docs/rules.md.
	Description string
	// Limitations records what the rule deliberately does not match, so a
	// reviewer knows what a quiet result does not cover.
	Limitations string
}

var specs = []Spec{
	{
		ID:         HintRelationIncomplete,
		Title:      "Incomplete hint relation",
		Class:      ClassUnboundWitness,
		Severities: []report.Severity{report.SeverityHigh},
		Confidence: "medium",
		Summary:    "A two-output hint is reconstructed as `n = q*d + r`, but no unconditional bound `0 <= r < d` was recognized, so a prover may be able to supply another quotient and remainder that satisfy the same equation.",
		Description: "Identifies a direct, type-resolved two-output `NewHint` call (`Compiler.NewHint` or the deprecated `API.NewHint`) " +
			"when one `AssertIsEqual` contains the typed `Add(Mul(q, d), r)` reconstruction, with output 0 as `q` and output 1 " +
			"as `r`, and assumes the hint means Euclidean division: `0 <= r < d`. It then looks, in the same function, for an " +
			"unconditional bound that proves that in gnark's field arithmetic. A bounded comparator's `AssertIsLess(r, d)` or " +
			"`AssertIsLessEq(r, api.Sub(d, 1))` (the same constraint) counts only together with a range check of `r`, because " +
			"the comparator compares signed values and a field element near the modulus encodes a negative `r`. " +
			"`api.AssertIsLessOrEqual(r, api.Sub(d, 1))` counts only together with `api.AssertIsDifferent(d, 0)` or a known " +
			"nonzero `d`, because when `d = 0`, `d - 1` is the largest field element. Indexed outputs may use literals, named " +
			"constants, constant expressions, or local aliases. Comparisons with the wrong operand order or a different bound do " +
			"not count. When `d` is known at compile time (a constant, `math.Pow(2, k)`, or an unexported package-level " +
			"`*big.Int` built from a constant that nothing in the package changes) and the circuit sees that same number, a " +
			"bound is also accepted when its value proves `r < d`. The circuit sees the same number only if Go computes it " +
			"without overflow in its type and it is below the field modulus, which the rule checks against `--field` or, " +
			"without it, by requiring constants below 2^240; a larger constant wraps around the field. Such bounds are: a non-negative constant bound such as `AssertIsLessOrEqual(r, lanes-1)`, a range check of `r` " +
			"(`api.ToBinary` or a range checker's `Check`), or range-checked limbs that `r` is rebuilt from, `r = hi*2^b + lo`, " +
			"including the check that forces `lo` to zero when `hi` is all ones (how emulated KoalaBear, BabyBear, and " +
			"Goldilocks code proves `r < p`). A range check counts when it runs unconditionally or in every branch of an " +
			"`if`/`else`. A comparison inside an `if`/`else`, loop, switch, select, or function literal, or after a successful " +
			"early return, is not universal coverage because that region may not execute; the exception is an `if err == nil` " +
			"block whose other path immediately returns that error, since a failing function yields no constraint system. " +
			"The finding points to the hint call and records the hint identity, the observed reconstruction, and the bound that " +
			"was not recognized. Its confidence is high only when, within the function, `r` reaches no constraint or code the " +
			"rule does not read; when `r` is returned, passed to a helper, used in another computation, or compared in a region " +
			"that may not run, the message says so after \"Not confirmed:\", the evidence lists up to three such uses, and the " +
			"confidence is medium. A bound of `r <= d-1` without a recognized `d != 0` is always medium, because `d` may be kept " +
			"nonzero outside the function. When the bound runs only under `if p` (or `!p`, or in the `else` branch) for a bool " +
			"parameter `p` that the function never reassigns, the function is unexported and not a method, and every use of it " +
			"in its package is a direct call with a constant for `p`, the finding moves to each call that disables the bound, " +
			"and calls that enable it are not reported. A shared helper therefore reports the vulnerable caller rather than the helper.",
		Limitations: "The rule checks one property, the remainder bound. It does not report a quotient without a range check, " +
			"although then `q*d + r` can exceed the field modulus and `q = (n - r)/d` computed in the field satisfies the " +
			"reconstruction for every `r` in `[0, d)`, so `r < d` alone does not make `q` and `r` unique; the JSON report's " +
			"`field_safety` invariant names the values with no recognized range check. " +
			"The rule matches only a two-output hint; a different output count, including one that cannot be determined " +
			"statically, is not analyzed by this rule at all. Within a two-output hint, only the literal " +
			"`AssertIsEqual(n, Add(Mul(q, d), r))` shape (operand and Add/Mul order may vary), written as one nested expression, " +
			"is recognized as the reconstruction; the same relation split across intermediate local variables, with the outputs " +
			"in the other order, or built any other way, is not, and is then not checked for a bound either. These stay quiet: " +
			"no finding, on a hint that may have no bound at all. " +
			"The rule does not know what the hint computes. A hint with another remainder convention, such as a signed digit " +
			"in `[-8, 8)`, shares the reconstruction shape, and requiring `r < d` there would reject honest witnesses; such a " +
			"finding is medium confidence when `r` also reaches a computation the rule does not follow. " +
			"One level of unconditional, direct, package-local helper calls is summarized; a bound placed two or more helper " +
			"calls away, in a caller, or in a helper declared in a different package is invisible to this analysis, and the " +
			"rule reports the hint anyway, so such a finding can be a false positive. Only `AssertIsDifferent(d, 0)` in the " +
			"function or in the helper that bounds `r` counts as proof that `d != 0`. Any arithmetic argument for canonicality " +
			"other than those in the description is not recognized and fails the same way. A range check in a switch, or " +
			"deferred to a later batch (a commit-based range checker's collected checks), is not seen. Without `--field`, " +
			"value-based evidence (constants below 2^240) and the range check of `r` that a comparator needs (at most 240 bits) " +
			"assume a pairing-friendly scalar field such " +
			"as BN254 or BLS12-381; on a small field such as BabyBear they are not sufficient. Limb reconstructions wider than 240 " +
			"bits are ignored. An `if err == nil` block " +
			"counts as unconditional on the assumption that callers propagate the error. Algebraically neutral wrappers such as " +
			"`Sub(x, 0)` are not simplified. Call-site specialization applies only to unexported plain functions whose every use " +
			"is a direct call in the same package with a constant guard; exported functions, methods, escaping function values, " +
			"and runtime arguments keep the finding at the hint. A quiet result is not evidence of soundness, and a reported one " +
			"is not a confirmed vulnerability until the shapes above are ruled out; see docs/relation-rule-review.md.",
	},
	{
		ID:         HintOutputUnused,
		Title:      "Unused hint output",
		Class:      ClassUnboundWitness,
		Severities: []report.Severity{report.SeverityMedium},
		Confidence: "high",
		Summary:    "A hint output is extracted from the returned slice but never referenced again. An unused prover-computed value often means a forgotten constraint, but it can also be intentional padding, so the rule asks for review.",
		Description: "Reports a statically indexed hint output that is extracted from the slice returned by `NewHint` but never " +
			"subsequently referenced, either directly or through its local alias. Every hint output is prover-controlled " +
			"advice; one that reaches no constraint contributes nothing the verifier can rely on.",
		Limitations: "Only statically indexed outputs and their local aliases are tracked. Dynamic indexes, outputs passed " +
			"through slices or struct fields, and complex aliasing remain unknown.",
	},
	{
		ID:         TagVisibilityAsName,
		Title:      "Visibility written as a witness name",
		Class:      ClassUnboundWitness,
		Severities: []report.Severity{report.SeverityHigh, report.SeverityInfo},
		Confidence: "high",
		Summary:    "A struct tag such as `gnark:\"public\"` names the witness element `public` instead of setting its visibility, so the field stays secret: a value the verifier meant to fix becomes one the prover chooses.",
		Description: "gnark parses `gnark:\"name,options\"` like `encoding/json`: the text before the first comma is the witness name and " +
			"visibility is an option after it. `gnark:\"public\"` therefore names the element \"public\" and leaves it at the " +
			"default visibility, secret, so it is absent from the public witness and the verifier cannot pin it. The fix is " +
			"`gnark:\",public\"`. High for `public`. The same mistake with `secret` is reported as info, because the field is " +
			"secret either way and only the name is surprising. Evidence: gnark v0.16.3 `frontend/schema/tags.go` `parseTag` " +
			"and `walk.go`.",
		Limitations: "Only tags whose name part is exactly `public` or `secret` are matched. Visibility inherited from a parent " +
			"struct is not evaluated.",
	},
	{
		ID:         GoEqualityOnVariable,
		Title:      "Go comparison of a circuit variable",
		Class:      ClassNonLoadBearing,
		Severities: []report.Severity{report.SeverityHigh},
		Confidence: "high",
		Summary:    "Go `==`, `!=`, or `switch` on a `frontend.Variable` compares the value the variable holds while the circuit is being compiled, a constraint expression rather than the witness, so the branch it guards is not a constraint.",
		Description: "`frontend.Variable` is `any`. During `frontend.Compile` it holds a linear expression, not the prover's value, " +
			"so `if c.Flag == 1 { api.AssertIsEqual(...) }` is decided once at compile time (the comparison is false) and the " +
			"guarded constraint is never emitted. Express conditions in the circuit instead, for example with `api.IsZero`, " +
			"`api.Select`, or `api.Mul(flag, ...)`. Comparisons with `nil`, fields tagged `gnark:\"-\"` (which hold Go " +
			"constants at compile time), and local variables or slices that only ever hold Go constants (a padding mask built " +
			"with `make` and constant stores, never passed on whole) are not reported. Evidence: gnark v0.16.3 `frontend/variable.go`.",
		Limitations: "Only direct comparisons and switch tags are matched; a Variable converted to another type first, or compared " +
			"through a helper, is not.",
	},
	{
		ID:         DiscardedPredicate,
		Title:      "Discarded predicate",
		Class:      ClassNonLoadBearing,
		Severities: []report.Severity{report.SeverityHigh},
		Confidence: "high",
		Summary:    "The result of a gnark predicate (`frontend.API`'s `IsZero` or `Cmp`, a bounded comparator's `IsLess`/`IsLessEq`, a recursive verifier's `IsValidProof`, or a hash `Sum`) is discarded, so the check it computes constrains nothing.",
		Description: "Predicates return a variable; they do not assert anything. A call used as a statement (also in " +
			"parentheses, deferred, or run with `go`), or bound only to `_` by an assignment or a `var` declaration, computes a " +
			"value the circuit never uses, so the line reads as a check that does not exist. A hasher's `Sum` called on the " +
			"enclosing method's own receiver, directly or through its embedded fields, is not reported, since that is how a " +
			"hasher such as gnark's `MiMC.State` flushes itself; inside a circuit's `Define`, and for every other predicate on " +
			"the receiver, such as an embedded verifier's `IsValidProof`, it is. Assert the result " +
			"(`api.AssertIsEqual(api.IsZero(x), 1)`), use the assertion form, or feed it into later constraints. Go already " +
			"rejects unused local variables, so a stored result is at least read. Evidence: gnark v0.16.3 `frontend/api.go` " +
			"(`IsZero`, `Cmp`), `std/math/cmp/bounded.go`, `std/recursion/groth16/verifier.go` (`IsValidProof`), and " +
			"`std/hash/hash.go`.",
		Limitations: "A result stored and then never read, wrapped in a conversion or a literal before it is dropped, or " +
			"discarded through a helper, is not matched, and neither is a predicate called through a method value or a " +
			"function variable. Predicates outside the list above, such as an emulated field's `IsZero` or the package-level " +
			"functions of `std/math/cmp`, are not checked.",
	},
	{
		ID:         VacuousAssert,
		Title:      "Vacuous assertion",
		Class:      ClassNonLoadBearing,
		Severities: []report.Severity{report.SeverityHigh, report.SeverityMedium},
		Confidence: "high",
		Summary:    "An assertion that holds by construction, such as `api.AssertIsEqual(x, x)` or an assertion over constants only, adds no restriction while reading like a check.",
		Description: "High when both sides are the same expression (`AssertIsEqual(x, x)`, `AssertIsLessOrEqual(x, x)`, or a bounded " +
			"comparator's `AssertIsLessEq(x, x)`); that is almost always a typo for a real check, such as `(computed, " +
			"expected)` written as `(expected, expected)`. Medium when every operand is a constant and the assertion always " +
			"holds (`AssertIsEqual(1, 1)`, `AssertIsBoolean(1)`), which is more often a placeholder. Constant assertions that " +
			"always fail (`AssertIsEqual(1, 0)`) abort compilation on purpose, and ones over `len` or `cap` check the shape of " +
			"fixed-size arrays, so neither is reported. Unsatisfiable forms such as `AssertIsDifferent(x, x)` are " +
			"liveness bugs, not vacuous ones, and are not reported.",
		Limitations: "Expressions are compared structurally: the same variable, field path, or constant index. Algebraically equal " +
			"but differently written operands are not matched.",
	},
	{
		ID:         BitsUnconstrained,
		Title:      "Unconstrained bit decomposition",
		Class:      ClassUnboundWitness,
		Severities: []report.Severity{report.SeverityHigh, report.SeverityMedium},
		Confidence: "medium",
		Summary:    "A `bits` decomposition opts out of digit constraints (`WithUnconstrainedOutputs` or `WithUnconstrainedInputs`) and nothing in the function constrains the digits, so the prover can choose non-boolean digits that still sum to the value.",
		Description: "`bits.ToBinary(api, v, bits.WithUnconstrainedOutputs())` constrains only the weighted sum of the digits; the " +
			"digits themselves are hint outputs. High when those digits are used in the function but never constrained " +
			"(`AssertIsBoolean`, `AssertIsCrumb`, `bits.AssertIsTrit`, `api.FromBinary`, or `bits.FromBinary` without the " +
			"option). Medium for `FromBinary`/`FromBase` with `WithUnconstrainedInputs` whose digits are prover advice (hint " +
			"outputs or an unconstrained decomposition) with no such constraint. Digits passed to another function, returned, " +
			"or stored elsewhere may be constrained there, so they are not reported. Evidence: gnark v0.16.3 " +
			"`std/math/bits/conversion.go`.",
		Limitations: "Options passed through a slice (`opts...`) are not resolved. Constraints in called functions are not " +
			"followed, so any hand-off silences the rule.",
	},
	{
		ID:         BitsOmitModulusCheck,
		Title:      "Bit decomposition without modulus check",
		Class:      ClassUnboundWitness,
		Severities: []report.Severity{report.SeverityMedium},
		Confidence: "high",
		Summary:    "`bits.OmitModulusCheck()` skips the comparison against the field modulus, so a full-width decomposition of `a` can also be one of `a + r`: the bits are not unique.",
		Description: "When the number of digits equals the field's bit length, both `a` and `a + r` (for modulus `r`) can have valid " +
			"decompositions, and gnark's modulus check is what excludes the second. Omitting it is safe only when the " +
			"decomposition is checked for uniqueness elsewhere or uniqueness does not matter; state which in a suppression. " +
			"Evidence: gnark v0.16.3 `std/math/bits/conversion.go` `OmitModulusCheck`.",
		Limitations: "The rule does not check the digit count; a decomposition narrower than the field is unique regardless.",
	},
	{
		ID:         ComparatorNondeterminism,
		Title:      "Nondeterministic bounded comparator",
		Class:      ClassUnboundWitness,
		Severities: []report.Severity{report.SeverityMedium},
		Confidence: "high",
		Summary:    "`cmp.NewBoundedComparator(api, bound, true)` allows nondeterministic behavior: when the operands differ by more than the bound, the constraint system can have several solutions, so comparison results are prover-selectable.",
		Description: "The third argument `allowNonDeterministicBehaviour` trades soundness outside the bound for fewer constraints. " +
			"It is sound only when range checks elsewhere guarantee `|a - b| <= bound` for every comparison. Prefer `false`, " +
			"which makes out-of-bound inputs fail to prove or return a deterministic result. Evidence: gnark v0.16.3 " +
			"`std/math/cmp/bounded.go`.",
		Limitations: "Only a literal constant `true` is matched. Whether the operands are range-checked is not analyzed.",
	},
	{
		ID:         IgnoreUnconstrainedInputs,
		Title:      "Unconstrained inputs explicitly allowed",
		Class:      ClassConfiguration,
		Severities: []report.Severity{report.SeverityMedium},
		Confidence: "high",
		Summary:    "`frontend.IgnoreUnconstrainedInputs()` declares that a circuit may have inputs no constraint uses; gnark documents a compile error for such inputs, but v0.16.3 does not raise it, so nothing in gnark catches them either way.",
		Description: "gnark's documentation says `frontend.Compile` fails when a public or secret input appears in no " +
			"constraint, that this option turns the error off, and that the option should not be used in production. As " +
			"of v0.16.3 the error is not raised with or without the option: a circuit with an unused input compiles with " +
			"default options, with the R1CS and PLONK builders alike. The option therefore disables nothing today. It is " +
			"still reported because it records that the author expects an input that no constraint binds, and such an " +
			"input is whatever the prover supplies; a gnark release that raises the documented error would also let this " +
			"option silence it. Test code is excluded by default. Evidence: the gnark v0.16.3 documentation of " +
			"`frontend.IgnoreUnconstrainedInputs`, and compiling a circuit with an unused input under default options.",
		Limitations: "Options assembled dynamically (`opts...`) are not resolved. The rule reports the option, not the " +
			"unused inputs themselves: an input that no constraint uses is not reported, with or without the option.",
	},
	{
		ID:         UnsafeSetup,
		Title:      "Unsafe setup outside tests",
		Class:      ClassConfiguration,
		Severities: []report.Severity{report.SeverityMedium, report.SeverityLow},
		Confidence: "high",
		Summary:    "Production code imports gnark's test-only `unsafekzg` SRS (medium), or runs a single-party `groth16.Setup` in a `main` package (low), so whoever ran setup could forge proofs.",
		Description: "`test/unsafekzg` generates KZG parameters from locally known randomness; it exists for tests. A `groth16.Setup` " +
			"run by one party leaves that party able to forge proofs unless the output comes from a multi-party ceremony. " +
			"Both are reported only outside `_test.go` files: the import at its import line, and `groth16.Setup` only in a " +
			"`main` package, where it most likely produces deployable keys.",
		Limitations: "Whether the resulting keys are actually deployed cannot be seen from source. Key generation in library " +
			"packages is not reported.",
	},
	{
		ID:         RecursionUnverified,
		Title:      "Recursive proof witness used without verification",
		Class:      ClassUnverifiedProof,
		Severities: []report.Severity{report.SeverityHigh},
		Confidence: "medium",
		Summary:    "A circuit's `Define` uses the public inputs of a `std/recursion` witness, but no in-circuit verification takes that witness, so the prover can supply any values for them.",
		Description: "gnark verifies a proof inside a circuit with a `Verifier` from `std/recursion/groth16` or `std/recursion/plonk`: " +
			"`AssertProof(vk, proof, witness)` asserts that the proof holds for the witness, plonk's `AssertSameProofs` and " +
			"`AssertDifferentProofs` assert several proofs at once, groth16's `IsValidProof` returns a variable that is 1 " +
			"only for a valid proof, and plonk's `PrepareVerification` returns KZG openings to verify in a later batch. A " +
			"`Witness` holds the inner proof's public inputs in its `Public` field. Those values mean what the inner circuit " +
			"proved only once a proof over that witness is verified; otherwise they are free inputs. The rule looks at each " +
			"`Define(frontend.API) error` method that no package code outside its own body refers to: the circuit entry point " +
			"that gnark compiles, which no caller can verify for. It reports the first read of a witness's `Public` " +
			"(directly, through an embedded witness, or through a type defined over `Witness`; not under `len` or `cap`, in a " +
			"`range` that takes no values, or as an assignment target) when no verification in `Define` takes that witness, " +
			"whether `Define` verifies nothing or verifies only other witnesses. A witness is matched by its field path from " +
			"the receiver, so a `[]Witness` passed to a batch method covers each element, a literal of witnesses (also " +
			"through a local holding it) covers each one it lists, a witness rebuilt as a literal from another witness's " +
			"`Public` counts as that witness, and a local defined once from a field path, or a `range` variable over one, " +
			"stands for that path when it is never reassigned (a `range` with `=` included) or addressed (calling a pointer " +
			"method on it included). An `IsValidProof` call whose result is thrown away (as a statement, deferred, or bound " +
			"to `_`) is not a verification; `GNARK_DISCARDED_PREDICATE` reports the call itself. gnark documents a " +
			"compile-time error for inputs that no constraint uses (`frontend.IgnoreUnconstrainedInputs`), but v0.16.3 does " +
			"not raise it, so a circuit that never touches its proof compiles with default options; the executable witness " +
			"for this rule compiles its unverified circuit that way. Evidence: the gnark v0.16.3 package documentation of " +
			"`std/recursion/groth16` and `std/recursion/plonk` (`Verifier`, `Witness`).",
		Limitations: "Only reads made in an entry-point `Define` count: public inputs read in a helper are not seen. A `Define` that " +
			"other package code refers to (typically another circuit calling it as a sub-circuit, but any reference outside " +
			"its own body counts) is skipped, and its reads are not seen from a caller either; composition across packages, " +
			"or only through an interface such as `frontend.Circuit`, is not recognized, so such a sub-circuit is analyzed as " +
			"an entry point and can be a false positive. Verification is looked for in `Define` and, one level deep, in " +
			"package-local functions and methods (generic ones included) that `Define` passes the witness, its public inputs " +
			"(the slice, part of it, its elements, or a local holding them), or the receiver; a method value bound to a value " +
			"holding the witness counts as handing it to that method wherever it appears, called or not. A helper that " +
			"contains any verification silences the rule for the whole method, whichever witness it verifies, and a " +
			"verification two or more calls away is missed and reported as absent. Public inputs handed to code in another " +
			"package are not followed, so verification there is reported as absent. The rule stays quiet for the whole method " +
			"when the witness itself reaches code it does not follow: another package (the standard library excepted, which " +
			"cannot verify), a function value (a function literal included), or an interface value (assigned, converted, " +
			"appended, sent on a channel, placed in a literal, or returned by a package-local helper), including a " +
			"sub-circuit run through `frontend.Circuit`, whether or not that code verifies; and when a verification's witness " +
			"argument is not a field path from the receiver, a literal of them, or a local standing for one (for example a " +
			"call result, or a local copy that is later modified). A read through such a value is reported only when `Define` " +
			"verifies nothing at all. Indexes and slice bounds are ignored, so verifying `c.Witnesses[0]` or " +
			"`c.Witnesses[:1]` covers a read of `c.Witnesses[1]`. Matching ignores statement order: a witness whose `Public` " +
			"elements `Define` overwrites, or a field it reassigns, still counts as verified wherever it is read. A " +
			"verification counts wherever it appears in `Define`: under a Go condition, after an early return, in a loop, in " +
			"a function literal, or in unreachable code, although it may not run while the circuit compiles. A kept " +
			"`IsValidProof` result counts as enforced: whether it reaches an assertion, rather than a `Select` or a return " +
			"value, is not followed. `PrepareVerification` counts as verification even if its openings are never " +
			"batch-verified. Whether the verifying key is fixed and the intended one, and whether `SwitchVerificationKey` " +
			"selects only trusted keys, is not checked.",
	},
}

// All returns every registered rule in declaration order.
func All() []Spec {
	out := make([]Spec, len(specs))
	copy(out, specs)
	return out
}

// Lookup returns the rule with the given ID.
func Lookup(id string) (Spec, bool) {
	for _, spec := range specs {
		if spec.ID == id {
			return spec, true
		}
	}
	return Spec{}, false
}

// DefaultSeverity is the most severe level the rule emits.
func (s Spec) DefaultSeverity() report.Severity { return s.Severities[0] }

// Allows reports whether the rule is registered to emit severity.
func (s Spec) Allows(severity report.Severity) bool {
	for _, allowed := range s.Severities {
		if allowed == severity {
			return true
		}
	}
	return false
}

// SeverityLabel renders the severity spread, for example "high / medium".
func (s Spec) SeverityLabel() string {
	labels := make([]string, len(s.Severities))
	for i, severity := range s.Severities {
		labels[i] = string(severity)
	}
	return strings.Join(labels, " / ")
}

// HelpURI links to the rule's heading in the published rule reference.
func (s Spec) HelpURI() string { return DocURL + "#" + strings.ToLower(s.ID) }
