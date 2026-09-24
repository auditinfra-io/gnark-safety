# Rules

## `GNARK_HINT_RELATION_INCOMPLETE`

**Severity:** high. **Confidence:** high for the recognized shape.

The first rule identifies a direct, type-resolved two-output `NewHint` call
when one `AssertIsEqual` contains the typed `Add(Mul(q, d), r)` reconstruction
but the function has no unconditional, type-resolved `AssertIsLess(r, d)` or
equivalent `AssertIsLessOrEqual(r, api.Sub(d, 1))`. Indexed outputs may use
literals, named constants, constant expressions, or local aliases. Comparisons
with the wrong operand order or a different bound do not count as coverage. A
comparison inside an `if`/`else`, loop, switch, select, or function literal is
not considered universal coverage because that region may not execute.

The finding points to the hint call and records three evidence items: the hint
identity, the observed reconstruction, and the missing canonical bound. The
repository's `constrainDivision` helper is the canonical regression fixture:
its vulnerable caller selects the path that omits `r < d`, whereas the
corrected caller selects the checked path.

This deliberately narrow recognition does not prove that unreported code is
sound. One level of unconditional direct local helper calls is summarized;
deeper, recursive, external, or dynamically dispatched helpers, more complex
aliases, and alternative comparison gadgets remain unknown.

## Per-output invariant assessments

JSON schema 1.1 adds an `invariants` array to every hint. Each output receives
separate `participation`, `range`, `relation`, `canonicality`, and
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

## `GNARK_HINT_OUTPUT_UNUSED`

**Severity:** review. **Confidence:** high for direct indexed outputs.

This rule reports a hint output that is extracted from the returned slice but
never subsequently referenced, either directly or through its local alias. An
unused prover-computed value often indicates a forgotten constraint, but it can
also be intentional API padding, so the rule requests review rather than
claiming a vulnerability. Dynamic indexes and complex aliasing remain unknown.
