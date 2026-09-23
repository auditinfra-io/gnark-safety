# Rules

## `GNARK_HINT_RELATION_INCOMPLETE`

**Severity:** high. **Confidence:** high for the recognized shape.

The first rule identifies a direct, type-resolved two-output `NewHint` call
when both indexed outputs participate in an `AssertIsEqual` reconstruction but
the function has no unconditional `AssertIsLess` covering the remainder. A
comparison guarded by a Go `if` is not considered universal coverage because a
caller may select the unchecked path.

The finding points to the hint call and records three evidence items: the hint
identity, the observed reconstruction, and the missing canonical bound. The
repository's `constrainDivision` helper is the canonical regression fixture:
its vulnerable caller selects the path that omits `r < d`, whereas the
corrected caller selects the checked path.

This deliberately narrow recognition does not prove that unreported code is
sound. More complex aliases, helper-mediated assertions, and alternative
comparison gadgets remain unknown until interprocedural dataflow is added.
