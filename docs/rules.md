# Rules

## `GNARK_HINT_RELATION_INCOMPLETE`

**Severity:** high. **Confidence:** high for the recognized shape.

The first rule identifies a direct, type-resolved two-output `NewHint` call
when one `AssertIsEqual` contains the typed `Add(Mul(q, d), r)` reconstruction
but the function has no unconditional, type-resolved `AssertIsLess(r, d)`.
Indexed outputs may be used directly or through local aliases. Comparisons with
the wrong operand order or a different bound do not count as coverage. A
comparison inside an `if`/`else`, loop, switch, select, or function literal is
not considered universal coverage because that region may not execute.

The finding points to the hint call and records three evidence items: the hint
identity, the observed reconstruction, and the missing canonical bound. The
repository's `constrainDivision` helper is the canonical regression fixture:
its vulnerable caller selects the path that omits `r < d`, whereas the
corrected caller selects the checked path.

This deliberately narrow recognition does not prove that unreported code is
sound. More complex aliases, helper-mediated assertions, and alternative
comparison gadgets remain unknown until interprocedural dataflow is added.
