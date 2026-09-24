// Package witness holds executable witnesses for gnark-safety's high rules.
//
// Each witness, in this package's tests, pairs a circuit the rule reports
// with a corrected circuit it does not, and shows the difference is real:
// the reported circuit accepts a semantically invalid witness (through the
// constraint solver, or a Groth16 proof) and the corrected one rejects it.
// The circuits live in _test.go files, so a default scan of this repository
// does not report them.
package witness
