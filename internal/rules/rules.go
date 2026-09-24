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
	HintRelationIncomplete = "GNARK_HINT_RELATION_INCOMPLETE"
	HintOutputUnused       = "GNARK_HINT_OUTPUT_UNUSED"
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
		Confidence: "high",
		Summary:    "A two-output hint is reconstructed as `n = q*d + r`, but no unconditional `r < d` bound makes the quotient and remainder unique, so the prover can supply a noncanonical pair that still satisfies the circuit.",
		Description: "Identifies a direct, type-resolved two-output `NewHint` call (`Compiler.NewHint` or the deprecated `API.NewHint`) " +
			"when one `AssertIsEqual` contains the typed `Add(Mul(q, d), r)` reconstruction but the function has no unconditional, " +
			"type-resolved `AssertIsLess(r, d)` or equivalent `AssertIsLessOrEqual(r, api.Sub(d, 1))`. Indexed outputs may use " +
			"literals, named constants, constant expressions, or local aliases. Comparisons with the wrong operand order or a " +
			"different bound do not count as coverage. A comparison inside an `if`/`else`, loop, switch, select, or function " +
			"literal, or after a successful early return, is not universal coverage because that region may not execute. " +
			"The finding points to the hint call and records the hint identity, the observed reconstruction, and the missing " +
			"canonical bound as evidence.",
		Limitations: "One level of unconditional, direct, package-local helper calls is summarized. Deeper, recursive, external, " +
			"or dynamically dispatched helpers, other aliasing, and alternative comparison gadgets remain unknown. Algebraically " +
			"neutral wrappers such as `Sub(x, 0)` are not simplified. A quiet result is not evidence of soundness.",
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
