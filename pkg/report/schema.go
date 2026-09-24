// Package report defines the stable, machine-readable gnark-safety report.
package report

const SchemaVersion = "1.1"

type InvariantStatus string

const (
	InvariantSatisfied InvariantStatus = "satisfied"
	InvariantMissing   InvariantStatus = "missing"
	InvariantUnknown   InvariantStatus = "unknown"
)

// Invariant records one independently evaluated property of a hint output.
// Unknown is intentionally distinct from missing: unsupported analysis is not
// evidence that a circuit lacks a constraint.
type Invariant struct {
	OutputIndex int             `json:"output_index"`
	Kind        string          `json:"kind"`
	Status      InvariantStatus `json:"status"`
	Evidence    []string        `json:"evidence"`
}

type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityReview Severity = "review"
)

type Location struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

type Hint struct {
	Package     string      `json:"package"`
	File        string      `json:"file"`
	Line        int         `json:"line"`
	Column      int         `json:"column"`
	Function    string      `json:"function"`
	Hint        string      `json:"hint"`
	OutputCount *int        `json:"output_count,omitempty"`
	InputCount  *int        `json:"input_count,omitempty"`
	Unknown     []string    `json:"unknown,omitempty"`
	Invariants  []Invariant `json:"invariants"`
}

type Finding struct {
	RuleID      string   `json:"rule_id"`
	Severity    Severity `json:"severity"`
	Confidence  string   `json:"confidence"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Column      int      `json:"column"`
	Function    string   `json:"function"`
	Message     string   `json:"message"`
	Evidence    []string `json:"evidence"`
	Limitations []string `json:"limitations"`
}

type Report struct {
	SchemaVersion string    `json:"schema_version"`
	Module        string    `json:"module,omitempty"`
	Findings      []Finding `json:"findings"`
	Hints         []Hint    `json:"hints"`
	Diagnostics   []string  `json:"diagnostics"`
	Limitations   []string  `json:"limitations"`
}
