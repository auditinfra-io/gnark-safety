// Package report defines the stable, machine-readable gnark-safety report.
package report

// SchemaVersion identifies the report layout. 2.0 replaced the
// high/review severity pair with a five-level scale and added tool identity.
const SchemaVersion = "2.0"

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

// Severity orders findings for triage and for the CLI exit gate.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Severities lists every severity, most severe first.
var Severities = []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}

// Rank orders severities: critical is highest, info is zero, and an
// unrecognized value is negative so it never satisfies a threshold.
func (s Severity) Rank() int {
	for i, known := range Severities {
		if s == known {
			return len(Severities) - 1 - i
		}
	}
	return -1
}

// ParseSeverity accepts exactly the lower-case severity names.
func ParseSeverity(value string) (Severity, bool) {
	s := Severity(value)
	return s, s.Rank() >= 0
}

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
	RuleID   string   `json:"rule_id"`
	Severity Severity `json:"severity"`
	// OriginalSeverity is set when a scan policy changed Severity, for
	// example when a finding in example code was downgraded to low.
	OriginalSeverity Severity `json:"original_severity,omitempty"`
	Confidence       string   `json:"confidence"`
	File             string   `json:"file"`
	Line             int      `json:"line"`
	Column           int      `json:"column"`
	Function         string   `json:"function"`
	Message          string   `json:"message"`
	Evidence         []string `json:"evidence"`
	Limitations      []string `json:"limitations"`
	// Suppression is set only on findings in Report.Suppressed.
	Suppression *Suppression `json:"suppression,omitempty"`
}

// Suppression records the in-source directive that silenced a finding.
type Suppression struct {
	// Kind is "inSource", matching SARIF's suppression kinds.
	Kind          string `json:"kind"`
	Justification string `json:"justification"`
	// Line is the line of the //gnark-safety:ignore directive.
	Line int `json:"line"`
}

// Coverage states what a scan examined, so a report with no findings can be
// told apart from a scan that analyzed nothing.
type Coverage struct {
	// Packages is the number of distinct requested packages analyzed.
	Packages int `json:"packages"`
	// GnarkPackages counts analyzed packages that import a gnark package.
	GnarkPackages int `json:"gnark_packages"`
	// Files is the number of distinct Go files analyzed.
	Files int `json:"files"`
	// TestsIncluded reports whether _test.go files were analyzed.
	TestsIncluded bool `json:"tests_included"`
	// ExamplesDowngraded counts findings lowered to low because they are in
	// example code.
	ExamplesDowngraded int `json:"examples_downgraded"`
	// TestSupportDowngraded counts findings lowered to low because they are
	// in test-support code (test/, testutil/, e2e/, ...).
	TestSupportDowngraded int `json:"test_support_downgraded"`
	// Skipped lists requested packages that failed to load or type-check
	// and were not analyzed. A report with skipped packages is partial.
	Skipped []SkippedPackage `json:"skipped,omitempty"`
}

// SkippedPackage is a requested package that was not analyzed.
type SkippedPackage struct {
	// Package is the go/packages ID, such as example.com/m/wasm.
	Package string `json:"package"`
	// Errors are the first load or type-checking errors for the package or
	// its dependencies.
	Errors []string `json:"errors"`
}

// Tool identifies the analyzer build that produced a report.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Report struct {
	SchemaVersion string    `json:"schema_version"`
	Tool          Tool      `json:"tool"`
	Module        string    `json:"module,omitempty"`
	Coverage      Coverage  `json:"coverage"`
	Findings      []Finding `json:"findings"`
	// Suppressed holds findings silenced by //gnark-safety:ignore. They
	// never count toward the exit gate but stay visible for audit.
	Suppressed  []Finding `json:"suppressed"`
	Hints       []Hint    `json:"hints"`
	Diagnostics []string  `json:"diagnostics"`
	Limitations []string  `json:"limitations"`
}
