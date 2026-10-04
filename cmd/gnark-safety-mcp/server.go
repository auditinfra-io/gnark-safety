package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/auditinfra-io/gnark-safety/internal/analyzer"
	"github.com/auditinfra-io/gnark-safety/internal/rules"
	"github.com/auditinfra-io/gnark-safety/internal/version"
	"github.com/auditinfra-io/gnark-safety/pkg/report"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// interpretation is the README's own wording on what a result means. Every
// scan description and response carries it, so an agent relaying a result
// has the caveat in hand.
const interpretation = "A clean run is not an audit. It means no shape these rules recognize matched, not that the circuit is sound. A finding is a lead, not a verdict. Never describe a clean result as a security guarantee."

const untrustedNote = "Scanning runs the local Go toolchain to load and type-check the packages (never another toolchain: GOTOOLCHAIN is forced to local), and may download their module dependencies. For code outside the user's trust boundary, follow docs/untrusted-scanning.md in the gnark-safety repository: scan in a disposable, network-restricted container rather than on a developer machine."

// config is fixed by whoever starts the server; no tool argument changes it.
type config struct {
	root           string
	env            []string
	timeout        time.Duration
	maxHints       int
	maxOutputBytes int
}

type server struct {
	cfg config
	// scanning admits one package load at a time, so an agent cannot fan out
	// many concurrent go commands.
	scanning sync.Mutex
}

func newMCPServer(cfg config) *mcp.Server {
	s := &server{cfg: cfg}
	srv := mcp.NewServer(&mcp.Implementation{Name: "gnark-safety", Version: version.String()}, &mcp.ServerOptions{
		Instructions: "gnark-safety statically analyzes gnark (Go zero-knowledge circuit) source for specific patterns that often mean a circuit accepts values it should reject. It runs locally and uploads nothing. " + interpretation,
	})
	readOnly := func(openWorld bool) *mcp.ToolAnnotations {
		return &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: &openWorld}
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:  "scan",
		Title: "Scan gnark circuits",
		Description: "Run gnark-safety's rules over Go packages below the server root (" + cfg.root + "). Patterns are relative and start with ./, for example ./... or ./circuits/.... " +
			"Errors are reported with a code and are never an empty success: no_gnark_packages when no scanned package imports gnark, packages_failed_to_load when a requested package does not load or type-check. " +
			"A successful result states what was analyzed (packages, gnark packages, files), the rules that ran, the field setting, and the analysis limitations. " +
			interpretation + " " + untrustedNote,
		InputSchema: scanSchema(),
		Annotations: readOnly(true),
	}, s.scan)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "inventory",
		Title:       "List gnark hint call sites",
		Description: "List every gnark hint call site in Go packages below the server root, with per-output invariant assessments, without applying rules. Same patterns and error codes as scan. " + untrustedNote,
		InputSchema: patternsSchema[inventoryInput](),
		Annotations: readOnly(true),
	}, s.inventory)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_rules",
		Title:       "List gnark-safety rules",
		Description: "List every rule this gnark-safety binary runs, with its severity, class, and summary.",
		Annotations: readOnly(false),
	}, s.listRules)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "explain_rule",
		Title:       "Explain a gnark-safety rule",
		Description: "Explain what one rule checks and where it stops: the cases it misses and where it can be wrong.",
		Annotations: readOnly(false),
	}, s.explainRule)
	return srv
}

type scanInput struct {
	Patterns           []string `json:"patterns" jsonschema:"Go package patterns relative to the server root, starting with ./ (for example ./... or ./circuits/...)"`
	FailOn             string   `json:"fail_on,omitempty" jsonschema:"lowest severity that makes the gate fail: critical, high, medium, low, info, or none (default high)"`
	Field              string   `json:"field,omitempty" jsonschema:"scalar field for bound checks: unknown, bn254, or bls12-381 (default unknown, which makes no field-safety claim)"`
	IncludeTests       bool     `json:"include_tests,omitempty" jsonschema:"also analyze _test.go files"`
	IncludeExamples    bool     `json:"include_examples,omitempty" jsonschema:"keep the original severity of findings in example directories (by default they are lowered to low)"`
	IncludeTestSupport bool     `json:"include_test_support,omitempty" jsonschema:"keep the original severity of findings in test-support directories (by default they are lowered to low)"`
}

type inventoryInput struct {
	Patterns []string `json:"patterns" jsonschema:"Go package patterns relative to the server root, starting with ./ (for example ./... or ./circuits/...)"`
}

type explainInput struct {
	RuleID string `json:"rule_id" jsonschema:"a rule ID from list_rules, such as GNARK_HINT_RELATION_INCOMPLETE"`
}

// patternsSchema infers the input schema of T and closes it: an argument the
// schema does not name, such as allow_empty or allow_partial, is rejected
// before the handler runs.
func patternsSchema[T any]() *jsonschema.Schema {
	schema, err := jsonschema.For[T](nil)
	if err != nil {
		panic(err)
	}
	schema.AdditionalProperties = &jsonschema.Schema{Not: &jsonschema.Schema{}}
	patterns := schema.Properties["patterns"]
	patterns.MinItems = jsonschema.Ptr(1)
	patterns.MaxItems = jsonschema.Ptr(maxPatterns)
	return schema
}

func scanSchema() *jsonschema.Schema {
	schema := patternsSchema[scanInput]()
	schema.Properties["fail_on"].Enum = []any{"critical", "high", "medium", "low", "info", "none"}
	schema.Properties["field"].Enum = []any{"unknown", "bn254", "bls12-381"}
	return schema
}

// --- results ---

type toolError struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// Packages names each requested package that failed to load, from
	// coverage.skipped, with its errors.
	Packages []report.SkippedPackage `json:"packages,omitempty"`
	// Coverage is what was examined before the error, when anything was.
	Coverage       *report.Coverage `json:"coverage,omitempty"`
	Interpretation string           `json:"interpretation"`
}

func fail(code, message string) (*mcp.CallToolResult, any, error) {
	return failWith(errorBody{Code: code, Message: message})
}

func failWith(body errorBody) (*mcp.CallToolResult, any, error) {
	body.Interpretation = "This is an error, not a result: nothing can be concluded about the circuits from it. Do not report the code as clean."
	return &mcp.CallToolResult{IsError: true}, toolError{Error: body}, nil
}

type fieldInfo struct {
	Setting string `json:"setting"`
	Claim   string `json:"claim"`
}

type gate struct {
	FailOn string `json:"fail_on"`
	// Result is "fails" when a finding is at or above fail_on, "passes" when
	// none is, and "not gated" for fail_on none.
	Result           string `json:"result"`
	FindingsAtOrOver int    `json:"findings_at_or_above"`
}

type truncation struct {
	Reason             string `json:"reason"`
	FindingsTotal      int    `json:"findings_total"`
	FindingsReturned   int    `json:"findings_returned"`
	SuppressedTotal    int    `json:"suppressed_total"`
	SuppressedReturned int    `json:"suppressed_returned"`
}

type scanResult struct {
	Tool     report.Tool     `json:"tool"`
	Root     string          `json:"root"`
	Patterns []string        `json:"patterns"`
	Module   string          `json:"module,omitempty"`
	Gate     gate            `json:"gate"`
	Coverage report.Coverage `json:"coverage"`
	// Skipped is coverage.skipped, always present. It is empty in every
	// successful result, because a scan with unloaded packages is an error.
	Skipped                []report.SkippedPackage `json:"skipped"`
	Field                  fieldInfo               `json:"field"`
	RulesRun               []string                `json:"rules_run"`
	HintCalls              int                     `json:"hint_calls"`
	QuotientRemainderShape int                     `json:"hint_calls_in_quotient_remainder_shape"`
	Findings               []report.Finding        `json:"findings"`
	Suppressed             []report.Finding        `json:"suppressed"`
	Limitations            []string                `json:"limitations"`
	Diagnostics            []string                `json:"diagnostics"`
	Truncated              *truncation             `json:"truncated,omitempty"`
	Interpretation         string                  `json:"interpretation"`
}

type inventoryResult struct {
	Tool          report.Tool             `json:"tool"`
	Root          string                  `json:"root"`
	Patterns      []string                `json:"patterns"`
	Coverage      report.Coverage         `json:"coverage"`
	Skipped       []report.SkippedPackage `json:"skipped"`
	Hints         []report.Hint           `json:"hints"`
	HintsTotal    int                     `json:"hints_total"`
	Truncated     *truncation             `json:"truncated,omitempty"`
	Limitations   []string                `json:"limitations"`
	Diagnostics   []string                `json:"diagnostics"`
	Inventoryonly string                  `json:"note"`
}

// --- handlers ---

func (s *server) scan(ctx context.Context, _ *mcp.CallToolRequest, in scanInput) (*mcp.CallToolResult, any, error) {
	failOn := in.FailOn
	if failOn == "" {
		failOn = "high"
	}
	threshold, gated := report.ParseSeverity(failOn)
	if !gated && failOn != "none" {
		return fail("invalid_arguments", fmt.Sprintf("fail_on %q is not one of critical, high, medium, low, info, none", failOn))
	}
	field := in.Field
	if field == "" {
		field = "unknown"
	}
	opts := analyzer.Options{MaxHints: s.cfg.maxHints, IncludeTests: in.IncludeTests, IncludeExamples: in.IncludeExamples, IncludeTestSupport: in.IncludeTestSupport}
	claim := "unknown: no field-safety claim is made; bounds are not compared with any scalar-field modulus."
	switch field {
	case "unknown":
	case "bn254":
		opts.FieldModulus, opts.FieldName = ecc.BN254.ScalarField(), "BN254 scalar field"
		claim = "Recognized bounded reconstructions are compared with the BN254 scalar-field modulus."
	case "bls12-381":
		opts.FieldModulus, opts.FieldName = ecc.BLS12_381.ScalarField(), "BLS12-381 scalar field"
		claim = "Recognized bounded reconstructions are compared with the BLS12-381 scalar-field modulus."
	default:
		return fail("invalid_arguments", fmt.Sprintf("field %q is not one of unknown, bn254, bls12-381", field))
	}
	r, res, out, failed := s.load(ctx, in.Patterns, opts)
	if failed {
		return res, out, nil
	}
	result := scanResult{
		Tool: r.Tool, Root: s.cfg.root, Patterns: in.Patterns, Module: r.Module,
		Coverage: r.Coverage, Skipped: []report.SkippedPackage{},
		Field:    fieldInfo{Setting: field, Claim: claim},
		Findings: sortedBySeverity(r.Findings), Suppressed: sortedBySeverity(r.Suppressed),
		Limitations: r.Limitations, Diagnostics: r.Diagnostics, HintCalls: len(r.Hints),
		QuotientRemainderShape: quotientRemainderShape(r), Interpretation: interpretation,
	}
	for _, spec := range rules.All() {
		result.RulesRun = append(result.RulesRun, spec.ID)
	}
	result.Gate = gate{FailOn: failOn, Result: "not gated"}
	if gated {
		for _, f := range r.Findings {
			if f.Severity.Rank() >= threshold.Rank() {
				result.Gate.FindingsAtOrOver++
			}
		}
		result.Gate.Result = "passes"
		if result.Gate.FindingsAtOrOver > 0 {
			result.Gate.Result = "fails"
		}
	}
	return s.bounded(&result, func(n, m int) {
		if result.Truncated == nil {
			result.Truncated = &truncation{FindingsTotal: len(result.Findings), SuppressedTotal: len(result.Suppressed)}
		}
		result.Findings, result.Suppressed = result.Findings[:n], result.Suppressed[:m]
		result.Truncated.FindingsReturned, result.Truncated.SuppressedReturned = n, m
		result.Truncated.Reason = fmt.Sprintf("The result exceeded the server's %d-byte output limit. Findings are ordered most severe first and only the first %d of %d are returned; the gate verdict counts all of them.", s.cfg.maxOutputBytes, n, result.Truncated.FindingsTotal)
	}, len(result.Findings), len(result.Suppressed))
}

func (s *server) inventory(ctx context.Context, _ *mcp.CallToolRequest, in inventoryInput) (*mcp.CallToolResult, any, error) {
	r, res, out, failed := s.load(ctx, in.Patterns, analyzer.Options{MaxHints: s.cfg.maxHints, IncludeExamples: true})
	if failed {
		return res, out, nil
	}
	result := inventoryResult{
		Tool: r.Tool, Root: s.cfg.root, Patterns: in.Patterns, Coverage: r.Coverage, Skipped: []report.SkippedPackage{},
		Hints: r.Hints, HintsTotal: len(r.Hints), Limitations: r.Limitations, Diagnostics: r.Diagnostics,
		Inventoryonly: "An inventory lists hint call sites and their invariant assessments; no rules are applied, so it makes no claim about findings.",
	}
	return s.bounded(&result, func(n, _ int) {
		result.Hints = result.Hints[:n]
		result.Truncated = &truncation{Reason: fmt.Sprintf("The result exceeded the server's %d-byte output limit; only the first %d of %d hint call sites are returned.", s.cfg.maxOutputBytes, n, result.HintsTotal), FindingsTotal: result.HintsTotal, FindingsReturned: n}
	}, len(result.Hints), 0)
}

// load runs the analyzer with the server's fixed environment and ceilings and
// maps every way a scan can fail to examine gnark code to a coded error.
// SkipUnloadable is set only so that coverage.skipped names each package
// that failed; a non-empty list is still an error.
func (s *server) load(ctx context.Context, patterns []string, opts analyzer.Options) (report.Report, *mcp.CallToolResult, any, bool) {
	errorResult := func(res *mcp.CallToolResult, out any, _ error) (report.Report, *mcp.CallToolResult, any, bool) {
		return report.Report{}, res, out, true
	}
	if err := checkPatterns(ctx, s.cfg.root, patterns); err != nil {
		if errors.Is(err, errOutsideRoot) {
			return errorResult(fail("path_outside_root", err.Error()))
		}
		return errorResult(fail("invalid_arguments", err.Error()))
	}
	s.scanning.Lock()
	defer s.scanning.Unlock()
	ctx, cancel := context.WithTimeout(ctx, s.cfg.timeout)
	defer cancel()
	opts.Env, opts.SkipUnloadable, opts.PathBase = s.cfg.env, true, s.cfg.root
	r, err := analyzer.ScanContext(ctx, s.cfg.root, patterns, opts)
	switch {
	case len(r.Coverage.Skipped) > 0:
		message := fmt.Sprintf("%d requested package(s) failed to load or type-check and were not analyzed, so the scan is incomplete and its result would be misleading.", len(r.Coverage.Skipped))
		if err != nil {
			message += " " + err.Error()
		} else if len(r.Diagnostics) > 0 {
			message += " " + strings.Join(r.Diagnostics, " ")
		}
		return errorResult(failWith(errorBody{Code: "packages_failed_to_load", Message: message, Packages: r.Coverage.Skipped}))
	case err == nil:
	case ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		return errorResult(fail("timeout", fmt.Sprintf("the scan did not finish within the server's %s timeout: %v", s.cfg.timeout, err)))
	case strings.Contains(err.Error(), "matched no packages"):
		return errorResult(fail("no_packages_matched", err.Error()))
	case strings.HasPrefix(err.Error(), "hint limit exceeded"):
		return errorResult(fail("hint_limit_exceeded", fmt.Sprintf("%v; the server was started with --max-hints %d", err, s.cfg.maxHints)))
	default:
		// The go command itself failed before reporting any package: a go.mod
		// that needs a newer Go than the local toolchain, a missing module, or
		// a malformed go.mod. Nothing was analyzed.
		return errorResult(failWith(errorBody{Code: "packages_failed_to_load", Message: "the go command could not load the requested packages, so nothing was analyzed: " + err.Error(), Packages: requested(patterns, err)}))
	}
	// A scan that examined no gnark code must not read as a clean pass.
	if r.Coverage.GnarkPackages == 0 {
		coverage := r.Coverage
		return errorResult(failWith(errorBody{Code: "no_gnark_packages", Message: fmt.Sprintf("none of the %d scanned package(s) import gnark, so no circuit code was analyzed. Check the package patterns.", r.Coverage.Packages), Coverage: &coverage}))
	}
	return r, nil, nil, false
}

// requested names each pattern as unloaded when the go command failed
// before reporting any package.
func requested(patterns []string, err error) []report.SkippedPackage {
	var out []report.SkippedPackage
	for _, pattern := range patterns {
		out = append(out, report.SkippedPackage{Package: pattern, Errors: []string{err.Error()}})
	}
	return out
}

// bounded returns result, shrinking it with cut(n, m) — n of the first list,
// m of the second — until its JSON fits the output limit. Truncation is
// recorded in the result by cut; if nothing fits, it is an error.
func (s *server) bounded(result any, cut func(n, m int), first, second int) (*mcp.CallToolResult, any, error) {
	size := func() int {
		data, err := json.Marshal(result)
		if err != nil {
			return s.cfg.maxOutputBytes + 1
		}
		return len(data)
	}
	if size() <= s.cfg.maxOutputBytes {
		return nil, result, nil
	}
	n, m := first, second
	for size() > s.cfg.maxOutputBytes {
		switch {
		case m > 0:
			m /= 2
		case n > 0:
			n /= 2
		default:
			return fail("output_limit_exceeded", fmt.Sprintf("even with every finding removed, the result exceeds the server's %d-byte output limit", s.cfg.maxOutputBytes))
		}
		cut(n, m)
	}
	return nil, result, nil
}

func sortedBySeverity(findings []report.Finding) []report.Finding {
	out := append([]report.Finding{}, findings...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity.Rank() > out[j].Severity.Rank() })
	return out
}

// quotientRemainderShape counts hint calls the relation rule could check,
// as the CLI summary does.
func quotientRemainderShape(r report.Report) int {
	shaped := 0
	for _, h := range r.Hints {
		for _, invariant := range h.Invariants {
			if invariant.Kind == "canonicality" && invariant.Status != report.InvariantUnknown {
				shaped++
				break
			}
		}
	}
	return shaped
}

type ruleInfo struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Class      string   `json:"class"`
	Severities []string `json:"severities"`
	Confidence string   `json:"confidence"`
	Summary    string   `json:"summary"`
	Reference  string   `json:"reference"`
}

func describe(spec rules.Spec) ruleInfo {
	info := ruleInfo{ID: spec.ID, Title: spec.Title, Class: spec.Class, Confidence: spec.Confidence, Summary: spec.Summary, Reference: spec.HelpURI()}
	for _, severity := range spec.Severities {
		info.Severities = append(info.Severities, string(severity))
	}
	return info
}

type rulesResult struct {
	Tool  report.Tool `json:"tool"`
	Rules []ruleInfo  `json:"rules"`
}

func (s *server) listRules(context.Context, *mcp.CallToolRequest, any) (*mcp.CallToolResult, any, error) {
	result := rulesResult{Tool: report.Tool{Name: "gnark-safety", Version: version.String()}}
	for _, spec := range rules.All() {
		result.Rules = append(result.Rules, describe(spec))
	}
	return nil, result, nil
}

type explainResult struct {
	ruleInfo
	Description string `json:"description"`
	WhereItStop string `json:"where_it_stops"`
}

func (s *server) explainRule(_ context.Context, _ *mcp.CallToolRequest, in explainInput) (*mcp.CallToolResult, any, error) {
	spec, ok := rules.Lookup(strings.TrimSpace(in.RuleID))
	if !ok {
		return fail("unknown_rule", fmt.Sprintf("no rule %q; list_rules names every rule", in.RuleID))
	}
	return nil, explainResult{ruleInfo: describe(spec), Description: spec.Description, WhereItStop: spec.Limitations}, nil
}
