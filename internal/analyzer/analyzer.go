// Package analyzer loads Go packages and performs conservative, type-aware
// checks over direct gnark API calls.
package analyzer

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"math/big"
	"path/filepath"
	"sort"
	"strings"

	"github.com/auditinfra-io/gnark-safety/internal/gnarkapi"
	"github.com/auditinfra-io/gnark-safety/internal/rules"
	"github.com/auditinfra-io/gnark-safety/internal/version"
	"github.com/auditinfra-io/gnark-safety/pkg/report"
	"golang.org/x/tools/go/packages"
)

const (
	relationRule     = rules.HintRelationIncomplete
	unusedOutputRule = rules.HintOutputUnused
)

const maximumAnalyzedBitWidth = 4096

var limitations = []string{
	"Analysis follows one level of unconditional direct local helper calls; deeper or recursive call graphs are not modeled.",
	"Reflection, generated code, external helpers, complex aliasing, and dynamic hint selection are not modeled.",
}

// Scan analyzes the requested package roots. Dependencies are loaded only for
// type resolution and are not reported.
func Scan(dir string, patterns []string) (report.Report, error) {
	return ScanContext(context.Background(), dir, patterns, Options{})
}

type Options struct {
	// MaxHints bounds reported call sites. Zero uses the default ceiling.
	MaxHints int
	// FieldModulus enables a concrete modular-wraparound assessment. It is
	// copied before use; callers may reuse their big.Int after ScanContext.
	FieldModulus *big.Int
	FieldName    string
	// IncludeTests also analyzes _test.go files.
	IncludeTests bool
	// IncludeExamples keeps the original severity of findings in example
	// directories. By default they are downgraded to low: example code is
	// deliberately simplified, but it is also copied into production, so it
	// is reported rather than hidden.
	IncludeExamples bool
	// PathBase is the directory reported paths are made relative to. Empty
	// means the scan directory. Setting it to the repository root keeps
	// SARIF locations valid when the scanned module is in a subdirectory.
	PathBase string
}

// gnarkModulePath prefixes every package in gnark's module (and excludes
// gnark-crypto, whose path differs after "gnark").
const gnarkModulePath = "github.com/consensys/gnark"

// exampleDirs are path segments that mark example code.
var exampleDirs = map[string]bool{"example": true, "examples": true, "_examples": true}

// IsExamplePath reports whether a slash-separated path lies in an example
// directory.
func IsExamplePath(path string) bool {
	segments := strings.Split(path, "/")
	for _, segment := range segments[:len(segments)-1] {
		if exampleDirs[segment] {
			return true
		}
	}
	return false
}

func importsGnark(p *packages.Package) bool {
	for path := range p.Imports {
		if isGnarkPath(path) {
			return true
		}
	}
	return false
}

func importsGnarkTypes(pkg *types.Package) bool {
	for _, imported := range pkg.Imports() {
		if isGnarkPath(imported.Path()) {
			return true
		}
	}
	return false
}

func isGnarkPath(path string) bool {
	return path == gnarkModulePath || strings.HasPrefix(path, gnarkModulePath+"/")
}

const defaultMaxHints = 10000

// ScanContext is Scan with cancellation and resource ceilings for callers that
// process repositories outside their trust boundary.
func ScanContext(ctx context.Context, dir string, patterns []string, opts Options) (report.Report, error) {
	r := newReport()
	maxHints := opts.MaxHints
	if maxHints == 0 {
		maxHints = defaultMaxHints
	}
	if maxHints < 0 {
		return r, errors.New("max hints must be positive")
	}
	fset := token.NewFileSet()
	pkgs, err := packages.Load(&packages.Config{Context: ctx, Dir: dir, Fset: fset, Tests: opts.IncludeTests, Mode: packages.NeedName | packages.NeedModule | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps}, patterns...)
	if err != nil {
		return r, err
	}
	if len(pkgs) == 0 {
		return r, errors.New("package patterns matched no packages")
	}
	var loadErrs []string
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			loadErrs = append(loadErrs, e.Error())
		}
	})
	if len(loadErrs) > 0 {
		sort.Strings(loadErrs)
		return r, fmt.Errorf("package loading/type checking failed:\n%s", strings.Join(loadErrs, "\n"))
	}
	base := dir
	if opts.PathBase != "" {
		base = opts.PathBase
	}
	absDir, err := filepath.Abs(base)
	if err != nil {
		return r, fmt.Errorf("resolve path base: %w", err)
	}
	r.Coverage.TestsIncluded = opts.IncludeTests
	// With tests included, go/packages returns a package and its test
	// variants, which share the non-test files. Each file is analyzed once,
	// and generated test mains are skipped.
	seenFiles := map[string]bool{}
	seenPackages := map[string]bool{}
	var directives []*directive
	gnarkPackages := map[string]bool{}
	for _, p := range pkgs {
		if err := ctx.Err(); err != nil {
			return r, fmt.Errorf("analysis canceled: %w", err)
		}
		if strings.HasSuffix(p.ID, ".test") {
			continue
		}
		if r.Module == "" && p.Module != nil {
			r.Module = p.Module.Path
		}
		seenPackages[p.PkgPath] = true
		if importsGnark(p) {
			gnarkPackages[p.PkgPath] = true
		}
		var files []*ast.File
		for _, file := range p.Syntax {
			name := fset.Position(file.Package).Filename
			if !seenFiles[name] {
				seenFiles[name] = true
				files = append(files, file)
			}
		}
		found, err := analyzeFiles(ctx, &r, p, files, fset, absDir, maxHints, opts)
		if err != nil {
			return r, err
		}
		directives = append(directives, found...)
	}
	r.Coverage.Packages, r.Coverage.GnarkPackages, r.Coverage.Files = len(seenPackages), len(gnarkPackages), len(seenFiles)
	finish(&r, directives, opts)
	return r, nil
}

// AnalyzePackage runs every rule over one package that a driver such as
// go vet has already parsed and type-checked. Reported paths are absolute
// file names. Suppressions apply; example downgrading does not, because a
// driver without severities has nothing to lower.
func AnalyzePackage(fset *token.FileSet, pkg *types.Package, info *types.Info, files []*ast.File) (report.Report, error) {
	r := newReport()
	p := &packages.Package{ID: pkg.Path(), Name: pkg.Name(), PkgPath: pkg.Path(), Types: pkg, TypesInfo: info, Syntax: files, Fset: fset}
	opts := Options{IncludeExamples: true}
	directives, err := analyzeFiles(context.Background(), &r, p, files, fset, "", defaultMaxHints, opts)
	if err != nil {
		return r, err
	}
	r.Coverage.Packages, r.Coverage.Files = 1, len(files)
	if importsGnarkTypes(pkg) {
		r.Coverage.GnarkPackages = 1
	}
	finish(&r, directives, opts)
	return r, nil
}

func newReport() report.Report {
	return report.Report{SchemaVersion: report.SchemaVersion, Tool: report.Tool{Name: "gnark-safety", Version: version.String()}, Findings: []report.Finding{}, Suppressed: []report.Finding{}, Hints: []report.Hint{}, Diagnostics: []string{}, Limitations: append([]string(nil), limitations...)}
}

// analyzeFiles runs every rule over files, which belong to the type-checked
// package p, and returns the suppression directives they contain. An empty
// absDir reports absolute paths.
func analyzeFiles(ctx context.Context, r *report.Report, p *packages.Package, files []*ast.File, fset *token.FileSet, absDir string, maxHints int, opts Options) ([]*directive, error) {
	helpers := packageFunctions(p)
	var directives []*directive
	for _, file := range files {
		if err := inspectFile(ctx, r, p, file, fset, absDir, helpers, maxHints, opts); err != nil {
			return nil, err
		}
		r.Findings = append(r.Findings, syntaxFindings(p, file, fset, absDir)...)
		found, diagnostics := collectDirectives(file, fset, relative(absDir, fset.Position(file.Package).Filename))
		directives = append(directives, found...)
		r.Diagnostics = append(r.Diagnostics, diagnostics...)
	}
	return directives, nil
}

// finish applies the example policy and suppressions, then sorts the
// report so output is deterministic.
func finish(r *report.Report, directives []*directive, opts Options) {
	if !opts.IncludeExamples {
		for i := range r.Findings {
			f := &r.Findings[i]
			if IsExamplePath(f.File) && f.Severity.Rank() > report.SeverityLow.Rank() {
				f.OriginalSeverity, f.Severity = f.Severity, report.SeverityLow
				f.Limitations = append(f.Limitations, "Downgraded from "+string(f.OriginalSeverity)+" to low because the file is in an example directory; example code is simplified on purpose but is often copied into production. Use --include-examples to keep the original severity.")
				r.Coverage.ExamplesDowngraded++
			}
		}
	}
	applySuppressions(r, directives)
	sort.Slice(r.Hints, func(i, j int) bool {
		a, b := r.Hints[i], r.Hints[j]
		return a.File < b.File || a.File == b.File && (a.Line < b.Line || a.Line == b.Line && a.Column < b.Column)
	})
	sortFindings(r.Findings)
	sortFindings(r.Suppressed)
	sort.Strings(r.Diagnostics)
}

func sortFindings(findings []report.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		return a.RuleID < b.RuleID
	})
}

func packageFunctions(p *packages.Package) map[*types.Func]*ast.FuncDecl {
	functions := make(map[*types.Func]*ast.FuncDecl)
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if obj, ok := p.TypesInfo.Defs[fn.Name].(*types.Func); ok {
				functions[obj] = fn
			}
		}
	}
	return functions
}

func inspectFile(ctx context.Context, r *report.Report, p *packages.Package, file *ast.File, fset *token.FileSet, dir string, helpers map[*types.Func]*ast.FuncDecl, maxHints int, opts Options) error {
	var inspectErr error
	for _, decl := range file.Decls {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("analysis canceled: %w", err)
		}
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		function := functionName(fn)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if inspectErr != nil {
				return false
			}
			if err := ctx.Err(); err != nil {
				inspectErr = fmt.Errorf("analysis canceled: %w", err)
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			selExpr, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			sel := p.TypesInfo.Selections[selExpr]
			if sel == nil || !gnarkapi.IsNewHint(sel.Obj()) {
				return true
			}
			if len(r.Hints) >= maxHints {
				inspectErr = fmt.Errorf("hint limit exceeded: maximum %d", maxHints)
				return false
			}
			offset := 0
			if sel.Kind() == types.MethodExpr {
				offset = 1
			}
			pos := fset.Position(call.Lparen)
			path := relative(dir, pos.Filename)
			h := report.Hint{Package: p.PkgPath, File: path, Line: pos.Line, Column: pos.Column, Function: function, Hint: "unknown"}
			if len(call.Args) > offset {
				h.Hint = gnarkapi.HintIdentity(p.TypesInfo, call.Args[offset])
				if h.Hint == "unknown" {
					h.Unknown = append(h.Unknown, "hint_function")
				}
			}
			if len(call.Args) > offset+1 {
				if v := p.TypesInfo.Types[call.Args[offset+1]].Value; v != nil && v.Kind() == constant.Int {
					if x, ok := constant.Int64Val(v); ok && int64(int(x)) == x {
						n := int(x)
						h.OutputCount = &n
					}
				}
			}
			if h.OutputCount == nil {
				h.Unknown = append(h.Unknown, "output_count")
			}
			if call.Ellipsis == token.NoPos {
				n := len(call.Args) - offset - 2
				if n < 0 {
					n = 0
				}
				h.InputCount = &n
			} else {
				h.Unknown = append(h.Unknown, "input_count")
			}
			if h.OutputCount != nil {
				h.Invariants = assessInvariants(fn.Body, call, p.TypesInfo, *h.OutputCount, helpers, opts)
			} else {
				h.Invariants = []report.Invariant{}
			}
			r.Hints = append(r.Hints, h)
			if h.OutputCount != nil {
				for _, index := range unusedOutputs(fn.Body, call, p.TypesInfo, *h.OutputCount) {
					r.Findings = append(r.Findings, report.Finding{RuleID: unusedOutputRule, Severity: report.SeverityMedium, Confidence: "high", File: path, Line: pos.Line, Column: pos.Column, Function: function, Message: fmt.Sprintf("Hint output %d is never used after extraction.", index), Evidence: []string{"hint output: " + h.Hint, fmt.Sprintf("unused output index: %d", index)}, Limitations: []string{}})
				}
			}
			if h.OutputCount != nil && *h.OutputCount == 2 {
				r.Findings = append(r.Findings, relationFindings(p, fset, dir, fn, call, h, helpers)...)
			}
			return true
		})
		if inspectErr != nil {
			return inspectErr
		}
	}
	return nil
}

// unusedOutputs returns the indexes of hint outputs that are extracted and
// never used. It answers only when every reference to the output slice is a
// constant-index read: a slice expression, a dynamic index, or passing the
// slice along could use any output, so the result is then unknown (nil).
func unusedOutputs(body *ast.BlockStmt, hintCall *ast.CallExpr, info *types.Info, outputCount int) []int {
	if outputCount <= 0 || outputCount > defaultMaxHints {
		return nil
	}
	relation := analyzeRelation(body, hintCall, info, nil)
	if relation.outputs == nil {
		return nil
	}
	used := make([]bool, outputCount)
	aliases := map[types.Object]int{}
	unknown := false
	var stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		id, ok := n.(*ast.Ident)
		if !ok || unknown || info.Uses[id] != relation.outputs {
			return true
		}
		// The slice itself (not one element) is referenced: only a constant
		// index read below it keeps the analysis precise.
		index, ok := stack[len(stack)-2].(*ast.IndexExpr)
		output := -1
		if ok && index.X == id {
			output = constantIndex(index.Index, info)
		}
		if output < 0 || output >= outputCount {
			unknown = true
			return true
		}
		switch target := aliasTarget(stack[:len(stack)-2], index); {
		case target == nil:
			used[output] = true // read in any other context: an argument, a field store, a return
		case target.Name == "_":
			// discarded explicitly
		default:
			// Only a variable declared in this function is an alias whose
			// uses can all be seen here; storing into anything else is a use.
			obj := info.Defs[target]
			if obj == nil {
				obj = info.Uses[target]
			}
			if obj != nil && obj.Pos() >= body.Pos() && obj.Pos() < body.End() {
				aliases[obj] = output
			} else {
				used[output] = true
			}
		}
		return true
	})
	if unknown {
		return nil
	}
	ast.Inspect(body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			if output, ok := aliases[info.Uses[id]]; ok && info.Uses[id] != nil {
				used[output] = true
			}
		}
		return true
	})
	var result []int
	for output, isUsed := range used {
		if !isUsed {
			result = append(result, output)
		}
	}
	return result
}

// aliasTarget returns the plain identifier an indexed output is assigned to
// (x := out[0], var x = out[0], or x = out[0]), or nil when the element is
// used in any other way, including a store into a field or another slice.
func aliasTarget(ancestors []ast.Node, element ast.Expr) *ast.Ident {
	if len(ancestors) == 0 {
		return nil
	}
	switch parent := ancestors[len(ancestors)-1].(type) {
	case *ast.AssignStmt:
		if len(parent.Lhs) != len(parent.Rhs) {
			return nil
		}
		for i, rhs := range parent.Rhs {
			if rhs == element {
				id, _ := parent.Lhs[i].(*ast.Ident)
				return id
			}
		}
	case *ast.ValueSpec:
		for i, value := range parent.Values {
			if value == element && i < len(parent.Names) {
				return parent.Names[i]
			}
		}
	}
	return nil
}

var invariantKinds = []string{"participation", "range", "relation", "canonicality", "field_safety"}

func unknownInvariants(outputCount int, reason string) []report.Invariant {
	if outputCount < 0 {
		return []report.Invariant{}
	}
	result := make([]report.Invariant, 0, outputCount*len(invariantKinds))
	for output := 0; output < outputCount; output++ {
		for _, kind := range invariantKinds {
			result = append(result, report.Invariant{OutputIndex: output, Kind: kind, Status: report.InvariantUnknown, Evidence: []string{reason}})
		}
	}
	return result
}

// assessInvariants reports independent facts instead of collapsing “used in a
// constraint” into “safe”. It remains deliberately narrow: detailed statuses
// are emitted only for the quotient/remainder reconstruction recognized by the
// first rule, and unsupported shapes stay explicitly unknown.
func assessInvariants(body *ast.BlockStmt, hintCall *ast.CallExpr, info *types.Info, outputCount int, helpers map[*types.Func]*ast.FuncDecl, opts Options) []report.Invariant {
	if outputCount != 2 {
		return unknownInvariants(outputCount, "unsupported output count")
	}
	relation := analyzeRelation(body, hintCall, info, helpers)
	if relation.outputs == nil || relation.divisor == nil {
		return unknownInvariants(outputCount, "recognized quotient/remainder reconstruction not found")
	}

	qBits, qBounded := unconditionalOutputBitBound(body, relation.outputs, relation.aliases, 0, info, helpers)
	rBits, rBounded := unconditionalOutputBitBound(body, relation.outputs, relation.aliases, 1, info, helpers)
	dBits, dBounded := unconditionalBitBound(body, relation.divisor, info, helpers)
	fieldEvidence := "compilation field is selected outside the analyzed function"
	fieldStatus := report.InvariantUnknown
	var fieldModulus *big.Int
	if opts.FieldModulus != nil {
		fieldModulus = new(big.Int).Set(opts.FieldModulus)
	}
	if qBounded && rBounded && dBounded && qBits <= maximumAnalyzedBitWidth && rBits <= maximumAnalyzedBitWidth && dBits <= maximumAnalyzedBitWidth {
		maximum := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(qBits)), big.NewInt(1))
		dMax := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(dBits)), big.NewInt(1))
		rMax := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(rBits)), big.NewInt(1))
		maximum.Mul(maximum, dMax).Add(maximum, rMax)
		fieldEvidence = "bounded reconstruction maximum: " + maximum.String() + "; compilation field is selected outside the analyzed function"
		if fieldModulus != nil {
			name := opts.FieldName
			if name == "" {
				name = "configured field"
			}
			if maximum.Cmp(fieldModulus) < 0 {
				fieldStatus = report.InvariantSatisfied
				fieldEvidence = "bounded reconstruction maximum: " + maximum.String() + "; below " + name + " modulus: " + fieldModulus.String()
			} else {
				fieldStatus = report.InvariantMissing
				fieldEvidence = "bounded reconstruction maximum: " + maximum.String() + "; not below " + name + " modulus: " + fieldModulus.String()
			}
		}
	} else if qBounded && rBounded && dBounded {
		fieldEvidence = fmt.Sprintf("bounded reconstruction maximum omitted: bit width exceeds analysis limit %d; compilation field is selected outside the analyzed function", maximumAnalyzedBitWidth)
	}

	result := make([]report.Invariant, 0, 10)
	for output := 0; output < 2; output++ {
		result = append(result,
			report.Invariant{OutputIndex: output, Kind: "participation", Status: report.InvariantSatisfied, Evidence: []string{"output participates in n = q*d + r"}},
			report.Invariant{OutputIndex: output, Kind: "relation", Status: report.InvariantSatisfied, Evidence: []string{"constraint: n = q*d + r"}},
		)
		bits, bounded := qBits, qBounded
		if output == 1 {
			bits, bounded = rBits, rBounded
		}
		if bounded {
			result = append(result, report.Invariant{OutputIndex: output, Kind: "range", Status: report.InvariantSatisfied, Evidence: []string{fmt.Sprintf("unconditional ToBinary width: %d", bits)}})
		} else {
			result = append(result, report.Invariant{OutputIndex: output, Kind: "range", Status: report.InvariantUnknown, Evidence: []string{"unconditional constant-width ToBinary not found"}})
		}
		canonicalStatus := report.InvariantMissing
		canonicalEvidence := "missing unconditional constraint: r < d"
		if relation.hasBound {
			canonicalStatus = report.InvariantSatisfied
			canonicalEvidence = relation.boundEvidence
		}
		result = append(result,
			report.Invariant{OutputIndex: output, Kind: "canonicality", Status: canonicalStatus, Evidence: []string{canonicalEvidence}},
			report.Invariant{OutputIndex: output, Kind: "field_safety", Status: fieldStatus, Evidence: []string{fieldEvidence}},
		)
	}
	return result
}

type relationAnalysis struct {
	outputs       types.Object
	aliases       map[types.Object]int
	divisor       ast.Expr
	hasBound      bool
	boundEvidence string
}

func analyzeRelation(body *ast.BlockStmt, hintCall *ast.CallExpr, info *types.Info, helpers map[*types.Func]*ast.FuncDecl) relationAnalysis {
	result := relationAnalysis{aliases: map[types.Object]int{}}
	var outputs types.Object
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, rhs := range as.Rhs {
			if rhs == hintCall && i < len(as.Lhs) {
				if id, ok := as.Lhs[i].(*ast.Ident); ok {
					outputs = objectOf(info, id)
				}
			}
		}
		return true
	})
	if outputs == nil {
		return result
	}
	result.outputs = outputs
	aliases := map[types.Object]int{}
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, rhs := range as.Rhs {
			idx, ok := rhs.(*ast.IndexExpr)
			if !ok || i >= len(as.Lhs) {
				continue
			}
			if objectOf(info, idx.X) != outputs {
				continue
			}
			v := constantIndex(idx.Index, info)
			id, ok := as.Lhs[i].(*ast.Ident)
			if ok && v >= 0 {
				aliases[objectOf(info, id)] = v
			}
		}
		return true
	})
	result.aliases = aliases
	var divisor ast.Expr
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isFrontendCall(info, call, "AssertIsEqual") || len(call.Args) != 2 {
			return true
		}
		if d, ok := reconstructionDivisor(info, call.Args[0], outputs, aliases); ok && plainRelationSide(info, call.Args[1], outputs, aliases) {
			divisor = d
		} else if d, ok := reconstructionDivisor(info, call.Args[1], outputs, aliases); ok && plainRelationSide(info, call.Args[0], outputs, aliases) {
			divisor = d
		}
		return true
	})
	if divisor == nil {
		return result
	}
	result.divisor = divisor
	result.hasBound, result.boundEvidence = boundWithin(body, info, helpers, outputs, aliases, divisor)
	return result
}

// boundWithin reports whether scope unconditionally constrains r < d, either
// directly or through one direct local helper call. "Unconditionally" is
// relative to scope, so callers can ask about the body of a branch.
func boundWithin(scope *ast.BlockStmt, info *types.Info, helpers map[*types.Func]*ast.FuncDecl, outputs types.Object, aliases map[types.Object]int, divisor ast.Expr) (bool, string) {
	found, evidence := false, ""
	ast.Inspect(scope, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 || conditionallyExecuted(scope, call) {
			return true
		}
		if outputIndex(info, call.Args[0], outputs, aliases) != 1 {
			return true
		}
		if isComparatorCall(info, call, "AssertIsLess") && sameValue(info, call.Args[1], divisor) {
			found, evidence = true, "unconditional constraint: r < d"
		} else if isFrontendCall(info, call, "AssertIsLessOrEqual") && oneLessThan(info, call.Args[1], divisor) {
			found, evidence = true, "unconditional equivalent constraint: r <= d-1"
		}
		return true
	})
	if !found {
		found, evidence = helperProvidesBound(scope, info, helpers, outputs, aliases, divisor)
	}
	return found, evidence
}

func unconditionalOutputBitBound(body *ast.BlockStmt, outputs types.Object, aliases map[types.Object]int, index int, info *types.Info, helpers map[*types.Func]*ast.FuncDecl) (int, bool) {
	return findBitBound(body, info, helpers, func(e ast.Expr) bool { return outputIndex(info, e, outputs, aliases) == index })
}

func unconditionalBitBound(body *ast.BlockStmt, value ast.Expr, info *types.Info, helpers map[*types.Func]*ast.FuncDecl) (int, bool) {
	return findBitBound(body, info, helpers, func(e ast.Expr) bool { return sameValue(info, e, value) })
}

func findBitBound(body *ast.BlockStmt, info *types.Info, helpers map[*types.Func]*ast.FuncDecl, matches func(ast.Expr) bool) (int, bool) {
	bits := 0
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isFrontendCall(info, call, "ToBinary") || len(call.Args) < 2 || conditionallyExecuted(body, call) || !matches(call.Args[0]) {
			return true
		}
		value := info.Types[call.Args[1]].Value
		if value == nil || value.Kind() != constant.Int {
			return true
		}
		width, ok := constant.Int64Val(value)
		if !ok || width <= 0 || int64(int(width)) != width {
			return true
		}
		bits, found = int(width), true
		return true
	})
	if !found {
		bits, found = helperProvidesBitBound(body, info, helpers, matches)
	}
	return bits, found
}

func helperProvidesBound(body *ast.BlockStmt, info *types.Info, helpers map[*types.Func]*ast.FuncDecl, outputs types.Object, aliases map[types.Object]int, divisor ast.Expr) (bool, string) {
	found := false
	evidence := ""
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found || conditionallyExecuted(body, call) {
			return !found
		}
		decl := localHelper(info, call, helpers)
		if decl == nil {
			return true
		}
		params := parameterIndexes(decl, info)
		ast.Inspect(decl.Body, func(n ast.Node) bool {
			bound, ok := n.(*ast.CallExpr)
			if !ok || len(bound.Args) != 2 || conditionallyExecuted(decl.Body, bound) {
				return true
			}
			left, leftOK := params[objectOf(info, bound.Args[0])]
			if !leftOK || left >= len(call.Args) || outputIndex(info, call.Args[left], outputs, aliases) != 1 {
				return true
			}
			right, rightOK := params[objectOf(info, bound.Args[1])]
			comparisonEvidence := "unconditional constraint in helper " + decl.Name.Name + ": r < d"
			valid := isComparatorCall(info, bound, "AssertIsLess") && rightOK && right < len(call.Args) && sameValue(info, call.Args[right], divisor)
			if isFrontendCall(info, bound, "AssertIsLessOrEqual") {
				if parameter, ok := oneLessThanParameter(info, bound.Args[1], params); ok && parameter < len(call.Args) && sameValue(info, call.Args[parameter], divisor) {
					valid = true
					comparisonEvidence = "unconditional equivalent constraint in helper " + decl.Name.Name + ": r <= d-1"
				}
			}
			if valid {
				found = true
				evidence = comparisonEvidence
			}
			return !found
		})
		return !found
	})
	return found, evidence
}

func oneLessThan(info *types.Info, expression, value ast.Expr) bool {
	args, ok := apiCallArgs(info, expression, "Sub")
	return ok && len(args) == 2 && sameValue(info, args[0], value) && isIntegerConstant(info, args[1], 1)
}

func oneLessThanParameter(info *types.Info, expression ast.Expr, parameters map[types.Object]int) (int, bool) {
	args, ok := apiCallArgs(info, expression, "Sub")
	if !ok || len(args) != 2 || !isIntegerConstant(info, args[1], 1) {
		return 0, false
	}
	index, ok := parameters[objectOf(info, args[0])]
	return index, ok
}

func isIntegerConstant(info *types.Info, expression ast.Expr, want int64) bool {
	value := info.Types[expression].Value
	if value == nil || value.Kind() != constant.Int {
		return false
	}
	got, ok := constant.Int64Val(value)
	return ok && got == want
}

func helperProvidesBitBound(body *ast.BlockStmt, info *types.Info, helpers map[*types.Func]*ast.FuncDecl, matches func(ast.Expr) bool) (int, bool) {
	bits := 0
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found || conditionallyExecuted(body, call) {
			return !found
		}
		decl := localHelper(info, call, helpers)
		if decl == nil {
			return true
		}
		params := parameterIndexes(decl, info)
		ast.Inspect(decl.Body, func(n ast.Node) bool {
			bound, ok := n.(*ast.CallExpr)
			if !ok || !isFrontendCall(info, bound, "ToBinary") || len(bound.Args) < 2 || conditionallyExecuted(decl.Body, bound) {
				return true
			}
			parameter, ok := params[objectOf(info, bound.Args[0])]
			if !ok || parameter >= len(call.Args) || !matches(call.Args[parameter]) {
				return true
			}
			value := info.Types[bound.Args[1]].Value
			if value == nil || value.Kind() != constant.Int {
				return true
			}
			width, ok := constant.Int64Val(value)
			if ok && width > 0 && int64(int(width)) == width {
				bits, found = int(width), true
			}
			return !found
		})
		return !found
	})
	return bits, found
}

func localHelper(info *types.Info, call *ast.CallExpr, helpers map[*types.Func]*ast.FuncDecl) *ast.FuncDecl {
	var obj types.Object
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		obj = info.Uses[fn]
	case *ast.SelectorExpr:
		obj = info.Uses[fn.Sel]
	}
	function, ok := obj.(*types.Func)
	if !ok {
		return nil
	}
	return helpers[function]
}

func parameterIndexes(decl *ast.FuncDecl, info *types.Info) map[types.Object]int {
	indexes := make(map[types.Object]int)
	index := 0
	if decl.Type.Params == nil {
		return indexes
	}
	for _, field := range decl.Type.Params.List {
		if len(field.Names) == 0 {
			index++
			continue
		}
		for _, name := range field.Names {
			indexes[info.Defs[name]] = index
			index++
		}
	}
	return indexes
}

func plainRelationSide(info *types.Info, e ast.Expr, outputs types.Object, aliases map[types.Object]int) bool {
	return objectOf(info, e) != nil && outputIndex(info, e, outputs, aliases) < 0
}

// reconstructionDivisor accepts exactly Add(Mul(q, d), r), including swapped
// operands of the commutative Add and Mul calls. Both hint outputs must occur
// in this single expression.
func reconstructionDivisor(info *types.Info, e ast.Expr, outputs types.Object, aliases map[types.Object]int) (ast.Expr, bool) {
	add, ok := apiCallArgs(info, e, "Add")
	if !ok || len(add) != 2 {
		return nil, false
	}
	for i := 0; i < 2; i++ {
		if outputIndex(info, add[1-i], outputs, aliases) != 1 {
			continue
		}
		mul, ok := apiCallArgs(info, add[i], "Mul")
		if !ok || len(mul) != 2 {
			continue
		}
		if outputIndex(info, mul[0], outputs, aliases) == 0 {
			return mul[1], true
		}
		if outputIndex(info, mul[1], outputs, aliases) == 0 {
			return mul[0], true
		}
	}
	return nil, false
}

func outputIndex(info *types.Info, e ast.Expr, outputs types.Object, aliases map[types.Object]int) int {
	e = unparen(e)
	if idx, ok := e.(*ast.IndexExpr); ok && objectOf(info, idx.X) == outputs {
		return constantIndex(idx.Index, info)
	}
	if i, ok := aliases[objectOf(info, e)]; ok {
		return i
	}
	return -1
}

func apiCallArgs(info *types.Info, e ast.Expr, name string) ([]ast.Expr, bool) {
	call, ok := unparen(e).(*ast.CallExpr)
	if !ok || !isFrontendCall(info, call, name) {
		return nil, false
	}
	return call.Args, true
}

func isFrontendCall(info *types.Info, call *ast.CallExpr, name string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	obj := info.Uses[sel.Sel]
	return obj != nil && obj.Name() == name && obj.Pkg() != nil && obj.Pkg().Path() == gnarkapi.FrontendPath
}

func isComparatorCall(info *types.Info, call *ast.CallExpr, name string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	obj := info.Uses[sel.Sel]
	return obj != nil && obj.Name() == name && obj.Pkg() != nil && obj.Pkg().Path() == "github.com/consensys/gnark/std/math/cmp"
}

func objectOf(info *types.Info, e ast.Expr) types.Object {
	switch x := unparen(e).(type) {
	case *ast.Ident:
		if obj := info.Uses[x]; obj != nil {
			return obj
		}
		return info.Defs[x]
	case *ast.SelectorExpr:
		return info.Uses[x.Sel]
	}
	return nil
}

func sameValue(info *types.Info, a, b ast.Expr) bool {
	ao, bo := objectOf(info, a), objectOf(info, b)
	return ao != nil && ao == bo
}
func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

func conditionallyExecuted(body *ast.BlockStmt, target ast.Node) bool {
	conditional := false
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil || conditional {
			return !conditional
		}
		var regions []ast.Node
		switch x := n.(type) {
		case *ast.IfStmt:
			regions = []ast.Node{x.Body}
			if x.Else != nil {
				regions = append(regions, x.Else)
			}
		case *ast.ForStmt:
			regions = []ast.Node{x.Body}
		case *ast.RangeStmt:
			regions = []ast.Node{x.Body}
		case *ast.SwitchStmt:
			regions = []ast.Node{x.Body}
		case *ast.TypeSwitchStmt:
			regions = []ast.Node{x.Body}
		case *ast.SelectStmt:
			regions = []ast.Node{x.Body}
		case *ast.FuncLit:
			regions = []ast.Node{x.Body}
		}
		for _, r := range regions {
			if target.Pos() >= r.Pos() && target.End() <= r.End() {
				conditional = true
				return false
			}
		}
		return true
	})
	if conditional {
		return true
	}
	// A successful return before the target means the constraint need not run.
	// Error returns are deliberately excluded: a failed Define does not produce
	// a usable constraint system.
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil || conditional {
			return !conditional
		}
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || ret.Pos() >= target.Pos() || !successfulReturn(ret) {
			return true
		}
		conditional = true
		return false
	})
	return conditional
}

func successfulReturn(ret *ast.ReturnStmt) bool {
	if len(ret.Results) == 0 {
		return true
	}
	if len(ret.Results) != 1 {
		return false
	}
	id, ok := ret.Results[0].(*ast.Ident)
	return ok && id.Name == "nil"
}

func constantIndex(e ast.Expr, info *types.Info) int {
	value := info.Types[e].Value
	if value == nil || value.Kind() != constant.Int {
		return -1
	}
	index, ok := constant.Int64Val(value)
	if !ok || index < 0 || int64(int(index)) != index {
		return -1
	}
	return int(index)
}
func relative(dir, path string) string {
	if rel, err := filepath.Rel(dir, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}
