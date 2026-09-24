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

	"github.com/auditinfra-io/gnark-safety/pkg/report"
	"golang.org/x/tools/go/packages"
)

const relationRule = "GNARK_HINT_RELATION_INCOMPLETE"

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
}

const defaultMaxHints = 10000

// ScanContext is Scan with cancellation and resource ceilings for callers that
// process repositories outside their trust boundary.
func ScanContext(ctx context.Context, dir string, patterns []string, opts Options) (report.Report, error) {
	r := report.Report{SchemaVersion: report.SchemaVersion, Findings: []report.Finding{}, Hints: []report.Hint{}, Diagnostics: []string{}, Limitations: append([]string(nil), limitations...)}
	maxHints := opts.MaxHints
	if maxHints == 0 {
		maxHints = defaultMaxHints
	}
	if maxHints < 0 {
		return r, errors.New("max hints must be positive")
	}
	fset := token.NewFileSet()
	pkgs, err := packages.Load(&packages.Config{Context: ctx, Dir: dir, Fset: fset, Mode: packages.NeedName | packages.NeedModule | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps}, patterns...)
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
	absDir, _ := filepath.Abs(dir)
	for _, p := range pkgs {
		if err := ctx.Err(); err != nil {
			return r, fmt.Errorf("analysis canceled: %w", err)
		}
		if r.Module == "" && p.Module != nil {
			r.Module = p.Module.Path
		}
		helpers := packageFunctions(p)
		for _, file := range p.Syntax {
			if err := inspectFile(ctx, &r, p, file, fset, absDir, helpers, maxHints); err != nil {
				return r, err
			}
		}
	}
	sort.Slice(r.Hints, func(i, j int) bool {
		a, b := r.Hints[i], r.Hints[j]
		return a.File < b.File || a.File == b.File && (a.Line < b.Line || a.Line == b.Line && a.Column < b.Column)
	})
	sort.Slice(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		return a.File < b.File || a.File == b.File && (a.Line < b.Line || a.Line == b.Line && a.Column < b.Column)
	})
	return r, nil
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

func inspectFile(ctx context.Context, r *report.Report, p *packages.Package, file *ast.File, fset *token.FileSet, dir string, helpers map[*types.Func]*ast.FuncDecl, maxHints int) error {
	var inspectErr error
	for _, decl := range file.Decls {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("analysis canceled: %w", err)
		}
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		function := fn.Name.Name
		if fn.Recv != nil && len(fn.Recv.List) > 0 {
			function = "(" + types.ExprString(fn.Recv.List[0].Type) + ")." + function
		}
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
			if sel == nil || !isMethod(sel.Obj(), "github.com/consensys/gnark/frontend", "Compiler", "NewHint") {
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
				h.Hint = identity(p.TypesInfo, call.Args[offset])
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
				h.Invariants = assessInvariants(fn.Body, call, p.TypesInfo, *h.OutputCount, helpers)
			} else {
				h.Invariants = []report.Invariant{}
			}
			r.Hints = append(r.Hints, h)
			if h.OutputCount != nil && *h.OutputCount == 2 && incompleteRelation(fn.Body, call, p.TypesInfo, helpers) {
				r.Findings = append(r.Findings, report.Finding{RuleID: relationRule, Severity: report.SeverityHigh, Confidence: "high", File: path, Line: pos.Line, Column: pos.Column, Function: function, Message: "Hint outputs participate in reconstruction, but the canonical remainder bound r < d is not constrained.", Evidence: []string{"hint output: " + h.Hint, "constraint: n = q*d + r", "missing constraint: r < d"}, Limitations: []string{}})
			}
			return true
		})
		if inspectErr != nil {
			return inspectErr
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
func assessInvariants(body *ast.BlockStmt, hintCall *ast.CallExpr, info *types.Info, outputCount int, helpers map[*types.Func]*ast.FuncDecl) []report.Invariant {
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
	const maximumAnalyzedBitWidth = 4096
	if qBounded && rBounded && dBounded && qBits <= maximumAnalyzedBitWidth && rBits <= maximumAnalyzedBitWidth && dBits <= maximumAnalyzedBitWidth {
		maximum := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(qBits)), big.NewInt(1))
		dMax := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(dBits)), big.NewInt(1))
		rMax := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(rBits)), big.NewInt(1))
		maximum.Mul(maximum, dMax).Add(maximum, rMax)
		fieldEvidence = "bounded reconstruction maximum: " + maximum.String() + "; compilation field is selected outside the analyzed function"
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
			report.Invariant{OutputIndex: output, Kind: "field_safety", Status: report.InvariantUnknown, Evidence: []string{fieldEvidence}},
		)
	}
	return result
}

// incompleteRelation recognizes the deliberately narrow first rule: a
// two-output hint whose indexed outputs occur in one n=q*d+r equality, with
// no unconditional AssertIsLess(r, d). It intentionally declines more complex
// aliases rather than claiming general soundness.
func incompleteRelation(body *ast.BlockStmt, hintCall *ast.CallExpr, info *types.Info, helpers map[*types.Func]*ast.FuncDecl) bool {
	relation := analyzeRelation(body, hintCall, info, helpers)
	return relation.divisor != nil && !relation.hasBound
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
			v := constantIndex(idx.Index)
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
	hasBound := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 || !isComparatorCall(info, call, "AssertIsLess") || conditionallyExecuted(body, call) {
			return true
		}
		if outputIndex(info, call.Args[0], outputs, aliases) == 1 && sameValue(info, call.Args[1], divisor) {
			hasBound = true
			result.boundEvidence = "unconditional constraint: r < d"
		}
		return true
	})
	if !hasBound {
		hasBound, result.boundEvidence = helperProvidesBound(body, info, helpers, outputs, aliases, divisor)
	}
	result.hasBound = hasBound
	return result
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
			if !ok || len(bound.Args) != 2 || !isComparatorCall(info, bound, "AssertIsLess") || conditionallyExecuted(decl.Body, bound) {
				return true
			}
			left, leftOK := params[objectOf(info, bound.Args[0])]
			right, rightOK := params[objectOf(info, bound.Args[1])]
			if leftOK && rightOK && left < len(call.Args) && right < len(call.Args) && outputIndex(info, call.Args[left], outputs, aliases) == 1 && sameValue(info, call.Args[right], divisor) {
				found = true
				evidence = "unconditional constraint in helper " + decl.Name.Name + ": r < d"
			}
			return !found
		})
		return !found
	})
	return found, evidence
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
		return constantIndex(idx.Index)
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
	return obj != nil && obj.Name() == name && obj.Pkg() != nil && obj.Pkg().Path() == "github.com/consensys/gnark/frontend"
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

func constantIndex(e ast.Expr) int {
	if l, ok := e.(*ast.BasicLit); ok {
		if l.Value == "0" {
			return 0
		}
		if l.Value == "1" {
			return 1
		}
	}
	return -1
}
func relative(dir, path string) string {
	if rel, err := filepath.Rel(dir, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}
func isMethod(obj types.Object, pkg, recv, name string) bool {
	f, ok := obj.(*types.Func)
	if !ok || f.Name() != name || f.Pkg() == nil || f.Pkg().Path() != pkg {
		return false
	}
	sig, ok := f.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	named, ok := types.Unalias(sig.Recv().Type()).(*types.Named)
	return ok && named.Obj().Name() == recv
}
func identity(info *types.Info, e ast.Expr) string {
	if p, ok := e.(*ast.ParenExpr); ok {
		return identity(info, p.X)
	}
	var obj types.Object
	switch x := e.(type) {
	case *ast.Ident:
		obj = info.Uses[x]
	case *ast.SelectorExpr:
		obj = info.Uses[x.Sel]
	}
	f, ok := obj.(*types.Func)
	if !ok || f.Pkg() == nil {
		return "unknown"
	}
	return f.Pkg().Path() + "." + f.Name()
}

func RuleHelp(id string) (string, bool) {
	if id != relationRule {
		return "", false
	}
	return "Detects a two-output hint used in a reconstruction equality when no unconditional AssertIsLess bound constrains the remainder against the divisor. The rule conservatively follows one direct local helper call.", true
}
