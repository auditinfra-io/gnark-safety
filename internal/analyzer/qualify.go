package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"
)

// maxQualifiers caps how many uninterpreted uses a finding lists.
const maxQualifiers = 3

// remainderQualifiers lists the uses of the remainder r, in the function
// containing the hint, that GNARK_HINT_RELATION_INCOMPLETE does not
// interpret. Each is a way its finding can be wrong: a bound the rule cannot
// see (in a caller, a deeper helper, or a region that may not run), or a
// remainder convention other than 0 <= r < d. Uses inside skip, the guarded
// branch of a call-site finding, are already accounted for. An empty result
// means that, within this function, r reaches only constraints the rule
// reads.
func remainderQualifiers(fset *token.FileSet, body *ast.BlockStmt, info *types.Info, helpers map[*types.Func]*ast.FuncDecl, relation relationAnalysis, skip ast.Node) []string {
	ev := newEvaluator(info, helpers)
	d := fieldConstant(ev, relation.divisor, relation.field)
	if d != nil && d.Sign() == 0 {
		d = nil
	}
	guarded := successGuards(body, info, helpers)
	line := func(n ast.Node) int { return fset.Position(n.Pos()).Line }
	within := func(n, region ast.Node) bool {
		return region != nil && n.Pos() >= region.Pos() && n.End() <= region.End()
	}
	// mayNotRun is conditionallyExecuted, except that an if err == nil block
	// whose other path returns the error runs on every successful path.
	mayNotRun := func(n ast.Node) bool {
		for _, block := range guarded {
			if within(n, block) {
				return conditionallyExecuted(block, n)
			}
		}
		return conditionallyExecuted(body, n)
	}
	var qualifiers []string
	add := func(q string) {
		if q == "" || len(qualifiers) == maxQualifiers {
			return
		}
		for _, existing := range qualifiers {
			if existing == q {
				return
			}
		}
		qualifiers = append(qualifiers, q)
	}

	// gnarkUse classifies r as argument i of a call into gnark.
	gnarkUse := func(call *ast.CallExpr, fn *types.Func, i int) string {
		name := callName(call)
		constrainedBy := fmt.Sprintf("r is also constrained by %s at line %d, which this rule does not interpret", name, line(call))
		switch fn.Name() {
		case "NewHint", "Println":
			return "" // a hint input or a debug print constrains nothing
		case "ToBinary", "Check":
			if i == 0 && receiverName(fn) != "" {
				return "" // a range check the rule reads
			}
			return fmt.Sprintf("r is range-checked by %s at line %d, whose width this rule does not read", name, line(call))
		case "AssertIsLess", "AssertIsLessEq", "AssertIsLessOrEqual":
			switch {
			case i != 0:
				return constrainedBy
			case mayNotRun(call):
				return fmt.Sprintf("a comparison of r at line %d may not run", line(call))
			case len(call.Args) == 2 && d != nil && fieldConstant(ev, call.Args[1], relation.field) != nil:
				return "" // compared with a known value: the rule evaluated it
			}
			if evidence, _, _ := remainderComparison(info, ev, call, relation.divisor, d, relation.field); evidence != "" {
				return "" // a bound whose missing precondition the finding names
			}
			return fmt.Sprintf("r is compared at line %d with a bound this rule could not relate to d", line(call))
		case "AssertIsEqual":
			if i < 2 && len(call.Args) == 2 {
				if _, _, _, ok := limbSum(ev, call.Args[1-i]); ok {
					return "" // r rebuilt from limbs, which the rule reads
				}
			}
			return constrainedBy
		}
		if strings.HasPrefix(fn.Name(), "Assert") {
			return constrainedBy
		}
		return fmt.Sprintf("r is used in %s at line %d, whose result this rule does not follow", name, line(call))
	}

	var stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		id, ok := n.(*ast.Ident)
		if !ok || within(id, skip) || within(id, relation.reconstruction) {
			return true
		}
		obj := info.Uses[id]
		if obj == nil {
			return true
		}
		// use is the expression that denotes r: out[1] or an alias of it.
		var use ast.Expr = id
		depth := len(stack) - 1
		if obj == relation.outputs {
			index, ok := stack[depth-1].(*ast.IndexExpr)
			if !ok || index.X != id {
				add(fmt.Sprintf("the hint's output slice is used whole at line %d", line(id)))
				return true
			}
			switch constantIndex(index.Index, info) {
			case 0:
				return true
			case 1:
				use, depth = index, depth-1
			default:
				add(fmt.Sprintf("the hint's outputs are read with a non-constant index at line %d", line(id)))
				return true
			}
		} else if i, ok := relation.aliases[obj]; !ok || i != 1 {
			return true
		}
		for depth > 1 {
			paren, ok := stack[depth-1].(*ast.ParenExpr)
			if !ok {
				break
			}
			use, depth = paren, depth-1
		}
		switch parent := stack[depth-1].(type) {
		case *ast.AssignStmt:
			for _, lhs := range parent.Lhs {
				if lhs == use {
					return true // r is being assigned, not used
				}
			}
			if target := aliasTarget(stack[:depth], use); target != nil {
				if _, isAlias := relation.aliases[objectOf(info, target)]; isAlias || target.Name == "_" {
					return true
				}
			}
			add(fmt.Sprintf("r is copied at line %d, and this rule does not follow the copy", line(use)))
		case *ast.ValueSpec:
			if target := aliasTarget(stack[:depth], use); target != nil {
				if _, isAlias := relation.aliases[objectOf(info, target)]; isAlias || target.Name == "_" {
					return true
				}
			}
			add(fmt.Sprintf("r is copied at line %d, and this rule does not follow the copy", line(use)))
		case *ast.ReturnStmt:
			add(fmt.Sprintf("r is returned to the caller at line %d, and bounds applied by callers are not analyzed", line(use)))
		case *ast.CallExpr:
			argument := -1
			for i, a := range parent.Args {
				if a == use {
					argument = i
				}
			}
			if argument < 0 {
				return true
			}
			fn := calledFunc(info, parent)
			switch {
			case fn != nil && fn.Pkg() != nil && isGnarkPath(fn.Pkg().Path()):
				add(gnarkUse(parent, fn, argument))
			case mayNotRun(parent):
				add(fmt.Sprintf("a call of %s with r at line %d may not run", callName(parent), line(parent)))
			default:
				if decl := localHelper(info, parent, helpers); decl != nil && helperRangeChecks(ev, decl, argument) {
					return true
				}
				add(fmt.Sprintf("r is passed to %s at line %d, whose constraints this rule does not fully analyze", callName(parent), line(parent)))
			}
		default:
			add(fmt.Sprintf("r is stored or combined at line %d, and this rule does not follow the result", line(use)))
		}
		return true
	})
	return qualifiers
}

// callName renders the called function for a message: api.Add, or just
// AssertIsLess when the receiver is itself a call such as a constructor.
func callName(call *ast.CallExpr) string {
	if sel, ok := unparen(call.Fun).(*ast.SelectorExpr); ok {
		if _, ok := unparen(sel.X).(*ast.CallExpr); ok {
			return sel.Sel.Name
		}
	}
	return types.ExprString(call.Fun)
}

// helperRangeChecks reports whether a local helper unconditionally
// range-checks its parameter at index.
func helperRangeChecks(ev *evaluator, decl *ast.FuncDecl, index int) bool {
	params := parameterIndexes(decl, ev.info)
	_, ok := rangeBits(decl.Body, ev, nil, func(e ast.Expr) bool {
		i, ok := params[objectOf(ev.info, e)]
		return ok && i == index
	})
	return ok
}
