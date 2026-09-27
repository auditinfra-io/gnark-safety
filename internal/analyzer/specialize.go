package analyzer

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/auditinfra-io/gnark-safety/pkg/report"
	"golang.org/x/tools/go/packages"
)

// relationMessage is the finding's message when no bound on r was
// recognized. It says what was not recognized, not that no bound exists.
const relationMessage = "The hint outputs are reconstructed as n = q*d + r, but no unconditional bound r < d was recognized, so a prover may be able to choose another quotient and remainder that satisfy the same equation."

// gapMessages replace relationMessage when a bound on r was recognized but a
// precondition it depends on was not.
var gapMessages = map[string]string{
	comparatorGap:  "The hint outputs are reconstructed as n = q*d + r and a bounded comparator asserts r < d, but no range check of r was recognized. The comparator compares signed values, so without one it also accepts a field element that encodes a negative r.",
	zeroDivisorGap: "The hint outputs are reconstructed as n = q*d + r and r <= d-1 is asserted, but nothing recognized rules out d = 0. Then d-1 is the largest field element, the bound admits every r, and q is unconstrained.",
}

// boundGuard describes an r < d bound that executes only for one value of a
// bool parameter of the function containing the hint, as in
//
//	if enforce { cmp.AssertIsLess(r, d) }
type boundGuard struct {
	param        *types.Var
	index        int
	enforcedWhen bool
	stmt         *ast.IfStmt
}

// guardSite is one package-local call of the guarded function whose guard
// argument is a compile-time constant.
type guardSite struct {
	call   *ast.CallExpr
	caller *ast.FuncDecl
	value  bool
}

// relationFindings reports GNARK_HINT_RELATION_INCOMPLETE for one hint.
// When the bound is guarded by a bool parameter and every use of the
// function is a direct package-local call with a constant guard argument,
// the finding moves to each call that disables the bound, and calls that
// enable it are quiet. Otherwise the finding stays at the hint.
func relationFindings(p *packages.Package, fset *token.FileSet, dir string, fn *ast.FuncDecl, hintCall *ast.CallExpr, h report.Hint, helpers map[*types.Func]*ast.FuncDecl) []report.Finding {
	info := p.TypesInfo
	relation := analyzeRelation(fn.Body, hintCall, info, helpers)
	if relation.divisor == nil || relation.hasBound {
		return nil
	}
	message := relationMessage
	evidence := []string{"hint output: " + h.Hint, "constraint: n = q*d + r", "no recognized constraint: r < d"}
	if relation.boundGap != "" {
		message = gapMessages[relation.boundGap]
		evidence = append(evidence, relation.boundGap)
	}
	guard := findGuard(fn, relation, info, helpers)
	if guard != nil {
		if sites, ok := resolveGuardSites(p, fn, guard); ok {
			return siteFindings(fset, dir, fn, h, guard, sites, remainderQualifiers(fset, fn.Body, info, helpers, relation, guard.stmt))
		}
		evidence = append(evidence, fmt.Sprintf("r < d is enforced only when parameter %s is %t, and not every call of %s passes a constant", guard.param.Name(), guard.enforcedWhen, fn.Name.Name))
	}
	qualifiers := remainderQualifiers(fset, fn.Body, info, helpers, relation, nil)
	finding := report.Finding{RuleID: relationRule, Severity: report.SeverityHigh, File: h.File, Line: h.Line, Column: h.Column, Function: h.Function, Message: message, Evidence: evidence, Limitations: []string{}}
	qualify(&finding, qualifiers)
	if relation.boundGap == zeroDivisorGap {
		// d may be kept nonzero where this function cannot see it.
		finding.Confidence = "medium"
		finding.Limitations = append(finding.Limitations, "d may be kept nonzero outside this function, by its callers or by the verifier's check of a public input.")
	}
	return []report.Finding{finding}
}

// qualify sets a finding's confidence and, when the rule may be wrong about
// it, says why in the message and records every reason in the evidence.
func qualify(f *report.Finding, qualifiers []string) {
	f.Confidence = "high"
	if len(qualifiers) == 0 {
		return
	}
	f.Confidence = "medium"
	f.Message += " Not confirmed: " + qualifiers[0] + "."
	for _, q := range qualifiers {
		f.Evidence = append(f.Evidence, "not analyzed: "+q)
	}
}

func siteFindings(fset *token.FileSet, dir string, fn *ast.FuncDecl, h report.Hint, guard *boundGuard, sites []guardSite, qualifiers []string) []report.Finding {
	var findings []report.Finding
	name := guard.param.Name()
	for _, site := range sites {
		if site.value == guard.enforcedWhen {
			continue
		}
		pos := fset.Position(site.call.Lparen)
		finding := report.Finding{
			RuleID: relationRule, Severity: report.SeverityHigh,
			File: relative(dir, pos.Filename), Line: pos.Line, Column: pos.Column, Function: functionName(site.caller),
			Message: fmt.Sprintf("This call passes %s=%t to %s, which then skips the canonical remainder bound r < d on its hint outputs.", name, site.value, fn.Name.Name),
			Evidence: []string{
				"hint output: " + h.Hint,
				fmt.Sprintf("hint call: %s:%d:%d in %s", h.File, h.Line, h.Column, h.Function),
				"constraint: n = q*d + r",
				fmt.Sprintf("r < d is enforced only when %s is %t", name, guard.enforcedWhen),
				fmt.Sprintf("argument at this call: %s=%t", name, site.value),
			},
			Limitations: []string{},
		}
		qualify(&finding, qualifiers)
		findings = append(findings, finding)
	}
	return findings
}

// findGuard recognizes an if statement whose condition is a bool parameter
// (or its negation) and whose branch unconditionally bounds r < d. The if
// statement itself must be unconditional, and the parameter must never be
// reassigned or have its address taken, so its value is the argument's.
func findGuard(fn *ast.FuncDecl, relation relationAnalysis, info *types.Info, helpers map[*types.Func]*ast.FuncDecl) *boundGuard {
	fnObj, ok := info.Defs[fn.Name].(*types.Func)
	if !ok {
		return nil
	}
	sig := fnObj.Type().(*types.Signature)
	params := parameterIndexes(fn, info)
	var guard *boundGuard
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if guard != nil {
			return false
		}
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		stmt, ok := n.(*ast.IfStmt)
		if !ok || stmt.Init != nil || conditionallyExecuted(fn.Body, stmt) {
			return true
		}
		cond, negated := unparen(stmt.Cond), false
		if not, ok := cond.(*ast.UnaryExpr); ok && not.Op == token.NOT {
			cond, negated = unparen(not.X), true
		}
		ident, ok := cond.(*ast.Ident)
		if !ok {
			return true
		}
		param, ok := info.Uses[ident].(*types.Var)
		if !ok {
			return true
		}
		index, ok := params[param]
		if !ok || (sig.Variadic() && index == sig.Params().Len()-1) || !isBool(param.Type()) || mutated(fn.Body, param, info) {
			return true
		}
		if boundWithin(stmt.Body, fn.Body, info, helpers, relation.outputs, relation.aliases, relation.divisor).found {
			guard = &boundGuard{param: param, index: index, enforcedWhen: !negated, stmt: stmt}
		} else if elseBlock, ok := stmt.Else.(*ast.BlockStmt); ok {
			if boundWithin(elseBlock, fn.Body, info, helpers, relation.outputs, relation.aliases, relation.divisor).found {
				guard = &boundGuard{param: param, index: index, enforcedWhen: negated, stmt: stmt}
			}
		}
		return true
	})
	return guard
}

func isBool(t types.Type) bool {
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Kind() == types.Bool
}

// mutated reports whether body assigns to v or takes its address.
func mutated(body *ast.BlockStmt, v *types.Var, info *types.Info) bool {
	found := false
	refers := func(e ast.Expr) bool {
		id, ok := unparen(e).(*ast.Ident)
		return ok && info.Uses[id] == v
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				found = found || refers(lhs)
			}
		case *ast.IncDecStmt:
			found = found || refers(x.X)
		case *ast.UnaryExpr:
			found = found || (x.Op == token.AND && refers(x.X))
		}
		return !found
	})
	return found
}

// resolveGuardSites returns every call of fn in its package. It fails unless
// each use of fn is a direct call inside a function body whose guard
// argument is a constant bool; an escaping function value, a method
// expression, or a runtime argument keeps the finding at the hint.
//
// Only unexported plain functions qualify: another package can call an
// exported function with any argument, and a method can be reached through
// an interface, neither of which appears as a use of fn in this package.
func resolveGuardSites(p *packages.Package, fn *ast.FuncDecl, guard *boundGuard) ([]guardSite, bool) {
	if fn.Recv != nil || fn.Name.IsExported() {
		return nil, false
	}
	info := p.TypesInfo
	fnObj := info.Defs[fn.Name]
	uses := 0
	for _, obj := range info.Uses {
		if obj == fnObj {
			uses++
		}
	}
	if uses == 0 {
		return nil, false
	}
	var sites []guardSite
	resolved := true
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			caller, ok := decl.(*ast.FuncDecl)
			if !ok || caller.Body == nil {
				continue
			}
			ast.Inspect(caller.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !resolved {
					return resolved
				}
				var callee types.Object
				switch f := unparen(call.Fun).(type) {
				case *ast.Ident:
					callee = info.Uses[f]
				case *ast.SelectorExpr:
					if sel := info.Selections[f]; sel != nil && sel.Kind() != types.MethodVal {
						return true
					}
					callee = info.Uses[f.Sel]
				}
				if callee != fnObj {
					return true
				}
				if call.Ellipsis != token.NoPos || guard.index >= len(call.Args) {
					resolved = false
					return false
				}
				value := info.Types[call.Args[guard.index]].Value
				if value == nil || value.Kind() != constant.Bool {
					resolved = false
					return false
				}
				sites = append(sites, guardSite{call: call, caller: caller, value: constant.BoolVal(value)})
				return true
			})
		}
	}
	return sites, resolved && len(sites) == uses
}

// functionName renders a declaration as it appears in reports, e.g.
// "(*Circuit).Define".
func functionName(fn *ast.FuncDecl) string {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		return "(" + types.ExprString(fn.Recv.List[0].Type) + ")." + fn.Name.Name
	}
	return fn.Name.Name
}
