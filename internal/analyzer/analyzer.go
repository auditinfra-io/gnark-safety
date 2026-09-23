// Package analyzer loads Go packages and performs conservative, type-aware
// checks over direct gnark API calls.
package analyzer

import (
	"errors"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strings"

	"github.com/auditinfra-io/gnark-safety/pkg/report"
	"golang.org/x/tools/go/packages"
)

const relationRule = "GNARK_HINT_RELATION_INCOMPLETE"

var limitations = []string{
	"Analysis is intra-function and limited to direct, type-resolved gnark API calls.",
	"Reflection, generated code, opaque helpers, complex aliasing, and dynamic hint selection are not modeled.",
}

// Scan analyzes the requested package roots. Dependencies are loaded only for
// type resolution and are not reported.
func Scan(dir string, patterns []string) (report.Report, error) {
	r := report.Report{SchemaVersion: report.SchemaVersion, Findings: []report.Finding{}, Hints: []report.Hint{}, Diagnostics: []string{}, Limitations: append([]string(nil), limitations...)}
	fset := token.NewFileSet()
	pkgs, err := packages.Load(&packages.Config{Dir: dir, Fset: fset, Mode: packages.NeedName | packages.NeedModule | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps}, patterns...)
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
		if r.Module == "" && p.Module != nil {
			r.Module = p.Module.Path
		}
		for _, file := range p.Syntax {
			inspectFile(&r, p, file, fset, absDir)
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

func inspectFile(r *report.Report, p *packages.Package, file *ast.File, fset *token.FileSet, dir string) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		function := fn.Name.Name
		if fn.Recv != nil && len(fn.Recv.List) > 0 {
			function = "(" + types.ExprString(fn.Recv.List[0].Type) + ")." + function
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
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
			r.Hints = append(r.Hints, h)
			if incompleteRelation(fn.Body, call) {
				r.Findings = append(r.Findings, report.Finding{RuleID: relationRule, Severity: report.SeverityHigh, Confidence: "high", File: path, Line: pos.Line, Column: pos.Column, Function: function, Message: "Hint outputs participate in reconstruction, but the canonical remainder bound r < d is not constrained.", Evidence: []string{"hint output: " + h.Hint, "constraint: n = q*d + r", "missing constraint: r < d"}, Limitations: []string{}})
			}
			return true
		})
	}
}

// incompleteRelation recognizes the deliberately narrow first rule: a
// two-output hint whose indexed outputs both occur in AssertIsEqual, with no
// AssertIsLess involving the second output. It intentionally declines more
// complex aliases rather than claiming general soundness.
func incompleteRelation(body *ast.BlockStmt, hintCall *ast.CallExpr) bool {
	var slice string
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, rhs := range as.Rhs {
			if rhs == hintCall && i < len(as.Lhs) {
				if id, ok := as.Lhs[i].(*ast.Ident); ok {
					slice = id.Name
				}
			}
		}
		return true
	})
	if slice == "" {
		return false
	}
	aliases := map[string]int{}
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
			base, ok := idx.X.(*ast.Ident)
			if !ok || base.Name != slice {
				continue
			}
			v := constantIndex(idx.Index)
			id, ok := as.Lhs[i].(*ast.Ident)
			if ok && v >= 0 {
				aliases[id.Name] = v
			}
		}
		return true
	})
	var conditional []struct{ start, end token.Pos }
	ast.Inspect(body, func(n ast.Node) bool {
		if x, ok := n.(*ast.IfStmt); ok {
			conditional = append(conditional, struct{ start, end token.Pos }{x.Body.Pos(), x.Body.End()})
		}
		return true
	})
	hasQ, hasR, hasLess := false, false, false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "AssertIsEqual":
			ast.Inspect(call, func(x ast.Node) bool {
				id, ok := x.(*ast.Ident)
				if !ok {
					return true
				}
				idx, exists := aliases[id.Name]
				if exists && idx == 0 {
					hasQ = true
				}
				if exists && idx == 1 {
					hasR = true
				}
				return true
			})
		case "AssertIsLess":
			for _, span := range conditional {
				if call.Pos() >= span.start && call.End() <= span.end {
					return true
				}
			}
			ast.Inspect(call, func(x ast.Node) bool {
				id, ok := x.(*ast.Ident)
				if !ok {
					return true
				}
				idx, exists := aliases[id.Name]
				if exists && idx == 1 {
					hasLess = true
				}
				return true
			})
		}
		return true
	})
	return hasQ && hasR && !hasLess
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
	return "Detects a two-output hint used in a reconstruction equality when no direct AssertIsLess bound constrains the remainder against the divisor. The rule is intentionally intra-function and conservative.", true
}
