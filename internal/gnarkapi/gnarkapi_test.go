package gnarkapi

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"
)

// TestIsNewHint type-checks a small file against stub frontend interfaces so
// the matcher is exercised without loading gnark itself.
func TestIsNewHint(t *testing.T) {
	const frontend = `package frontend
type Variable any
type Compiler interface{ NewHint(f any, n int, in ...Variable) ([]Variable, error) }
type API interface {
	Compiler() Compiler
	NewHint(f any, n int, in ...Variable) ([]Variable, error)
}
type Other interface{ NewHint(f any, n int, in ...Variable) ([]Variable, error) }
`
	const user = `package user
import fe "github.com/consensys/gnark/frontend"
type wrapped struct{ fe.API }
type unrelated struct{}
func (unrelated) NewHint(any, int, ...fe.Variable) ([]fe.Variable, error) { return nil, nil }
func calls(api fe.API, w wrapped, o fe.Other) {
	api.Compiler().NewHint(nil, 1) // compiler
	api.NewHint(nil, 1)            // api
	w.NewHint(nil, 1)              // embedded
	fe.API.NewHint(api, nil, 1)    // expression
	o.NewHint(nil, 1)              // other
	unrelated{}.NewHint(nil, 1)    // unrelated
}
`
	fset := token.NewFileSet()
	frontendFile, err := parser.ParseFile(fset, "frontend.go", frontend, 0)
	if err != nil {
		t.Fatal(err)
	}
	frontendPkg, err := (&types.Config{Importer: importer.Default()}).Check(FrontendPath, fset, []*ast.File{frontendFile}, nil)
	if err != nil {
		t.Fatal(err)
	}
	userFile, err := parser.ParseFile(fset, "user.go", user, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Selections: map[*ast.SelectorExpr]*types.Selection{}, Uses: map[*ast.Ident]types.Object{}}
	config := &types.Config{Importer: importerFunc(func(path string) (*types.Package, error) { return frontendPkg, nil })}
	if _, err := config.Check("user", fset, []*ast.File{userFile}, info); err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{"compiler": true, "api": true, "embedded": true, "expression": true, "other": false, "unrelated": false}
	got := map[string]bool{}
	comments := ast.NewCommentMap(fset, userFile, userFile.Comments)
	ast.Inspect(userFile, func(n ast.Node) bool {
		stmt, ok := n.(*ast.ExprStmt)
		if !ok {
			return true
		}
		call := stmt.X.(*ast.CallExpr)
		sel := call.Fun.(*ast.SelectorExpr)
		if sel.Sel.Name != "NewHint" {
			return true
		}
		label := comments[stmt][0].List[0].Text[3:]
		got[label] = IsNewHint(info.Selections[sel].Obj())
		return true
	})
	if len(got) != len(want) {
		t.Fatalf("visited %v, want every case in %v", got, want)
	}
	for label, expected := range want {
		if got[label] != expected {
			t.Errorf("%s: IsNewHint=%v, want %v", label, got[label], expected)
		}
	}
}

type importerFunc func(string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }
