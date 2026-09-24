package divmod

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// mutationTargets records the hint functions covered by TestHintMutationMatrix.
// A newly added source call to NewHint must be registered and exercised instead
// of silently escaping the adversarial test suite.
var mutationTargets = map[string]func(*testing.T){
	"QuotientRemainderHint": testQuotientRemainderHintMutations,
}

func TestEveryHintCallHasMutationCoverage(t *testing.T) {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	discovered := make(map[string]bool)
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "NewHint" {
				return true
			}
			identity, ok := call.Args[0].(*ast.Ident)
			if !ok {
				t.Errorf("%s: dynamically selected hint needs an explicit mutation target", fset.Position(call.Pos()))
				return true
			}
			discovered[identity.Name] = true
			return true
		})
	}

	var missing, stale []string
	for hint := range discovered {
		if mutationTargets[hint] == nil {
			missing = append(missing, hint)
		}
	}
	for hint := range mutationTargets {
		if !discovered[hint] {
			stale = append(stale, hint)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) != 0 || len(stale) != 0 {
		t.Fatalf("hint mutation registry mismatch: missing=%v stale=%v", missing, stale)
	}
}
