package analyzer

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/auditinfra-io/gnark-safety/internal/rules"
	"github.com/auditinfra-io/gnark-safety/pkg/report"
)

const recursionFixtures = "internal/analyzer/testdata/corpus/recursionwitness"

// TestRecursionWitnessFixtures requires every circuit in the rule's tp_*.go
// fixtures to be reported and nothing in its fp_*.go fixtures, by any rule.
func TestRecursionWitnessFixtures(t *testing.T) {
	r, err := ScanContext(context.Background(), "../..", []string{"./" + recursionFixtures}, Options{IncludeExamples: true})
	if err != nil {
		t.Fatal(err)
	}
	reported := map[string]bool{}
	for _, f := range r.Findings {
		name := path.Base(f.File)
		switch {
		case strings.HasPrefix(name, "fp_"):
			t.Errorf("%s:%d %s: %s is reported in a false-positive fixture: %s", name, f.Line, f.Function, f.RuleID, f.Message)
		case f.RuleID == rules.RecursionUnverified:
			if f.Severity != report.SeverityHigh {
				t.Errorf("%s:%d: severity %s, want high", name, f.Line, f.Severity)
			}
			reported[f.Function] = true
		}
	}
	for _, function := range []string{
		"(*UnverifiedCircuit).Define", "(*DiscardedCircuit).Define", "(*NoVerifierCircuit).Define",
		"(*EmbeddedCircuit).Define", "(*DefinedTypeCircuit).Define", "(*VarDiscardCircuit).Define", "(*DeferDiscardCircuit).Define",
		"(*DigestCircuit).Define", "(*TreeCircuit).Define", "(*LoopCircuit).Define",
		"(*AssertedCircuit).Define", "(*ErrorPathCircuit).Define",
	} {
		if !reported[function] {
			t.Errorf("%s is not reported", function)
		}
	}
}

// TestRecursionWitnessMutation removes only the line marked "enforcement"
// from fp_recursion_verified.go, changing nothing else, and requires the
// finding to appear in exactly that circuit. If it does not, the rule is
// keyed on something other than the missing verification.
func TestRecursionWitnessMutation(t *testing.T) {
	source := filepath.Join("../..", recursionFixtures)
	scratch, err := os.MkdirTemp(filepath.Join("../..", "internal/analyzer/testdata"), "mutation-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(scratch) })
	target := filepath.Join(scratch, "recursionwitness")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	var removed []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if entry.Name() == "fp_recursion_verified.go" {
			var kept []string
			for _, line := range strings.SplitAfter(string(content), "\n") {
				if strings.Contains(line, "// enforcement") {
					removed = append(removed, strings.TrimSpace(line))
					continue
				}
				kept = append(kept, line)
			}
			content = []byte(strings.Join(kept, ""))
		}
		if err := os.WriteFile(filepath.Join(target, entry.Name()), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if len(removed) != 1 || !strings.Contains(removed[0], "AssertProof") {
		t.Fatalf("expected to remove exactly one AssertProof enforcement line, removed %q", removed)
	}

	pattern := "./" + filepath.ToSlash(strings.TrimPrefix(target, "../../"))
	before := recursionFindings(t, "./"+recursionFixtures)
	after := recursionFindings(t, pattern)
	if before["fp_recursion_verified.go"] != nil {
		t.Fatalf("unmutated fp_recursion_verified.go is already reported: %v", before["fp_recursion_verified.go"])
	}
	got := after["fp_recursion_verified.go"]
	if len(got) != 1 || got[0] != "(*VerifiedCircuit).Define" {
		t.Fatalf("removing %q: findings in fp_recursion_verified.go = %v, want one in (*VerifiedCircuit).Define", removed[0], got)
	}
	for file, functions := range before {
		if strings.Join(after[file], ",") != strings.Join(functions, ",") {
			t.Errorf("the mutation changed findings in %s: %v -> %v", file, functions, after[file])
		}
	}
}

// recursionFindings returns, per file, the functions where the rule reports.
func recursionFindings(t *testing.T, pattern string) map[string][]string {
	t.Helper()
	r, err := ScanContext(context.Background(), "../..", []string{pattern}, Options{IncludeExamples: true})
	if err != nil {
		t.Fatal(err)
	}
	byFile := map[string][]string{}
	for _, f := range r.Findings {
		if f.RuleID == rules.RecursionUnverified {
			byFile[path.Base(f.File)] = append(byFile[path.Base(f.File)], f.Function)
		}
	}
	for _, functions := range byFile {
		sort.Strings(functions)
	}
	return byFile
}
