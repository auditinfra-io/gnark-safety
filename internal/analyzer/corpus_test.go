package analyzer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/auditinfra-io/gnark-safety/internal/rules"
)

const corpusRoot = "internal/analyzer/testdata/corpus"

// corpusPatterns lists the corpus packages. The go tool never expands
// wildcards into testdata, so each directory is named explicitly.
func corpusPatterns(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("../..", corpusRoot))
	if err != nil {
		t.Fatal(err)
	}
	var patterns []string
	for _, entry := range entries {
		if entry.IsDir() {
			patterns = append(patterns, "./"+corpusRoot+"/"+entry.Name())
		}
	}
	return patterns
}

var wantPattern = regexp.MustCompile(`// want ((?:GNARK_[A-Z_]+(?::[a-z]+)?\s*)+)`)

// corpusExpectations reads "// want RULE[:severity] ..." annotations. Each
// becomes "file:line RULE", plus ":severity" when the annotation names one.
func corpusExpectations(t *testing.T, patterns []string) []string {
	t.Helper()
	var want []string
	for _, pattern := range patterns {
		files, err := filepath.Glob(filepath.Join("../..", pattern, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			content, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			rel := strings.TrimPrefix(filepath.ToSlash(file), "../../")
			for i, line := range strings.Split(string(content), "\n") {
				m := wantPattern.FindStringSubmatch(line)
				if m == nil {
					continue
				}
				for _, expectation := range strings.Fields(m[1]) {
					want = append(want, fmt.Sprintf("%s:%d %s", rel, i+1, expectation))
				}
			}
		}
	}
	sort.Strings(want)
	return want
}

// TestCorpus requires every finding on the corpus to be annotated and every
// annotation to be found: true positives and false-positive guards are both
// pinned, line by line.
func TestCorpus(t *testing.T) {
	patterns := corpusPatterns(t)
	want := corpusExpectations(t, patterns)
	if len(want) == 0 {
		t.Fatal("corpus has no annotations")
	}
	r, err := ScanContext(context.Background(), "../..", patterns, Options{IncludeExamples: true})
	if err != nil {
		t.Fatal(err)
	}
	annotatedSeverity := map[string]bool{}
	for _, w := range want {
		if strings.Contains(w[strings.LastIndex(w, " "):], ":") {
			annotatedSeverity[w[:strings.LastIndex(w, ":")]] = true
		}
	}
	var got []string
	for _, f := range r.Findings {
		key := fmt.Sprintf("%s:%d %s", f.File, f.Line, f.RuleID)
		if annotatedSeverity[key] {
			key += ":" + string(f.Severity)
		}
		got = append(got, key)
	}
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("corpus findings differ from annotations\n got:\n%s\n\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Every registered rule must have at least one true positive here or
	// in the older fixtures.
	covered := map[string]bool{rules.HintRelationIncomplete: true, rules.HintOutputUnused: true}
	for _, f := range r.Findings {
		covered[f.RuleID] = true
	}
	for _, spec := range rules.All() {
		if !covered[spec.ID] {
			t.Errorf("%s has no true positive in the corpus", spec.ID)
		}
	}
}
