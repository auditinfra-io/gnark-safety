package main

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/auditinfra-io/gnark-safety/internal/analyzer"
)

const repoRoot = "../.."

// TestVetParity runs the tool under `go vet -vettool` and requires the same
// active findings, at the same positions, as the gnark-safety analyzer
// reports for those packages (with example severities kept).
func TestVetParity(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go command not on PATH")
	}
	tool := filepath.Join(t.TempDir(), "gnark-safety-vet")
	if out, err := exec.Command(goTool, "build", "-o", tool, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	patterns := []string{"./examples/divmod", "./internal/analyzer/testdata/deprecated", "./internal/analyzer/testdata/suppress", "./internal/analyzer/testdata/specialize"}
	vet := exec.Command(goTool, append([]string{"vet", "-vettool=" + tool}, patterns...)...)
	vet.Dir = repoRoot
	out, err := vet.CombinedOutput()
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("go vet should exit 1 with findings, got %v:\n%s", err, out)
	}
	finding := regexp.MustCompile(`^(\S+\.go:\d+:\d+): (critical|high|medium|low|info) \[(GNARK_[A-Z_]+)\] `)
	var got []string
	suppressionWarnings := 0
	for _, line := range strings.Split(string(out), "\n") {
		if m := finding.FindStringSubmatch(line); m != nil {
			got = append(got, m[1]+" "+m[3])
		} else if strings.Contains(line, "suppression") {
			suppressionWarnings++
		}
	}

	r, err := analyzer.ScanContext(t.Context(), repoRoot, patterns, analyzer.Options{IncludeExamples: true})
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, f := range r.Findings {
		want = append(want, f.File+":"+strconv.Itoa(f.Line)+":"+strconv.Itoa(f.Column)+" "+f.RuleID)
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("vet findings differ from the analyzer\n got:\n%s\nwant:\n%s\nvet output:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"), out)
	}
	if suppressionWarnings != len(r.Diagnostics) {
		t.Fatalf("got %d suppression warnings from vet, want %d:\n%s", suppressionWarnings, len(r.Diagnostics), out)
	}
}
