package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/auditinfra-io/gnark-safety/internal/analyzer"
)

const repoRoot = "../.."

func TestFixtureInventory(t *testing.T) {
	r, err := scan(repoRoot, []string{"./cmd/gnark-hint-scan/testdata/fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(r.Hints), 11; got != want {
		t.Fatalf("got %d hints, want %d: %#v", got, want, r.Hints)
	}
	var unknownHint, unknownOutput, unknownInputs, methodExpression, generic, methodValue, deprecated bool
	for _, h := range r.Hints {
		if h.Hint == "unknown" {
			unknownHint = true
		}
		if h.OutputCount.Value == nil {
			unknownOutput = true
		}
		if h.InputCount.Value == nil {
			unknownInputs = true
		}
		if strings.Contains(h.Function, "ignored") {
			t.Error("unrelated NewHint was reported")
		}
		switch h.Function {
		case "methodExpression":
			methodExpression = h.Hint == "github.com/auditinfra-io/gnark-safety/cmd/gnark-hint-scan/testdata/fixture.knownHint" && value(h.OutputCount) == 2 && value(h.InputCount) == 1
		case "instantiated":
			generic = h.Hint == "github.com/auditinfra-io/gnark-safety/cmd/gnark-hint-scan/testdata/fixture.genericHint"
		case "deprecatedShortcut":
			deprecated = h.Hint == "github.com/auditinfra-io/gnark-safety/cmd/gnark-hint-scan/testdata/fixture.knownHint"
		case "methodValue":
			methodValue = h.Hint == "(github.com/auditinfra-io/gnark-safety/cmd/gnark-hint-scan/testdata/fixture.hintHandler).Compute"
		}
	}
	if !unknownHint || !unknownOutput || !unknownInputs {
		t.Fatalf("missing explicit unknown cases: hint=%v output=%v inputs=%v", unknownHint, unknownOutput, unknownInputs)
	}
	if !methodExpression || !generic || !methodValue || !deprecated {
		t.Fatalf("special call forms not reported correctly: method expression=%v generic=%v method value=%v deprecated=%v", methodExpression, generic, methodValue, deprecated)
	}
}

func value(v unknownInt) int {
	if v.Value == nil {
		return -1
	}
	return *v.Value
}

func TestDemoIntegration(t *testing.T) {
	r, err := scan(repoRoot, []string{"./examples/divmod"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(r.Hints), 1; got != want {
		t.Fatalf("demo has %d hint call sites, want %d", got, want)
	}
	if r.Hints[0].Function != "constrainDivision" {
		t.Fatalf("unexpected enclosing function %q", r.Hints[0].Function)
	}
}

func TestNoHintsText(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := run([]string{"scan", "./cmd/gnark-hint-scan/testdata/nohint"}, &out, &stderr, repoRoot); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(out.String(), "No direct gnark hint calls found in the scanned packages.") || !strings.Contains(out.String(), "Inventory only:") {
		t.Fatalf("unexpected output: %s", out.String())
	}
}

func TestPackageLoadingFailure(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := run([]string{"scan", "./does-not-exist"}, &out, &stderr, repoRoot); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
}

func TestJSONDeterministicAndValid(t *testing.T) {
	args := []string{"scan", "--format", "json", "./cmd/gnark-hint-scan/testdata/fixture"}
	var first, second, stderr bytes.Buffer
	if code := run(args, &first, &stderr, repoRoot); code != 0 {
		t.Fatalf("first exit %d: %s", code, stderr.String())
	}
	stderr.Reset()
	if code := run(args, &second, &stderr, repoRoot); code != 0 {
		t.Fatalf("second exit %d: %s", code, stderr.String())
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("JSON output is not deterministic")
	}
	var got report
	if err := json.Unmarshal(first.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.SchemaVersion != schemaVersion || got.Hints == nil || got.Diagnostics == nil || got.Limitations == nil {
		t.Fatalf("incomplete report: %#v", got)
	}
	// A second scan also protects deterministic ordering, independent of JSON whitespace.
	a, _ := scan(repoRoot, args[3:])
	b, _ := scan(repoRoot, args[3:])
	if !reflect.DeepEqual(a, b) {
		t.Fatal("scan results differ")
	}
}

func TestInvalidArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"scan"}, {"scan", "--format", "xml", "."}} {
		if code := run(args, &bytes.Buffer{}, &bytes.Buffer{}, repoRoot); code != 2 {
			t.Errorf("run(%q)=%d", args, code)
		}
	}
}

// TestInventoryParity guards the fold into `gnark-safety inventory`: the
// analyzer must report exactly the call sites, identities, and counts this
// deprecated command reports.
func TestInventoryParity(t *testing.T) {
	patterns := []string{"./cmd/gnark-hint-scan/testdata/fixture", "./examples/divmod"}
	legacy, err := scan(repoRoot, patterns)
	if err != nil {
		t.Fatal(err)
	}
	current, err := analyzer.Scan(repoRoot, patterns)
	if err != nil {
		t.Fatal(err)
	}
	key := func(file string, line, column int, hint string, outputs, inputs *int) string {
		return fmt.Sprintf("%s:%d:%d %s outputs=%s inputs=%s", file, line, column, hint, display(unknownInt{outputs}), display(unknownInt{inputs}))
	}
	var want, got []string
	for _, h := range legacy.Hints {
		want = append(want, key(h.File, h.Line, h.Column, h.Hint, h.OutputCount.Value, h.InputCount.Value))
	}
	for _, h := range current.Hints {
		got = append(got, key(h.File, h.Line, h.Column, h.Hint, h.OutputCount, h.InputCount))
	}
	sort.Strings(want)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("inventory drift\n got %v\nwant %v", got, want)
	}
}

func TestDeprecationNotice(t *testing.T) {
	var out, stderr bytes.Buffer
	run([]string{"scan", "./cmd/gnark-hint-scan/testdata/nohint"}, &out, &stderr, repoRoot)
	if !strings.Contains(stderr.String(), "gnark-safety inventory") {
		t.Fatalf("missing deprecation notice: %q", stderr.String())
	}
}
