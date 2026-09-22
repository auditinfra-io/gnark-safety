package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestFixtureInventory(t *testing.T) {
	r, err := scan("../../..", []string{"./cmd/gnark-hint-scan/testdata/fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(r.Hints), 10; got != want {
		t.Fatalf("got %d hints, want %d: %#v", got, want, r.Hints)
	}
	var unknownHint, unknownOutput, unknownInputs, methodExpression, generic, methodValue bool
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
		case "methodValue":
			methodValue = h.Hint == "(github.com/auditinfra-io/gnark-safety/cmd/gnark-hint-scan/testdata/fixture.hintHandler).Compute"
		}
	}
	if !unknownHint || !unknownOutput || !unknownInputs {
		t.Fatalf("missing explicit unknown cases: hint=%v output=%v inputs=%v", unknownHint, unknownOutput, unknownInputs)
	}
	if !methodExpression || !generic || !methodValue {
		t.Fatalf("special call forms not reported correctly: method expression=%v generic=%v method value=%v", methodExpression, generic, methodValue)
	}
}

func value(v unknownInt) int {
	if v.Value == nil {
		return -1
	}
	return *v.Value
}

func TestDemoIntegration(t *testing.T) {
	r, err := scan("../../..", []string{"."})
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
	if code := run([]string{"scan", "./cmd/gnark-hint-scan/testdata/nohint"}, &out, &stderr, "../../.."); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(out.String(), "No direct gnark hint calls found in the scanned packages.") || !strings.Contains(out.String(), "Inventory only:") {
		t.Fatalf("unexpected output: %s", out.String())
	}
}

func TestPackageLoadingFailure(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := run([]string{"scan", "./does-not-exist"}, &out, &stderr, "../../.."); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
}

func TestJSONDeterministicAndValid(t *testing.T) {
	args := []string{"scan", "--format", "json", "./cmd/gnark-hint-scan/testdata/fixture"}
	var first, second, stderr bytes.Buffer
	if code := run(args, &first, &stderr, "../../.."); code != 0 {
		t.Fatalf("first exit %d: %s", code, stderr.String())
	}
	stderr.Reset()
	if code := run(args, &second, &stderr, "../../.."); code != 0 {
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
	a, _ := scan("../../..", args[3:])
	b, _ := scan("../../..", args[3:])
	if !reflect.DeepEqual(a, b) {
		t.Fatal("scan results differ")
	}
}

func TestInvalidArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"scan"}, {"scan", "--format", "xml", "."}} {
		if code := run(args, &bytes.Buffer{}, &bytes.Buffer{}, "../../.."); code != 2 {
			t.Errorf("run(%q)=%d", args, code)
		}
	}
}
