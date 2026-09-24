package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONAndExitPolicy(t *testing.T) {
	var out, stderr bytes.Buffer
	code := run([]string{"scan", "--format", "json", "."}, &out, &stderr, "../..")
	if code != 1 {
		t.Fatalf("exit %d, want 1: %s", code, stderr.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc["schema_version"] != "1.1" {
		t.Fatalf("unexpected report: %s", out.String())
	}
	out.Reset()
	stderr.Reset()
	if code := run([]string{"scan", "--fail-on", "none", "."}, &out, &stderr, "../.."); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

func TestSARIF(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := run([]string{"scan", "--format", "sarif", "--fail-on", "none", "."}, &out, &stderr, "../.."); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(out.String(), `"version": "2.1.0"`) || !strings.Contains(out.String(), "GNARK_HINT_RELATION_INCOMPLETE") {
		t.Fatalf("unexpected SARIF: %s", out.String())
	}
}

func TestExplain(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := run([]string{"explain", "GNARK_HINT_RELATION_INCOMPLETE"}, &out, &stderr, "."); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

func TestResourceLimitValidationAndOutputLimit(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--timeout=0", "."},
		{"scan", "--max-hints=0", "."},
		{"scan", "--max-output-bytes=0", "."},
	} {
		var out, stderr bytes.Buffer
		if code := run(args, &out, &stderr, "../.."); code != 2 {
			t.Fatalf("run(%v) exit=%d, want 2", args, code)
		}
	}

	var out, stderr bytes.Buffer
	code := run([]string{"scan", "--format=json", "--max-output-bytes=1", "."}, &out, &stderr, "../..")
	if code != 2 || !strings.Contains(stderr.String(), "output limit exceeded") || out.Len() != 0 {
		t.Fatalf("unexpected limited output: exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
}
