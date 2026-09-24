package rules

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var idPattern = regexp.MustCompile(`^GNARK_[A-Z0-9_]+$`)

func TestRegistryIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, spec := range All() {
		if !idPattern.MatchString(spec.ID) {
			t.Errorf("%q: rule IDs must match %s", spec.ID, idPattern)
		}
		if seen[spec.ID] {
			t.Errorf("%s: duplicate rule ID", spec.ID)
		}
		seen[spec.ID] = true
		if spec.Title == "" || spec.Summary == "" || spec.Description == "" || spec.Confidence == "" {
			t.Errorf("%s: title, summary, description, and confidence are required", spec.ID)
		}
		if len(spec.Severities) == 0 {
			t.Errorf("%s: no severities", spec.ID)
		}
		for i, severity := range spec.Severities {
			if severity.Rank() < 0 {
				t.Errorf("%s: unknown severity %q", spec.ID, severity)
			}
			if i > 0 && spec.Severities[i-1].Rank() <= severity.Rank() {
				t.Errorf("%s: severities must be listed most severe first without repeats", spec.ID)
			}
		}
		known := false
		for _, class := range Classes {
			known = known || spec.Class == class
		}
		if !known {
			t.Errorf("%s: unknown class %q", spec.ID, spec.Class)
		}
		if got, ok := Lookup(spec.ID); !ok || got.ID != spec.ID {
			t.Errorf("%s: Lookup failed", spec.ID)
		}
	}
	if _, ok := Lookup("NO_SUCH_RULE"); ok {
		t.Error("Lookup accepted an unknown rule")
	}
}

func TestExplainCoversEveryRule(t *testing.T) {
	for _, spec := range All() {
		text, ok := Explain(spec.ID)
		if !ok || !strings.Contains(text, spec.Summary) || !strings.Contains(text, spec.HelpURI()) {
			t.Errorf("%s: incomplete explain text: %q", spec.ID, text)
		}
	}
	if _, ok := Explain("NO_SUCH_RULE"); ok {
		t.Error("Explain accepted an unknown rule")
	}
}

// TestGeneratedDocsUpToDate is the drift guard: the committed docs must be
// exactly what the registry renders.
func TestGeneratedDocsUpToDate(t *testing.T) {
	for _, doc := range Documents {
		current, err := os.ReadFile(filepath.Join("..", "..", doc.Path))
		if err != nil {
			t.Fatal(err)
		}
		updated, err := doc.Regenerate(current)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(current, updated) {
			t.Errorf("%s is out of date; run go generate ./internal/rules", doc.Path)
		}
	}
}

func TestRegenerateRejectsMissingMarkers(t *testing.T) {
	doc := Document{Path: "x.md", Sections: []Section{{Name: "RULE TABLE", Render: Table}}}
	if _, err := doc.Regenerate([]byte("no markers here\n")); err == nil {
		t.Fatal("missing markers were accepted")
	}
	twice := "<!-- BEGIN GENERATED RULE TABLE -->\n<!-- END GENERATED RULE TABLE -->\n"
	if _, err := doc.Regenerate([]byte(twice + twice)); err == nil {
		t.Fatal("duplicate markers were accepted")
	}
	reversed := "<!-- END GENERATED RULE TABLE --><!-- BEGIN GENERATED RULE TABLE -->\n"
	if _, err := doc.Regenerate([]byte(reversed)); err == nil {
		t.Fatal("reversed markers were accepted")
	}
}
