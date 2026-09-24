package analyzer

import "testing"

func TestCanonicalFixture(t *testing.T) {
	r, err := Scan("../..", []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Hints) != 1 {
		t.Fatalf("got %d hints, want 1", len(r.Hints))
	}
	if len(r.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %#v", len(r.Findings), r.Findings)
	}
	f := r.Findings[0]
	if f.RuleID != relationRule || f.Function != "constrainDivision" {
		t.Fatalf("unexpected finding: %#v", f)
	}
}

func TestRelationShapeAndCoverage(t *testing.T) {
	r, err := Scan("../..", []string{"./internal/analyzer/testdata/relation"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range r.Findings {
		got[f.Function] = true
	}
	for _, name := range []string{"wrongBound", "invertedBound", "elseBound", "loopBound", "directIndex"} {
		if !got[name] {
			t.Errorf("missing finding for %s", name)
		}
	}
	for _, name := range []string{"separateAssertions", "safe"} {
		if got[name] {
			t.Errorf("unexpected finding for %s", name)
		}
	}
	if len(r.Findings) != 5 {
		t.Fatalf("got %d findings, want 5: %#v", len(r.Findings), r.Findings)
	}
}

func TestRuleHelp(t *testing.T) {
	if _, ok := RuleHelp(relationRule); !ok {
		t.Fatal("documented rule is missing")
	}
	if _, ok := RuleHelp("NO_SUCH_RULE"); ok {
		t.Fatal("unknown rule was accepted")
	}
}
