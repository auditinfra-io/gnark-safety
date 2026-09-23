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

func TestRuleHelp(t *testing.T) {
	if _, ok := RuleHelp(relationRule); !ok {
		t.Fatal("documented rule is missing")
	}
	if _, ok := RuleHelp("NO_SUCH_RULE"); ok {
		t.Fatal("unknown rule was accepted")
	}
}
