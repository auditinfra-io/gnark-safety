package report

import "testing"

func TestSeverityOrder(t *testing.T) {
	for i := 1; i < len(Severities); i++ {
		if Severities[i-1].Rank() <= Severities[i].Rank() {
			t.Fatalf("%s must rank above %s", Severities[i-1], Severities[i])
		}
	}
	if SeverityInfo.Rank() != 0 {
		t.Fatalf("info rank = %d, want 0", SeverityInfo.Rank())
	}
	for _, value := range []string{"", "review", "HIGH", "none"} {
		if _, ok := ParseSeverity(value); ok {
			t.Errorf("ParseSeverity(%q) accepted an unknown severity", value)
		}
		if Severity(value).Rank() >= 0 {
			t.Errorf("unknown severity %q has a non-negative rank", value)
		}
	}
	if s, ok := ParseSeverity("medium"); !ok || s != SeverityMedium {
		t.Fatalf("ParseSeverity(medium) = %q, %v", s, ok)
	}
}
