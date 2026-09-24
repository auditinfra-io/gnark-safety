package contract

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestPreCommitHook pins .pre-commit-hooks.yaml to what the README
// documents, and runs the hook's exact command against this repository.
func TestPreCommitHook(t *testing.T) {
	hooks := readFile(t, ".pre-commit-hooks.yaml")
	field := func(name string) string {
		m := regexp.MustCompile(`(?m)^\s*-?\s*` + name + `: (.+)$`).FindStringSubmatch(hooks)
		if m == nil {
			t.Fatalf(".pre-commit-hooks.yaml has no %s", name)
		}
		return strings.TrimSpace(m[1])
	}
	for name, want := range map[string]string{"id": "gnark-safety", "entry": "gnark-safety", "language": "golang", "pass_filenames": "false"} {
		if got := field(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	var args []string
	for _, arg := range strings.Split(strings.Trim(field("args"), "[]"), ",") {
		args = append(args, strings.TrimSpace(arg))
	}
	command := "gnark-safety " + strings.Join(args, " ")
	if !strings.Contains(readFile(t, "README.md"), "runs `"+command+"`") {
		t.Errorf("README does not document the hook command %q", command)
	}
	root, _ := filepath.Abs(repoRoot)
	cmd := exec.Command(installedBinary(t), args...)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hook command fails on this repository: %v\n%s", err, out)
	}
}
