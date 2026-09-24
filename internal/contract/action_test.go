package contract

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

const repoRoot = "../.."

// actionInputs returns the input names declared in action.yml, in order.
func actionInputs(t *testing.T, action string) []string {
	t.Helper()
	var inputs []string
	inside := false
	for _, line := range strings.Split(action, "\n") {
		switch {
		case line == "inputs:":
			inside = true
		case inside && line != "" && !strings.HasPrefix(line, " "):
			return inputs
		case inside:
			if m := regexp.MustCompile(`^  ([a-z][a-z-]*):$`).FindStringSubmatch(line); m != nil {
				inputs = append(inputs, m[1])
			}
		}
	}
	t.Fatal("action.yml has no inputs block")
	return nil
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repoRoot, path))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func TestActionInputsAreUsedAndDocumented(t *testing.T) {
	action := readFile(t, "action.yml")
	inputs := actionInputs(t, action)
	if len(inputs) == 0 {
		t.Fatal("no inputs parsed")
	}
	readme := readFile(t, "README.md")
	start := strings.Index(readme, "## GitHub Action")
	if start < 0 {
		t.Fatal("README has no GitHub Action section")
	}
	section := readme[start:]
	if end := strings.Index(section[3:], "\n## "); end >= 0 {
		section = section[:end+3]
	}
	for _, input := range inputs {
		if !strings.Contains(action, "inputs."+input) {
			t.Errorf("input %q is declared but never used", input)
		}
		if !strings.Contains(section, "| `"+input+"` |") {
			t.Errorf("input %q is not documented in the README's GitHub Action table", input)
		}
	}
}

// TestActionScriptsTakeInputsFromEnvironment enforces that no run block
// interpolates an expression: composite actions substitute ${{ }} before
// bash parses the script, so an input could inject shell syntax.
func TestActionScriptsTakeInputsFromEnvironment(t *testing.T) {
	lines := strings.Split(readFile(t, "action.yml"), "\n")
	runLine := regexp.MustCompile(`^(\s+)(- )?run: ?(.*)$`)
	for i := 0; i < len(lines); i++ {
		m := runLine.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		block := []string{m[3]}
		if m[3] == "|" {
			indent := len(m[1])
			for i+1 < len(lines) && (strings.TrimSpace(lines[i+1]) == "" || len(lines[i+1])-len(strings.TrimLeft(lines[i+1], " ")) > indent) {
				i++
				block = append(block, lines[i])
			}
		}
		for _, line := range block {
			if strings.Contains(line, "${{") {
				t.Errorf("run block interpolates an expression: %q", strings.TrimSpace(line))
			}
		}
	}
}

func TestActionPinsThirdPartyActions(t *testing.T) {
	uses := regexp.MustCompile(`^\s+(- )?uses: (\S+)`)
	pinned := regexp.MustCompile(`^[\w.-]+/[\w./-]+@[0-9a-f]{40}$`)
	found := 0
	for _, line := range strings.Split(readFile(t, "action.yml"), "\n") {
		if m := uses.FindStringSubmatch(line); m != nil {
			found++
			if !pinned.MatchString(m[2]) {
				t.Errorf("action reference %q is not pinned to a full commit SHA", m[2])
			}
		}
	}
	if found == 0 {
		t.Fatal("no uses: lines found")
	}
}

var (
	buildOnce sync.Once
	buildDir  string
	binary    string
	buildErr  error
	buildLog  []byte
)

func TestMain(m *testing.M) {
	code := m.Run()
	if buildDir != "" {
		os.RemoveAll(buildDir)
	}
	os.Exit(code)
}

// installedBinary runs the action's install script exactly as the action
// does, building from the repository checkout, and returns the binary.
func installedBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		temp, err := os.MkdirTemp("", "gnark-safety-action")
		if err != nil {
			buildErr = err
			return
		}
		buildDir = temp
		root, _ := filepath.Abs(repoRoot)
		cmd := exec.Command("bash", filepath.Join(root, "scripts/action-install.sh"))
		cmd.Env = append(os.Environ(), "RUNNER_TEMP="+temp, "GITHUB_ACTION_PATH="+root, "ACTION_REF=v9.9.9-contract", "GITHUB_PATH="+filepath.Join(temp, "path"), "VERSION=")
		buildLog, buildErr = cmd.CombinedOutput()
		binary = filepath.Join(temp, "gnark-safety-bin", "gnark-safety")
	})
	if buildErr != nil {
		t.Fatalf("install script failed: %v\n%s", buildErr, buildLog)
	}
	return binary
}

func TestActionInstallScript(t *testing.T) {
	bin := installedBinary(t)
	if !strings.Contains(string(buildLog), "gnark-safety v9.9.9-contract") {
		t.Fatalf("install did not stamp the action ref:\n%s", buildLog)
	}
	path, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(bin)), "path"))
	if err != nil || strings.TrimSpace(string(path)) != filepath.Dir(bin) {
		t.Fatalf("install did not add the binary to GITHUB_PATH: %q, %v", path, err)
	}
	for _, version := range []string{"main; rm -rf /", "1.0.0", "v1.0.0 extra"} {
		cmd := exec.Command("bash", filepath.Join(repoRoot, "scripts/action-install.sh"))
		cmd.Env = append(os.Environ(), "RUNNER_TEMP="+t.TempDir(), "VERSION="+version)
		if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "version must be a release") {
			t.Errorf("VERSION=%q was accepted: %v\n%s", version, err, out)
		}
	}
}

type scanResult struct {
	status  int
	outputs map[string]string
	log     string
	sarif   string
}

func runScanScript(t *testing.T, workdir string, env ...string) scanResult {
	t.Helper()
	bin := installedBinary(t)
	root, _ := filepath.Abs(repoRoot)
	temp := t.TempDir()
	outputFile := filepath.Join(temp, "github-output")
	sarif := filepath.Join(temp, "gnark-safety.sarif")
	cmd := exec.Command("bash", filepath.Join(root, "scripts/action-scan.sh"))
	cmd.Dir = filepath.Join(root, workdir)
	cmd.Env = append(os.Environ(), "GNARK_SAFETY="+bin, "GITHUB_OUTPUT="+outputFile, "SARIF_FILE="+sarif, "REPO_ROOT="+root)
	cmd.Env = append(cmd.Env, env...)
	log, err := cmd.CombinedOutput()
	result := scanResult{outputs: map[string]string{}, log: string(log)}
	if exitErr, ok := err.(*exec.ExitError); ok {
		result.status = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	if file, err := os.Open(outputFile); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if key, value, ok := strings.Cut(scanner.Text(), "="); ok {
				result.outputs[key] = value
			}
		}
		file.Close()
	}
	if content, err := os.ReadFile(sarif); err == nil {
		result.sarif = string(content)
	}
	return result
}

func sarifURIs(t *testing.T, content string) []string {
	t.Helper()
	var doc struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		t.Fatalf("invalid SARIF: %v", err)
	}
	var uris []string
	for _, result := range doc.Runs[0].Results {
		uris = append(uris, result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	return uris
}

func TestActionScanScriptGate(t *testing.T) {
	r := runScanScript(t, ".", "SCAN_PATH=./examples/divmod", "FAIL_ON=high", "INCLUDE_EXAMPLES=true")
	// The script succeeds so the upload step can run; the gate is the
	// recorded exit code, which the action's final step enforces.
	if r.status != 0 || r.outputs["exit-code"] != "1" || r.outputs["sarif-file"] == "" {
		t.Fatalf("status=%d outputs=%v\n%s", r.status, r.outputs, r.log)
	}
	if uris := sarifURIs(t, r.sarif); len(uris) != 1 || uris[0] != "examples/divmod/circuits.go" {
		t.Fatalf("unexpected SARIF locations %v", uris)
	}
	r = runScanScript(t, ".", "SCAN_PATH=./examples/divmod", "FAIL_ON=high")
	if r.status != 0 || r.outputs["exit-code"] != "0" {
		t.Fatalf("downgraded example should pass: status=%d outputs=%v\n%s", r.status, r.outputs, r.log)
	}
}

// TestActionScanScriptSubdirectory covers a module scanned from a
// working directory below the repository root: SARIF paths must still be
// relative to the root so code scanning can place them.
func TestActionScanScriptSubdirectory(t *testing.T) {
	r := runScanScript(t, "examples/divmod", "SCAN_PATH=.", "FAIL_ON=none", "INCLUDE_EXAMPLES=true")
	if r.status != 0 || r.outputs["exit-code"] != "0" {
		t.Fatalf("status=%d outputs=%v\n%s", r.status, r.outputs, r.log)
	}
	if uris := sarifURIs(t, r.sarif); len(uris) != 1 || uris[0] != "examples/divmod/circuits.go" {
		t.Fatalf("SARIF paths are not repository-relative: %v", uris)
	}
}

func TestActionScanScriptMultiplePatterns(t *testing.T) {
	r := runScanScript(t, ".", "SCAN_PATH=./examples/divmod\n  ./internal/analyzer/testdata/deprecated\n", "FAIL_ON=none")
	if r.status != 0 || !strings.Contains(r.log, "scanned 2 package(s)") {
		t.Fatalf("multi-line path not split into patterns: status=%d\n%s", r.status, r.log)
	}
}

func TestActionScanScriptFailures(t *testing.T) {
	r := runScanScript(t, ".", "SCAN_PATH=./cmd/gnark-hint-scan/testdata/nohint")
	if r.status != 2 || r.outputs["exit-code"] != "2" || r.outputs["sarif-file"] != "" || r.sarif != "" {
		t.Fatalf("an empty scan must fail the step without SARIF: status=%d outputs=%v\n%s", r.status, r.outputs, r.log)
	}
	for _, env := range [][]string{
		{"SCAN_PATH=./examples/divmod --output=/tmp/owned"},
		{"SCAN_PATH=-h"},
		{"SCAN_PATH=   "},
		{"SCAN_PATH=./examples/divmod", "INCLUDE_TESTS=yes"},
		{"SCAN_PATH=./examples/divmod", "FAIL_ON=review"},
	} {
		r := runScanScript(t, ".", env...)
		if r.status != 2 || r.outputs["exit-code"] == "0" || r.outputs["exit-code"] == "1" {
			t.Errorf("%v: want a failed step, got status=%d outputs=%v\n%s", env, r.status, r.outputs, r.log)
		}
	}
}
