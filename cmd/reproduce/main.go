// Command reproduce regenerates the evidence retained for this demonstration.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var sourceFiles = []string{
	"circuits.go", "circuits_test.go", "adversarial_hints_test.go", "hints.go",
	"proof_test.go", "cmd/reproduce/main.go", "go.mod", "go.sum",
}

func main() {
	root, err := repositoryRoot()
	must(err)
	output, testErr := run(root, "go", "test", "-count=1", "-v", "./...")
	must(os.WriteFile(filepath.Join(root, "evidence", "test-output.txt"), output, 0o644))
	if testErr != nil {
		fmt.Fprint(os.Stderr, string(output))
		must(fmt.Errorf("test suite failed: %w", testErr))
	}

	hashes := make(map[string]string, len(sourceFiles))
	for _, name := range sourceFiles {
		hashes[name] = hashFile(filepath.Join(root, name))
	}
	kernel, _ := run(root, "uname", "-r")
	result := map[string]any{
		"schema_version":   3,
		"generated_at_utc": time.Now().UTC().Format(time.RFC3339),
		"generator":        "go run ./cmd/reproduce",
		"source_binding":   map[string]any{"method": "sha256", "files": hashes},
		"environment": map[string]string{
			"os": runtime.GOOS, "kernel": strings.TrimSpace(string(kernel)),
			"architecture": runtime.GOARCH, "go": runtime.Version(),
			"gnark":        moduleVersion(root, "github.com/consensys/gnark"),
			"gnark_crypto": moduleVersion(root, "github.com/consensys/gnark-crypto"),
			"backend":      "Groth16", "curve": "BN254",
		},
		"command": map[string]any{"value": "go test -count=1 -v ./...", "exit_code": 0},
		"semantic_outcomes": map[string]string{
			"honest_advice": "both circuits accept",
			"reconstruction_preserving_noncanonical_advice": "vulnerable accepts; corrected rejects",
			"invalid_range_or_zero_divisor_advice":          "both circuits reject",
			"groth16_vulnerable_invalid_proof":              "generated and verified",
			"groth16_corrected_invalid_proof":               "proving rejects the witness",
		},
		"retained_output": map[string]string{
			"path": "evidence/test-output.txt", "sha256": hashFile(filepath.Join(root, "evidence", "test-output.txt")),
		},
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(root, "evidence", "results.json"), append(encoded, '\n'), 0o644))
}

func repositoryRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	return strings.TrimSpace(string(out)), err
}

func run(dir, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir, cmd.Env = dir, os.Environ()
	return cmd.CombinedOutput()
}

func moduleVersion(root, module string) string {
	out, err := run(root, "go", "list", "-m", "-f", "{{.Version}}", module)
	must(err)
	return strings.TrimSpace(string(out))
}

func hashFile(path string) string {
	contents, err := os.ReadFile(path)
	must(err)
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
