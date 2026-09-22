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
	"sort"
	"strings"
	"time"
)

func main() {
	root, err := repositoryRoot()
	must(err)
	output, testErr := run(root, "go", "test", "-count=1", "-v", "./...")
	if testErr != nil {
		fmt.Fprint(os.Stderr, string(output))
		must(fmt.Errorf("test suite failed: %w", testErr))
	}

	sourceFiles, err := discoverSourceFiles(root)
	must(err)
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
			"path": "evidence/test-output.txt", "sha256": hashBytes(output),
		},
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	must(err)
	must(publishEvidence(filepath.Join(root, "evidence"), output, append(encoded, '\n')))
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

// discoverSourceFiles binds the evidence to every non-ignored Go source file
// in the worktree, including new files that have not been added to Git yet.
func discoverSourceFiles(root string) ([]string, error) {
	out, err := run(root, "git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "*.go")
	if err != nil {
		return nil, fmt.Errorf("discover Go source files: %w", err)
	}
	files := []string{"go.mod", "go.sum"}
	for _, name := range strings.Split(string(out), "\x00") {
		if name != "" {
			files = append(files, filepath.ToSlash(name))
		}
	}
	sort.Strings(files)
	return files, nil
}

// publishEvidence prepares both artifacts before replacing either retained
// file. In particular, failed tests never call this function and therefore
// leave the prior evidence pair untouched.
func publishEvidence(dir string, output, result []byte) error {
	outputTemp, err := writeTemp(dir, "test-output-*.tmp", output)
	if err != nil {
		return err
	}
	defer os.Remove(outputTemp)
	resultTemp, err := writeTemp(dir, "results-*.tmp", result)
	if err != nil {
		return err
	}
	defer os.Remove(resultTemp)
	if err := os.Rename(outputTemp, filepath.Join(dir, "test-output.txt")); err != nil {
		return fmt.Errorf("publish test output: %w", err)
	}
	if err := os.Rename(resultTemp, filepath.Join(dir, "results.json")); err != nil {
		return fmt.Errorf("publish results: %w", err)
	}
	return nil
}

func writeTemp(dir, pattern string, contents []byte) (path string, err error) {
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	path = file.Name()
	defer func() {
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			os.Remove(path)
		}
	}()
	if err = file.Chmod(0o644); err != nil {
		return path, err
	}
	_, err = file.Write(contents)
	return path, err
}

func hashFile(path string) string {
	contents, err := os.ReadFile(path)
	must(err)
	return hashBytes(contents)
}

func hashBytes(contents []byte) string {
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
