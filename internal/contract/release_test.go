package contract

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func runScript(t *testing.T, env []string, script string, args ...string) (string, error) {
	t.Helper()
	root, _ := filepath.Abs(repoRoot)
	cmd := exec.Command("bash", append([]string{filepath.Join(root, "scripts", script)}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestReleasePreflight(t *testing.T) {
	changelog := filepath.Join(t.TempDir(), "CHANGELOG.md")
	content := "# Changelog\n\n## [Unreleased]\n\n- pending\n\n## [1.2.3-rc.1+build.7] - 2026-09-24\n\n### Added\n\n- a feature\n\n## [1.2.2] - 2026-09-01\n\n## [1.0.0] - 2026-01-01\n\n- first\n"
	if err := os.WriteFile(changelog, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := runScript(t, nil, "release-preflight.sh", "v1.2.3-rc.1+build.7", changelog); err != nil {
		t.Fatalf("described release rejected: %v\n%s", err, out)
	}
	for _, tag := range []string{"v1.2.4", "v1.2.3", "v1.2.3.4", "v01.2.3", "v1.2.3-01", "1.2.3", "v1.2", "v1.2.2", "main"} {
		if out, err := runScript(t, nil, "release-preflight.sh", tag, changelog); err == nil {
			t.Errorf("tag %q passed preflight:\n%s", tag, out)
		}
	}
}

// TestBuildRelease builds the host platform and Windows twice, checks the
// archives are byte-for-byte reproducible, and runs the host binary.
func TestBuildRelease(t *testing.T) {
	host := runtime.GOOS + "/" + runtime.GOARCH
	env := []string{"PLATFORMS=" + host + " windows/amd64", "SOURCE_DATE_EPOCH=1700000000"}
	first, second := t.TempDir(), t.TempDir()
	for _, dir := range []string{first, second} {
		if out, err := runScript(t, env, "build-release.sh", "v0.0.0-rc.1+build.7", dir); err != nil {
			t.Fatalf("build failed: %v\n%s", err, out)
		}
	}
	sums := func(dir string) string {
		content, err := os.ReadFile(filepath.Join(dir, "gnark-safety-binaries.sha256"))
		if err != nil {
			t.Fatal(err)
		}
		return string(content)
	}
	if sums(first) != sums(second) {
		t.Fatalf("builds are not reproducible:\n%s\n%s", sums(first), sums(second))
	}
	if lines := strings.Count(sums(first), "\n"); lines != 2 {
		t.Fatalf("want 2 checksummed archives, got:\n%s", sums(first))
	}

	name := "gnark-safety_0.0.0-rc.1+build.7_" + runtime.GOOS + "_" + runtime.GOARCH
	if runtime.GOOS != "windows" {
		bin := extractTarGz(t, filepath.Join(first, name+".tar.gz"), name+"/gnark-safety")
		out, err := exec.Command(bin, "--version").CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != "gnark-safety v0.0.0-rc.1+build.7" {
			t.Fatalf("released binary reports %q, %v", out, err)
		}
	}
	archive, err := zip.OpenReader(filepath.Join(first, "gnark-safety_0.0.0-rc.1+build.7_windows_amd64.zip"))
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	var entries []string
	for _, file := range archive.File {
		entries = append(entries, file.Name)
	}
	if strings.Join(entries, ",") != "gnark-safety_0.0.0-rc.1+build.7_windows_amd64/CHANGELOG.md,gnark-safety_0.0.0-rc.1+build.7_windows_amd64/LICENSE,gnark-safety_0.0.0-rc.1+build.7_windows_amd64/README.md,gnark-safety_0.0.0-rc.1+build.7_windows_amd64/gnark-safety.exe" {
		t.Fatalf("unexpected zip entries: %v", entries)
	}

	if out, err := runScript(t, env, "build-release.sh", "latest", t.TempDir()); err == nil {
		t.Fatalf("non-semver version accepted:\n%s", out)
	}
}

func extractTarGz(t *testing.T, archive, member string) string {
	t.Helper()
	file, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			t.Fatalf("%s not found in %s", member, archive)
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Name != member {
			continue
		}
		if header.Uid != 0 || header.Gid != 0 || header.ModTime.Unix() != 1700000000 {
			t.Fatalf("archive metadata is not normalized: uid=%d gid=%d mtime=%v", header.Uid, header.Gid, header.ModTime)
		}
		path := filepath.Join(t.TempDir(), "gnark-safety")
		out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(out, reader); err != nil {
			t.Fatal(err)
		}
		out.Close()
		return path
	}
}
