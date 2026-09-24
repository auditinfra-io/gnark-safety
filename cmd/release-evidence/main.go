// Command release-evidence creates auditable artifacts for a tagged release.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/auditinfra-io/gnark-safety/internal/analyzer"
	"github.com/auditinfra-io/gnark-safety/internal/output"
)

type module struct {
	Path, Version, Sum string
	Main               bool
	Replace            *module
}

type spdxPackage struct {
	Name             string `json:"name"`
	SPDXID           string `json:"SPDXID"`
	VersionInfo      string `json:"versionInfo,omitempty"`
	DownloadLocation string `json:"downloadLocation"`
	FilesAnalyzed    bool   `json:"filesAnalyzed"`
	LicenseConcluded string `json:"licenseConcluded"`
	LicenseDeclared  string `json:"licenseDeclared"`
	CopyrightText    string `json:"copyrightText"`
	Checksum         string `json:"comment,omitempty"`
}

type relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

type spdxDocument struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      creationInfo   `json:"creationInfo"`
	Packages          []spdxPackage  `json:"packages"`
	Relationships     []relationship `json:"relationships"`
}

type creationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

func main() {
	outputDir := flag.String("output", "dist/release-evidence", "artifact output directory")
	flag.Parse()
	if flag.NArg() != 0 {
		fatalf("unexpected arguments: %s", strings.Join(flag.Args(), " "))
	}
	root, err := commandOutput("", "git", "rev-parse", "--show-toplevel")
	if err != nil {
		fatalf("find repository root: %v", err)
	}
	dir := *outputDir
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(root, dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fatalf("create output directory: %v", err)
	}

	hashes, treeDigest, err := sourceHashes(root)
	if err != nil {
		fatalf("hash source tree: %v", err)
	}
	modules, err := listModules(root)
	if err != nil {
		fatalf("list modules: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if epoch := os.Getenv("SOURCE_DATE_EPOCH"); epoch != "" {
		var seconds int64
		if _, err := fmt.Sscan(epoch, &seconds); err != nil {
			fatalf("invalid SOURCE_DATE_EPOCH: %v", err)
		}
		now = time.Unix(seconds, 0).UTC()
	}
	writeJSON(filepath.Join(dir, "source-hashes.json"), map[string]any{"algorithm": "SHA-256", "tree_digest": treeDigest, "files": hashes})
	writeJSON(filepath.Join(dir, "toolchain.json"), map[string]any{"go": runtime.Version(), "os": runtime.GOOS, "architecture": runtime.GOARCH, "source_date_epoch": os.Getenv("SOURCE_DATE_EPOCH")})
	writeJSON(filepath.Join(dir, "sbom.spdx.json"), makeSPDX(modules, treeDigest, now))

	report, err := analyzer.Scan(root, []string{"./..."})
	if err != nil {
		fatalf("analyze repository: %v", err)
	}
	file, err := os.Create(filepath.Join(dir, "analysis.sarif"))
	if err != nil {
		fatalf("create SARIF: %v", err)
	}
	if err := output.SARIF(file, report); err != nil {
		file.Close()
		fatalf("write SARIF: %v", err)
	}
	if err := file.Close(); err != nil {
		fatalf("close SARIF: %v", err)
	}
}

func makeSPDX(modules []module, digest string, now time.Time) spdxDocument {
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })
	packages := make([]spdxPackage, 0, len(modules))
	relationships := make([]relationship, 0, 1)
	for i, item := range modules {
		id := fmt.Sprintf("SPDXRef-Package-%d", i+1)
		version, location, sum := item.Version, "NOASSERTION", item.Sum
		if item.Replace != nil {
			version, sum = item.Replace.Version, item.Replace.Sum
			if item.Replace.Path != "" && item.Replace.Version != "" {
				location = "https://proxy.golang.org/" + item.Replace.Path + "/@v/" + item.Replace.Version + ".zip"
			}
		} else if !item.Main {
			location = "https://proxy.golang.org/" + item.Path + "/@v/" + item.Version + ".zip"
		}
		packages = append(packages, spdxPackage{Name: item.Path, SPDXID: id, VersionInfo: version, DownloadLocation: location, FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION", Checksum: "Go module sum: " + sum})
		if item.Main {
			relationships = append(relationships, relationship{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: id})
		}
	}
	return spdxDocument{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: "gnark-safety", DocumentNamespace: "https://auditinfra.io/spdx/gnark-safety/" + digest, CreationInfo: creationInfo{Created: now.Format(time.RFC3339), Creators: []string{"Tool: github.com/auditinfra-io/gnark-safety/cmd/release-evidence"}}, Packages: packages, Relationships: relationships}
}

func listModules(root string) ([]module, error) {
	contents, err := commandBytes(root, "go", "list", "-m", "-json", "all")
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	var modules []module
	for {
		var item module
		if err := decoder.Decode(&item); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		modules = append(modules, item)
	}
	return modules, nil
}

func sourceHashes(root string) (map[string]string, string, error) {
	contents, err := commandBytes(root, "git", "ls-files", "-z")
	if err != nil {
		return nil, "", err
	}
	result := map[string]string{}
	var binding strings.Builder
	names := strings.Split(string(contents), "\x00")
	sort.Strings(names)
	for _, name := range names {
		if name == "" {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return nil, "", err
		}
		digest := sha256.Sum256(contents)
		encoded := hex.EncodeToString(digest[:])
		result[filepath.ToSlash(name)] = encoded
		binding.WriteString(filepath.ToSlash(name) + "\x00" + encoded + "\n")
	}
	tree := sha256.Sum256([]byte(binding.String()))
	return result, hex.EncodeToString(tree[:]), nil
}

func writeJSON(path string, value any) {
	contents, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fatalf("encode %s: %v", path, err)
	}
	contents = append(contents, '\n')
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		fatalf("write %s: %v", path, err)
	}
}

func commandOutput(dir, name string, args ...string) (string, error) {
	contents, err := commandBytes(dir, name, args...)
	return strings.TrimSpace(string(contents)), err
}

func commandBytes(dir, name string, args ...string) ([]byte, error) {
	command := exec.Command(name, args...)
	command.Dir = dir
	contents, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, contents)
	}
	return contents, nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
