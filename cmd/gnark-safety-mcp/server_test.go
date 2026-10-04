package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/auditinfra-io/gnark-safety/internal/rules"
	"github.com/auditinfra-io/gnark-safety/pkg/report"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	envOnce   sync.Once
	sharedEnv []string
	envErr    error
)

func testEnv(t *testing.T) []string {
	t.Helper()
	envOnce.Do(func() { sharedEnv, envErr = loadEnv(context.Background()) })
	if envErr != nil {
		t.Fatal(envErr)
	}
	return sharedEnv
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := resolveRoot("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// connect starts a server for root and returns a client session to it.
func connect(t *testing.T, root string, tweak ...func(*config)) *mcp.ClientSession {
	t.Helper()
	resolved, err := resolveRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config{root: resolved, env: testEnv(t), timeout: 2 * time.Minute, maxHints: 10000, maxOutputBytes: 16 << 20}
	for _, f := range tweak {
		f(&cfg)
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx := context.Background()
	serverSession, err := newMCPServer(cfg).Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { serverSession.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	return session
}

func call(t *testing.T, session *mcp.ClientSession, tool string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", tool, err)
	}
	return res
}

// decode reads the structured content of res into v.
func decode(t *testing.T, res *mcp.CallToolResult, v any) {
	t.Helper()
	data, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
}

func text(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// requireError checks res is a tool error with code and returns its body.
func requireError(t *testing.T, res *mcp.CallToolResult, code string) errorBody {
	t.Helper()
	if !res.IsError {
		t.Fatalf("want error %s, got success:\n%s", code, text(res))
	}
	var body toolError
	decode(t, res, &body)
	if body.Error.Code != code {
		t.Fatalf("want error code %s, got %q:\n%s", code, body.Error.Code, text(res))
	}
	if !strings.Contains(text(res), `"code":"`+code+`"`) {
		t.Fatalf("error code is not in the text content a client without structured content reads:\n%s", text(res))
	}
	return body.Error
}

func requireScan(t *testing.T, res *mcp.CallToolResult) scanResult {
	t.Helper()
	if res.IsError {
		t.Fatalf("scan failed:\n%s", text(res))
	}
	var result scanResult
	decode(t, res, &result)
	return result
}

// requireCoverageFields checks a successful scan states what it examined
// and on what terms.
func requireCoverageFields(t *testing.T, result scanResult) {
	t.Helper()
	c := result.Coverage
	if c.Packages == 0 || c.GnarkPackages == 0 || c.Files == 0 {
		t.Errorf("coverage not populated: %+v", c)
	}
	if result.Skipped == nil || len(result.Skipped) != 0 {
		t.Errorf("skipped must be present and empty on success: %+v", result.Skipped)
	}
	if len(result.Limitations) == 0 {
		t.Error("the report's limitations are missing")
	}
	if result.Field.Setting == "" || result.Field.Claim == "" {
		t.Errorf("field setting not reported: %+v", result.Field)
	}
	if result.Tool.Name != "gnark-safety" || result.Tool.Version == "" {
		t.Errorf("tool version missing: %+v", result.Tool)
	}
	var want []string
	for _, spec := range rules.All() {
		want = append(want, spec.ID)
	}
	if strings.Join(result.RulesRun, ",") != strings.Join(want, ",") {
		t.Errorf("rules_run = %v, want %v", result.RulesRun, want)
	}
	if result.Interpretation != interpretation {
		t.Errorf("interpretation missing: %q", result.Interpretation)
	}
}

func TestScanVulnerableCircuit(t *testing.T) {
	session := connect(t, "../..")
	result := requireScan(t, call(t, session, "scan", map[string]any{"patterns": []string{"./examples/divmod"}, "include_examples": true}))
	requireCoverageFields(t, result)
	if result.Gate.Result != "fails" || result.Gate.FailOn != "high" || result.Gate.FindingsAtOrOver != 1 {
		t.Errorf("gate = %+v, want fails at high with 1 finding", result.Gate)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %+v, want one", result.Findings)
	}
	f := result.Findings[0]
	if f.RuleID != rules.HintRelationIncomplete || f.Severity != report.SeverityHigh || f.File != "examples/divmod/circuits.go" || f.Line != 44 || f.Function != "(*VulnerableCircuit).Define" {
		t.Errorf("finding = %+v, want the high GNARK_HINT_RELATION_INCOMPLETE at circuits.go:44 in VulnerableCircuit", f)
	}
	if result.Field.Setting != "unknown" || !strings.Contains(result.Field.Claim, "no field-safety claim") {
		t.Errorf("field = %+v, want unknown with no field-safety claim", result.Field)
	}
}

func TestScanCorrectedCircuit(t *testing.T) {
	session := connect(t, "../..")
	result := requireScan(t, call(t, session, "scan", map[string]any{"patterns": []string{"./cmd/gnark-safety-mcp/testdata/corrected"}}))
	requireCoverageFields(t, result)
	if len(result.Findings) != 0 || result.Gate.Result != "passes" {
		t.Errorf("corrected circuit: findings %+v, gate %+v; want none and passes", result.Findings, result.Gate)
	}
	if result.HintCalls != 1 || result.QuotientRemainderShape != 1 {
		t.Errorf("hint calls %d (%d in shape), want 1 (1): a clean result must show the rule had something to check", result.HintCalls, result.QuotientRemainderShape)
	}
	// The corrected circuit in examples/divmod shares a package with the
	// vulnerable one; its own call site is not reported.
	divmod := requireScan(t, call(t, session, "scan", map[string]any{"patterns": []string{"./examples/divmod"}, "include_examples": true}))
	for _, f := range divmod.Findings {
		if strings.Contains(f.Function, "CorrectedCircuit") {
			t.Errorf("CorrectedCircuit is reported: %+v", f)
		}
	}
}

func TestNoGnarkPackagesIsAnError(t *testing.T) {
	session := connect(t, "../..")
	for _, tool := range []string{"scan", "inventory"} {
		res := call(t, session, tool, map[string]any{"patterns": []string{"./cmd/gnark-safety-mcp/testdata/nognark"}})
		body := requireError(t, res, "no_gnark_packages")
		if body.Coverage == nil || body.Coverage.Packages != 1 || body.Coverage.GnarkPackages != 0 {
			t.Errorf("%s: coverage in error = %+v, want 1 package, 0 importing gnark", tool, body.Coverage)
		}
		if res.StructuredContent == nil || strings.Contains(text(res), `"findings"`) {
			t.Errorf("%s: an empty scan must carry no findings list that could read as clean:\n%s", tool, text(res))
		}
	}
}

func TestPackageThatFailsToTypeCheckIsAnError(t *testing.T) {
	session := connect(t, "../..")
	for _, patterns := range [][]string{
		{"./cmd/gnark-safety-mcp/testdata/broken"},
		// One good package does not make a partial scan acceptable.
		{"./cmd/gnark-safety-mcp/testdata/corrected", "./cmd/gnark-safety-mcp/testdata/broken"},
	} {
		body := requireError(t, call(t, session, "scan", map[string]any{"patterns": patterns}), "packages_failed_to_load")
		if len(body.Packages) != 1 || !strings.HasSuffix(body.Packages[0].Package, "testdata/broken") || len(body.Packages[0].Errors) == 0 {
			t.Errorf("patterns %v: packages = %+v, want the broken package named with its errors", patterns, body.Packages)
		}
	}
}

// TestToolchainDirectiveDoesNotSwitch scans a module whose go.mod names
// go1.99.0, which does not exist. Under GOTOOLCHAIN=auto the go command
// tries to download and run it; the server's environment must keep the local
// toolchain, so the scan reaches the analyzer and fails only because the
// module has no gnark code.
func TestToolchainDirectiveDoesNotSwitch(t *testing.T) {
	fixture, err := filepath.Abs("testdata/toolchainmod")
	if err != nil {
		t.Fatal(err)
	}
	env := testEnv(t)
	goVersion := func(env []string) (string, error) {
		cmd := exec.Command("go", "env", "GOVERSION")
		cmd.Dir, cmd.Env = fixture, env
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	// Control: the fixture really does request a switch.
	auto := append(append([]string{}, env...), "GOTOOLCHAIN=auto")
	if out, err := goVersion(auto); err == nil || !strings.Contains(out, "go1.99.0") {
		t.Fatalf("control: under GOTOOLCHAIN=auto the fixture should try go1.99.0, got %q, %v", out, err)
	}
	if got := envValue(env, "GOTOOLCHAIN"); got != "local" {
		t.Fatalf("server environment has GOTOOLCHAIN=%q", got)
	}
	got, err := goVersion(env)
	if err != nil || strings.Contains(got, "go1.99.0") || !strings.HasPrefix(got, "go1.") {
		t.Fatalf("go env GOVERSION in the fixture with the server environment = %q, %v; want the local toolchain", got, err)
	}
	// The same through a scan, even with the caller's environment asking for
	// auto: the server environment is used, not the process's.
	t.Setenv("GOTOOLCHAIN", "auto")
	t.Setenv("GOFLAGS", "-toolexec=/bin/false")
	body := requireError(t, call(t, connect(t, fixture), "scan", map[string]any{"patterns": []string{"./..."}}), "no_gnark_packages")
	if strings.Contains(body.Message, "go1.99.0") || strings.Contains(body.Message, "toolchain") {
		t.Errorf("scan mentions the requested toolchain: %s", body.Message)
	}
}

func TestEnvironmentIsFixed(t *testing.T) {
	t.Setenv("GOFLAGS", "-toolexec=/bin/false")
	t.Setenv("GOTOOLCHAIN", "auto")
	t.Setenv("GOINSECURE", "*")
	t.Setenv("GOEXPERIMENT", "boringcrypto")
	env, err := loadEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"GOTOOLCHAIN": "local", "GOFLAGS": "", "GOWORK": "off", "GOENV": "off", "CGO_ENABLED": "0", "GOINSECURE": "", "GOEXPERIMENT": ""}
	for name, value := range want {
		if got := envValue(env, name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
	for _, entry := range env {
		if strings.HasPrefix(entry, "GOINSECURE=") || strings.HasPrefix(entry, "GOEXPERIMENT=") {
			t.Errorf("caller's %s leaked into the loading environment", entry)
		}
	}
	if envValue(env, "GOMODCACHE") == "" {
		t.Error("GOMODCACHE was not carried from the user's settings")
	}
}

func TestDowngradeFlagsAreNotArguments(t *testing.T) {
	session := connect(t, "../..")
	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools.Tools {
		schema, _ := json.Marshal(tool.InputSchema)
		for _, flag := range []string{"allow_empty", "allow-empty", "allow_partial", "allow-partial", "allowEmpty", "allowPartial"} {
			if strings.Contains(string(schema), flag) {
				t.Errorf("%s accepts %s", tool.Name, flag)
			}
		}
	}
	for _, tool := range []string{"scan", "inventory"} {
		for _, flag := range []string{"allow_empty", "allow-empty", "allow_partial", "allow-partial"} {
			res := call(t, session, tool, map[string]any{"patterns": []string{"./cmd/gnark-safety-mcp/testdata/nognark"}, flag: true})
			if !res.IsError || strings.Contains(text(res), `"coverage"`) {
				t.Errorf("%s with %s was not rejected before scanning:\n%s", tool, flag, text(res))
			}
		}
	}
}

func TestPathsStayBelowRoot(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "x.go"), []byte("package x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, path)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, path), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/m\n\ngo 1.21\n")
	write("a/a.go", "package a\n")
	session := connect(t, root)
	for _, pattern := range []string{"../..", "./../x", "/etc", "github.com/consensys/gnark/frontend", "std", "./a/.../b", "-toolexec=x"} {
		requireError(t, call(t, session, "scan", map[string]any{"patterns": []string{pattern}}), "invalid_arguments")
	}
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	requireError(t, call(t, session, "scan", map[string]any{"patterns": []string{"./escape"}}), "path_outside_root")
	requireError(t, call(t, session, "scan", map[string]any{"patterns": []string{"./..."}}), "path_outside_root")
	if err := os.Remove(filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "x.go"), filepath.Join(root, "a", "linked.go")); err != nil {
		t.Fatal(err)
	}
	requireError(t, call(t, session, "scan", map[string]any{"patterns": []string{"./a"}}), "path_outside_root")
	if err := os.Remove(filepath.Join(root, "a", "linked.go")); err != nil {
		t.Fatal(err)
	}
	write("go.mod", "module example.com/m\n\ngo 1.21\n\nreplace example.com/dep => "+outside+"\n")
	requireError(t, call(t, session, "scan", map[string]any{"patterns": []string{"./a"}}), "path_outside_root")
}

func TestOutputLimitTruncationIsReported(t *testing.T) {
	session := connect(t, "../..")
	args := map[string]any{"patterns": []string{"./examples/divmod"}, "include_examples": true}
	full := call(t, session, "scan", args)
	size := len(text(full))
	limited := connect(t, "../..", func(c *config) { c.maxOutputBytes = size - 1 })
	result := requireScan(t, call(t, limited, "scan", args))
	if result.Truncated == nil || result.Truncated.FindingsTotal != 1 || result.Truncated.FindingsReturned != 0 || result.Truncated.Reason == "" {
		t.Fatalf("truncation not reported: %+v", result.Truncated)
	}
	if result.Gate.Result != "fails" {
		t.Errorf("gate must count findings that were cut: %+v", result.Gate)
	}
	tiny := connect(t, "../..", func(c *config) { c.maxOutputBytes = 100 })
	requireError(t, call(t, tiny, "scan", args), "output_limit_exceeded")
}

func TestRuleTools(t *testing.T) {
	session := connect(t, "../..")
	res := call(t, session, "list_rules", nil)
	var list rulesResult
	decode(t, res, &list)
	all := rules.All()
	if len(list.Rules) != len(all) {
		t.Fatalf("list_rules returned %d rules, the registry has %d", len(list.Rules), len(all))
	}
	for i, spec := range all {
		if list.Rules[i].ID != spec.ID {
			t.Errorf("rule %d = %s, want %s", i, list.Rules[i].ID, spec.ID)
		}
	}
	var explained explainResult
	decode(t, call(t, session, "explain_rule", map[string]any{"rule_id": rules.HintRelationIncomplete}), &explained)
	spec, _ := rules.Lookup(rules.HintRelationIncomplete)
	if explained.ID != spec.ID || explained.Description != spec.Description || explained.WhereItStop != spec.Limitations {
		t.Errorf("explain_rule = %+v", explained)
	}
	requireError(t, call(t, session, "explain_rule", map[string]any{"rule_id": "GNARK_NOT_A_RULE"}), "unknown_rule")
}

func TestInventory(t *testing.T) {
	var result inventoryResult
	res := call(t, connect(t, "../.."), "inventory", map[string]any{"patterns": []string{"./examples/divmod"}})
	if res.IsError {
		t.Fatal(text(res))
	}
	decode(t, res, &result)
	if result.HintsTotal != 1 || len(result.Hints) != 1 || result.Hints[0].Function != "constrainDivision" || result.Coverage.GnarkPackages != 1 {
		t.Errorf("inventory = %+v", result)
	}
}

func TestScanDescriptionCarriesTheCaveat(t *testing.T) {
	tools, err := connect(t, "../..").ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range tools.Tools {
		if !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s is not marked read-only", tool.Name)
		}
		if tool.Name == "scan" {
			found = true
			for _, want := range []string{interpretation, "docs/untrusted-scanning.md", "no_gnark_packages", "packages_failed_to_load"} {
				if !strings.Contains(tool.Description, want) {
					t.Errorf("scan description lacks %q", want)
				}
			}
		}
	}
	if !found {
		t.Fatal("no scan tool")
	}
}

// TestStdio runs the built binary as a client would: over stdin and stdout.
func TestStdio(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "gnark-safety-mcp")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	session, err := client.Connect(context.Background(), &mcp.CommandTransport{Command: exec.Command(bin, "--root", repoRoot(t))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	if strings.Join(names, ",") != "explain_rule,inventory,list_rules,scan" {
		t.Errorf("tools = %v", names)
	}
	res := call(t, session, "scan", map[string]any{"patterns": []string{"./examples/divmod"}, "include_examples": true})
	if result := requireScan(t, res); result.Gate.Result != "fails" {
		t.Errorf("stdio scan gate = %+v", result.Gate)
	}
}
