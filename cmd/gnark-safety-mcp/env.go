package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// passThrough lists the variables copied from this process's environment.
// They let the go command find itself, a home and temporary directory, and
// the network through a proxy. No Go variable is copied: a scanned
// repository's documentation, or the agent reading it, could otherwise talk
// the user into settings that change how packages load.
var passThrough = []string{
	"PATH", "PATHEXT", "HOME", "USER", "LOGNAME", "TMPDIR", "TMP", "TEMP",
	"SystemRoot", "SYSTEMROOT", "windir", "LOCALAPPDATA", "APPDATA", "USERPROFILE",
	"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
}

// carried lists the Go settings resolved once, at startup, from the user's
// own configuration (environment and go env file) in a neutral directory:
// where the caches live and how modules are fetched and verified.
var carried = []string{"GOPATH", "GOMODCACHE", "GOCACHE", "GOPROXY", "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOSUMDB"}

// forced pins everything else that could change what loading executes or
// reads. GOTOOLCHAIN=local keeps a scanned module's go or toolchain line from
// selecting, downloading, and running another Go toolchain. GOENV=off ignores
// the go env file; the settings it held that loading needs are carried above.
// GOFLAGS is emptied so no -toolexec, -overlay, or -mod=mod applies. GOWORK=off
// keeps a go.work file from pulling in directories outside the scanned root.
// CGO_ENABLED=0 keeps the C toolchain out of package loading.
var forced = map[string]string{
	"GOTOOLCHAIN": "local",
	"GOENV":       "off",
	"GOFLAGS":     "",
	"GOWORK":      "off",
	"CGO_ENABLED": "0",
	"GO111MODULE": "on",
}

// loadEnv builds the complete environment for every go command the server
// runs while loading packages.
func loadEnv(ctx context.Context) ([]string, error) {
	base := map[string]string{}
	for _, name := range passThrough {
		if value, ok := os.LookupEnv(name); ok {
			base[name] = value
		}
	}
	probe := map[string]string{}
	for name, value := range base {
		probe[name] = value
	}
	// The probe reads the user's go env file, so GOENV stays unset here, but
	// it never selects a toolchain or honors GOFLAGS.
	probe["GOTOOLCHAIN"], probe["GOFLAGS"], probe["GOWORK"] = "local", "", "off"
	cmd := exec.CommandContext(ctx, "go", append([]string{"env", "-json"}, carried...)...)
	cmd.Dir = os.TempDir()
	cmd.Env = envList(probe)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("resolve Go settings with go env: %w", err)
	}
	var settings map[string]string
	if err := json.Unmarshal(out, &settings); err != nil {
		return nil, fmt.Errorf("parse go env output: %w", err)
	}
	for _, name := range carried {
		if value := settings[name]; value != "" {
			base[name] = value
		}
	}
	for name, value := range forced {
		base[name] = value
	}
	return envList(base), nil
}

func envList(m map[string]string) []string {
	list := make([]string, 0, len(m))
	for name, value := range m {
		list = append(list, name+"="+value)
	}
	sort.Strings(list)
	return list
}

// envValue returns the value of name in env, or "" if absent.
func envValue(env []string, name string) string {
	for _, entry := range env {
		if key, value, ok := strings.Cut(entry, "="); ok && key == name {
			return value
		}
	}
	return ""
}
