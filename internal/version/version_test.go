package version

import (
	"runtime/debug"
	"testing"
)

func TestFromBuildInfo(t *testing.T) {
	for _, tc := range []struct {
		name string
		info debug.BuildInfo
		want string
	}{
		{"tagged install", debug.BuildInfo{Main: debug.Module{Path: ModulePath, Version: "v0.1.0"}}, "v0.1.0"},
		{"local build", debug.BuildInfo{Main: debug.Module{Path: ModulePath, Version: "(devel)"}}, "devel"},
		{"library dependency", debug.BuildInfo{Main: debug.Module{Path: "example.com/host", Version: "v9.9.9"}, Deps: []*debug.Module{{Path: ModulePath, Version: "v0.2.0"}}}, "v0.2.0"},
		{"replaced dependency", debug.BuildInfo{Main: debug.Module{Path: "example.com/host"}, Deps: []*debug.Module{{Path: ModulePath, Version: "v0.2.0", Replace: &debug.Module{Path: "../gnark-safety"}}}}, "devel"},
		{"unrelated host", debug.BuildInfo{Main: debug.Module{Path: "example.com/host", Version: "v9.9.9"}}, "devel"},
	} {
		if got := fromBuildInfo(&tc.info); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestOverrideWins(t *testing.T) {
	previous := override
	t.Cleanup(func() { override = previous })
	override = "v1.2.3"
	if got := String(); got != "v1.2.3" {
		t.Fatalf("got %q, want override", got)
	}
}
