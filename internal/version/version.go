// Package version reports the gnark-safety build identity.
package version

import "runtime/debug"

// ModulePath is this module's import path.
const ModulePath = "github.com/auditinfra-io/gnark-safety"

// override is set for release binaries with
// -ldflags "-X github.com/auditinfra-io/gnark-safety/internal/version.override=vX.Y.Z".
var override string

// String returns the release version for tagged builds and `go install
// ...@vX.Y.Z`, the VCS-derived pseudo-version for local builds when Go
// recorded one, and "devel" otherwise. When another program imports this
// module as a library, the version of the dependency is reported rather than
// the host program's.
func String() string {
	if override != "" {
		return override
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "devel"
	}
	return fromBuildInfo(info)
}

func fromBuildInfo(info *debug.BuildInfo) string {
	module := &info.Main
	if module.Path != ModulePath {
		module = nil
		for _, dep := range info.Deps {
			if dep.Path == ModulePath {
				module = dep
				if dep.Replace != nil {
					module = dep.Replace
				}
				break
			}
		}
	}
	if module == nil || module.Version == "" || module.Version == "(devel)" {
		return "devel"
	}
	return module.Version
}
