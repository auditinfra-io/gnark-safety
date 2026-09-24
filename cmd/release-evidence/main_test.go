package main

import (
	"strings"
	"testing"
	"time"
)

func TestMakeSPDXDeterministicAndIncludesReplacement(t *testing.T) {
	modules := []module{
		{Path: "example.com/z", Version: "v1.0.0", Sum: "h1:z"},
		{Path: "example.com/a", Version: "v1.0.0", Main: true, Replace: &module{Path: "example.com/fork", Version: "v1.1.0", Sum: "h1:a"}},
	}
	document := makeSPDX(modules, "abc", time.Unix(0, 0).UTC())
	if document.SPDXVersion != "SPDX-2.3" || document.DocumentNamespace != "https://auditinfra.io/spdx/gnark-safety/abc" {
		t.Fatalf("unexpected document metadata: %#v", document)
	}
	if got := document.Packages[0]; got.Name != "example.com/a" || got.VersionInfo != "v1.1.0" || !strings.Contains(got.DownloadLocation, "example.com/fork") || !strings.Contains(got.Checksum, "h1:a") {
		t.Fatalf("replacement was not represented: %#v", got)
	}
	if len(document.Relationships) != 1 || document.Relationships[0].RelatedSPDXElement != document.Packages[0].SPDXID {
		t.Fatalf("main module is not described: %#v", document.Relationships)
	}
}
