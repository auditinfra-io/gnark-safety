# Releases and release evidence

Tagged releases publish prebuilt `gnark-safety` archives for Linux, macOS, and
Windows on amd64 and arm64, and `gnark-safety-release-evidence.tar.gz`. Both
are generated from the tagged source by
`.github/workflows/release-evidence.yml`. v0.1.0 has none of them: its tag
was cut before `CHANGELOG.md` had a 0.1.0 section, so the workflow stopped at
its preflight check. v0.1.1 is the first release with them.

Each archive (`gnark-safety_X.Y.Z_<os>_<arch>.tar.gz`, or `.zip` on Windows)
contains the binary, `LICENSE`, `README.md`, and `CHANGELOG.md`.
`scripts/build-release.sh` builds them reproducibly for a given Go toolchain:

- `-trimpath` and no cgo;
- no VCS stamping, since the version comes from the tag through `-ldflags`;
- archives with fixed timestamps, ownership, and entry order.

`gnark-safety --version` reports the tag.

The toolchain is the `toolchain` line in `go.mod` (Go 1.27.1), which the
release workflow installs; the `go` line (1.26.0, required by
`golang.org/x/tools` v0.50.0) is the minimum for `go install`. Building with the newest stable Go matters for prebuilt
binaries: the analyzer type-checks the standard library of the `go` command
on the user's `PATH`, and a type checker older than that release cannot load
it. A binary built with Go 1.27 scans code for Go 1.27 and earlier; with a
newer `go` command, it reports the mismatch and asks for a rebuild.

The evidence bundle contains:

- `gnark-safety-binaries.sha256`: SHA-256 checksums of every release archive;
- `sbom.spdx.json`: an SPDX 2.3 inventory of the selected Go module graph;
- `analysis.sarif`: the analyzer result for all repository packages;
- `source-hashes.json`: SHA-256 hashes of every tracked file and a deterministic
  digest over the path/hash pairs;
- `toolchain.json`: Go, operating-system, and architecture metadata;
- `test-output.txt`: verbose output from the complete test suite; and
- `SHA256SUMS`: checksums for all of the preceding artifacts.

The SPDX document records Go module sums as comments. It deliberately reports
dependency licenses as `NOASSERTION`; generating an inventory is not equivalent
to performing license or vulnerability analysis. The PLONK tests use a
test-only unsafe SRS and do not create production setup material.

## Reproduce locally

Start from a clean checkout of the tag with the pinned Go toolchain and a
reviewed module proxy/cache:

```bash
git status --porcelain # must be empty
go mod verify
mkdir -p dist/release-evidence
go test -count=1 -v ./... | tee dist/release-evidence/test-output.txt
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
bash scripts/build-release.sh vX.Y.Z dist/binaries
cp dist/binaries/gnark-safety-binaries.sha256 dist/release-evidence/
go run -ldflags "-X github.com/auditinfra-io/gnark-safety/internal/version.override=vX.Y.Z" \
  ./cmd/release-evidence --output dist/release-evidence
(cd dist/release-evidence && \
  sha256sum analysis.sarif gnark-safety-binaries.sha256 sbom.spdx.json \
    source-hashes.json test-output.txt toolchain.json > SHA256SUMS)
```

Compare the source tree digest, module inventory, analyzer report, toolchain,
and individual checksums. With the same Go toolchain, the archive checksums
must match the published `gnark-safety-binaries.sha256` exactly. Exact proof bytes and test logs need not be identical
because proof generation and test timing may use randomness; semantic test
results must agree.

## Cutting a release

1. Move the `[Unreleased]` notes in `CHANGELOG.md` under a new
   `## [X.Y.Z] - YYYY-MM-DD` heading and merge that change. The workflow's
   preflight (`scripts/release-preflight.sh`) refuses any tag without a
   non-empty section for its version.
2. Tag the merged commit as below. The version is taken from the tag, so there
   is no version string in the source to update.

## Tagging and verification

Release tags are plain (lightweight) git tags on the merged commit, and they
are not signed. Every release so far, v0.1.0 through v0.2.0, was tagged this
way. Tag only after CI passes on that commit:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

There is therefore no tag signature to verify. What a consumer can check:

- **The tag's commit.** `git ls-remote --tags https://github.com/auditinfra-io/gnark-safety`
  shows the commit each tag names. A lightweight tag can be moved by anyone
  with push access, so note the commit you reviewed or depend on, not only
  the tag name. The Go checksum database (`sum.golang.org`) records each
  version's content the first time it is fetched, and `go.sum` pins it in
  modules that depend on gnark-safety, so a moved tag fails verification in
  `go install` and `go get` rather than silently changing what they build.
- **The archives.** Check a downloaded archive against the published list:

  ```bash
  sha256sum --check --ignore-missing gnark-safety-binaries.sha256
  ```

  The list is published in the same GitHub release as the archives, and
  anyone who can edit the release can replace both, so a match shows the
  download is intact, not who produced it. Rebuilding from the tagged source
  with the same toolchain, as above, gives byte-identical archives and is the
  independent check.

Trust in a release therefore rests on the GitHub repository and its account,
a successful GitHub Actions run, matching checksums, and your own review of
the source; none of them is a maintainer signature. Monitor gnark's published
advisory page and `gnark-announce` before releasing; `govulncheck` cannot
identify unpublished or semantic circuit flaws.
