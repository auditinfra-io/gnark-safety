# Release evidence

Tagged releases publish `gnark-safety-release-evidence.tar.gz`. The bundle is
generated from the tagged source by `.github/workflows/release-evidence.yml`
and contains:

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
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
  go run ./cmd/release-evidence --output dist/release-evidence
(cd dist/release-evidence && \
  sha256sum analysis.sarif sbom.spdx.json source-hashes.json \
    test-output.txt toolchain.json > SHA256SUMS)
```

Compare the source tree digest, module inventory, analyzer report, toolchain,
and individual checksums. Exact proof bytes and test logs need not be identical
because proof generation and test timing may use randomness; semantic test
results must agree.

## Tagging and verification

Maintainers should create signed annotated tags and push the tag only after CI
passes:

```bash
git tag -s vX.Y.Z -m "gnark-safety vX.Y.Z"
git tag -v vX.Y.Z
git push origin vX.Y.Z
```

Consumers must verify the tag with a maintainer key obtained through an
independent trusted channel. A successful GitHub Actions run and matching
checksums provide provenance evidence, not a substitute for signature or source
review. Monitor gnark's published advisory page and `gnark-announce` before
releasing; `govulncheck` cannot identify unpublished or semantic circuit flaws.
