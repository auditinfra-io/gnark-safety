# Security research and robustness roadmap

This review uses the audit reports and security material published in the
gnark v0.16.3 repository. Links are pinned to the same upstream commit as this
project's dependency review, so the evidence does not drift. The reports audit
gnark, gnark-crypto, or particular integrations—not this repository. Their
findings are therefore design input, not evidence that this fixture has those
vulnerabilities.

## Sources reviewed

| Source | Relevant lesson for this project |
|---|---|
| [ZKSecurity, gnark standard library (May 2024)](https://github.com/Consensys/gnark/blob/cfc7b2f907cc4212ec152077e022c6d0b4805759/audits/2024-05%20-%20zksecurity%20-%20gnark%20std.pdf) | Findings include missing constraints, incomplete recomposition, underflow, and values treated as reduced when they were not. Track range, canonicality, and representation invariants separately rather than equating “used in a constraint” with “fully constrained.” |
| [Least Authority, arithmetic and GKR (September 2024)](https://github.com/Consensys/gnark/blob/cfc7b2f907cc4212ec152077e022c6d0b4805759/audits/2024-09%20-%20Least%20Authority%20-%20arithm%20and%20GKR.pdf) | Keep security assumptions, field semantics, and unsupported behavior explicit; test the boundaries between APIs and proof-system components. |
| [Kudelski Security, gnark-crypto (October 2022)](https://github.com/Consensys/gnark/blob/cfc7b2f907cc4212ec152077e022c6d0b4805759/audits/2022-10%20-%20Kudelski%20-%20gnark-crypto.pdf) | Dependency assurance is part of circuit assurance. Pin and continuously scan the exact cryptographic stack used by tests. |
| [gnark security policy](https://github.com/Consensys/gnark/blob/cfc7b2f907cc4212ec152077e022c6d0b4805759/SECURITY.md) and [published advisory index](https://github.com/Consensys/gnark/security/advisories) | Maintain a private reporting path and monitor upstream announcements; do not disclose suspected upstream issues in a public issue first. |
| [gnark testing package documentation](https://github.com/Consensys/gnark/blob/cfc7b2f907cc4212ec152077e022c6d0b4805759/test/assert.go) and [hint documentation](https://github.com/Consensys/gnark/blob/cfc7b2f907cc4212ec152077e022c6d0b4805759/constraint/solver/hint.go) | Cross-check valid witnesses across curves/backends and treat every hint output as untrusted advice requiring constraints. |

## Prioritized improvements

### 1. Mutate hint outputs systematically

**Implemented:** the test suite now keeps an explicit registry for every direct
source `NewHint` call and fails if a call lacks a mutation suite. The first
suite establishes honest output, mutates each output independently, and covers
reconstruction-preserving noncanonical values, negative integers, declared-bit
overflow, and the native field-modulus boundary. Both vulnerable and corrected
circuits are checked with identical public inputs and replacement advice.

The existing hand-written matrix is a strong regression test, but it exercises
selected tuples. The reusable mutation registry expands that matrix while
holding public inputs fixed. It classifies:

- unconstrained output changes;
- reconstruction-preserving but noncanonical changes;
- negative values represented as field elements;
- values outside the declared bit width; and
- boundary cases at zero, one, the maximum declared integer, and the field
  modulus.

The coverage guard intentionally scans local, non-test Go syntax so that it is
fast and hermetic. The type-aware inventory remains authoritative for CLI
reports. A future scanner mode could emit a test skeleton from that inventory.
This directly generalizes the repository's current `OverrideHint` technique
without pretending static analysis alone proves soundness.

### 2. Model invariants independently

**Implemented for the recognized quotient/remainder shape:** JSON schema 1.1
now reports a status and supporting evidence for each invariant and each hint
output. Unsupported shapes remain `unknown`, while a recognized absent
canonicality constraint is `missing`. The analyzer also records the bounded
reconstruction maximum but does not claim field safety because callers select
the compilation field outside the analyzed function. Callers can now provide
BN254 or BLS12-381 explicitly to obtain a modulus comparison.

The analyzer reports separate facts for each hint output:

1. **participation**—the output reaches a constraint;
2. **range**—the intended integer or limb bounds are enforced;
3. **relation**—the output is tied to its inputs;
4. **canonicality**—alternate representations are excluded; and
5. **field safety**—integer equalities cannot be satisfied only through modular
   wraparound.

This taxonomy follows the recurring audit themes while avoiding an unsafe
binary “constrained/unconstrained” conclusion. Findings should preserve the
supporting expression and bound calculation in machine-readable evidence.

### 3. Add interprocedural and path-sensitive analysis

**Implemented for direct local helpers:** the analyzer builds a package-local
function index and recognizes unconditional `r < d` and constant-width
`ToBinary` constraints one helper call away. Conditional helper calls do not
count as coverage. A successful `return nil` before a constraint also prevents
that constraint from being classified as unconditional, while an error return
does not create a false positive because compilation cannot proceed on that
path.

The next implementation milestone should extend these summaries through deeper
acyclic call graphs. Unsupported external or dynamic dispatch, closures, and
recursion remain explicit top-level limitations rather than silently lowering
confidence. Regression fixtures cover assertions in one branch, after a
successful early return, and in unconditional versus conditional helper calls.
An SSA-based pass is a candidate for deeper def-use and phi-node tracking, but
must preserve stable source locations and the current conservative fallbacks.

### 4. Differential-test specifications and proof systems

**Implemented for the demonstration relation:** an ordinary integer predicate
is the independent semantic oracle. All 65,280 valid 8-bit `(n,d)` pairs are
checked against the honest hint, including a noncanonical alternative whenever
the quotient is positive. A boundary/adversarial corpus then compares the
corrected circuit with the predicate under both R1CS and sparse R1CS on BN254
and BLS12-381. Finally, valid end-to-end proofs are generated and verified with
Groth16 and PLONK on both curves. PLONK's test-only SRS is generated with
gnark's `unsafekzg` package and is not production ceremony guidance.

For each demonstration relation, keep an ordinary-Go reference predicate and
compare it with circuit acceptance over bounded exhaustive domains where
feasible. Then run a smaller corpus through constraint solving and end-to-end
proof verification on every supported backend/curve combination. Solver-only
tests are faster, but proof tests catch setup, witness-publication, hint
registration, and verifier integration mistakes.

### 5. Make dependency and release evidence auditable

**Implemented:** tagged-release CI verifies the module cache, retains complete
test output, generates SPDX 2.3 and SARIF artifacts, binds all tracked sources
with SHA-256, records toolchain metadata, publishes artifact checksums, and
attaches the bundle to the GitHub release. The release guide documents clean
checkout reproduction, signed tags, checksum verification, the SBOM's license
limitations, and upstream advisory monitoring.

- Treat `go.mod` and `go.sum` as one reviewed change and run `go mod verify`.
- Keep GitHub Actions pinned by commit and let Dependabot propose reviewed
  updates for both Go modules and actions.
- Generate an SBOM and attach it, the analyzer SARIF, test output, source hashes,
  and toolchain metadata to tagged releases.
- Monitor the upstream advisory page and `gnark-announce`; `govulncheck` cannot
  find an unpublished advisory or a semantic circuit error.
- Sign release tags and document how generated evidence can be reproduced from
  a clean checkout.

### 6. Harden scanner operation on untrusted repositories

**Implemented at the application boundary:** package loading and AST traversal
now share a cancellation context, and the CLI enforces positive timeout,
hint-count, and rendered-output ceilings. Output is buffered within the limit
before a destination file is written. The untrusted-scanning guide specifies a
read-only mount, fixed toolchain, isolated caches, restricted networking,
non-root execution, and OS-level CPU/memory/process limits, while explicitly
stating that the built-in controls are not a sandbox.

Package loading invokes the Go toolchain and may download modules or execute
toolchain selection. Document that trust boundary prominently. For hosted use,
scan in a network-restricted, resource-limited container with a read-only source
mount, a controlled module proxy/cache, a fixed toolchain, and time/output
limits. Add cancellation and resource ceilings before presenting the CLI as a
service suitable for arbitrary repositories.

## Definition of done for the next milestone

A useful next release should build on the mutation registry with: (1) generated
test skeletons for newly discovered hints, (2) summaries for deeper acyclic
local call graphs, (3) additional invariant recognizers beyond the initial
relation shape, (4) a larger differential corpus for future relations, and (5)
independent reproduction of published release evidence. Until then,
reports must continue to state that absence of findings is not proof of circuit
soundness.
