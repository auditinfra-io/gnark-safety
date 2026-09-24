# Security policy

## Supported versions

This research project is pre-1.0. Security fixes are made on the default branch
and are not backported. Users should reproduce a report against the latest
commit before submitting it.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability in this repository or
for a previously undisclosed issue in gnark. Use GitHub's **Report a
vulnerability** button under the repository's Security tab to start a private
advisory. Include:

- the affected commit and Go/toolchain version;
- a minimal circuit and witness, if applicable;
- the expected invariant and the observed solver or verifier result;
- whether the result reproduces with an adversarial `solver.OverrideHint`;
- the backend, curve, and exact commands used; and
- an assessment of disclosure urgency and known downstream exposure.

If the report concerns gnark itself rather than this repository, follow
[gnark's security policy](https://github.com/Consensys/gnark/blob/cfc7b2f907cc4212ec152077e022c6d0b4805759/SECURITY.md).
Do not send an upstream zero-knowledge vulnerability only to this project.

## Scope

The intentionally vulnerable circuit is an educational fixture, so acceptance
of its documented noncanonical remainder is not a reportable vulnerability.
Unexpected acceptance by `CorrectedCircuit`, a false negative that contradicts
a documented analyzer rule, unsafe handling of untrusted source trees, or a
dependency vulnerability with a reachable impact is in scope.

Reports will be acknowledged as project maintainers are available. No bounty,
response deadline, or embargo duration is promised.
