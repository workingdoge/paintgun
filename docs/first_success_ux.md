# Paint First-Success UX Contract

This document defines the canonical first successful Paintgun experience for a new user.

It is not a quickstart walkthrough and it is not an implementation plan. It is the product contract that later install, docs, and witness-UX work should satisfy.

## Goal

A first-time user should be able to:

1. install `paint`
2. build one pack from a real resolver document
3. verify the emitted manifest
4. understand one intentional failure
5. fix that failure
6. rerun the same flow to green

The user should come away with three clear answers:

- what Paint does
- what it produced
- what to do when verification fails

## Consumer vs Contributor Boundary

This contract is consumer-facing.

Consumer success must not depend on understanding:

- `./premath`
- `jj` workspaces
- `bd`
- local repo bootstrapping details
- contributor-only CI wrappers

Contributor and maintainer complexity may still exist, but it must stay outside the first-success path. The public install path in [`docs/install.md`](install.md) and the future quickstart in `tbp-qnb.5` should be judged against that boundary.

## Canonical First-Success Path

The canonical path is a single-pack flow over one real example resolver.

Current reference assets:

- `examples/charter-steel/charter-steel.resolver.json`
- `examples/charter-steel/component-contracts.json`
- `examples/charter-steel/policy.json`

The intended user flow is:

1. Install `paint`.
2. Run `paint build ...` for one backend.
3. Inspect the emitted primary token artifact plus the verification bundle.
4. Run `paint verify ...` on the generated manifest.
5. If verification fails, use `paint explain ...` and/or the report artifacts to understand the failure.
6. Change authored input or policy.
7. Rebuild and reverify until the result is green.

That path should work without introducing multi-pack compose, signing policy, Storybook, or design-system consumers.

## Required Command Surfaces

The first-success path depends on these commands only:

- `paint build`
- `paint verify`
- `paint explain`

`compose`, `verify-compose`, `sign`, and `annotate-report` are important, but they are not part of the minimum first-success contract.

## Required Visible Outputs

After the first successful `build`, the user must be able to identify:

1. the primary emitted backend artifact
2. the manifest that should be verified
3. the witness/report artifact that explains findings
4. the authored inputs that were actually bound into the bundle

Minimum output categories:

- one primary token output
- one manifest
- one witness/report artifact
- one human-readable success/failure summary

The user should not need to infer which file matters by reading source code or internal docs.

## Required Failure Experience

The first failure in the onboarding path must be intentional and instructive, not accidental environment breakage.

That means:

- no panic backtraces
- no hidden dependency on missing local repo state
- no requirement to understand internal witness math before locating the authored cause

For the first-failure case, the user must be able to answer:

1. what failed
2. where it failed
3. why it failed at a high level
4. what concrete change would likely fix it

## Explain Contract

`paint explain` is the bridge from verifier output to action.

For first-success UX, `explain` must make these fields legible:

- user-facing finding family
- technical witness kind
- severity and fixability
- affected token path or component contract path
- authored source location or file/pointer blame when available
- high-level cause summary
- next-action guidance

The exact wording may evolve, but the path from finding to action must stay stable.

The stable family model for that presentation is defined in [`docs/witness_taxonomy.md`](witness_taxonomy.md).

## Machine vs Human Surfaces

The first-success path needs both:

- machine-readable verification artifacts for CI and later tooling
- human-readable summaries for first-time understanding

The user-facing contract is:

- JSON/report stability belongs to `docs/ci_contract.md` and `docs/backend_contract.md`
- human success/failure comprehension belongs here

Those surfaces should reinforce each other rather than compete.

## Scope Exclusions

This contract intentionally excludes:

- multi-pack compose onboarding
- signing-by-default flows
- package-manager distribution strategy beyond the chosen install surface
- Storybook, Figma, or editor integrations
- design-system schema authoring

Those belong to later issues in `tbp-qnb`.

## Acceptance Criteria For Follow-On Work

Later onboarding and witness issues should satisfy this contract if they produce:

- one supported install path that a consumer can follow without contributor lore
- one short single-pack walkthrough from build to verify
- one intentional failure with a clear remediation path
- one successful rerun after the fix

## Related Work

- `tbp-qnb.2` owns the public install path
- `tbp-qnb.3` owns the witness taxonomy/remediation model
- `tbp-qnb.4` owns action-oriented `explain` and report surfaces
- `tbp-qnb.5` owns the polished quickstart walkthrough that implements this contract
