# Paint Witness Taxonomy And Remediation Model

This document defines the stable user-facing classification for Paint findings.

It exists so `explain`, reports, docs, and future live-consumer integrations can present findings in language a first-time user can act on, without erasing the underlying math or technical witness types.

## Scope

This is a product-language contract.

It does:

- define the stable user-facing finding families
- define default severity and fixability expectations
- map current technical witness kinds into those families

It does not:

- change the current witness JSON schemas
- rename existing technical witness kinds in machine-readable artifacts
- remove Kan / Beck-Chevalley / admissibility concepts from detailed explanations

## Model

Paint findings should be presented in two layers:

1. **User-facing family**
   The stable label a user sees first.
2. **Technical witness kind**
   The underlying emitted witness/report kind that preserves implementation and mathematical precision.

The rule is:

- family first for human comprehension
- technical kind second for precision, debugging, and contract continuity

Example shape:

- Family: `Ambiguous definition`
- Technical kind: `conflict`

## Stable Families

### 1. Missing definition

- Family ID: `missing-definition`
- Default severity: `error`
- Fixability: `direct`
- Meaning:
  Paint expected a value at a specific context, but no explicit winning definition exists.

Primary user action:

- author an explicit value in the intended winning layer or context

Maps from current technical kinds:

- `gap`
- admissibility source witness `kan_gap`

### 2. Ambiguous definition

- Family ID: `ambiguous-definition`
- Default severity: `error`
- Fixability: `direct`
- Meaning:
  Multiple authored definitions compete for the same token/context and Paint cannot treat the result as a clean explicit choice.

Primary user action:

- make the intended winner explicit
- remove or narrow competing definitions

Maps from current technical kinds:

- `conflict`
- `composeConflict`
- admissibility source witness `kan_conflict`

Notes:

- `composeConflict` is a scope variant of the same family, not a separate family.
- UI surfaces may render this as `Ambiguous definition (cross-pack)` when the conflict spans packs.

### 3. Order-dependent resolution

- Family ID: `order-dependent-resolution`
- Default severity: `error`
- Fixability: `guided`
- Meaning:
  The resolved result changes depending on evaluation order or composition order.

Primary user action:

- normalize authoring so the same result is produced regardless of traversal/composition order
- follow the fix guidance emitted by the witness when available

Maps from current technical kinds:

- `bcViolation`
- admissibility failure class `stability_failure`
- admissibility source witness `bc_violation`

Notes:

- Beck-Chevalley violations are the precise technical form today.
- `stability_failure` is the admissibility-layer rollup and should be presented to users in the same family unless a more specific subtype is introduced later.

### 4. Constraint failure

- Family ID: `constraint-failure`
- Default severity: `error`
- Fixability: `guided`
- Meaning:
  The authored system violates a required restriction or coverage rule even if a value can still be resolved technically.

Primary user action:

- repair the missing restriction, base definition, or required supporting definition

Maps from current technical kinds:

- admissibility failure class `locality_failure`
- admissibility source witness `locality_check`

Notes:

- This is intentionally a family at the admissibility layer.
- If later work adds more admissibility classes, they should either map here or introduce a new user-facing family explicitly.

### 5. Ownership overlap

- Family ID: `ownership-overlap`
- Default severity: `warn`
- Fixability: `review`
- Meaning:
  Multiple axes or domains appear to own the same token paths, which creates governance ambiguity even if it is not yet a blocking conflict.

Primary user action:

- partition ownership or make the overlap intentional and documented

Maps from current technical kinds:

- `orthogonality`

### 6. Inherited value

- Family ID: `inherited-value`
- Default severity: `info`
- Fixability: `trace`
- Meaning:
  The resolved value is inherited from another layer or context rather than defined explicitly here.

Primary user action:

- none if inheritance is intended
- otherwise author the value explicitly at the current location

Maps from current technical kinds:

- `inherited`

## Severity Contract

Default user-facing severities should mean:

- `error`
  - blocks clean verification or acceptance
  - should be treated as a required change unless explicitly allowlisted or accepted by policy
- `warn`
  - does not necessarily block the current build
  - should be reviewed because it signals future ambiguity or ownership debt
- `info`
  - explanatory only
  - useful for traceability and understanding, not a failure by itself

This document defines defaults, not hardcoded CLI formatting. A future surface may escalate or suppress presentation, but it should not silently change the family itself.

## Fixability Contract

Default fixability levels:

- `direct`
  - one obvious authored change should resolve the issue
- `guided`
  - a user can act, but likely needs remediation help from `explain`, docs, or source-local hints
- `review`
  - requires a design or ownership decision rather than a single mechanical edit
- `trace`
  - explanatory only; no change required unless the current inheritance is unwanted

## Mapping To Current Surfaces

### Explain

`paint explain` should present:

1. user-facing family
2. technical witness kind
3. severity
4. fixability
5. source location
6. remediation guidance

`tbp-qnb.4` implements that family-first presentation without removing the technical kind.

### Human-readable reports

`validation.txt` and the compose text report should present:

1. action summary by user-facing family
2. family-specific what-it-means language
3. source-local examples when available
4. concrete next-action guidance
5. technical summary sections after the user-facing framing

### JSON reports

Current report JSON uses technical kinds such as:

- `gap`
- `conflict`
- `inherited`
- `bcViolation`
- `orthogonality`

This issue does not change those machine-readable fields.

If future work adds user-facing family data to machine-readable reports, it should be additive and should not silently replace the current technical kind contract.

### Admissibility witnesses

Full-profile admissibility emits:

- result: `accepted` / `rejected`
- failure classes such as `locality_failure` and `stability_failure`
- source witness provenance such as `kan_gap`, `kan_conflict`, and `bc_violation`

For user-facing surfaces, admissibility should be explained through the family model above, while preserving the underlying failure class and law reference.

## Design Principles For Follow-On Work

Follow-on work should preserve these rules:

1. Do not make first-time users decode technical witness kinds before they see the family.
2. Do not throw away the mathematical language; keep it available as the detailed layer.
3. Do not fork separate taxonomies for pack, compose, and admissibility if one family model can cover them.
4. Do not change machine-readable technical kinds casually; user-facing family labels are the safer layer to evolve presentation.

## Related Work

- `tbp-qnb.4` should use this taxonomy to redesign `explain` and report wording
- `tbp-qnb.5` should use this taxonomy in the first intentional failure walkthrough
- future Storybook/docs/editor integrations should surface the family first and the technical kind second
