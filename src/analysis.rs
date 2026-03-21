use std::collections::{BTreeMap, HashMap};

use crate::dtcg::TypedValue;
use crate::provenance::{AuthoredValue, TokenProvenance};
use crate::resolver::Input;
use premath_admissibility::EntryOps;

//──────────────────────────────────────────────────────────────────────────────
// Val⊥ (consistency semilattice)
//──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValBot<T> {
    Consistent(T),
    Conflict(Vec<T>),
}

impl<T: PartialEq + Clone> ValBot<T> {
    pub fn merge(a: ValBot<T>, b: ValBot<T>) -> ValBot<T> {
        match (a, b) {
            (ValBot::Conflict(xs), _) => ValBot::Conflict(xs),
            (_, ValBot::Conflict(ys)) => ValBot::Conflict(ys),
            (ValBot::Consistent(x), ValBot::Consistent(y)) => {
                if x == y {
                    ValBot::Consistent(x)
                } else {
                    ValBot::Conflict(vec![x, y])
                }
            }
        }
    }
}

//──────────────────────────────────────────────────────────────────────────────
// premath-admissibility adapters
//──────────────────────────────────────────────────────────────────────────────

pub type PartialAssignment = premath_admissibility::PartialAssignment<AuthoredValue>;
pub type KanDiag = premath_admissibility::KanDiag<AuthoredValue, TypedValue>;
pub type BcViolation = premath_admissibility::BcViolation<TypedValue, TokenProvenance>;
pub type StabilityFailureKind = premath_admissibility::StabilityFailureKind;
pub type StabilityFailure = premath_admissibility::StabilityFailure<TokenProvenance>;
pub type LocalityFailureKind = premath_admissibility::LocalityFailureKind;
pub type LocalityFailure = premath_admissibility::LocalityFailure<TokenProvenance>;
pub type OrthogonalityOverlap = premath_admissibility::OrthogonalityOverlap;

impl EntryOps<TypedValue, TokenProvenance> for AuthoredValue {
    fn value_key(&self) -> TypedValue {
        TypedValue {
            ty: self.ty,
            value: self.value.clone(),
        }
    }

    fn source_key(&self) -> TokenProvenance {
        self.provenance.clone()
    }
}

/// Canonical context-key encoding used by the analysis layer.
///
/// Note: this matches the TS prototype: keys are sorted by axis name.
pub fn context_key(input: &Input) -> String {
    premath_admissibility::context_key(input)
}

/// Fast Kan completion lookup.
///
/// Delegates to witness-producing `kan_diag` and drops witness payloads.
pub fn fast_kan_at(
    entries: &HashMap<String, AuthoredValue>,
    target: &Input,
) -> Option<ValBot<TypedValue>> {
    match premath_admissibility::kan_diag(entries, target) {
        premath_admissibility::KanDiag::Gap => None,
        premath_admissibility::KanDiag::Consistent { value, .. } => Some(ValBot::Consistent(value)),
        premath_admissibility::KanDiag::Conflict { candidates } => {
            let mut uniq: Vec<TypedValue> = Vec::new();
            for (_ctx, entry) in candidates {
                let tv = entry.value_key();
                if !uniq.iter().any(|u| u == &tv) {
                    uniq.push(tv);
                }
            }
            Some(ValBot::Conflict(uniq))
        }
    }
}

pub fn kan_diag(entries: &HashMap<String, AuthoredValue>, target: &Input) -> KanDiag {
    premath_admissibility::kan_diag(entries, target)
}

pub fn bc_violations(
    assignments: &[PartialAssignment],
    axes: &BTreeMap<String, Vec<String>>,
) -> Vec<BcViolation> {
    premath_admissibility::bc_violations(assignments, axes)
}

pub fn stability_failures(
    assignments: &[PartialAssignment],
    axes: &BTreeMap<String, Vec<String>>,
) -> Vec<StabilityFailure> {
    premath_admissibility::stability_failures(assignments, axes)
}

pub fn locality_failures(
    assignments: &[PartialAssignment],
    contexts: &[Input],
) -> Vec<LocalityFailure> {
    premath_admissibility::locality_failures(assignments, contexts)
}

pub fn orthogonality_overlaps(
    assignments: &[PartialAssignment],
    axes: &BTreeMap<String, Vec<String>>,
) -> Vec<OrthogonalityOverlap> {
    premath_admissibility::orthogonality_overlaps(assignments, axes)
}
