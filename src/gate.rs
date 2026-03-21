use std::collections::BTreeMap;

use crate::analysis::{locality_failures, stability_failures, PartialAssignment};
use crate::cert::CtcAnalysis;
use crate::provenance::TokenProvenance;
use crate::resolver::Input;

pub use premath_gate::{
    evaluate_admissibility, AdmissibilityInput, BcViolationInput, GateFailure, GateInputSource,
    GateResult, GateSource, GateWitnesses, KanConflictInput, KanGapInput, LocalityFailureInput,
    StabilityFailureInput, GATE_WITNESS_SCHEMA_VERSION,
};

fn gate_input_source_from_provenance(prov: &TokenProvenance) -> Option<GateInputSource> {
    let file_path = prov.file_path.clone().unwrap_or_default();
    let json_pointer = prov.json_pointer.clone().unwrap_or_default();
    let file_hash = prov.file_hash.clone().unwrap_or_default();
    if prov.source_id.is_empty() || file_path.is_empty() || json_pointer.is_empty() {
        return None;
    }
    Some(GateInputSource {
        source_id: prov.source_id.clone(),
        file_path,
        json_pointer,
        file_hash,
    })
}

fn gate_input_source_from_candidate(
    source_id: &str,
    file_path: &str,
    json_pointer: &str,
    file_hash: &str,
) -> GateInputSource {
    GateInputSource {
        source_id: source_id.to_string(),
        file_path: file_path.to_string(),
        json_pointer: json_pointer.to_string(),
        file_hash: file_hash.to_string(),
    }
}

/// Adapter from tbp analysis/certificate structures to the generic
/// admissibility evaluator housed in `premath-gate`.
pub fn evaluate_from_analysis(
    analysis: &CtcAnalysis,
    assignments: &[PartialAssignment],
    axes: &BTreeMap<String, Vec<String>>,
    contexts: &[Input],
) -> GateWitnesses {
    let stability_inputs = stability_failures(assignments, axes)
        .into_iter()
        .map(|w| StabilityFailureInput {
            token_path: w.token_path,
            context: w.context,
            axis_a: w.axis_a,
            value_a: w.value_a,
            axis_b: w.axis_b,
            value_b: w.value_b,
            kind: w.kind.as_str().to_string(),
            sources: w
                .sources
                .iter()
                .filter_map(gate_input_source_from_provenance)
                .collect(),
        })
        .collect();

    let locality_inputs = locality_failures(assignments, contexts)
        .into_iter()
        .map(|w| LocalityFailureInput {
            token_path: w.token_path,
            context: w.context,
            restricted_context: w.restricted_context,
            kind: w.kind.as_str().to_string(),
            sources: w
                .sources
                .iter()
                .filter_map(gate_input_source_from_provenance)
                .collect(),
        })
        .collect();

    let kan_gap_inputs = analysis
        .witnesses
        .gaps
        .iter()
        .map(|w| KanGapInput {
            witness_id: w.witness_id.clone(),
            token_path: w.token_path.clone(),
            target: w.target.clone(),
            authored_sources: w
                .authored_sources
                .iter()
                .map(|s| {
                    gate_input_source_from_candidate(
                        &s.source_id,
                        &s.file_path,
                        &s.json_pointer,
                        &s.file_hash,
                    )
                })
                .collect(),
        })
        .collect();

    let kan_conflict_inputs = analysis
        .witnesses
        .conflicts
        .iter()
        .map(|w| KanConflictInput {
            witness_id: w.witness_id.clone(),
            token_path: w.token_path.clone(),
            target: w.target.clone(),
            candidates: w
                .candidates
                .iter()
                .map(|s| {
                    gate_input_source_from_candidate(
                        &s.source_id,
                        &s.file_path,
                        &s.json_pointer,
                        &s.file_hash,
                    )
                })
                .collect(),
        })
        .collect();

    let bc_inputs = analysis
        .witnesses
        .bc_violations
        .iter()
        .map(|w| BcViolationInput {
            witness_id: w.witness_id.clone(),
            token_path: w.token_path.clone(),
            axis_a: w.axis_a.clone(),
            value_a: w.value_a.clone(),
            axis_b: w.axis_b.clone(),
            value_b: w.value_b.clone(),
            left_source: w
                .left_source
                .as_ref()
                .and_then(gate_input_source_from_provenance),
            right_source: w
                .right_source
                .as_ref()
                .and_then(gate_input_source_from_provenance),
        })
        .collect();

    evaluate_admissibility(AdmissibilityInput {
        stability_failures: stability_inputs,
        locality_failures: locality_inputs,
        kan_gaps: kan_gap_inputs,
        kan_conflicts: kan_conflict_inputs,
        bc_violations: bc_inputs,
    })
}
