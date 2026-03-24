//! Single-pack composability analysis kernel.
//!
//! This crate evaluates authored-vs-derived coherence inside one resolver/token pack
//! (Kan gaps/conflicts, BC violations, orthogonality overlaps, witness assembly).
//! For cross-pack composition and conflict assembly, see `premath-compose`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConflictMode {
    Semantic,
    Normalized,
}

impl Default for ConflictMode {
    fn default() -> Self {
        ConflictMode::Semantic
    }
}

impl std::fmt::Display for ConflictMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConflictMode::Semantic => write!(f, "semantic"),
            ConflictMode::Normalized => write!(f, "normalized"),
        }
    }
}

pub const WITNESS_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub tokens: usize,
    pub contexts: usize,
    pub kan_gaps: usize,
    pub kan_conflicts: usize,
    pub kan_inherited: usize,
    pub bc_violations: usize,
    pub orthogonality_overlaps: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictCandidate {
    pub source_context: String,
    pub source_id: String,
    #[serde(rename = "resolutionLayerId")]
    pub resolution_layer_id: String,
    #[serde(rename = "resolutionRank")]
    pub resolution_rank: u64,
    #[serde(rename = "packId")]
    pub pack_id: String,
    #[serde(rename = "packVersion", skip_serializing_if = "Option::is_none")]
    pub pack_version: Option<String>,
    #[serde(rename = "packHash")]
    pub pack_hash: String,
    #[serde(rename = "filePath")]
    pub file_path: String,
    #[serde(rename = "fileHash")]
    pub file_hash: String,
    #[serde(rename = "jsonPointer")]
    pub json_pointer: String,
    pub value_json: String,
    pub value_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GapWitness {
    #[serde(rename = "witnessId")]
    pub witness_id: String,
    pub token_path: String,
    pub target: String,
    pub authored_sources: Vec<ConflictCandidate>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictWitness {
    #[serde(rename = "witnessId")]
    pub witness_id: String,
    pub token_path: String,
    pub target: String,
    pub candidates: Vec<ConflictCandidate>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InheritedWitness {
    #[serde(rename = "witnessId")]
    pub witness_id: String,
    pub token_path: String,
    pub target: String,
    pub inherited_from: Vec<String>,
    pub sources: Vec<ConflictCandidate>,
    pub resolved_value_json: String,
    pub resolved_value_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BcWitness<S> {
    #[serde(rename = "witnessId")]
    pub witness_id: String,
    pub token_path: String,
    pub axis_a: String,
    pub value_a: String,
    pub axis_b: String,
    pub value_b: String,

    pub left_value_json: String,
    pub right_value_json: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub left_source: Option<S>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub right_source: Option<S>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolver_value_json: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolver_source: Option<S>,

    pub fix: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OverlapWitness {
    #[serde(rename = "witnessId")]
    pub witness_id: String,
    pub axis_a: String,
    pub axis_b: String,
    pub overlap_token_paths: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalysisWitnesses<S> {
    #[serde(rename = "witnessSchema")]
    pub witness_schema: u32,
    #[serde(rename = "conflictMode", default)]
    pub conflict_mode: ConflictMode,
    #[serde(rename = "policyDigest", skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<String>,
    #[serde(rename = "normalizerVersion", skip_serializing_if = "Option::is_none")]
    pub normalizer_version: Option<String>,
    pub gaps: Vec<GapWitness>,
    pub conflicts: Vec<ConflictWitness>,
    pub inherited: Vec<InheritedWitness>,
    #[serde(rename = "bcViolations")]
    pub bc_violations: Vec<BcWitness<S>>,
    pub orthogonality: Vec<OverlapWitness>,
}

impl<S> AnalysisWitnesses<S> {
    pub fn validate_schema_version(&self) -> Result<(), String> {
        if self.witness_schema != WITNESS_SCHEMA_VERSION {
            return Err(format!(
                "unsupported pack witness schema version: expected {}, got {}",
                WITNESS_SCHEMA_VERSION, self.witness_schema
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Analysis<S> {
    pub summary: AnalysisSummary,
    pub witnesses: AnalysisWitnesses<S>,
}

fn witness_id(kind: &str, seed: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{kind}|{seed}").as_bytes());
    let digest = hasher.finalize();
    let hex = hex::encode(digest);
    format!("{kind}-{}", &hex[..16])
}

fn cmp_conflict_candidate(a: &ConflictCandidate, b: &ConflictCandidate) -> Ordering {
    a.source_context
        .cmp(&b.source_context)
        .then(a.resolution_rank.cmp(&b.resolution_rank))
        .then(a.source_id.cmp(&b.source_id))
        .then(a.file_path.cmp(&b.file_path))
        .then(a.json_pointer.cmp(&b.json_pointer))
        .then(a.value_digest.cmp(&b.value_digest))
}

/// Analyze composability witnesses over a prepared assignment/context surface.
///
/// This kernel is target-agnostic and operates over contextual assignments.
/// Callers provide mapping closures for:
/// - authored entries -> `ConflictCandidate`
/// - values -> canonical JSON string / digest
/// - optional resolver winner lookup for BC witnesses
pub fn analyze_assignments<E, V, S, FCand, FValueJson, FValueDigest, FResolverValue>(
    assignments: &[premath_admissibility::PartialAssignment<E>],
    contexts: &[premath_admissibility::Context],
    axes: &BTreeMap<String, Vec<String>>,
    conflict_mode: ConflictMode,
    policy_digest: Option<String>,
    normalizer_version: Option<String>,
    candidate_from_entry: FCand,
    value_to_json: FValueJson,
    value_digest: FValueDigest,
    resolver_value_json: FResolverValue,
) -> Analysis<S>
where
    E: premath_admissibility::EntryOps<V, S> + Clone,
    V: Clone + Eq,
    S: Clone,
    FCand: Fn(&str, &E) -> ConflictCandidate,
    FValueJson: Fn(&V) -> String,
    FValueDigest: Fn(&V) -> String,
    FResolverValue: Fn(&str, &str, &str, &str, &str) -> Option<String>,
{
    let mut gaps: Vec<GapWitness> = Vec::new();
    let mut conflicts: Vec<ConflictWitness> = Vec::new();
    let mut inherited: Vec<InheritedWitness> = Vec::new();
    let mut inherited_total: usize = 0;

    for asn in assignments {
        for ctx in contexts {
            let target_key = premath_admissibility::context_key(ctx);
            match premath_admissibility::kan_diag::<E, V, S>(&asn.entries, ctx) {
                premath_admissibility::KanDiag::Gap => {
                    let mut authored_sources: Vec<ConflictCandidate> = asn
                        .entries
                        .iter()
                        .map(|(ctx_key, entry)| candidate_from_entry(ctx_key, entry))
                        .collect();
                    authored_sources.sort_by(cmp_conflict_candidate);
                    gaps.push(GapWitness {
                        witness_id: witness_id(
                            "gap",
                            &format!("{}|{}", asn.token_path, target_key),
                        ),
                        token_path: asn.token_path.clone(),
                        target: target_key,
                        authored_sources,
                    });
                }
                premath_admissibility::KanDiag::Conflict { candidates: cs } => {
                    let mut candidates: Vec<ConflictCandidate> = cs
                        .iter()
                        .map(|(ctx_key, entry)| candidate_from_entry(ctx_key, entry))
                        .collect();
                    candidates.sort_by(cmp_conflict_candidate);
                    conflicts.push(ConflictWitness {
                        witness_id: witness_id(
                            "conflict",
                            &format!("{}|{}", asn.token_path, target_key),
                        ),
                        token_path: asn.token_path.clone(),
                        target: target_key,
                        candidates,
                    });
                }
                premath_admissibility::KanDiag::Consistent { value, sources } => {
                    if !asn.entries.contains_key(&target_key) {
                        inherited_total += 1;
                        let nontrivial = !(sources.len() == 1 && sources[0] == "(base)");
                        if nontrivial {
                            let mut srcs = sources.clone();
                            srcs.sort();
                            let mut rich_sources: Vec<ConflictCandidate> = srcs
                                .iter()
                                .filter_map(|ctx_key| {
                                    asn.entries
                                        .get(ctx_key)
                                        .map(|entry| candidate_from_entry(ctx_key, entry))
                                })
                                .collect();
                            rich_sources.sort_by(cmp_conflict_candidate);
                            inherited.push(InheritedWitness {
                                witness_id: witness_id(
                                    "inherited",
                                    &format!(
                                        "{}|{}|{}",
                                        asn.token_path,
                                        target_key,
                                        srcs.join(",")
                                    ),
                                ),
                                token_path: asn.token_path.clone(),
                                target: target_key,
                                inherited_from: srcs,
                                sources: rich_sources,
                                resolved_value_json: value_to_json(&value),
                                resolved_value_digest: value_digest(&value),
                            });
                        }
                    }
                }
            }
        }
    }

    let bc = premath_admissibility::bc_violations::<E, V, S>(assignments, axes);
    let mut bc_witnesses: Vec<BcWitness<S>> = Vec::new();
    for v in &bc {
        let left_json = value_to_json(&v.left);
        let right_json = value_to_json(&v.right);
        let resolver_value_json =
            resolver_value_json(&v.token_path, &v.axis_a, &v.value_a, &v.axis_b, &v.value_b);

        let bc_seed = format!(
            "{}|{}:{}|{}:{}|{}|{}",
            v.token_path, v.axis_a, v.value_a, v.axis_b, v.value_b, left_json, right_json
        );
        bc_witnesses.push(BcWitness {
            witness_id: witness_id("bc", &bc_seed),
            token_path: v.token_path.clone(),
            axis_a: v.axis_a.clone(),
            value_a: v.value_a.clone(),
            axis_b: v.axis_b.clone(),
            value_b: v.value_b.clone(),
            left_value_json: left_json,
            right_value_json: right_json,
            left_source: Some(v.left_source.clone()),
            right_source: Some(v.right_source.clone()),
            resolver_value_json,
            resolver_source: None,
            fix: format!(
                "Add an explicit override for {} at ({}={}, {}={})",
                v.token_path, v.axis_a, v.value_a, v.axis_b, v.value_b
            ),
        });
    }

    let overlaps = premath_admissibility::orthogonality_overlaps(assignments, axes);
    let mut overlap_witnesses: Vec<OverlapWitness> = overlaps
        .iter()
        .filter(|o| !o.overlap_paths.is_empty())
        .map(|o| {
            let seed = format!("{}|{}|{}", o.axis_a, o.axis_b, o.overlap_paths.join(","));
            OverlapWitness {
                witness_id: witness_id("orthogonality", &seed),
                axis_a: o.axis_a.clone(),
                axis_b: o.axis_b.clone(),
                overlap_token_paths: o.overlap_paths.clone(),
            }
        })
        .collect();

    gaps.sort_by(|a, b| {
        a.token_path
            .cmp(&b.token_path)
            .then(a.target.cmp(&b.target))
            .then(a.witness_id.cmp(&b.witness_id))
    });
    conflicts.sort_by(|a, b| {
        a.token_path
            .cmp(&b.token_path)
            .then(a.target.cmp(&b.target))
            .then(a.witness_id.cmp(&b.witness_id))
    });
    inherited.sort_by(|a, b| {
        a.token_path
            .cmp(&b.token_path)
            .then(a.target.cmp(&b.target))
            .then(a.witness_id.cmp(&b.witness_id))
    });
    bc_witnesses.sort_by(|a, b| {
        a.token_path
            .cmp(&b.token_path)
            .then(a.axis_a.cmp(&b.axis_a))
            .then(a.value_a.cmp(&b.value_a))
            .then(a.axis_b.cmp(&b.axis_b))
            .then(a.value_b.cmp(&b.value_b))
            .then(a.witness_id.cmp(&b.witness_id))
    });
    overlap_witnesses.sort_by(|a, b| {
        a.axis_a
            .cmp(&b.axis_a)
            .then(a.axis_b.cmp(&b.axis_b))
            .then(a.witness_id.cmp(&b.witness_id))
    });

    let summary = AnalysisSummary {
        tokens: assignments.len(),
        contexts: contexts.len(),
        kan_gaps: gaps.len(),
        kan_conflicts: conflicts.len(),
        kan_inherited: inherited_total,
        bc_violations: bc_witnesses.len(),
        orthogonality_overlaps: overlap_witnesses.len(),
    };

    Analysis {
        summary,
        witnesses: AnalysisWitnesses {
            witness_schema: WITNESS_SCHEMA_VERSION,
            conflict_mode,
            policy_digest,
            normalizer_version,
            gaps,
            conflicts,
            inherited,
            bc_violations: bc_witnesses,
            orthogonality: overlap_witnesses,
        },
    }
}
