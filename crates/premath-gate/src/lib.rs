use serde::{Deserialize, Serialize};
use serde_json::json;

pub const GATE_WITNESS_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GateResult {
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateWitnesses {
    #[serde(rename = "witnessSchema")]
    pub witness_schema: u32,
    pub profile: String,
    pub result: GateResult,
    pub failures: Vec<GateFailure>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSource {
    #[serde(rename = "sourceId")]
    pub source_id: String,
    #[serde(rename = "filePath")]
    pub file_path: String,
    #[serde(rename = "jsonPointer")]
    pub json_pointer: String,
    #[serde(rename = "fileHash")]
    pub file_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateFailure {
    #[serde(rename = "witnessId")]
    pub witness_id: String,
    #[serde(rename = "class")]
    pub class_name: String,
    #[serde(rename = "lawRef")]
    pub law_ref: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(rename = "tokenPath", skip_serializing_if = "Option::is_none")]
    pub token_path: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sources: Vec<GateSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl GateFailure {
    fn sort_key(&self) -> (String, String, String, String, String) {
        (
            self.class_name.clone(),
            self.law_ref.clone(),
            self.token_path.clone().unwrap_or_default(),
            self.context.clone().unwrap_or_default(),
            self.witness_id.clone(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateInputSource {
    pub source_id: String,
    pub file_path: String,
    pub json_pointer: String,
    pub file_hash: String,
}

impl From<GateInputSource> for GateSource {
    fn from(value: GateInputSource) -> Self {
        GateSource {
            source_id: value.source_id,
            file_path: value.file_path,
            json_pointer: value.json_pointer,
            file_hash: value.file_hash,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StabilityFailureInput {
    pub token_path: String,
    pub context: String,
    pub axis_a: String,
    pub value_a: String,
    pub axis_b: String,
    pub value_b: String,
    pub kind: String,
    pub sources: Vec<GateInputSource>,
}

#[derive(Clone, Debug)]
pub struct LocalityFailureInput {
    pub token_path: String,
    pub context: String,
    pub restricted_context: String,
    pub kind: String,
    pub sources: Vec<GateInputSource>,
}

#[derive(Clone, Debug)]
pub struct KanGapInput {
    pub witness_id: String,
    pub token_path: String,
    pub target: String,
    pub authored_sources: Vec<GateInputSource>,
}

#[derive(Clone, Debug)]
pub struct KanConflictInput {
    pub witness_id: String,
    pub token_path: String,
    pub target: String,
    pub candidates: Vec<GateInputSource>,
}

#[derive(Clone, Debug)]
pub struct BcViolationInput {
    pub witness_id: String,
    pub token_path: String,
    pub axis_a: String,
    pub value_a: String,
    pub axis_b: String,
    pub value_b: String,
    pub left_source: Option<GateInputSource>,
    pub right_source: Option<GateInputSource>,
}

#[derive(Clone, Debug, Default)]
pub struct AdmissibilityInput {
    pub stability_failures: Vec<StabilityFailureInput>,
    pub locality_failures: Vec<LocalityFailureInput>,
    pub kan_gaps: Vec<KanGapInput>,
    pub kan_conflicts: Vec<KanConflictInput>,
    pub bc_violations: Vec<BcViolationInput>,
}

fn unique_sorted_sources(mut sources: Vec<GateSource>) -> Vec<GateSource> {
    sources.sort_by(|a, b| {
        a.source_id
            .cmp(&b.source_id)
            .then(a.file_path.cmp(&b.file_path))
            .then(a.json_pointer.cmp(&b.json_pointer))
            .then(a.file_hash.cmp(&b.file_hash))
    });
    sources.dedup();
    sources
}

/// Evaluate full-profile admissibility over prepared witness-bearing inputs.
///
/// This function intentionally lives in `premath-gate` so law mapping and
/// witness canonicalization are independent from token-system plumbing.
pub fn evaluate_admissibility(input: AdmissibilityInput) -> GateWitnesses {
    let mut failures: Vec<GateFailure> = Vec::new();

    for w in input.stability_failures {
        failures.push(GateFailure {
            witness_id: format!("stability:{}:{}:{}", w.token_path, w.context, w.kind),
            class_name: "stability_failure".to_string(),
            law_ref: "GATE-3.1".to_string(),
            message: format!(
                "reindex composition does not commute for {} at {}:{},{}:{}",
                w.token_path, w.axis_a, w.value_a, w.axis_b, w.value_b
            ),
            context: Some(w.context),
            token_path: Some(w.token_path),
            sources: unique_sorted_sources(w.sources.into_iter().map(Into::into).collect()),
            details: Some(json!({
                "sourceWitnessType": "stability_check",
                "reason": w.kind,
                "axisA": w.axis_a,
                "valueA": w.value_a,
                "axisB": w.axis_b,
                "valueB": w.value_b
            })),
        });
    }

    for w in input.locality_failures {
        failures.push(GateFailure {
            witness_id: format!(
                "locality:{}:{}:{}:{}",
                w.token_path, w.context, w.restricted_context, w.kind
            ),
            class_name: "locality_failure".to_string(),
            law_ref: "GATE-3.2".to_string(),
            message: format!(
                "missing local restriction for {} from {} to {}",
                w.token_path, w.context, w.restricted_context
            ),
            context: Some(w.context),
            token_path: Some(w.token_path),
            sources: unique_sorted_sources(w.sources.into_iter().map(Into::into).collect()),
            details: Some(json!({
                "sourceWitnessType": "locality_check",
                "reason": w.kind,
                "restrictedContext": w.restricted_context
            })),
        });
    }

    for w in input.kan_gaps {
        let authored_sources_len = w.authored_sources.len();
        failures.push(GateFailure {
            witness_id: w.witness_id,
            class_name: "descent_failure".to_string(),
            law_ref: "GATE-3.3".to_string(),
            message: format!("no gluable candidate for {} at {}", w.token_path, w.target),
            context: Some(w.target),
            token_path: Some(w.token_path),
            sources: unique_sorted_sources(
                w.authored_sources.into_iter().map(Into::into).collect(),
            ),
            details: Some(json!({
                "sourceWitnessType": "kan_gap",
                "authoredSources": authored_sources_len
            })),
        });
    }

    for w in input.kan_conflicts {
        let candidate_count = w.candidates.len();
        failures.push(GateFailure {
            witness_id: w.witness_id,
            class_name: "glue_non_contractible".to_string(),
            law_ref: "GATE-3.4".to_string(),
            message: format!("non-unique glue for {} at {}", w.token_path, w.target),
            context: Some(w.target),
            token_path: Some(w.token_path),
            sources: unique_sorted_sources(w.candidates.into_iter().map(Into::into).collect()),
            details: Some(json!({
                "sourceWitnessType": "kan_conflict",
                "candidateCount": candidate_count
            })),
        });
    }

    for w in input.bc_violations {
        let mut sources: Vec<GateSource> = Vec::new();
        if let Some(left) = w.left_source {
            sources.push(left.into());
        }
        if let Some(right) = w.right_source {
            sources.push(right.into());
        }
        failures.push(GateFailure {
            witness_id: w.witness_id,
            class_name: "adjoint_triple_coherence_failure".to_string(),
            law_ref: "GATE-3.5".to_string(),
            message: format!(
                "context-change coherence failed for {} at {}:{},{}:{}",
                w.token_path, w.axis_a, w.value_a, w.axis_b, w.value_b
            ),
            context: Some(format!(
                "{}:{},{}:{}",
                w.axis_a, w.value_a, w.axis_b, w.value_b
            )),
            token_path: Some(w.token_path),
            sources: unique_sorted_sources(sources),
            details: Some(json!({
                "sourceWitnessType": "bc_violation",
                "axisA": w.axis_a,
                "valueA": w.value_a,
                "axisB": w.axis_b,
                "valueB": w.value_b
            })),
        });
    }

    failures.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    let result = if failures.is_empty() {
        GateResult::Accepted
    } else {
        GateResult::Rejected
    };

    GateWitnesses {
        witness_schema: GATE_WITNESS_SCHEMA_VERSION,
        profile: "full".to_string(),
        result,
        failures,
    }
}

impl GateWitnesses {
    pub fn validate(&self) -> Result<(), String> {
        if self.witness_schema != GATE_WITNESS_SCHEMA_VERSION {
            return Err(format!(
                "unsupported gate witness schema version: expected {}, got {}",
                GATE_WITNESS_SCHEMA_VERSION, self.witness_schema
            ));
        }
        if self.profile != "full" {
            return Err(format!(
                "unsupported gate profile: expected \"full\", got {:?}",
                self.profile
            ));
        }

        match self.result {
            GateResult::Accepted if !self.failures.is_empty() => {
                return Err("accepted gate result must not include failures".to_string())
            }
            GateResult::Rejected if self.failures.is_empty() => {
                return Err("rejected gate result must include at least one failure".to_string())
            }
            _ => {}
        }

        for f in &self.failures {
            let law_ok = match f.class_name.as_str() {
                "stability_failure" => f.law_ref == "GATE-3.1",
                "locality_failure" => f.law_ref == "GATE-3.2",
                "descent_failure" => f.law_ref == "GATE-3.3",
                "glue_non_contractible" => f.law_ref == "GATE-3.4",
                "adjoint_triple_coherence_failure" => f.law_ref == "GATE-3.5",
                other => {
                    return Err(format!("unsupported gate failure class: {other}"));
                }
            };
            if !law_ok {
                return Err(format!(
                    "gate failure {} has inconsistent lawRef {}",
                    f.class_name, f.law_ref
                ));
            }
        }

        let mut sorted = self.failures.clone();
        sorted.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
        if self
            .failures
            .iter()
            .map(GateFailure::sort_key)
            .collect::<Vec<_>>()
            != sorted.iter().map(GateFailure::sort_key).collect::<Vec<_>>()
        {
            return Err(
                "gate witness failures must be deterministically ordered by class, lawRef, tokenPath, context, witnessId"
                    .to_string(),
            );
        }

        Ok(())
    }

    pub fn rejected(&self) -> bool {
        self.result == GateResult::Rejected
    }
}
