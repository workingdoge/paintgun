use serde::{Deserialize, Serialize};

use crate::cert::{CtcBcWitness, CtcConflictWitness};
use crate::ids::{TokenPathId, WitnessId};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
    pub version: u32,
    #[serde(default)]
    pub conflicts: Vec<ConflictAllowEntry>,
    #[serde(rename = "bcViolations", default)]
    pub bc_violations: Vec<BcAllowEntry>,
}

impl Allowlist {
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.version != 1 {
            errors.push(format!("allowlist.version must be 1, got {}", self.version));
        }
        for (i, e) in self.conflicts.iter().enumerate() {
            errors.extend(
                e.validate()
                    .into_iter()
                    .map(|msg| format!("conflicts[{i}]: {msg}")),
            );
        }
        for (i, e) in self.bc_violations.iter().enumerate() {
            errors.extend(
                e.validate()
                    .into_iter()
                    .map(|msg| format!("bcViolations[{i}]: {msg}")),
            );
        }
        errors
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictAllowEntry {
    #[serde(rename = "witnessId", default)]
    pub witness_id: Option<WitnessId>,
    #[serde(default)]
    pub selector: Option<ConflictSelector>,
    pub reason: String,
}

impl ConflictAllowEntry {
    fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let has_witness = self
            .witness_id
            .as_ref()
            .map(|s| !s.as_str().trim().is_empty())
            .unwrap_or(false);
        let has_selector = self.selector.is_some();
        if has_witness == has_selector {
            errors.push("must include exactly one of `witnessId` or `selector`".to_string());
        }
        if self.reason.trim().is_empty() {
            errors.push("`reason` must be non-empty".to_string());
        }
        errors
    }

    pub fn matches(&self, w: &CtcConflictWitness) -> bool {
        if let Some(id) = &self.witness_id {
            return w.witness_id == id.as_str();
        }
        if let Some(sel) = &self.selector {
            return sel.matches(w);
        }
        false
    }

    pub fn describe(&self) -> String {
        if let Some(id) = &self.witness_id {
            format!("witnessId={id}")
        } else if let Some(sel) = &self.selector {
            format!(
                "selector(tokenPath={}, target={})",
                sel.token_path, sel.target
            )
        } else {
            "invalid-entry".to_string()
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictSelector {
    #[serde(rename = "tokenPath")]
    pub token_path: TokenPathId,
    pub target: String,
}

impl ConflictSelector {
    fn matches(&self, w: &CtcConflictWitness) -> bool {
        self.token_path.as_str() == w.token_path && self.target == w.target
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BcAllowEntry {
    #[serde(rename = "witnessId", default)]
    pub witness_id: Option<WitnessId>,
    #[serde(default)]
    pub selector: Option<BcSelector>,
    pub reason: String,
}

impl BcAllowEntry {
    fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let has_witness = self
            .witness_id
            .as_ref()
            .map(|s| !s.as_str().trim().is_empty())
            .unwrap_or(false);
        let has_selector = self.selector.is_some();
        if has_witness == has_selector {
            errors.push("must include exactly one of `witnessId` or `selector`".to_string());
        }
        if self.reason.trim().is_empty() {
            errors.push("`reason` must be non-empty".to_string());
        }
        errors
    }

    pub fn matches(&self, w: &CtcBcWitness) -> bool {
        if let Some(id) = &self.witness_id {
            return w.witness_id == id.as_str();
        }
        if let Some(sel) = &self.selector {
            return sel.matches(w);
        }
        false
    }

    pub fn describe(&self) -> String {
        if let Some(id) = &self.witness_id {
            format!("witnessId={id}")
        } else if let Some(sel) = &self.selector {
            format!(
                "selector(tokenPath={}, axisA={}, valueA={}, axisB={}, valueB={})",
                sel.token_path, sel.axis_a, sel.value_a, sel.axis_b, sel.value_b
            )
        } else {
            "invalid-entry".to_string()
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BcSelector {
    #[serde(rename = "tokenPath")]
    pub token_path: TokenPathId,
    #[serde(rename = "axisA")]
    pub axis_a: String,
    #[serde(rename = "valueA")]
    pub value_a: String,
    #[serde(rename = "axisB")]
    pub axis_b: String,
    #[serde(rename = "valueB")]
    pub value_b: String,
}

impl BcSelector {
    fn matches(&self, w: &CtcBcWitness) -> bool {
        if self.token_path.as_str() != w.token_path {
            return false;
        }
        let direct = self.axis_a == w.axis_a
            && self.value_a == w.value_a
            && self.axis_b == w.axis_b
            && self.value_b == w.value_b;
        let swapped = self.axis_a == w.axis_b
            && self.value_a == w.value_b
            && self.axis_b == w.axis_a
            && self.value_b == w.value_a;
        direct || swapped
    }
}
