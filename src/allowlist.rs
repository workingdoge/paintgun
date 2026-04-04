use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::cert::{CtcBcWitness, CtcConflictWitness, CtcWitnesses};
use crate::ids::{TokenPathId, WitnessId};

pub const DEFAULT_ALLOWLIST_REASON_TEMPLATE: &str = "TODO: replace with reviewed justification";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllowlistMatcherMode {
    WitnessId,
    Selector,
}

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

pub fn generate_allowlist(
    witnesses: &CtcWitnesses,
    matcher: AllowlistMatcherMode,
    witness_ids: &BTreeSet<String>,
    reason: &str,
) -> Result<Allowlist, Vec<String>> {
    let mut errors = Vec::new();
    if reason.trim().is_empty() {
        errors.push("reason template must be non-empty".to_string());
    }

    let mut available = BTreeSet::new();
    for witness in &witnesses.conflicts {
        available.insert(witness.witness_id.clone());
    }
    for witness in &witnesses.bc_violations {
        available.insert(witness.witness_id.clone());
    }

    for requested in witness_ids {
        if !available.contains(requested) {
            errors.push(format!(
                "witness id {requested} did not match any current allowlistable conflict or bcViolation witness"
            ));
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let include = |witness_id: &str| witness_ids.is_empty() || witness_ids.contains(witness_id);

    let conflicts: Vec<ConflictAllowEntry> = witnesses
        .conflicts
        .iter()
        .filter(|witness| include(&witness.witness_id))
        .map(|witness| match matcher {
            AllowlistMatcherMode::WitnessId => ConflictAllowEntry {
                witness_id: Some(WitnessId::from(witness.witness_id.as_str())),
                selector: None,
                reason: reason.to_string(),
            },
            AllowlistMatcherMode::Selector => ConflictAllowEntry {
                witness_id: None,
                selector: Some(ConflictSelector {
                    token_path: TokenPathId::from(witness.token_path.as_str()),
                    target: witness.target.clone(),
                }),
                reason: reason.to_string(),
            },
        })
        .collect();

    let bc_violations: Vec<BcAllowEntry> = witnesses
        .bc_violations
        .iter()
        .filter(|witness| include(&witness.witness_id))
        .map(|witness| match matcher {
            AllowlistMatcherMode::WitnessId => BcAllowEntry {
                witness_id: Some(WitnessId::from(witness.witness_id.as_str())),
                selector: None,
                reason: reason.to_string(),
            },
            AllowlistMatcherMode::Selector => BcAllowEntry {
                witness_id: None,
                selector: Some(BcSelector {
                    token_path: TokenPathId::from(witness.token_path.as_str()),
                    axis_a: witness.axis_a.clone(),
                    value_a: witness.value_a.clone(),
                    axis_b: witness.axis_b.clone(),
                    value_b: witness.value_b.clone(),
                }),
                reason: reason.to_string(),
            },
        })
        .collect();

    if conflicts.is_empty() && bc_violations.is_empty() {
        return Err(vec![
            "no allowlistable conflict or bcViolation witnesses matched the current selection"
                .to_string(),
        ]);
    }

    Ok(Allowlist {
        version: 1,
        conflicts,
        bc_violations,
    })
}
