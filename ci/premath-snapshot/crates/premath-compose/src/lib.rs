//! Multi-pack composition and compose-verify kernel.
//!
//! This crate assembles conflicts across multiple pack artifacts/manifests and
//! provides compose-level witness and verification utilities.
//! For single-pack composability analysis, see `premath-composability`.

use std::collections::{BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const COMPOSE_WITNESS_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComposeInheritedRef<W> {
    pub pack: String,
    #[serde(rename = "witnessType")]
    pub witness_type: String,
    #[serde(rename = "witnessId")]
    pub witness_id: W,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComposeCandidateSource<P> {
    pub context: String,
    pub provenance: P,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "I: Serialize, S: Serialize",
    deserialize = "I: Deserialize<'de>, S: Deserialize<'de>"
))]
pub struct ComposeConflictCandidate<I, S> {
    pub pack: String,
    #[serde(rename = "valueType")]
    pub value_type: String,
    pub value_json: String,
    pub value_digest: String,
    #[serde(
        rename = "inheritedFrom",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub inherited_from: Vec<I>,
    #[serde(default)]
    pub sources: Vec<S>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "W: Serialize, T: Serialize, I: Serialize, S: Serialize",
    deserialize = "W: Deserialize<'de>, T: Deserialize<'de>, I: Deserialize<'de>, S: Deserialize<'de>"
))]
pub struct ComposeConflictWitness<W, T, I, S> {
    #[serde(rename = "witnessId")]
    pub witness_id: W,
    pub token_path: T,
    pub context: String,
    pub candidates: Vec<ComposeConflictCandidate<I, S>>,
    pub winner_pack: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "M: Serialize, W: Serialize, T: Serialize, I: Serialize, S: Serialize",
    deserialize = "M: Deserialize<'de> + Default, W: Deserialize<'de>, T: Deserialize<'de>, I: Deserialize<'de>, S: Deserialize<'de>"
))]
pub struct ComposeWitnesses<M, W, T, I, S> {
    #[serde(rename = "witnessSchema")]
    pub witness_schema: u32,
    #[serde(rename = "conflictMode", default)]
    pub conflict_mode: M,
    #[serde(rename = "policyDigest", skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<String>,
    #[serde(rename = "normalizerVersion", skip_serializing_if = "Option::is_none")]
    pub normalizer_version: Option<String>,
    pub conflicts: Vec<ComposeConflictWitness<W, T, I, S>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComposeSummary {
    pub packs: usize,
    pub contexts: usize,
    pub token_paths_union: usize,
    pub overlapping_token_paths: usize,
    pub conflicts: usize,
}

pub fn summarize_pack_paths<P, S>(
    pack_paths: P,
    context_count: usize,
    conflict_count: usize,
) -> ComposeSummary
where
    P: IntoIterator<Item = S>,
    S: IntoIterator,
    S::Item: AsRef<str>,
{
    let mut union: HashSet<String> = HashSet::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut packs = 0usize;

    for paths in pack_paths {
        packs += 1;
        let mut pack_unique: HashSet<String> = HashSet::new();
        for p in paths {
            pack_unique.insert(p.as_ref().to_string());
        }
        for path in pack_unique {
            union.insert(path.clone());
            *counts.entry(path).or_insert(0) += 1;
        }
    }

    let overlapping_token_paths = counts.values().filter(|c| **c >= 2).count();
    ComposeSummary {
        packs,
        contexts: context_count,
        token_paths_union: union.len(),
        overlapping_token_paths,
        conflicts: conflict_count,
    }
}

impl<M, W, T, I, S> ComposeWitnesses<M, W, T, I, S> {
    pub fn validate_schema_version(&self) -> Result<(), String> {
        if self.witness_schema != COMPOSE_WITNESS_SCHEMA_VERSION {
            return Err(format!(
                "unsupported compose witness schema version: expected {}, got {}",
                COMPOSE_WITNESS_SCHEMA_VERSION, self.witness_schema
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ComposeCandidateInput<V, I, S> {
    pub pack_name: String,
    pub value: V,
    pub value_type: String,
    pub value_json: String,
    pub value_digest: String,
    pub inherited_from: Vec<I>,
    pub sources: Vec<S>,
}

#[derive(Clone, Debug)]
pub struct ComposeConflictDraftCandidate<I, S> {
    pub pack: String,
    pub value_type: String,
    pub value_json: String,
    pub value_digest: String,
    pub inherited_from: Vec<I>,
    pub sources: Vec<S>,
}

#[derive(Clone, Debug)]
pub struct ComposeConflictDraft<I, S> {
    pub witness_id: String,
    pub token_path: String,
    pub context: String,
    pub candidates: Vec<ComposeConflictDraftCandidate<I, S>>,
    pub winner_pack: String,
}

fn compose_witness_id(seed: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("compose-conflict|{seed}").as_bytes());
    let digest = hasher.finalize();
    let hex = hex::encode(digest);
    format!("compose-conflict-{}", &hex[..16])
}

pub fn assemble_conflicts<C, V, I, S, K, F>(
    contexts: &[C],
    overlap_paths: &BTreeSet<String>,
    mut context_key: K,
    mut candidates_for: F,
) -> Vec<ComposeConflictDraft<I, S>>
where
    V: Eq,
    I: Clone,
    S: Clone,
    K: FnMut(&C) -> String,
    F: FnMut(&C, &str) -> Vec<ComposeCandidateInput<V, I, S>>,
{
    let mut out: Vec<ComposeConflictDraft<I, S>> = Vec::new();

    for ctx in contexts {
        let ck = context_key(ctx);
        for path in overlap_paths {
            let candidates_all = candidates_for(ctx, path);
            if candidates_all.len() < 2 {
                continue;
            }

            let mut uniq_values: Vec<&V> = Vec::new();
            for c in &candidates_all {
                if !uniq_values.iter().any(|u| **u == c.value) {
                    uniq_values.push(&c.value);
                }
            }
            if uniq_values.len() <= 1 {
                continue;
            }

            let winner_pack = candidates_all
                .last()
                .map(|c| c.pack_name.clone())
                .unwrap_or_default();

            let candidates: Vec<ComposeConflictDraftCandidate<I, S>> = candidates_all
                .iter()
                .map(|c| ComposeConflictDraftCandidate {
                    pack: c.pack_name.clone(),
                    value_type: c.value_type.clone(),
                    value_json: c.value_json.clone(),
                    value_digest: c.value_digest.clone(),
                    inherited_from: c.inherited_from.clone(),
                    sources: c.sources.clone(),
                })
                .collect();

            let seed = format!(
                "{}|{}|{}",
                path,
                ck,
                candidates_all
                    .iter()
                    .map(|c| format!("{}:{}", c.pack_name, c.value_digest))
                    .collect::<Vec<_>>()
                    .join(",")
            );

            out.push(ComposeConflictDraft {
                witness_id: compose_witness_id(&seed),
                token_path: path.clone(),
                context: ck.clone(),
                candidates,
                winner_pack,
            });
        }
    }

    out.sort_by(|a, b| {
        a.token_path
            .cmp(&b.token_path)
            .then(a.context.cmp(&b.context))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_inherited_from_defaults_when_omitted() {
        let json = serde_json::json!({
            "witnessSchema": COMPOSE_WITNESS_SCHEMA_VERSION,
            "conflictMode": "semantic",
            "conflicts": [
                {
                    "witnessId": "w-1",
                    "token_path": "color.primary",
                    "context": "base",
                    "winner_pack": "pack-b",
                    "candidates": [
                        {
                            "pack": "pack-a",
                            "valueType": "color",
                            "value_json": "\"#111111\"",
                            "value_digest": "sha256:111",
                            "sources": ["src-a"]
                        }
                    ]
                }
            ]
        });

        let parsed: ComposeWitnesses<String, String, String, String, String> =
            serde_json::from_value(json).expect("parse witnesses");
        assert_eq!(parsed.conflicts.len(), 1);
        assert!(parsed.conflicts[0].candidates[0].inherited_from.is_empty());
    }

    #[test]
    fn candidate_omits_inherited_from_when_empty_on_serialize() {
        let witnesses = ComposeWitnesses {
            witness_schema: COMPOSE_WITNESS_SCHEMA_VERSION,
            conflict_mode: "semantic".to_string(),
            policy_digest: None,
            normalizer_version: None,
            conflicts: vec![ComposeConflictWitness {
                witness_id: "w-1".to_string(),
                token_path: "color.primary".to_string(),
                context: "base".to_string(),
                candidates: vec![ComposeConflictCandidate {
                    pack: "pack-a".to_string(),
                    value_type: "color".to_string(),
                    value_json: "\"#111111\"".to_string(),
                    value_digest: "sha256:111".to_string(),
                    inherited_from: Vec::<String>::new(),
                    sources: vec!["src-a".to_string()],
                }],
                winner_pack: "pack-b".to_string(),
            }],
        };

        let value = serde_json::to_value(&witnesses).expect("serialize witnesses");
        let candidate = &value["conflicts"][0]["candidates"][0];
        assert!(
            candidate.get("inheritedFrom").is_none(),
            "expected inheritedFrom to be omitted when empty"
        );
    }

    #[test]
    fn summarize_pack_paths_counts_union_and_overlap() {
        let pack_paths = vec![
            vec!["a.x", "a.x", "a.y"],
            vec!["a.y", "a.z"],
            vec!["a.z", "a.w"],
        ];
        let summary = summarize_pack_paths(pack_paths, 7, 2);
        assert_eq!(summary.packs, 3);
        assert_eq!(summary.contexts, 7);
        assert_eq!(summary.token_paths_union, 4);
        assert_eq!(summary.overlapping_token_paths, 2);
        assert_eq!(summary.conflicts, 2);
    }

    #[test]
    fn witness_schema_validation_rejects_unknown_versions() {
        let witnesses = ComposeWitnesses::<String, String, String, String, String> {
            witness_schema: COMPOSE_WITNESS_SCHEMA_VERSION + 1,
            conflict_mode: "semantic".to_string(),
            policy_digest: None,
            normalizer_version: None,
            conflicts: Vec::new(),
        };

        let err = witnesses
            .validate_schema_version()
            .expect_err("schema validation should reject unexpected versions");
        assert!(err.contains("unsupported compose witness schema version"));
    }

    #[test]
    fn assemble_conflicts_filters_non_conflicts_and_hashes_witness_ids() {
        let contexts = vec!["(base)".to_string(), "theme=dark".to_string()];
        let overlap_paths = BTreeSet::from([
            "color.bg".to_string(),
            "color.same".to_string(),
            "color.single".to_string(),
        ]);

        let drafts = assemble_conflicts(
            &contexts,
            &overlap_paths,
            |ctx| ctx.clone(),
            |ctx, path| match (ctx.as_str(), path) {
                ("(base)", "color.bg") => vec![
                    ComposeCandidateInput {
                        pack_name: "pack-a".to_string(),
                        value: 1u32,
                        value_type: "number".to_string(),
                        value_json: "1".to_string(),
                        value_digest: "sha256:one".to_string(),
                        inherited_from: vec!["base-a".to_string()],
                        sources: vec!["src-a".to_string()],
                    },
                    ComposeCandidateInput {
                        pack_name: "pack-b".to_string(),
                        value: 2u32,
                        value_type: "number".to_string(),
                        value_json: "2".to_string(),
                        value_digest: "sha256:two".to_string(),
                        inherited_from: vec!["base-b".to_string()],
                        sources: vec!["src-b".to_string()],
                    },
                ],
                ("theme=dark", "color.bg") => vec![
                    ComposeCandidateInput {
                        pack_name: "pack-a".to_string(),
                        value: 7u32,
                        value_type: "number".to_string(),
                        value_json: "7".to_string(),
                        value_digest: "sha256:seven".to_string(),
                        inherited_from: Vec::new(),
                        sources: vec!["src-a-dark".to_string()],
                    },
                    ComposeCandidateInput {
                        pack_name: "pack-b".to_string(),
                        value: 9u32,
                        value_type: "number".to_string(),
                        value_json: "9".to_string(),
                        value_digest: "sha256:nine".to_string(),
                        inherited_from: Vec::new(),
                        sources: vec!["src-b-dark".to_string()],
                    },
                ],
                ("(base)", "color.same") => vec![
                    ComposeCandidateInput {
                        pack_name: "pack-a".to_string(),
                        value: 5u32,
                        value_type: "number".to_string(),
                        value_json: "5".to_string(),
                        value_digest: "sha256:five-a".to_string(),
                        inherited_from: Vec::new(),
                        sources: vec!["src-a".to_string()],
                    },
                    ComposeCandidateInput {
                        pack_name: "pack-b".to_string(),
                        value: 5u32,
                        value_type: "number".to_string(),
                        value_json: "5".to_string(),
                        value_digest: "sha256:five-b".to_string(),
                        inherited_from: Vec::new(),
                        sources: vec!["src-b".to_string()],
                    },
                ],
                ("(base)", "color.single") => vec![ComposeCandidateInput {
                    pack_name: "pack-a".to_string(),
                    value: 3u32,
                    value_type: "number".to_string(),
                    value_json: "3".to_string(),
                    value_digest: "sha256:three".to_string(),
                    inherited_from: Vec::new(),
                    sources: vec!["src-a".to_string()],
                }],
                _ => Vec::new(),
            },
        );

        assert_eq!(
            drafts.len(),
            2,
            "only conflicting multi-pack paths should remain"
        );
        assert_eq!(drafts[0].token_path, "color.bg");
        assert_eq!(drafts[0].context, "(base)");
        assert_eq!(drafts[0].winner_pack, "pack-b");
        assert_eq!(drafts[0].candidates[0].pack, "pack-a");
        assert_eq!(drafts[0].candidates[1].pack, "pack-b");
        assert!(
            drafts[0].witness_id.starts_with("compose-conflict-"),
            "witness ids should use the stable compose-conflict hash prefix"
        );
        assert_eq!(drafts[1].context, "theme=dark");
    }
}
