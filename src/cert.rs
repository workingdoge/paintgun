use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::analysis::PartialAssignment;
use crate::dtcg::TypedValue;
use crate::ids::{TokenPathId, WitnessId};
use crate::kcir_v2::{default_kcir_profile_binding, KcirProfileBinding, KCIR_VERSION};
use crate::pack_identity::{parse_pack_identity_label, parse_vendor_pack_identity_from_file_path};
use crate::policy::Policy;
use crate::provenance::{AuthoredValue, TokenProvenance};
use crate::resolver::{
    collect_explicit_token_defs, context_key, parse_context_key, Input, ResolverDoc, ResolverError,
    TokenStore,
};
use crate::util::sha256_hex;

//──────────────────────────────────────────────────────────────────────────────
// Assignment construction (authored subposet S)
//──────────────────────────────────────────────────────────────────────────────

/// Build the authored-definition index used to construct partial assignments.
///
/// For each *authored* context (base + single modifiers), record which token paths
/// are explicitly defined (contain a `$value`) in that context's sources.
///
/// This is deliberately presence-based (not inferred by value diffs), so we do not
/// miss explicit definitions that happen to equal base.
/// Build an index of explicit authored definitions with provenance.
///
/// Result structure: ctxKey -> tokenPath -> provenance.
///
/// We attribute each token path to the *last* source in that authored context
/// whose tree contains an explicit `$value` at that path.
pub fn build_explicit_index(
    doc: &ResolverDoc,
    store: &TokenStore,
    resolver_path: &Path,
) -> Result<HashMap<String, HashMap<String, TokenProvenance>>, ResolverError> {
    let base_dir = resolver_path.parent().unwrap_or_else(|| Path::new("."));
    let mut file_hash_cache: HashMap<PathBuf, String> = HashMap::new();
    let mut resolution_rank_by_layer: HashMap<String, u64> = HashMap::new();
    for (rank, entry) in doc.resolution_order.iter().enumerate() {
        let ptr = entry.as_ref_str();
        let segments: Vec<&str> = ptr.trim_start_matches("#/").split('/').collect();
        if segments.len() >= 2 && segments[0] == "sets" {
            resolution_rank_by_layer.insert(format!("set:{}", segments[1]), rank as u64);
        } else if segments.len() >= 2 && segments[0] == "modifiers" {
            resolution_rank_by_layer.insert(format!("modifier:{}", segments[1]), rank as u64);
        }
    }

    fn json_pointer_for_token_path(path: &str) -> String {
        // Approximate location of the `$value` for a leaf token.
        // Note: `$root` tokens will be reported as if their `$value` were at the group path;
        // this is still actionable for humans, and stable for certificates.
        if path.is_empty() {
            return "/$value".to_string();
        }
        let segs = path.split('.').collect::<Vec<_>>();
        format!("/{}/$value", segs.join("/"))
    }

    fn normalize_source_path(base_dir: &Path, source_ref: &str) -> String {
        let joined = base_dir.join(source_ref);
        if let (Ok(base_abs), Ok(joined_abs)) =
            (fs::canonicalize(base_dir), fs::canonicalize(&joined))
        {
            if let Ok(rel) = joined_abs.strip_prefix(&base_abs) {
                return rel.to_string_lossy().replace('\\', "/");
            }
            return joined_abs.to_string_lossy().replace('\\', "/");
        }
        source_ref.replace('\\', "/")
    }

    fn source_file_hash(
        base_dir: &Path,
        source_ref: &str,
        cache: &mut HashMap<PathBuf, String>,
    ) -> Option<String> {
        let joined = base_dir.join(source_ref);
        let key = fs::canonicalize(&joined).unwrap_or_else(|_| joined.clone());
        if let Some(v) = cache.get(&key) {
            return Some(v.clone());
        }
        let bytes = fs::read(&joined).ok()?;
        let sha = format!("sha256:{}", sha256_hex(&bytes));
        cache.insert(key, sha.clone());
        Some(sha)
    }

    fn provenance_from_source(
        base_dir: &Path,
        source_ref: Option<&str>,
        source_id: String,
        resolution_layer_id: Option<String>,
        resolution_rank: Option<u64>,
        token_path: &str,
        json_pointer: Option<String>,
        file_hash_cache: &mut HashMap<PathBuf, String>,
    ) -> TokenProvenance {
        let (mut file_path, mut file_hash, mut pack_id, pack_version, mut pack_hash) =
            match source_ref {
                Some(r) => {
                    let file_path = normalize_source_path(base_dir, r);
                    let file_hash = source_file_hash(base_dir, r, file_hash_cache);
                    let parsed = parse_vendor_pack_identity_from_file_path(&file_path);
                    (
                        Some(file_path),
                        file_hash,
                        parsed.pack_id,
                        parsed.pack_version,
                        parsed.pack_hash,
                    )
                }
                None => (None, None, None, None, None),
            };
        if file_path.is_none() {
            file_path = Some("(inline)".to_string());
        }
        if file_hash.is_none() {
            file_hash = Some("sha256:unknown".to_string());
        }
        if pack_id.is_none() {
            pack_id = Some("local-pack".to_string());
        }
        if pack_hash.is_none() {
            pack_hash = file_hash.clone();
        }
        let resolved_layer = resolution_layer_id.unwrap_or_else(|| source_id.clone());
        let resolved_rank = resolution_rank.unwrap_or(0);

        TokenProvenance {
            source_id,
            resolution_layer_id: Some(resolved_layer),
            resolution_rank: Some(resolved_rank),
            pack_id,
            pack_version,
            pack_hash,
            file_path,
            file_hash,
            json_pointer: Some(
                json_pointer.unwrap_or_else(|| json_pointer_for_token_path(token_path)),
            ),
        }
    }

    let mut out: HashMap<String, HashMap<String, TokenProvenance>> = HashMap::new();

    // Base: attribute explicit definitions from sets in Resolver Module order.
    let base_key = "(base)".to_string();
    let mut base_map: HashMap<String, TokenProvenance> = HashMap::new();

    for entry in &doc.resolution_order {
        let ptr = entry.as_ref_str();
        if let Some(rest) = ptr.strip_prefix("#/sets/") {
            if let Some(set) = doc.sets.get(rest) {
                for src in &set.sources {
                    let tree = crate::resolver::load_source(doc, src, base_dir)?;
                    let defs = collect_explicit_token_defs(&tree);

                    for (p, json_pointer) in defs {
                        base_map.insert(
                            p.clone(),
                            provenance_from_source(
                                base_dir,
                                src.r#ref.as_deref(),
                                format!("set:{rest}"),
                                Some(format!("set:{rest}")),
                                resolution_rank_by_layer
                                    .get(&format!("set:{rest}"))
                                    .copied(),
                                &p,
                                Some(json_pointer),
                                &mut file_hash_cache,
                            ),
                        );
                    }
                }
            }
        }
    }

    // Fallback: if resolutionOrder omits sets, include them in a deterministic order.
    if base_map.is_empty() {
        let mut set_names: Vec<String> = doc.sets.keys().cloned().collect();
        set_names.sort();
        for rest in set_names {
            if let Some(set) = doc.sets.get(&rest) {
                for src in &set.sources {
                    let tree = crate::resolver::load_source(doc, src, base_dir)?;
                    let defs = collect_explicit_token_defs(&tree);
                    for (p, json_pointer) in defs {
                        base_map.insert(
                            p.clone(),
                            provenance_from_source(
                                base_dir,
                                src.r#ref.as_deref(),
                                format!("set:{rest}"),
                                Some(format!("set:{rest}")),
                                resolution_rank_by_layer
                                    .get(&format!("set:{rest}"))
                                    .copied(),
                                &p,
                                Some(json_pointer),
                                &mut file_hash_cache,
                            ),
                        );
                    }
                }
            }
        }
    }

    // Ensure every base token in the resolved store has *some* provenance entry.
    // (e.g. values introduced via $extends).
    if let Some(toks) = store.resolved_by_ctx.get(&base_key) {
        for t in toks {
            base_map.entry(t.path.clone()).or_insert(TokenProvenance {
                source_id: "base".to_string(),
                resolution_layer_id: Some("base".to_string()),
                resolution_rank: Some(0),
                pack_id: Some("local-pack".to_string()),
                pack_version: None,
                pack_hash: Some("sha256:unknown".to_string()),
                file_path: Some("(inline)".to_string()),
                file_hash: Some("sha256:unknown".to_string()),
                json_pointer: Some(json_pointer_for_token_path(&t.path)),
            });
        }
    }

    out.insert(base_key, base_map);

    // Single modifier contexts: scan only that modifier's sources (no sets) and attribute to the last writer.
    for (axis, modifier) in &doc.modifiers {
        for (val, ctx) in &modifier.contexts {
            let mut map: HashMap<String, TokenProvenance> = HashMap::new();
            for src in &ctx.sources {
                let tree = crate::resolver::load_source(doc, src, base_dir)?;
                let defs = collect_explicit_token_defs(&tree);

                for (p, json_pointer) in defs {
                    map.insert(
                        p.clone(),
                        provenance_from_source(
                            base_dir,
                            src.r#ref.as_deref(),
                            format!("modifier:{axis}/{val}"),
                            Some(format!("modifier:{axis}/{val}")),
                            resolution_rank_by_layer
                                .get(&format!("modifier:{axis}"))
                                .copied(),
                            &p,
                            Some(json_pointer),
                            &mut file_hash_cache,
                        ),
                    );
                }
            }

            let mut input = Input::new();
            input.insert(axis.clone(), val.clone());
            out.insert(context_key(&input), map);
        }
    }

    Ok(out)
}

/// Build per-token authored partial assignments from the resolved store.
///
/// Authored model:
/// - base context provides defaults
/// - each single-modifier context contributes only token paths that were explicitly
///   defined in that modifier's sources (presence of `$value`).
///
/// Values are taken from the spec-resolved single-context output (so aliases resolve
/// the same way the shipping resolver does), but we *omit* tokens that were not
/// explicitly provided by that modifier.
pub fn build_assignments(
    store: &TokenStore,
    explicit: &HashMap<String, HashMap<String, TokenProvenance>>,
) -> Vec<PartialAssignment> {
    let mut map: HashMap<String, HashMap<String, AuthoredValue>> = HashMap::new();
    let mut insert = |token_path: &str, ctx_key: &str, av: AuthoredValue| {
        map.entry(token_path.to_string())
            .or_insert_with(HashMap::new)
            .insert(ctx_key.to_string(), av);
    };

    // Base provides defaults (with best-effort provenance).
    let base_key = "(base)".to_string();
    if let Some(toks) = store.resolved_by_ctx.get(&base_key) {
        for t in toks {
            let prov = explicit
                .get(&base_key)
                .and_then(|m| m.get(&t.path))
                .cloned()
                .unwrap_or(TokenProvenance {
                    source_id: "base".to_string(),
                    resolution_layer_id: Some("base".to_string()),
                    resolution_rank: Some(0),
                    pack_id: Some("local-pack".to_string()),
                    pack_version: None,
                    pack_hash: Some("sha256:unknown".to_string()),
                    file_path: Some("(inline)".to_string()),
                    file_hash: Some("sha256:unknown".to_string()),
                    json_pointer: Some("/$value".to_string()),
                });
            insert(
                &t.path,
                &base_key,
                AuthoredValue::new(t.ty, t.value.clone(), prov),
            );
        }
    }

    // Single modifiers contribute explicit token definitions.
    for (axis, vals) in &store.axes {
        for v in vals {
            let mut ctx = Input::new();
            ctx.insert(axis.clone(), v.clone());
            let key = context_key(&ctx);
            let Some(paths) = explicit.get(&key) else {
                continue;
            };
            for (path, prov) in paths {
                if let Some(tok) = store.token_at(path, &ctx) {
                    insert(
                        path,
                        &key,
                        AuthoredValue::new(tok.ty, tok.value.clone(), prov.clone()),
                    );
                }
            }
        }
    }

    let mut out: Vec<PartialAssignment> = map
        .into_iter()
        .map(|(token_path, entries)| PartialAssignment {
            token_path,
            entries,
        })
        .collect();
    out.sort_by(|a, b| a.token_path.cmp(&b.token_path));
    out
}

/// Generate all full contexts (cartesian product over axes).
pub fn full_contexts(axes: &BTreeMap<String, Vec<String>>) -> Vec<Input> {
    crate::contexts::full_inputs(axes)
}

//──────────────────────────────────────────────────────────────────────────────
// Composability certificate (CTC) — manifest + witnesses
//──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub file: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

pub const NORMALIZER_VERSION: &str = "tbp-policy-v1";

pub use premath_composability::{
    ConflictMode, CtcConflictCandidate, CtcConflictWitness, CtcGapWitness, CtcInheritedWitness,
    CtcOverlapWitness, CtcSummary, PACK_WITNESS_SCHEMA_VERSION,
};
pub type CtcBcWitness = premath_composability::CtcBcWitness<TokenProvenance>;
pub type CtcWitnesses = premath_composability::CtcWitnesses<TokenProvenance>;
pub type CtcAnalysis = premath_composability::CtcAnalysis<TokenProvenance>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CtcSemantics {
    #[serde(rename = "eqValueId")]
    pub eq_value_id: String,

    #[serde(rename = "policyDigest", skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<String>,

    #[serde(rename = "conflictMode", default)]
    pub conflict_mode: ConflictMode,

    #[serde(rename = "normalizerVersion", skip_serializing_if = "Option::is_none")]
    pub normalizer_version: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CtcInputs {
    #[serde(rename = "resolverSpec")]
    pub resolver_spec: ManifestEntry,

    #[serde(rename = "tokenDocs")]
    pub token_docs: Vec<ManifestEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CtcOutputs {
    #[serde(rename = "resolvedJson")]
    pub resolved_json: ManifestEntry,

    #[serde(rename = "tokensCss", skip_serializing_if = "Option::is_none")]
    pub tokens_css: Option<ManifestEntry>,

    #[serde(rename = "tokensSwift", skip_serializing_if = "Option::is_none")]
    pub tokens_swift: Option<ManifestEntry>,

    #[serde(rename = "tokensKotlin", skip_serializing_if = "Option::is_none")]
    pub tokens_kotlin: Option<ManifestEntry>,

    #[serde(rename = "tokensDts", skip_serializing_if = "Option::is_none")]
    pub tokens_dts: Option<ManifestEntry>,
    #[serde(rename = "authoredJson", skip_serializing_if = "Option::is_none")]
    pub authored_json: Option<ManifestEntry>,

    #[serde(rename = "validationTxt", skip_serializing_if = "Option::is_none")]
    pub validation_txt: Option<ManifestEntry>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NativeApiVersions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swift: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kotlin: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustStatus {
    Unsigned,
    Signed,
}

impl Default for TrustStatus {
    fn default() -> Self {
        TrustStatus::Unsigned
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrustMetadata {
    #[serde(default)]
    pub status: TrustStatus,
    #[serde(rename = "signatureScheme", skip_serializing_if = "Option::is_none")]
    pub signature_scheme: Option<String>,
    #[serde(rename = "signatureFile", skip_serializing_if = "Option::is_none")]
    pub signature_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(rename = "claimsSha256", skip_serializing_if = "Option::is_none")]
    pub claims_sha256: Option<String>,
}

impl TrustMetadata {
    pub fn unsigned() -> Self {
        TrustMetadata::default()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackIdentity {
    #[serde(rename = "packId")]
    pub pack_id: String,
    #[serde(rename = "packVersion")]
    pub pack_version: String,
    #[serde(rename = "contentHash")]
    pub content_hash: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RequiredArtifactKind {
    CtcWitnesses,
    AdmissibilityWitnesses,
}

impl RequiredArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RequiredArtifactKind::CtcWitnesses => "ctcWitnesses",
            RequiredArtifactKind::AdmissibilityWitnesses => "admissibilityWitnesses",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequiredArtifactBinding {
    pub kind: RequiredArtifactKind,
    #[serde(flatten)]
    pub entry: ManifestEntry,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CtcManifest {
    #[serde(rename = "ctcVersion")]
    pub ctc_version: String,
    #[serde(rename = "kcirVersion")]
    pub kcir_version: String,

    pub tool: ToolInfo,

    /// The DTCG spec version (e.g. "2025.10").
    pub spec: String,

    #[serde(rename = "packIdentity")]
    pub pack_identity: PackIdentity,
    #[serde(default)]
    pub trust: TrustMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<KcirProfileBinding>,

    pub axes: BTreeMap<String, Vec<String>>,

    pub semantics: CtcSemantics,
    #[serde(rename = "nativeApiVersions", skip_serializing_if = "Option::is_none")]
    pub native_api_versions: Option<NativeApiVersions>,
    pub inputs: CtcInputs,
    pub outputs: CtcOutputs,

    pub summary: CtcSummary,

    #[serde(rename = "witnessesSha256")]
    pub witnesses_sha256: String,
    #[serde(
        rename = "requiredArtifacts",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub required_artifacts: Vec<RequiredArtifactBinding>,
    #[serde(
        rename = "admissibilityWitnessesSha256",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub admissibility_witnesses_sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReportFinding {
    #[serde(rename = "witnessId")]
    pub witness_id: WitnessId,
    pub kind: String,
    pub severity: String,
    pub message: String,
    #[serde(rename = "tokenPath", skip_serializing_if = "Option::is_none")]
    pub token_path: Option<TokenPathId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(rename = "filePath", skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(rename = "jsonPointer", skip_serializing_if = "Option::is_none")]
    pub json_pointer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack: Option<String>,
}

pub fn build_validation_report_json(analysis: &CtcAnalysis) -> serde_json::Value {
    let mut findings: Vec<ReportFinding> = Vec::new();

    for w in &analysis.witnesses.gaps {
        if w.authored_sources.is_empty() {
            findings.push(ReportFinding {
                witness_id: w.witness_id.clone().into(),
                kind: "gap".to_string(),
                severity: "error".to_string(),
                message: format!("Kan gap for {} at {}", w.token_path, w.target),
                token_path: Some(w.token_path.clone().into()),
                context: Some(w.target.clone()),
                file_path: None,
                json_pointer: None,
                pack: None,
            });
            continue;
        }
        for s in &w.authored_sources {
            findings.push(ReportFinding {
                witness_id: w.witness_id.clone().into(),
                kind: "gap".to_string(),
                severity: "error".to_string(),
                message: format!(
                    "Kan gap for {} at {} (source {})",
                    w.token_path, w.target, s.source_context
                ),
                token_path: Some(w.token_path.clone().into()),
                context: Some(w.target.clone()),
                file_path: Some(s.file_path.clone()),
                json_pointer: Some(s.json_pointer.clone()),
                pack: Some(s.pack_id.clone()),
            });
        }
    }

    for w in &analysis.witnesses.conflicts {
        for c in &w.candidates {
            findings.push(ReportFinding {
                witness_id: w.witness_id.clone().into(),
                kind: "conflict".to_string(),
                severity: "error".to_string(),
                message: format!(
                    "Kan conflict for {} at {} (candidate from {})",
                    w.token_path, w.target, c.source_context
                ),
                token_path: Some(w.token_path.clone().into()),
                context: Some(w.target.clone()),
                file_path: Some(c.file_path.clone()),
                json_pointer: Some(c.json_pointer.clone()),
                pack: Some(c.pack_id.clone()),
            });
        }
    }

    for w in &analysis.witnesses.inherited {
        for s in &w.sources {
            findings.push(ReportFinding {
                witness_id: w.witness_id.clone().into(),
                kind: "inherited".to_string(),
                severity: "info".to_string(),
                message: format!("Inherited value for {} at {}", w.token_path, w.target),
                token_path: Some(w.token_path.clone().into()),
                context: Some(w.target.clone()),
                file_path: Some(s.file_path.clone()),
                json_pointer: Some(s.json_pointer.clone()),
                pack: Some(s.pack_id.clone()),
            });
        }
    }

    for w in &analysis.witnesses.bc_violations {
        let ctx = format!("{}:{},{}:{}", w.axis_a, w.value_a, w.axis_b, w.value_b);
        if let Some(src) = &w.left_source {
            findings.push(ReportFinding {
                witness_id: w.witness_id.clone().into(),
                kind: "bcViolation".to_string(),
                severity: "error".to_string(),
                message: format!("Beck-Chevalley violation for {} at {}", w.token_path, ctx),
                token_path: Some(w.token_path.clone().into()),
                context: Some(ctx.clone()),
                file_path: src.file_path.clone(),
                json_pointer: src.json_pointer.clone(),
                pack: src.pack_id.clone(),
            });
        }
        if let Some(src) = &w.right_source {
            findings.push(ReportFinding {
                witness_id: w.witness_id.clone().into(),
                kind: "bcViolation".to_string(),
                severity: "error".to_string(),
                message: format!("Beck-Chevalley violation for {} at {}", w.token_path, ctx),
                token_path: Some(w.token_path.clone().into()),
                context: Some(ctx.clone()),
                file_path: src.file_path.clone(),
                json_pointer: src.json_pointer.clone(),
                pack: src.pack_id.clone(),
            });
        }
        if w.left_source.is_none() && w.right_source.is_none() {
            findings.push(ReportFinding {
                witness_id: w.witness_id.clone().into(),
                kind: "bcViolation".to_string(),
                severity: "error".to_string(),
                message: format!("Beck-Chevalley violation for {} at {}", w.token_path, ctx),
                token_path: Some(w.token_path.clone().into()),
                context: Some(ctx),
                file_path: None,
                json_pointer: None,
                pack: None,
            });
        }
    }

    for w in &analysis.witnesses.orthogonality {
        findings.push(ReportFinding {
            witness_id: w.witness_id.clone().into(),
            kind: "orthogonality".to_string(),
            severity: "warn".to_string(),
            message: format!(
                "Orthogonality overlap between {} and {} ({} paths)",
                w.axis_a,
                w.axis_b,
                w.overlap_token_paths.len()
            ),
            token_path: None,
            context: None,
            file_path: None,
            json_pointer: None,
            pack: None,
        });
    }

    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    for f in &findings {
        *by_kind.entry(f.kind.clone()).or_insert(0) += 1;
    }

    let policy_digest = analysis
        .witnesses
        .policy_digest
        .clone()
        .unwrap_or_else(|| "sha256:unknown".to_string());
    let mut out = json!({
        "reportVersion": 1,
        "reportKind": "pack",
        "conflictMode": analysis.witnesses.conflict_mode,
        "policyDigest": policy_digest,
        "summary": analysis.summary,
        "counts": {
            "total": findings.len(),
            "byKind": by_kind,
        },
        "findings": findings,
    });
    if let Some(v) = &analysis.witnesses.normalizer_version {
        out.as_object_mut()
            .expect("pack report object")
            .insert("normalizerVersion".to_string(), json!(v));
    }
    out
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthoredExport {
    pub spec: String,
    pub tool: String,
    pub axes: BTreeMap<String, Vec<String>>,
    pub contexts: Vec<AuthoredContextExport>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthoredContextExport {
    pub context: String,
    pub input: Input,
    pub tokens: Vec<AuthoredTokenExport>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthoredTokenExport {
    pub path: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub value: crate::dtcg::DtcgValue,
    pub provenance: TokenProvenance,
}

pub fn build_authored_export(
    doc: &ResolverDoc,
    store: &TokenStore,
    assignments: &[PartialAssignment],
) -> AuthoredExport {
    let mut by_ctx: BTreeMap<String, Vec<AuthoredTokenExport>> = BTreeMap::new();

    for asn in assignments {
        for (ctx_key, av) in &asn.entries {
            by_ctx
                .entry(ctx_key.clone())
                .or_default()
                .push(AuthoredTokenExport {
                    path: asn.token_path.clone(),
                    ty: av.ty.to_string(),
                    value: av.value.clone(),
                    provenance: av.provenance.clone(),
                });
        }
    }

    let mut contexts = Vec::new();
    for (ctx_key, mut tokens) in by_ctx {
        tokens.sort_by(|a, b| a.path.cmp(&b.path));
        contexts.push(AuthoredContextExport {
            context: ctx_key.clone(),
            input: parse_context_key(&ctx_key),
            tokens,
        });
    }

    AuthoredExport {
        spec: doc.version.clone(),
        tool: "tbp-rs".to_string(),
        axes: store.axes.clone(),
        contexts,
    }
}

fn digest_typed(tv: &TypedValue) -> String {
    format!(
        "sha256:{}",
        sha256_hex(tv.to_canonical_json_string().as_bytes())
    )
}

fn eq_value_id_for_mode(mode: ConflictMode) -> &'static str {
    match mode {
        ConflictMode::Semantic => "dtcg-2025.10-typed-structural",
        ConflictMode::Normalized => "dtcg-2025.10-typed-normalized",
    }
}

fn normalizer_version_for_mode(mode: ConflictMode) -> Option<String> {
    match mode {
        ConflictMode::Semantic => None,
        ConflictMode::Normalized => Some(NORMALIZER_VERSION.to_string()),
    }
}

fn normalize_assignments_for_mode(
    assignments: &[PartialAssignment],
    conflict_mode: ConflictMode,
    policy: &Policy,
) -> Vec<PartialAssignment> {
    match conflict_mode {
        ConflictMode::Semantic => assignments.to_vec(),
        ConflictMode::Normalized => assignments
            .iter()
            .map(|asn| {
                let entries = asn
                    .entries
                    .iter()
                    .map(|(ctx_key, av)| {
                        let normalized = AuthoredValue::new(
                            av.ty,
                            policy.normalize(av.ty, &av.value),
                            av.provenance.clone(),
                        );
                        (ctx_key.clone(), normalized)
                    })
                    .collect();
                PartialAssignment {
                    token_path: asn.token_path.clone(),
                    entries,
                }
            })
            .collect(),
    }
}

fn source_id_from_context_key(key: &str) -> String {
    if key == "(base)" {
        return "base".to_string();
    }
    let ctx = parse_context_key(key);
    if ctx.len() == 1 {
        let (axis, val) = ctx.iter().next().unwrap();
        return format!("modifier:{axis}/{val}");
    }
    format!("context:{key}")
}

fn conflict_candidate_from_authored(ctx_key: &str, av: &AuthoredValue) -> CtcConflictCandidate {
    let source_id = if av.provenance.source_id.is_empty() {
        source_id_from_context_key(ctx_key)
    } else {
        av.provenance.source_id.clone()
    };
    let resolution_layer_id = av
        .provenance
        .resolution_layer_id
        .clone()
        .unwrap_or_else(|| source_id.clone());
    let resolution_rank = av.provenance.resolution_rank.unwrap_or(0);
    let pack_id = av
        .provenance
        .pack_id
        .clone()
        .unwrap_or_else(|| "local-pack".to_string());
    let file_path = av
        .provenance
        .file_path
        .clone()
        .unwrap_or_else(|| "(inline)".to_string());
    let file_hash = av
        .provenance
        .file_hash
        .clone()
        .unwrap_or_else(|| "sha256:unknown".to_string());
    let pack_hash = av
        .provenance
        .pack_hash
        .clone()
        .unwrap_or_else(|| file_hash.clone());
    let json_pointer = av
        .provenance
        .json_pointer
        .clone()
        .unwrap_or_else(|| "/$value".to_string());

    CtcConflictCandidate {
        source_context: ctx_key.to_string(),
        source_id,
        resolution_layer_id,
        resolution_rank,
        pack_id,
        pack_version: av.provenance.pack_version.clone(),
        pack_hash,
        file_path,
        file_hash,
        json_pointer,
        value_json: av.value.to_canonical_json_string(),
        value_digest: digest_typed(&TypedValue {
            ty: av.ty,
            value: av.value.clone(),
        }),
    }
}

/// Compute the composability analysis (Kan gaps/conflicts, BC violations, orthogonality).
///
/// This is the target-agnostic part: it operates in the structured IR.
pub fn analyze_composability_with_mode(
    doc: &ResolverDoc,
    store: &TokenStore,
    resolver_path: &Path,
    conflict_mode: ConflictMode,
    policy: &Policy,
) -> Result<CtcAnalysis, ResolverError> {
    analyze_composability_with_mode_and_contexts(
        doc,
        store,
        resolver_path,
        conflict_mode,
        policy,
        crate::contexts::ContextMode::FullOnly,
        None,
    )
}

pub fn analyze_composability_with_mode_and_contexts(
    doc: &ResolverDoc,
    store: &TokenStore,
    resolver_path: &Path,
    conflict_mode: ConflictMode,
    policy: &Policy,
    context_mode: crate::contexts::ContextMode,
    contract_tokens: Option<&BTreeSet<String>>,
) -> Result<CtcAnalysis, ResolverError> {
    let explicit = build_explicit_index(doc, store, resolver_path)?;
    let mut assignments = build_assignments(store, &explicit);
    if let Some(tokens) = contract_tokens {
        assignments.retain(|a| tokens.contains(&a.token_path));
    }
    let assignments_for_analysis =
        normalize_assignments_for_mode(&assignments, conflict_mode, policy);
    let relevant_axes = if context_mode == crate::contexts::ContextMode::FromContracts {
        let mut axes = BTreeSet::new();
        for asn in &assignments_for_analysis {
            for ctx_key in asn.entries.keys() {
                let ctx = parse_context_key(ctx_key);
                for axis in ctx.keys() {
                    axes.insert(axis.clone());
                }
            }
        }
        if axes.is_empty() {
            None
        } else {
            Some(axes)
        }
    } else {
        None
    };
    let contexts = crate::contexts::plan_inputs(context_mode, &store.axes, relevant_axes.as_ref());
    Ok(premath_composability::analyze_assignments(
        &assignments_for_analysis,
        &contexts,
        &store.axes,
        conflict_mode,
        Some(crate::policy::policy_digest(policy)),
        normalizer_version_for_mode(conflict_mode),
        conflict_candidate_from_authored,
        |tv: &TypedValue| tv.to_canonical_json_string(),
        digest_typed,
        |token_path, axis_a, value_a, axis_b, value_b| {
            let mut input = Input::new();
            input.insert(axis_a.to_string(), value_a.to_string());
            input.insert(axis_b.to_string(), value_b.to_string());
            store.token_at(token_path, &input).map(|t| {
                let value = match conflict_mode {
                    ConflictMode::Semantic => t.value.clone(),
                    ConflictMode::Normalized => policy.normalize(t.ty, &t.value),
                };
                value.to_canonical_json_string()
            })
        },
    ))
}

pub fn analyze_composability(
    doc: &ResolverDoc,
    store: &TokenStore,
    resolver_path: &Path,
) -> Result<CtcAnalysis, ResolverError> {
    analyze_composability_with_mode(
        doc,
        store,
        resolver_path,
        ConflictMode::Semantic,
        &Policy::default(),
    )
}

/// Build a CTC manifest that binds inputs/outputs + semantics to a witnesses hash.
pub fn build_ctc_manifest(
    doc: &ResolverDoc,
    resolver_path: &Path,
    store: &TokenStore,
    policy: Option<&Policy>,
    conflict_mode: ConflictMode,
    resolved_json_path: &Path,
    tokens_css_path: Option<&Path>,
    tokens_swift_path: Option<&Path>,
    tokens_kotlin_path: Option<&Path>,
    tokens_dts_path: Option<&Path>,
    authored_json_path: Option<&Path>,
    validation_txt_path: Option<&Path>,
    summary: CtcSummary,
    witnesses_sha256: String,
) -> CtcManifest {
    fn default_pack_id(doc: &ResolverDoc, resolver_path: &Path) -> String {
        if let Some(name) = &doc.name {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        resolver_path
            .file_stem()
            .and_then(|s| s.to_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("pack")
            .to_string()
    }

    let manifest_dir = resolved_json_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let resolver_spec = hash_file_rel(resolver_path, manifest_dir).expect("hash resolver spec");
    let token_docs = build_manifest_rel(doc, resolver_path, manifest_dir);

    let outputs = CtcOutputs {
        resolved_json: hash_file_rel(resolved_json_path, manifest_dir).expect("hash resolved.json"),
        tokens_css: tokens_css_path
            .map(|p| hash_file_rel(p, manifest_dir).expect("hash tokens.css")),
        tokens_swift: tokens_swift_path
            .map(|p| hash_file_rel(p, manifest_dir).expect("hash tokens.swift")),
        tokens_kotlin: tokens_kotlin_path
            .map(|p| hash_file_rel(p, manifest_dir).expect("hash tokens.kt")),
        tokens_dts: tokens_dts_path
            .map(|p| hash_file_rel(p, manifest_dir).expect("hash tokens.d.ts")),
        authored_json: authored_json_path
            .map(|p| hash_file_rel(p, manifest_dir).expect("hash authored.json")),
        validation_txt: validation_txt_path
            .map(|p| hash_file_rel(p, manifest_dir).expect("hash validation.txt")),
    };
    let mut native_versions = NativeApiVersions::default();
    if tokens_swift_path.is_some() {
        native_versions.swift = Some(crate::emit::SWIFT_EMITTER_API_VERSION.to_string());
    }
    if tokens_kotlin_path.is_some() {
        native_versions.kotlin = Some(crate::emit::KOTLIN_EMITTER_API_VERSION.to_string());
    }
    let native_api_versions = if native_versions.swift.is_none() && native_versions.kotlin.is_none()
    {
        None
    } else {
        Some(native_versions)
    };
    let default_pack_id = default_pack_id(doc, resolver_path);
    let parsed_pack = parse_pack_identity_label(&default_pack_id);
    let pack_identity = PackIdentity {
        pack_id: parsed_pack.pack_id.unwrap_or(default_pack_id),
        pack_version: parsed_pack
            .pack_version
            .unwrap_or_else(|| doc.version.clone()),
        content_hash: outputs.resolved_json.sha256.clone(),
    };

    CtcManifest {
        ctc_version: "0.1".to_string(),
        kcir_version: KCIR_VERSION.to_string(),
        tool: ToolInfo {
            name: "tbp-rs".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        spec: doc.version.clone(),
        pack_identity,
        trust: TrustMetadata::unsigned(),
        profile: Some(default_kcir_profile_binding()),
        axes: store.axes.clone(),
        semantics: CtcSemantics {
            eq_value_id: eq_value_id_for_mode(conflict_mode).to_string(),
            policy_digest: policy.map(crate::policy::policy_digest),
            conflict_mode,
            normalizer_version: normalizer_version_for_mode(conflict_mode),
        },
        native_api_versions,
        inputs: CtcInputs {
            resolver_spec,
            token_docs,
        },
        outputs,
        summary,
        witnesses_sha256,
        required_artifacts: Vec::new(),
        admissibility_witnesses_sha256: None,
    }
}

//──────────────────────────────────────────────────────────────────────────────
// Human-readable report
//──────────────────────────────────────────────────────────────────────────────

/// Render a human-readable validation report similar to the prototype's `validation.txt`.
///
/// This is purely a convenience layer over the certified witnesses.
pub fn render_validation_report(store: &TokenStore, analysis: &CtcAnalysis) -> String {
    let mut out = String::new();

    out.push_str("═══════════════════════════════════════\n");
    out.push_str("  AA-VS/TBP Validation Report\n");
    out.push_str("═══════════════════════════════════════\n\n");

    // Orthogonality
    out.push_str("Orthogonality:\n");
    if analysis.witnesses.orthogonality.is_empty() {
        out.push_str("  (no overlaps)\n\n");
    } else {
        for o in &analysis.witnesses.orthogonality {
            out.push_str(&format!(
                "  {} × {}: {} shared token paths\n",
                o.axis_a,
                o.axis_b,
                o.overlap_token_paths.len()
            ));
            for p in &o.overlap_token_paths {
                out.push_str(&format!("    {}\n", p));
            }
        }
        out.push('\n');
    }

    // Beck–Chevalley
    out.push_str("Beck–Chevalley:\n");
    let axis_names: Vec<String> = store.axes.keys().cloned().collect();
    let mut axis_pairs: Vec<(String, String)> = Vec::new();
    for i in 0..axis_names.len() {
        for j in (i + 1)..axis_names.len() {
            axis_pairs.push((axis_names[i].clone(), axis_names[j].clone()));
        }
    }

    let total_tokens = analysis.summary.tokens as u64;

    if axis_pairs.len() == 1 {
        let (a, b) = &axis_pairs[0];
        let total = total_tokens
            * (store.axes.get(a).map(|v| v.len()).unwrap_or(0) as u64)
            * (store.axes.get(b).map(|v| v.len()).unwrap_or(0) as u64);
        let fails = analysis.witnesses.bc_violations.len() as u64;
        let commutes = total.saturating_sub(fails);
        out.push_str(&format!(
            "  ✓ {}/{} token×context pairs commute\n",
            commutes, total
        ));
        if fails == 0 {
            out.push_str("\n");
        } else {
            out.push_str(&format!("  ✗ {} order-dependent resolutions:\n", fails));
            for v in &analysis.witnesses.bc_violations {
                out.push_str(&format!(
                    "    {} @ ({}:{}, {}:{}):\n",
                    v.token_path, v.axis_a, v.value_a, v.axis_b, v.value_b
                ));
                out.push_str(&format!(
                    "      via {}→{}: {}\n",
                    v.axis_a, v.axis_b, v.left_value_json
                ));
                out.push_str(&format!(
                    "      via {}→{}: {}\n",
                    v.axis_b, v.axis_a, v.right_value_json
                ));
                if let Some(chosen) = &v.resolver_value_json {
                    out.push_str(&format!("      resolver chose: {}\n", chosen));
                }
                out.push_str(&format!("      → {}\n", v.fix));
            }
            out.push('\n');
        }
    } else {
        // Multi-axis: summarize per axis pair.
        for (a, b) in axis_pairs {
            let total = total_tokens
                * (store.axes.get(&a).map(|v| v.len()).unwrap_or(0) as u64)
                * (store.axes.get(&b).map(|v| v.len()).unwrap_or(0) as u64);
            let fails = analysis
                .witnesses
                .bc_violations
                .iter()
                .filter(|v| v.axis_a == a && v.axis_b == b)
                .count() as u64;
            let commutes = total.saturating_sub(fails);
            out.push_str(&format!(
                "  {} × {}: ✓ {}/{} commute\n",
                a, b, commutes, total
            ));
        }
        out.push('\n');
    }

    // Kan completion
    out.push_str("Kan completion:\n");
    let total_pairs = (analysis.summary.tokens as u64) * (analysis.summary.contexts as u64);
    let gaps = analysis.summary.kan_gaps as u64;
    let tiebreaks = analysis.summary.kan_conflicts as u64;
    let inherited = analysis.summary.kan_inherited as u64;
    let explicit = total_pairs.saturating_sub(gaps + tiebreaks + inherited);
    out.push_str(&format!(
        "  ✓ {}/{} explicit values\n",
        explicit, total_pairs
    ));
    out.push_str(&format!(
        "  ⚠ {}/{} inherited (unique ancestor, no explicit value)\n",
        inherited, total_pairs
    ));
    out.push_str(&format!(
        "  ✗ {}/{} tiebreaks (conflicting ancestors)\n",
        tiebreaks, total_pairs
    ));
    out.push_str(&format!(
        "  ✗ {}/{} gaps (no ancestor)\n",
        gaps, total_pairs
    ));

    out
}

//──────────────────────────────────────────────────────────────────────────────
// Manifest helpers
//──────────────────────────────────────────────────────────────────────────────

pub fn hash_file(path: &Path) -> Option<ManifestEntry> {
    let bytes = fs::read(path).ok()?;
    let size = bytes.len() as u64;
    let sha256 = format!("sha256:{}", sha256_hex(&bytes));
    Some(ManifestEntry {
        file: path.display().to_string(),
        sha256,
        size,
    })
}

fn relpath(manifest_dir: &Path, target: &Path) -> Option<String> {
    // Compute a stable relative path from `manifest_dir` (directory containing the manifest)
    // to `target`. If we cannot compute one, return None.
    let base_abs = std::fs::canonicalize(manifest_dir).ok()?;
    let target_abs = std::fs::canonicalize(target).ok()?;

    let base_comps: Vec<_> = base_abs.components().collect();
    let target_comps: Vec<_> = target_abs.components().collect();

    let mut i = 0usize;
    while i < base_comps.len() && i < target_comps.len() && base_comps[i] == target_comps[i] {
        i += 1;
    }

    let mut rel = PathBuf::new();
    for _ in i..base_comps.len() {
        rel.push("..");
    }
    for c in &target_comps[i..] {
        rel.push(c.as_os_str());
    }

    Some(rel.display().to_string())
}

pub fn hash_file_rel(path: &Path, manifest_dir: &Path) -> Option<ManifestEntry> {
    let bytes = fs::read(path).ok()?;
    let size = bytes.len() as u64;
    let sha256 = format!("sha256:{}", sha256_hex(&bytes));
    let file = relpath(manifest_dir, path).unwrap_or_else(|| path.display().to_string());
    Some(ManifestEntry { file, sha256, size })
}

pub fn required_artifact_binding(
    kind: RequiredArtifactKind,
    path: &Path,
    manifest_dir: &Path,
) -> RequiredArtifactBinding {
    RequiredArtifactBinding {
        kind,
        entry: hash_file_rel(path, manifest_dir).expect("hash required artifact"),
    }
}

fn collect_ref_paths(doc: &ResolverDoc, resolver_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for set in doc.sets.values() {
        for src in &set.sources {
            if let Some(r) = &src.r#ref {
                if !r.starts_with("#/") {
                    out.push(resolver_dir.join(r));
                }
            }
        }
    }
    for modifier in doc.modifiers.values() {
        for ctx in modifier.contexts.values() {
            for src in &ctx.sources {
                if let Some(r) = &src.r#ref {
                    if !r.starts_with("#/") {
                        out.push(resolver_dir.join(r));
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

pub fn build_manifest(doc: &ResolverDoc, resolver_path: &Path) -> Vec<ManifestEntry> {
    let dir = resolver_path.parent().unwrap_or_else(|| Path::new("."));
    collect_ref_paths(doc, dir)
        .into_iter()
        .filter_map(|p| hash_file(&p))
        .collect()
}

/// Build a manifest of referenced token docs, storing paths relative to `manifest_dir`.
pub fn build_manifest_rel(
    doc: &ResolverDoc,
    resolver_path: &Path,
    manifest_dir: &Path,
) -> Vec<ManifestEntry> {
    let dir = resolver_path.parent().unwrap_or_else(|| Path::new("."));
    collect_ref_paths(doc, dir)
        .into_iter()
        .filter_map(|p| hash_file_rel(&p, manifest_dir))
        .collect()
}
