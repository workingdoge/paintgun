//! Multi-pack composition.
//!
//! Composition model (v1):
//! - Each pack is a standard `paint` build output directory containing:
//!   - `resolved.json`
//!   - `ctc.manifest.json`
//!   - `ctc.witnesses.json`
//!   - (optional) `authored.json`
//! - We compose packs by **layering their resolved token sets** in pack order.
//!   Later packs override earlier ones (LWW) *per token path*.
//! - Packs may have different axes; a pack is evaluated at a composed context
//!   by projecting the context onto the pack's axis set.
//!
//! The output is:
//! - a composed `TokenStore` (for emission)
//! - a meta-certificate describing **cross-pack conflicts** (order dependence)
//!
//! This is distinct from the per-pack CTC (Kan/BC inside a pack).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use premath_compose::{
    assemble_conflicts, check_required_signed, prefix_pack_diagnostics, summarize_pack_paths,
    verify_pack_with_callbacks, verify_witnesses_payload,
    ComposeCandidateInput as ComposeKernelCandidateInput, ExternalVerifyOutcome, PackEntryBytes,
};

use crate::analysis::{kan_diag, KanDiag};
use crate::artifact::{read_resolved_json, stable_context_key, token_value_at};
use crate::cert::{
    AuthoredExport, ConflictMode, CtcManifest, CtcWitnesses, ManifestEntry, TrustStatus,
    NORMALIZER_VERSION,
};
use crate::dtcg::{DtcgType, TypedValue};
use crate::ids::{TokenPathId, WitnessId};
use crate::pack_identity::parse_pack_identity_label;
use crate::policy::Policy;
use crate::provenance::{AuthoredValue, TokenProvenance};
use crate::resolver::{parse_context_key, Input, ResolvedToken, TokenStore};
use crate::util::sha256_hex;
use crate::verify::{
    validate_manifest_profile_binding, validate_manifest_required_artifacts, verify_ctc,
    verify_ctc_with_options, CtcVerifyOptions, VerifyProfile,
};

pub use premath_compose::COMPOSE_WITNESS_SCHEMA_VERSION;
pub type ComposeInheritedRef = premath_compose::ComposeInheritedRef<WitnessId>;
pub type ComposeCandidateSource = premath_compose::ComposeCandidateSource<TokenProvenance>;
pub type ComposeConflictCandidate =
    premath_compose::ComposeConflictCandidate<ComposeInheritedRef, ComposeCandidateSource>;
pub type ComposeConflictWitness = premath_compose::ComposeConflictWitness<
    WitnessId,
    TokenPathId,
    ComposeInheritedRef,
    ComposeCandidateSource,
>;
pub type ComposeWitnesses = premath_compose::ComposeWitnesses<
    ConflictMode,
    WitnessId,
    TokenPathId,
    ComposeInheritedRef,
    ComposeCandidateSource,
>;
pub type ComposeSummary = premath_compose::ComposeSummary;
pub type ComposePackEntry =
    premath_compose::ComposePackEntry<crate::cert::PackIdentity, ManifestEntry>;
pub type ComposeManifest = premath_compose::ComposeManifest<
    crate::cert::ToolInfo,
    crate::cert::TrustMetadata,
    crate::cert::CtcSemantics,
    crate::cert::NativeApiVersions,
    crate::cert::PackIdentity,
    ManifestEntry,
>;
pub type ComposeVerifyError = premath_compose::ComposeVerifyError;
pub type ComposeVerifyReport = premath_compose::ComposeVerifyReport;
use premath_compose::push_verify_error as push_compose_error;

pub mod error_codes {
    pub use premath_compose::verify_error_codes::*;
}

#[derive(Clone, Debug)]
pub struct Pack {
    pub name: String,
    pub dir: PathBuf,
    pub ctc_manifest: CtcManifest,
    /// Per-pack witnesses (loaded from `ctc.witnesses.json`) for transitive linkage.
    pub ctc_witnesses: Option<CtcWitnesses>,
    pub store: TokenStore,
    /// Optional authored index for richer provenance.
    /// token_path -> (contextKey -> authored value)
    pub authored_by_token: Option<HashMap<String, HashMap<String, AuthoredValue>>>,
}

fn default_pack_name(dir: &Path) -> String {
    dir.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("pack")
        .to_string()
}

pub fn load_pack(dir: &Path, verify: bool, require_pack_composable: bool) -> Result<Pack, String> {
    let manifest_path = dir.join("ctc.manifest.json");
    let witnesses_path = dir.join("ctc.witnesses.json");
    let resolved_path = dir.join("resolved.json");

    if verify {
        let rep = verify_ctc(
            &manifest_path,
            Some(&witnesses_path),
            require_pack_composable,
        );
        if !rep.ok {
            let mut msg = format!("pack certificate verification failed for {}", dir.display());
            for e in rep.errors {
                msg.push_str(&format!("\n  - {e}"));
            }
            return Err(msg);
        }
    }

    let manifest_bytes = fs::read(&manifest_path).map_err(|e| e.to_string())?;
    let ctc_manifest: CtcManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|e| e.to_string())?;
    let witness_bytes = fs::read(&witnesses_path).map_err(|e| e.to_string())?;
    let ctc_witnesses: CtcWitnesses =
        serde_json::from_slice(&witness_bytes).map_err(|e| e.to_string())?;
    ctc_witnesses.validate_schema_version().map_err(|e| {
        format!(
            "invalid ctc.witnesses.json schema version for {}: {e}",
            dir.display()
        )
    })?;
    let store = read_resolved_json(&resolved_path)?;

    // Optional authored index for richer provenance in meta-certs.
    let authored_path = dir.join("authored.json");
    let authored_by_token = if authored_path.exists() {
        let bytes = fs::read(&authored_path).map_err(|e| e.to_string())?;
        let authored: AuthoredExport = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        Some(index_authored(&authored)?)
    } else {
        None
    };

    let pack_name = if ctc_manifest.pack_identity.pack_id.trim().is_empty() {
        default_pack_name(dir)
    } else if ctc_manifest.pack_identity.pack_version.trim().is_empty() {
        ctc_manifest.pack_identity.pack_id.clone()
    } else {
        format!(
            "{}@{}",
            ctc_manifest.pack_identity.pack_id, ctc_manifest.pack_identity.pack_version
        )
    };
    Ok(Pack {
        name: pack_name,
        dir: dir.to_path_buf(),
        ctc_manifest,
        ctc_witnesses: Some(ctc_witnesses),
        store,
        authored_by_token,
    })
}

fn index_authored(
    authored: &AuthoredExport,
) -> Result<HashMap<String, HashMap<String, AuthoredValue>>, String> {
    let mut out: HashMap<String, HashMap<String, AuthoredValue>> = HashMap::new();
    for ctx in &authored.contexts {
        for tok in &ctx.tokens {
            let ty: DtcgType = tok.ty.parse().map_err(|e: String| e)?;
            out.entry(tok.path.clone())
                .or_insert_with(HashMap::new)
                .insert(
                    ctx.context.clone(),
                    AuthoredValue::new(ty, tok.value.clone(), tok.provenance.clone()),
                );
        }
    }
    Ok(out)
}

/// Union axes across packs.
pub fn union_axes(packs: &[Pack]) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for p in packs {
        for (axis, vals) in &p.store.axes {
            out.entry(axis.clone())
                .or_default()
                .extend(vals.iter().cloned());
        }
    }
    for (_axis, vals) in out.iter_mut() {
        vals.sort();
        vals.dedup();
    }
    out
}

/// Enumerate all partial selections over axes: each axis absent or set to a value.
pub fn enumerate_partial_inputs(axes: &BTreeMap<String, Vec<String>>) -> Vec<Input> {
    crate::contexts::partial_inputs(axes)
}

fn project_input(input: &Input, axes: &BTreeMap<String, Vec<String>>) -> Input {
    let mut out = Input::new();
    for (k, v) in input {
        if axes.contains_key(k) {
            out.insert(k.clone(), v.clone());
        }
    }
    out
}

/// Compose multiple packs into a single store by LWW-per-token across packs.
pub fn compose_store(packs: &[Pack]) -> TokenStore {
    compose_store_with_context_mode(packs, crate::contexts::ContextMode::Partial, None)
}

pub fn relevant_axes_for_contract_tokens(
    packs: &[Pack],
    contract_tokens: &BTreeSet<String>,
) -> Option<BTreeSet<String>> {
    if contract_tokens.is_empty() {
        return None;
    }
    let mut axes = BTreeSet::new();
    for pack in packs {
        for (ctx_key, tokens) in &pack.store.resolved_by_ctx {
            if !tokens.iter().any(|t| contract_tokens.contains(&t.path)) {
                continue;
            }
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
}

pub fn compose_store_with_context_mode(
    packs: &[Pack],
    context_mode: crate::contexts::ContextMode,
    contract_tokens: Option<&BTreeSet<String>>,
) -> TokenStore {
    let axes = union_axes(packs);
    let relevant_axes = match (context_mode, contract_tokens) {
        (crate::contexts::ContextMode::FromContracts, Some(tokens)) => {
            relevant_axes_for_contract_tokens(packs, tokens)
        }
        _ => None,
    };
    let inputs = crate::contexts::plan_inputs(context_mode, &axes, relevant_axes.as_ref());

    let mut resolved_by_ctx: HashMap<String, Vec<ResolvedToken>> = HashMap::new();

    for input in inputs {
        let ck = stable_context_key(&input);

        // LWW per token path in pack order.
        let mut by_path: HashMap<String, ResolvedToken> = HashMap::new();
        for pack in packs {
            let proj = project_input(&input, &pack.store.axes);
            for t in pack.store.tokens_at(&proj) {
                if let Some(tokens) = contract_tokens {
                    if !tokens.contains(&t.path) {
                        continue;
                    }
                }
                let mut tok = t.clone();
                // stamp source with pack name for debugging
                tok.source = format!("{}:{}", pack.name, tok.source);
                by_path.insert(tok.path.clone(), tok);
            }
        }

        let mut toks: Vec<ResolvedToken> = by_path.into_values().collect();
        toks.sort_by(|a, b| a.path.cmp(&b.path));
        resolved_by_ctx.insert(ck, toks);
    }

    TokenStore {
        axes,
        resolved_by_ctx,
    }
}

//──────────────────────────────────────────────────────────────────────────────
// Meta-certificate for cross-pack composition
//──────────────────────────────────────────────────────────────────────────────

fn hash_file_entry(path: &Path) -> Result<ManifestEntry, String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    Ok(ManifestEntry {
        file: path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("file")
            .to_string(),
        sha256: format!("sha256:{}", sha256_hex(&bytes)),
        size: bytes.len() as u64,
    })
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

fn json_pointer_for_token_path(path: &str) -> String {
    let esc = |seg: &str| seg.replace('~', "~0").replace('/', "~1");
    if path.is_empty() {
        return "/$value".to_string();
    }
    format!(
        "/{}/$value",
        path.split('.').map(esc).collect::<Vec<_>>().join("/")
    )
}

fn stamp_pack_identity(
    pack: &Pack,
    token_path: &str,
    pack_rank: u64,
    mut prov: TokenProvenance,
) -> TokenProvenance {
    let parsed = parse_pack_identity_label(&pack.name);
    if prov.source_id.is_empty() {
        prov.source_id = "resolved".to_string();
    }
    if prov.pack_id.is_none() {
        prov.pack_id = parsed.pack_id.or_else(|| Some(pack.name.clone()));
    }
    if prov.pack_version.is_none() {
        prov.pack_version = parsed.pack_version;
    }
    if prov.pack_hash.is_none() {
        prov.pack_hash = parsed
            .pack_hash
            .or_else(|| Some(pack.ctc_manifest.inputs.resolver_spec.sha256.clone()));
    }
    if prov.file_path.is_none() {
        prov.file_path = Some(pack.ctc_manifest.outputs.resolved_json.file.clone());
    }
    if prov.file_hash.is_none() {
        prov.file_hash = Some(pack.ctc_manifest.outputs.resolved_json.sha256.clone());
    }
    if prov.json_pointer.is_none() {
        prov.json_pointer = Some(json_pointer_for_token_path(token_path));
    }
    if prov.resolution_layer_id.is_none() {
        prov.resolution_layer_id = Some("compose:pack-order".to_string());
    }
    if prov.resolution_rank.is_none() {
        prov.resolution_rank = Some(pack_rank);
    }
    prov
}

fn fallback_source_for_value(
    pack: &Pack,
    token_path: &str,
    target: &Input,
    pack_rank: u64,
) -> ComposeCandidateSource {
    let parsed = parse_pack_identity_label(&pack.name);
    let prov = TokenProvenance {
        source_id: "resolved".to_string(),
        resolution_layer_id: Some("compose:pack-order".to_string()),
        resolution_rank: Some(pack_rank),
        pack_id: parsed.pack_id.or_else(|| Some(pack.name.clone())),
        pack_version: parsed.pack_version,
        pack_hash: parsed
            .pack_hash
            .or_else(|| Some(pack.ctc_manifest.inputs.resolver_spec.sha256.clone())),
        file_path: Some(pack.ctc_manifest.outputs.resolved_json.file.clone()),
        file_hash: Some(pack.ctc_manifest.outputs.resolved_json.sha256.clone()),
        json_pointer: Some(json_pointer_for_token_path(token_path)),
    };
    ComposeCandidateSource {
        context: stable_context_key(target),
        provenance: prov,
    }
}

fn best_sources_for_value(
    pack: &Pack,
    token_path: &str,
    target: &Input,
    tv: &TypedValue,
    conflict_mode: ConflictMode,
    policy: &Policy,
    pack_rank: u64,
) -> Vec<ComposeCandidateSource> {
    let authored = match &pack.authored_by_token {
        None => {
            return vec![fallback_source_for_value(
                pack, token_path, target, pack_rank,
            )]
        }
        Some(a) => a,
    };
    let entries = match authored.get(token_path) {
        None => {
            return vec![fallback_source_for_value(
                pack, token_path, target, pack_rank,
            )]
        }
        Some(e) => e,
    };

    let normalized_entries = if conflict_mode == ConflictMode::Normalized {
        let mut out = HashMap::new();
        for (ctx_key, av) in entries {
            out.insert(
                ctx_key.clone(),
                AuthoredValue::new(
                    av.ty,
                    policy.normalize(av.ty, &av.value),
                    av.provenance.clone(),
                ),
            );
        }
        out
    } else {
        entries.clone()
    };

    let out = match kan_diag(&normalized_entries, target) {
        KanDiag::Consistent { sources, .. } => sources
            .into_iter()
            .filter_map(|ctx_key| {
                entries.get(&ctx_key).map(|av| ComposeCandidateSource {
                    context: ctx_key,
                    provenance: stamp_pack_identity(
                        pack,
                        token_path,
                        pack_rank,
                        av.provenance.clone(),
                    ),
                })
            })
            .collect::<Vec<_>>(),

        KanDiag::Conflict { candidates } => {
            // Prefer contexts that match the resolved value (if any).
            let mut out = Vec::new();
            for cand in candidates {
                if cand.1.ty == tv.ty && cand.1.value == tv.value {
                    if let Some(av) = entries.get(&cand.0) {
                        out.push(ComposeCandidateSource {
                            context: cand.0,
                            provenance: stamp_pack_identity(
                                pack,
                                token_path,
                                pack_rank,
                                av.provenance.clone(),
                            ),
                        });
                    }
                }
            }
            out
        }

        KanDiag::Gap => Vec::new(),
    };

    let mut out = if out.is_empty() {
        vec![fallback_source_for_value(
            pack, token_path, target, pack_rank,
        )]
    } else {
        out
    };
    out.sort_by(|a, b| {
        a.context
            .cmp(&b.context)
            .then(a.provenance.source_id.cmp(&b.provenance.source_id))
            .then(a.provenance.file_path.cmp(&b.provenance.file_path))
            .then(a.provenance.json_pointer.cmp(&b.provenance.json_pointer))
    });
    out
}

fn inherited_refs_for_value(
    pack: &Pack,
    token_path: &str,
    target: &Input,
    value_digest: &str,
) -> Vec<ComposeInheritedRef> {
    let Some(w) = &pack.ctc_witnesses else {
        return Vec::new();
    };

    let target_key = stable_context_key(target);
    let mut refs: BTreeSet<(String, WitnessId)> = BTreeSet::new();

    for iw in &w.inherited {
        if iw.token_path == token_path
            && iw.target == target_key
            && iw.resolved_value_digest == value_digest
        {
            refs.insert(("inherited".to_string(), iw.witness_id.clone().into()));
        }
    }
    for cw in &w.conflicts {
        if cw.token_path == token_path
            && cw.target == target_key
            && cw.candidates.iter().any(|c| c.value_digest == value_digest)
        {
            refs.insert(("conflict".to_string(), cw.witness_id.clone().into()));
        }
    }

    refs.into_iter()
        .map(|(witness_type, witness_id)| ComposeInheritedRef {
            pack: pack.name.clone(),
            witness_type,
            witness_id,
        })
        .collect()
}

/// Compute cross-pack conflicts for a composed system.
///
/// A conflict exists when 2+ packs provide different **typed** values
/// for the same token path at the same composed context.
pub fn analyze_cross_pack_conflicts_with_mode(
    packs: &[Pack],
    axes: &BTreeMap<String, Vec<String>>,
    conflict_mode: ConflictMode,
    policy: &Policy,
) -> ComposeWitnesses {
    analyze_cross_pack_conflicts_with_mode_and_contexts(
        packs,
        axes,
        conflict_mode,
        policy,
        crate::contexts::ContextMode::Partial,
        None,
    )
}

pub fn analyze_cross_pack_conflicts_with_mode_and_contexts(
    packs: &[Pack],
    axes: &BTreeMap<String, Vec<String>>,
    conflict_mode: ConflictMode,
    policy: &Policy,
    context_mode: crate::contexts::ContextMode,
    contract_tokens: Option<&BTreeSet<String>>,
) -> ComposeWitnesses {
    let token_filter = contract_tokens.filter(|s| !s.is_empty());

    // Token-path universe + overlap count.
    let mut counts: HashMap<String, usize> = HashMap::new();
    for p in packs {
        let mut p_paths: HashSet<String> = HashSet::new();
        for toks in p.store.resolved_by_ctx.values() {
            for t in toks {
                if let Some(tokens) = token_filter {
                    if !tokens.contains(&t.path) {
                        continue;
                    }
                }
                p_paths.insert(t.path.clone());
            }
        }
        for path in p_paths {
            *counts.entry(path.clone()).or_insert(0) += 1;
        }
    }

    let overlap_paths: BTreeSet<String> = counts
        .iter()
        .filter(|(_k, c)| **c >= 2)
        .map(|(k, _)| k.clone())
        .collect();

    let relevant_axes = match (context_mode, token_filter) {
        (crate::contexts::ContextMode::FromContracts, Some(tokens)) => {
            relevant_axes_for_contract_tokens(packs, tokens)
        }
        _ => None,
    };
    let contexts = crate::contexts::plan_inputs(context_mode, axes, relevant_axes.as_ref());

    let conflict_drafts = assemble_conflicts(
        &contexts,
        &overlap_paths,
        stable_context_key,
        |ctx, path| {
            let mut candidates_all: Vec<
                ComposeKernelCandidateInput<
                    TypedValue,
                    ComposeInheritedRef,
                    ComposeCandidateSource,
                >,
            > = Vec::new();
            for (pack_rank, pack) in packs.iter().enumerate() {
                let proj = project_input(ctx, &pack.store.axes);
                if let Some((ty, v)) = token_value_at(&pack.store, path, &proj) {
                    let value = match conflict_mode {
                        ConflictMode::Semantic => v,
                        ConflictMode::Normalized => policy.normalize(ty, &v),
                    };
                    let tv = TypedValue { ty, value };
                    let value_digest = digest_typed(&tv);
                    let inherited_from = inherited_refs_for_value(pack, path, &proj, &value_digest);
                    let sources = best_sources_for_value(
                        pack,
                        path,
                        &proj,
                        &tv,
                        conflict_mode,
                        policy,
                        pack_rank as u64,
                    );
                    candidates_all.push(ComposeKernelCandidateInput {
                        pack_name: pack.name.clone(),
                        value_type: tv.ty.to_string(),
                        value_json: tv.value.to_canonical_json_string(),
                        value_digest,
                        value: tv,
                        inherited_from,
                        sources,
                    });
                }
            }
            candidates_all
        },
    );

    let conflicts: Vec<ComposeConflictWitness> = conflict_drafts
        .into_iter()
        .map(|d| ComposeConflictWitness {
            witness_id: d.witness_id.into(),
            token_path: d.token_path.into(),
            context: d.context,
            candidates: d
                .candidates
                .into_iter()
                .map(|c| ComposeConflictCandidate {
                    pack: c.pack,
                    value_type: c.value_type,
                    value_json: c.value_json,
                    value_digest: c.value_digest,
                    inherited_from: c.inherited_from,
                    sources: c.sources,
                })
                .collect(),
            winner_pack: d.winner_pack,
        })
        .collect();

    ComposeWitnesses {
        witness_schema: COMPOSE_WITNESS_SCHEMA_VERSION,
        conflict_mode,
        policy_digest: Some(crate::policy::policy_digest(policy)),
        normalizer_version: normalizer_version_for_mode(conflict_mode),
        conflicts,
    }
}

pub fn analyze_cross_pack_conflicts(
    packs: &[Pack],
    axes: &BTreeMap<String, Vec<String>>,
) -> ComposeWitnesses {
    analyze_cross_pack_conflicts_with_mode(packs, axes, ConflictMode::Semantic, &Policy::default())
}

pub fn build_compose_manifest(
    packs: &[Pack],
    manifest_dir: &Path,
    axes: &BTreeMap<String, Vec<String>>,
    policy: &Policy,
    conflict_mode: ConflictMode,
    native_api_versions: Option<crate::cert::NativeApiVersions>,
    witnesses_sha256: String,
    witnesses: &ComposeWitnesses,
) -> Result<ComposeManifest, String> {
    build_compose_manifest_with_context_count(
        packs,
        manifest_dir,
        axes,
        policy,
        conflict_mode,
        native_api_versions,
        witnesses_sha256,
        enumerate_partial_inputs(axes).len(),
        witnesses,
    )
}

pub fn build_compose_manifest_with_context_count(
    packs: &[Pack],
    manifest_dir: &Path,
    axes: &BTreeMap<String, Vec<String>>,
    policy: &Policy,
    conflict_mode: ConflictMode,
    native_api_versions: Option<crate::cert::NativeApiVersions>,
    witnesses_sha256: String,
    context_count: usize,
    witnesses: &ComposeWitnesses,
) -> Result<ComposeManifest, String> {
    let mut pack_entries: Vec<ComposePackEntry> = Vec::new();
    for p in packs {
        let ctc_manifest_path = p.dir.join("ctc.manifest.json");
        let ctc_witnesses_path = p.dir.join("ctc.witnesses.json");
        let resolved_json_path = p.dir.join("resolved.json");
        let authored_json_path = p.dir.join("authored.json");

        pack_entries.push(ComposePackEntry {
            name: p.name.clone(),
            dir: crate::cert::relpath(manifest_dir, &p.dir)
                .unwrap_or_else(|| p.dir.display().to_string()),
            pack_identity: p.ctc_manifest.pack_identity.clone(),
            ctc_manifest: hash_file_entry(&ctc_manifest_path)?,
            ctc_witnesses: hash_file_entry(&ctc_witnesses_path)?,
            resolved_json: hash_file_entry(&resolved_json_path)?,
            authored_json: if authored_json_path.exists() {
                Some(hash_file_entry(&authored_json_path)?)
            } else {
                None
            },
        });
    }
    pack_entries.sort_by(|a, b| a.name.cmp(&b.name));

    let summary = summarize_pack_paths(
        packs.iter().map(|p| {
            p.store
                .resolved_by_ctx
                .values()
                .flat_map(|toks| toks.iter().map(|t| t.path.clone()))
                .collect::<Vec<_>>()
        }),
        context_count,
        witnesses.conflicts.len(),
    );

    Ok(ComposeManifest {
        compose_version: "0.1".to_string(),
        tool: crate::cert::ToolInfo {
            name: "paintgun".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        axes: axes.clone(),
        pack_order: packs.iter().map(|p| p.name.clone()).collect(),
        packs: pack_entries,
        trust: crate::cert::TrustMetadata::unsigned(),
        semantics: crate::cert::CtcSemantics {
            eq_value_id: eq_value_id_for_mode(conflict_mode).to_string(),
            policy_digest: Some(crate::policy::policy_digest(policy)),
            conflict_mode,
            normalizer_version: normalizer_version_for_mode(conflict_mode),
        },
        native_api_versions,
        summary,
        witnesses_sha256,
    })
}

pub fn render_compose_report(manifest: &ComposeManifest, witnesses: &ComposeWitnesses) -> String {
    premath_compose::render_compose_report_text(
        manifest,
        witnesses,
        |r| format!("{}/{}/{}", r.pack, r.witness_type, r.witness_id),
        |s| s.context.clone(),
        |s| s.provenance.file_path.clone(),
        |s| s.provenance.json_pointer.clone(),
    )
}

pub fn build_compose_report_json(
    manifest: &ComposeManifest,
    witnesses: &ComposeWitnesses,
) -> serde_json::Value {
    premath_compose::build_compose_report_json_value(
        manifest,
        witnesses,
        |s| s.provenance.file_path.clone(),
        |s| s.provenance.json_pointer.clone(),
        |s| s.provenance.pack_id.clone(),
    )
}

//──────────────────────────────────────────────────────────────────────────────
// Verification
//──────────────────────────────────────────────────────────────────────────────

pub fn verify_compose(
    manifest_path: &Path,
    witnesses_path: Option<&Path>,
    verify_packs: bool,
    require_packs_composable: bool,
) -> ComposeVerifyReport {
    verify_compose_with_signing(
        manifest_path,
        witnesses_path,
        verify_packs,
        require_packs_composable,
        false,
        false,
        VerifyProfile::Core,
    )
}

pub fn verify_compose_with_signing(
    manifest_path: &Path,
    witnesses_path: Option<&Path>,
    verify_packs: bool,
    require_packs_composable: bool,
    require_signed: bool,
    require_packs_signed: bool,
    pack_profile: VerifyProfile,
) -> ComposeVerifyReport {
    let mut errors: Vec<String> = Vec::new();
    let mut error_details: Vec<ComposeVerifyError> = Vec::new();
    let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let compose_root = manifest_dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let manifest_bytes = match fs::read(manifest_path) {
        Ok(b) => b,
        Err(e) => {
            push_compose_error(
                &mut errors,
                &mut error_details,
                error_codes::MANIFEST_READ_ERROR,
                format!("failed to read compose manifest: {e}"),
            );
            return ComposeVerifyReport {
                ok: false,
                errors,
                error_details,
            };
        }
    };
    let manifest: ComposeManifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(m) => m,
        Err(e) => {
            push_compose_error(
                &mut errors,
                &mut error_details,
                error_codes::MANIFEST_PARSE_ERROR,
                format!("failed to parse compose manifest: {e}"),
            );
            return ComposeVerifyReport {
                ok: false,
                errors,
                error_details,
            };
        }
    };
    if let Some(e) = check_required_signed(
        require_signed,
        manifest.trust.status == TrustStatus::Signed,
        "compose manifest trust.status must be 'signed'",
    ) {
        push_compose_error(&mut errors, &mut error_details, &e.code, e.message);
    }
    if manifest.trust.status == TrustStatus::Signed {
        if let Err(e) = crate::signing::verify_compose_signature(manifest_path, &manifest) {
            push_compose_error(
                &mut errors,
                &mut error_details,
                error_codes::SIGNATURE_INVALID,
                format!("compose signature verification failed: {e}"),
            );
        }
    }

    let witnesses_path = witnesses_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| manifest_dir.join("compose.witnesses.json"));

    // Verify witnesses binding
    match fs::read(&witnesses_path) {
        Ok(wb) => {
            let (_parsed, witness_errors) =
                verify_witnesses_payload::<ComposeWitnesses>(&manifest.witnesses_sha256, &wb);
            for e in witness_errors {
                push_compose_error(&mut errors, &mut error_details, &e.code, e.message);
            }
        }
        Err(e) => push_compose_error(
            &mut errors,
            &mut error_details,
            error_codes::WITNESSES_READ_ERROR,
            format!("failed to read compose witnesses: {e}"),
        ),
    }

    // Verify pack artifacts + referenced per-pack manifests
    for p in &manifest.packs {
        let dir =
            match crate::path_safety::resolve_existing_within(manifest_dir, &p.dir, compose_root) {
                Ok(d) => d,
                Err(e) => {
                    push_compose_error(
                        &mut errors,
                        &mut error_details,
                        error_codes::PATH_UNSAFE,
                        format!("[{}:dir] unsafe pack dir {}: {e}", p.name, p.dir),
                    );
                    continue;
                }
            };

        for e in verify_pack_with_callbacks(
            p,
            require_packs_signed,
            verify_packs,
            error_codes::PACK_VERIFICATION_FAILED,
            |label, entry| {
                let path =
                    crate::path_safety::resolve_existing_within(&dir, &entry.file, compose_root)
                        .map_err(|e| ComposeVerifyError {
                            code: error_codes::PATH_UNSAFE.to_string(),
                            message: format!(
                                "[{}:{}] unsafe manifest path {}: {e}",
                                p.name, label, entry.file
                            ),
                        })?;
                let bytes = fs::read(&path).map_err(|e| ComposeVerifyError {
                    code: error_codes::FILE_READ_ERROR.to_string(),
                    message: format!(
                        "[{}:{}] failed to read {}: {e}",
                        p.name,
                        label,
                        path.display()
                    ),
                })?;
                Ok(PackEntryBytes {
                    display_path: path.display().to_string(),
                    bytes,
                })
            },
            |entry| (entry.sha256.clone(), entry.size),
            |payload| {
                serde_json::from_slice::<CtcManifest>(&payload.bytes).map_err(|e| {
                    ComposeVerifyError {
                        code: error_codes::MANIFEST_PARSE_ERROR.to_string(),
                        message: format!(
                            "[{}:ctcManifest] failed to parse referenced ctc manifest {}: {e}",
                            p.name, payload.display_path
                        ),
                    }
                })
            },
            |inner_manifest| {
                let mut out = Vec::new();
                out.extend(prefix_pack_diagnostics(
                    &p.name,
                    validate_manifest_profile_binding(inner_manifest),
                    |e| e.code.as_str(),
                    |e| e.message.clone(),
                ));
                out.extend(prefix_pack_diagnostics(
                    &p.name,
                    validate_manifest_required_artifacts(inner_manifest, pack_profile),
                    |e| e.code.as_str(),
                    |e| e.message.clone(),
                ));
                out
            },
            |pack| {
                (
                    pack.pack_identity.pack_id.clone(),
                    pack.pack_identity.pack_version.clone(),
                    pack.pack_identity.content_hash.clone(),
                )
            },
            |inner_manifest| {
                (
                    inner_manifest.pack_identity.pack_id.clone(),
                    inner_manifest.pack_identity.pack_version.clone(),
                    inner_manifest.pack_identity.content_hash.clone(),
                )
            },
            |inner_manifest| inner_manifest.trust.status == TrustStatus::Signed,
            |inner_manifest, payload| {
                crate::signing::verify_ctc_signature(
                    Path::new(&payload.display_path),
                    inner_manifest,
                )
                .map_err(|e| ComposeVerifyError {
                    code: error_codes::SIGNATURE_INVALID.to_string(),
                    message: format!("[{}:trust] pack signature verification failed: {e}", p.name),
                })
            },
            || {
                let ctc_manifest_path = crate::path_safety::resolve_existing_within(
                    &dir,
                    &p.ctc_manifest.file,
                    compose_root,
                )
                .map_err(|e| ComposeVerifyError {
                    code: error_codes::PATH_UNSAFE.to_string(),
                    message: format!(
                        "[{}:ctcManifest] unsafe manifest path {}: {e}",
                        p.name, p.ctc_manifest.file
                    ),
                })?;
                let ctc_witnesses_path = crate::path_safety::resolve_existing_within(
                    &dir,
                    &p.ctc_witnesses.file,
                    compose_root,
                )
                .map_err(|e| ComposeVerifyError {
                    code: error_codes::PATH_UNSAFE.to_string(),
                    message: format!(
                        "[{}:ctcWitnesses] unsafe manifest path {}: {e}",
                        p.name, p.ctc_witnesses.file
                    ),
                })?;
                let rep = verify_ctc_with_options(
                    &ctc_manifest_path,
                    CtcVerifyOptions {
                        witnesses_path: Some(&ctc_witnesses_path),
                        require_composable: require_packs_composable,
                        allowlist: None,
                        require_signed: require_packs_signed,
                        profile: pack_profile,
                        admissibility_witnesses_path: None,
                        expected_profile_anchors: None,
                    },
                );
                Ok(ExternalVerifyOutcome {
                    ok: rep.ok,
                    errors: rep.errors,
                    error_details: rep.error_details,
                })
            },
            |e| e.code.as_str(),
            |e| e.message.as_str(),
        ) {
            push_compose_error(&mut errors, &mut error_details, &e.code, e.message);
        }
    }

    ComposeVerifyReport {
        ok: errors.is_empty(),
        errors,
        error_details,
    }
}
