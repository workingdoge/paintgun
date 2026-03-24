//! Multi-pack composition and compose-verify kernel.
//!
//! This crate assembles conflicts across multiple pack artifacts/manifests and
//! provides compose-level witness and verification utilities.
//! For single-pack composability analysis, see `premath-composability`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Display;

use serde::de::DeserializeOwned;
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "P: Serialize, M: Serialize",
    deserialize = "P: Deserialize<'de>, M: Deserialize<'de>"
))]
pub struct ComposePackEntry<P, M> {
    pub name: String,
    pub dir: String,
    #[serde(rename = "packIdentity")]
    pub pack_identity: P,
    #[serde(rename = "ctcManifest")]
    pub ctc_manifest: M,
    #[serde(rename = "ctcWitnesses")]
    pub ctc_witnesses: M,
    #[serde(rename = "resolvedJson")]
    pub resolved_json: M,
    #[serde(rename = "authoredJson", skip_serializing_if = "Option::is_none")]
    pub authored_json: Option<M>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "T: Serialize, Tr: Serialize, Sem: Serialize, N: Serialize, P: Serialize, M: Serialize",
    deserialize = "T: Deserialize<'de>, Tr: Deserialize<'de> + Default, Sem: Deserialize<'de>, N: Deserialize<'de>, P: Deserialize<'de>, M: Deserialize<'de>"
))]
pub struct ComposeManifest<T, Tr, Sem, N, P, M> {
    #[serde(rename = "composeVersion")]
    pub compose_version: String,
    pub tool: T,
    pub axes: BTreeMap<String, Vec<String>>,
    pub pack_order: Vec<String>,
    pub packs: Vec<ComposePackEntry<P, M>>,
    #[serde(default)]
    pub trust: Tr,
    pub semantics: Sem,
    #[serde(rename = "nativeApiVersions", skip_serializing_if = "Option::is_none")]
    pub native_api_versions: Option<N>,
    pub summary: ComposeSummary,
    #[serde(rename = "witnessesSha256")]
    pub witnesses_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposeVerifyError {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComposeVerifyReport {
    pub ok: bool,
    pub errors: Vec<String>,
    #[serde(default)]
    pub error_details: Vec<ComposeVerifyError>,
}

pub mod verify_error_codes {
    pub const MANIFEST_READ_ERROR: &str = "compose_verify.manifest_read_error";
    pub const MANIFEST_PARSE_ERROR: &str = "compose_verify.manifest_parse_error";
    pub const SIGNATURE_REQUIRED: &str = "compose_verify.signature_required";
    pub const SIGNATURE_INVALID: &str = "compose_verify.signature_invalid";
    pub const WITNESSES_READ_ERROR: &str = "compose_verify.witnesses_read_error";
    pub const WITNESSES_PARSE_ERROR: &str = "compose_verify.witnesses_parse_error";
    pub const WITNESS_SCHEMA_INVALID: &str = "compose_verify.witness_schema_invalid";
    pub const HASH_MISMATCH: &str = "compose_verify.hash_mismatch";
    pub const SIZE_MISMATCH: &str = "compose_verify.size_mismatch";
    pub const FILE_READ_ERROR: &str = "compose_verify.file_read_error";
    pub const PATH_UNSAFE: &str = "compose_verify.path_unsafe";
    pub const PACK_IDENTITY_MISMATCH: &str = "compose_verify.pack_identity_mismatch";
    pub const PACK_VERIFICATION_FAILED: &str = "compose_verify.pack_verification_failed";
}

pub fn push_verify_error(
    errors: &mut Vec<String>,
    error_details: &mut Vec<ComposeVerifyError>,
    code: &str,
    msg: impl Into<String>,
) {
    let message = msg.into();
    errors.push(message.clone());
    error_details.push(ComposeVerifyError {
        code: code.to_string(),
        message,
    });
}

pub trait SchemaVersionChecked {
    fn validate_schema_version(&self) -> Result<(), String>;
}

impl<M, W, T, I, S> SchemaVersionChecked for ComposeWitnesses<M, W, T, I, S> {
    fn validate_schema_version(&self) -> Result<(), String> {
        ComposeWitnesses::validate_schema_version(self)
    }
}

pub fn check_required_signed(
    require_signed: bool,
    is_signed: bool,
    message: impl Into<String>,
) -> Option<ComposeVerifyError> {
    if require_signed && !is_signed {
        return Some(ComposeVerifyError {
            code: verify_error_codes::SIGNATURE_REQUIRED.to_string(),
            message: message.into(),
        });
    }
    None
}

pub fn check_pack_identity_match(
    pack_name: &str,
    expected: (&str, &str, &str),
    actual: (&str, &str, &str),
) -> Option<ComposeVerifyError> {
    if expected != actual {
        return Some(ComposeVerifyError {
            code: verify_error_codes::PACK_IDENTITY_MISMATCH.to_string(),
            message: format!(
                "[{}:packIdentity] mismatch between compose pack entry and referenced ctc manifest",
                pack_name
            ),
        });
    }
    None
}

pub fn verify_witnesses_payload<W>(
    expected_sha256: &str,
    payload: &[u8],
) -> (Option<W>, Vec<ComposeVerifyError>)
where
    W: DeserializeOwned + SchemaVersionChecked,
{
    let mut errors: Vec<ComposeVerifyError> = Vec::new();

    let mut hasher = Sha256::new();
    hasher.update(payload);
    let got = format!("sha256:{}", hex::encode(hasher.finalize()));
    if got != expected_sha256 {
        errors.push(ComposeVerifyError {
            code: verify_error_codes::HASH_MISMATCH.to_string(),
            message: format!(
                "witnesses sha mismatch: expected {}, got {}",
                expected_sha256, got
            ),
        });
    }

    match serde_json::from_slice::<W>(payload) {
        Ok(w) => {
            if let Err(e) = w.validate_schema_version() {
                errors.push(ComposeVerifyError {
                    code: verify_error_codes::WITNESS_SCHEMA_INVALID.to_string(),
                    message: e,
                });
            }
            (Some(w), errors)
        }
        Err(e) => {
            errors.push(ComposeVerifyError {
                code: verify_error_codes::WITNESSES_PARSE_ERROR.to_string(),
                message: format!("failed to parse compose witnesses JSON: {e}"),
            });
            (None, errors)
        }
    }
}

pub fn check_manifest_entry_binding(
    pack_name: &str,
    label: &str,
    display_path: &str,
    expected_sha256: &str,
    expected_size: u64,
    bytes: &[u8],
) -> Vec<ComposeVerifyError> {
    let mut errors = Vec::new();

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let got = format!("sha256:{}", hex::encode(hasher.finalize()));
    if got != expected_sha256 {
        errors.push(ComposeVerifyError {
            code: verify_error_codes::HASH_MISMATCH.to_string(),
            message: format!(
                "[{}:{}] sha mismatch for {}: expected {}, got {}",
                pack_name, label, display_path, expected_sha256, got
            ),
        });
    }
    if bytes.len() as u64 != expected_size {
        errors.push(ComposeVerifyError {
            code: verify_error_codes::SIZE_MISMATCH.to_string(),
            message: format!(
                "[{}:{}] size mismatch for {}: expected {}, got {}",
                pack_name,
                label,
                display_path,
                expected_size,
                bytes.len()
            ),
        });
    }
    errors
}

pub fn fold_pack_verify_outcome<D, I, C, M>(
    pack_name: &str,
    fallback_code: &str,
    errors: I,
    error_details: &[D],
    detail_code: C,
    detail_message: M,
) -> Vec<ComposeVerifyError>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
    C: Fn(&D) -> &str,
    M: Fn(&D) -> &str,
{
    let mut out = Vec::new();
    if error_details.is_empty() {
        for e in errors {
            out.push(ComposeVerifyError {
                code: fallback_code.to_string(),
                message: format!("[{}] {}", pack_name, e.as_ref()),
            });
        }
        return out;
    }

    for e in error_details {
        out.push(ComposeVerifyError {
            code: detail_code(e).to_string(),
            message: format!("[{}] {}", pack_name, detail_message(e)),
        });
    }
    out
}

pub fn prefix_pack_diagnostics<D, I, C, M>(
    pack_name: &str,
    diagnostics: I,
    code: C,
    message: M,
) -> Vec<ComposeVerifyError>
where
    I: IntoIterator<Item = D>,
    C: Fn(&D) -> &str,
    M: Fn(&D) -> String,
{
    diagnostics
        .into_iter()
        .map(|d| ComposeVerifyError {
            code: code(&d).to_string(),
            message: format!("[{}] {}", pack_name, message(&d)),
        })
        .collect()
}

#[derive(Clone, Debug)]
pub struct PackEntryBytes {
    pub display_path: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ExternalVerifyOutcome<D> {
    pub ok: bool,
    pub errors: Vec<String>,
    pub error_details: Vec<D>,
}

pub fn verify_pack_with_callbacks<
    P,
    M,
    Inner,
    D,
    ReadEntry,
    EntryBinding,
    ParseInner,
    ValidateInner,
    PackIdentity,
    InnerIdentity,
    InnerSigned,
    VerifyInnerSignature,
    VerifyExternal,
    DetailCode,
    DetailMessage,
>(
    pack: &ComposePackEntry<P, M>,
    require_packs_signed: bool,
    verify_packs: bool,
    fallback_pack_verify_code: &str,
    mut read_entry: ReadEntry,
    entry_binding: EntryBinding,
    mut parse_inner_manifest: ParseInner,
    mut validate_inner_manifest: ValidateInner,
    pack_identity: PackIdentity,
    inner_identity: InnerIdentity,
    inner_is_signed: InnerSigned,
    mut verify_inner_signature: VerifyInnerSignature,
    mut verify_external: VerifyExternal,
    detail_code: DetailCode,
    detail_message: DetailMessage,
) -> Vec<ComposeVerifyError>
where
    ReadEntry: FnMut(&str, &M) -> Result<PackEntryBytes, ComposeVerifyError>,
    EntryBinding: Fn(&M) -> (String, u64),
    ParseInner: FnMut(&PackEntryBytes) -> Result<Inner, ComposeVerifyError>,
    ValidateInner: FnMut(&Inner) -> Vec<ComposeVerifyError>,
    PackIdentity: Fn(&ComposePackEntry<P, M>) -> (String, String, String),
    InnerIdentity: Fn(&Inner) -> (String, String, String),
    InnerSigned: Fn(&Inner) -> bool,
    VerifyInnerSignature: FnMut(&Inner, &PackEntryBytes) -> Result<(), ComposeVerifyError>,
    VerifyExternal: FnMut() -> Result<ExternalVerifyOutcome<D>, ComposeVerifyError>,
    DetailCode: Fn(&D) -> &str,
    DetailMessage: Fn(&D) -> &str,
{
    let mut out: Vec<ComposeVerifyError> = Vec::new();

    let mut check_binding = |label: &str, entry: &M| match read_entry(label, entry) {
        Ok(payload) => {
            let (expected_sha256, expected_size) = entry_binding(entry);
            out.extend(check_manifest_entry_binding(
                &pack.name,
                label,
                &payload.display_path,
                &expected_sha256,
                expected_size,
                &payload.bytes,
            ));
        }
        Err(e) => out.push(e),
    };

    check_binding("ctcManifest", &pack.ctc_manifest);
    check_binding("ctcWitnesses", &pack.ctc_witnesses);
    check_binding("resolvedJson", &pack.resolved_json);
    if let Some(a) = &pack.authored_json {
        check_binding("authoredJson", a);
    }

    let parsed_payload = match read_entry("ctcManifest", &pack.ctc_manifest) {
        Ok(payload) => Some(payload),
        Err(e) => {
            out.push(e);
            None
        }
    };
    if let Some(payload) = parsed_payload.as_ref() {
        match parse_inner_manifest(payload) {
            Ok(inner_manifest) => {
                out.extend(validate_inner_manifest(&inner_manifest));

                let expected = pack_identity(pack);
                let actual = inner_identity(&inner_manifest);
                if let Some(e) = check_pack_identity_match(
                    &pack.name,
                    (&expected.0, &expected.1, &expected.2),
                    (&actual.0, &actual.1, &actual.2),
                ) {
                    out.push(e);
                }
                if let Some(e) = check_required_signed(
                    require_packs_signed,
                    inner_is_signed(&inner_manifest),
                    format!(
                        "[{}:trust] pack manifest trust.status must be 'signed'",
                        pack.name
                    ),
                ) {
                    out.push(e);
                }
                if inner_is_signed(&inner_manifest) {
                    if let Err(e) = verify_inner_signature(&inner_manifest, payload) {
                        out.push(e);
                    }
                }
            }
            Err(e) => out.push(e),
        }
    }

    if verify_packs {
        match verify_external() {
            Ok(rep) => {
                if !rep.ok {
                    out.extend(fold_pack_verify_outcome(
                        &pack.name,
                        fallback_pack_verify_code,
                        rep.errors.iter(),
                        &rep.error_details,
                        detail_code,
                        detail_message,
                    ));
                }
            }
            Err(e) => out.push(e),
        }
    }

    out
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

pub fn render_compose_report_text<M, W, T, I, S, Tool, Tr, Sem, N, P, E, IF, SC, SF, SP>(
    manifest: &ComposeManifest<Tool, Tr, Sem, N, P, E>,
    witnesses: &ComposeWitnesses<M, W, T, I, S>,
    format_inherited_ref: IF,
    source_context: SC,
    source_file: SF,
    source_pointer: SP,
) -> String
where
    W: Display,
    T: Display,
    IF: Fn(&I) -> String,
    SC: Fn(&S) -> String,
    SF: Fn(&S) -> Option<String>,
    SP: Fn(&S) -> Option<String>,
{
    let mut out = String::new();
    out.push_str("═══════════════════════════════════════\n");
    out.push_str("  Paintgun Compose Report\n");
    out.push_str("═══════════════════════════════════════\n\n");

    out.push_str(&format!(
        "Packs (order): {}\n",
        manifest.pack_order.join(" → ")
    ));
    out.push_str(&format!(
        "Axes: {}\n",
        manifest.axes.keys().cloned().collect::<Vec<_>>().join(", ")
    ));
    out.push_str(&format!(
        "Contexts checked: {}\nToken paths (union): {}\nOverlapping token paths: {}\n\n",
        manifest.summary.contexts,
        manifest.summary.token_paths_union,
        manifest.summary.overlapping_token_paths
    ));

    if witnesses.conflicts.is_empty() {
        out.push_str("✓ No cross-pack conflicts (pack order does not affect values).\n");
        return out;
    }

    out.push_str(&format!(
        "✗ Cross-pack conflicts: {}\n\n",
        witnesses.conflicts.len()
    ));

    for (i, c) in witnesses.conflicts.iter().take(50).enumerate() {
        out.push_str(&format!("{}. {} @ {}\n", i + 1, c.token_path, c.context));
        for cand in &c.candidates {
            out.push_str(&format!(
                "    - {} ({}): {}\n",
                cand.pack, cand.value_type, cand.value_json
            ));
            if !cand.inherited_from.is_empty() {
                let refs = cand
                    .inherited_from
                    .iter()
                    .map(&format_inherited_ref)
                    .collect::<Vec<_>>()
                    .join(", ");
                out.push_str(&format!("        inheritedFrom: {refs}\n"));
            }
            for src in cand.sources.iter().take(3) {
                let file = source_file(src).unwrap_or_else(|| "(inline)".to_string());
                out.push_str(&format!(
                    "        from {} @ {}  {}\n",
                    source_context(src),
                    file,
                    source_pointer(src).unwrap_or_else(|| "(unknown)".to_string())
                ));
            }
            if cand.sources.len() > 3 {
                out.push_str("        …\n");
            }
        }
        out.push_str(&format!(
            "    winner (by pack order): {}\n\n",
            c.winner_pack
        ));
    }
    if witnesses.conflicts.len() > 50 {
        out.push_str(&format!(
            "(… {} more; see compose.witnesses.json)\n",
            witnesses.conflicts.len() - 50
        ));
    }

    out
}

#[derive(Clone, Debug, Serialize)]
struct ComposeReportFinding {
    #[serde(rename = "witnessId")]
    witness_id: String,
    kind: String,
    severity: String,
    message: String,
    #[serde(rename = "tokenPath", skip_serializing_if = "Option::is_none")]
    token_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
    #[serde(rename = "filePath", skip_serializing_if = "Option::is_none")]
    file_path: Option<String>,
    #[serde(rename = "jsonPointer", skip_serializing_if = "Option::is_none")]
    json_pointer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pack: Option<String>,
}

pub fn build_compose_report_json_value<M, W, T, I, S, Tool, Tr, Sem, N, P, E, SF, SP, SK>(
    manifest: &ComposeManifest<Tool, Tr, Sem, N, P, E>,
    witnesses: &ComposeWitnesses<M, W, T, I, S>,
    source_file: SF,
    source_pointer: SP,
    source_pack: SK,
) -> serde_json::Value
where
    M: Serialize,
    W: Display,
    T: Display,
    SF: Fn(&S) -> Option<String>,
    SP: Fn(&S) -> Option<String>,
    SK: Fn(&S) -> Option<String>,
{
    let mut findings: Vec<ComposeReportFinding> = Vec::new();
    for w in &witnesses.conflicts {
        for c in &w.candidates {
            for src in &c.sources {
                findings.push(ComposeReportFinding {
                    witness_id: w.witness_id.to_string(),
                    kind: "composeConflict".to_string(),
                    severity: "error".to_string(),
                    message: format!(
                        "Cross-pack conflict for {} at {} (winner: {}, candidate: {})",
                        w.token_path, w.context, w.winner_pack, c.pack
                    ),
                    token_path: Some(w.token_path.to_string()),
                    context: Some(w.context.clone()),
                    file_path: source_file(src),
                    json_pointer: source_pointer(src),
                    pack: source_pack(src).or_else(|| Some(c.pack.clone())),
                });
            }
        }
    }

    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    for f in &findings {
        *by_kind.entry(f.kind.clone()).or_insert(0) += 1;
    }

    let policy_digest = witnesses
        .policy_digest
        .clone()
        .unwrap_or_else(|| "sha256:unknown".to_string());
    let conflict_mode = serde_json::to_value(&witnesses.conflict_mode)
        .unwrap_or_else(|_| serde_json::json!("unknown"));
    let mut out = serde_json::json!({
        "reportVersion": 1,
        "reportKind": "compose",
        "conflictMode": conflict_mode,
        "policyDigest": policy_digest,
        "summary": manifest.summary,
        "counts": {
            "total": findings.len(),
            "byKind": by_kind,
        },
        "findings": findings,
    });
    if let Some(v) = &witnesses.normalizer_version {
        out.as_object_mut()
            .expect("compose report object")
            .insert("normalizerVersion".to_string(), serde_json::json!(v));
    }
    out
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
    fn compose_report_json_builder_produces_findings() {
        let manifest = ComposeManifest::<String, String, String, String, String, String> {
            compose_version: "0.1".to_string(),
            tool: "paintgun".to_string(),
            axes: BTreeMap::new(),
            pack_order: vec!["pack-a".to_string(), "pack-b".to_string()],
            packs: Vec::new(),
            trust: "unsigned".to_string(),
            semantics: "semantic".to_string(),
            native_api_versions: None,
            summary: ComposeSummary {
                packs: 2,
                contexts: 1,
                token_paths_union: 1,
                overlapping_token_paths: 1,
                conflicts: 1,
            },
            witnesses_sha256: "sha256:w".to_string(),
        };
        let witnesses = ComposeWitnesses::<String, String, String, String, String> {
            witness_schema: COMPOSE_WITNESS_SCHEMA_VERSION,
            conflict_mode: "semantic".to_string(),
            policy_digest: Some("sha256:p".to_string()),
            normalizer_version: None,
            conflicts: vec![ComposeConflictWitness {
                witness_id: "w-1".to_string(),
                token_path: "color.bg".to_string(),
                context: "(base)".to_string(),
                candidates: vec![ComposeConflictCandidate {
                    pack: "pack-a".to_string(),
                    value_type: "number".to_string(),
                    value_json: "1".to_string(),
                    value_digest: "sha256:1".to_string(),
                    inherited_from: Vec::new(),
                    sources: vec!["src-a".to_string()],
                }],
                winner_pack: "pack-b".to_string(),
            }],
        };

        let report = build_compose_report_json_value(
            &manifest,
            &witnesses,
            |s| Some(format!("{s}.json")),
            |_| Some("/color/bg/$value".to_string()),
            |_| Some("pack-a".to_string()),
        );
        assert_eq!(report["reportKind"], "compose");
        assert_eq!(report["counts"]["total"], 1);
        assert_eq!(report["findings"][0]["witnessId"], "w-1");
        assert_eq!(report["findings"][0]["tokenPath"], "color.bg");
        assert_eq!(report["findings"][0]["pack"], "pack-a");
    }

    #[test]
    fn compose_text_report_builder_includes_inherited_refs() {
        let manifest = ComposeManifest::<String, String, String, String, String, String> {
            compose_version: "0.1".to_string(),
            tool: "paintgun".to_string(),
            axes: BTreeMap::new(),
            pack_order: vec!["pack-a".to_string(), "pack-b".to_string()],
            packs: Vec::new(),
            trust: "unsigned".to_string(),
            semantics: "semantic".to_string(),
            native_api_versions: None,
            summary: ComposeSummary {
                packs: 2,
                contexts: 1,
                token_paths_union: 1,
                overlapping_token_paths: 1,
                conflicts: 1,
            },
            witnesses_sha256: "sha256:w".to_string(),
        };
        let witnesses = ComposeWitnesses::<String, String, String, String, String> {
            witness_schema: COMPOSE_WITNESS_SCHEMA_VERSION,
            conflict_mode: "semantic".to_string(),
            policy_digest: Some("sha256:p".to_string()),
            normalizer_version: None,
            conflicts: vec![ComposeConflictWitness {
                witness_id: "w-1".to_string(),
                token_path: "color.bg".to_string(),
                context: "(base)".to_string(),
                candidates: vec![ComposeConflictCandidate {
                    pack: "pack-a".to_string(),
                    value_type: "number".to_string(),
                    value_json: "1".to_string(),
                    value_digest: "sha256:1".to_string(),
                    inherited_from: vec!["pack-a/inherited/w-0".to_string()],
                    sources: vec!["ctx-a".to_string()],
                }],
                winner_pack: "pack-b".to_string(),
            }],
        };

        let report = render_compose_report_text(
            &manifest,
            &witnesses,
            |i| i.clone(),
            |s| s.clone(),
            |_| Some("pack-a.tokens.json".to_string()),
            |_| Some("/color/bg/$value".to_string()),
        );
        assert!(report.contains("Cross-pack conflicts: 1"));
        assert!(report.contains("inheritedFrom: pack-a/inherited/w-0"));
        assert!(report.contains("winner (by pack order): pack-b"));
    }

    #[test]
    fn required_signed_check_enforces_policy() {
        assert!(check_required_signed(false, false, "x").is_none());
        assert!(check_required_signed(true, true, "x").is_none());
        let err = check_required_signed(true, false, "must be signed")
            .expect("require_signed should fail when unsigned");
        assert_eq!(err.code, verify_error_codes::SIGNATURE_REQUIRED);
        assert_eq!(err.message, "must be signed");
    }

    #[test]
    fn pack_identity_match_check_detects_mismatch() {
        assert!(check_pack_identity_match(
            "pack-a",
            ("pack-a", "1.0.0", "sha256:a"),
            ("pack-a", "1.0.0", "sha256:a"),
        )
        .is_none());

        let err = check_pack_identity_match(
            "pack-a",
            ("pack-a", "1.0.0", "sha256:a"),
            ("pack-a", "2.0.0", "sha256:a"),
        )
        .expect("pack identity mismatch should be detected");
        assert_eq!(err.code, verify_error_codes::PACK_IDENTITY_MISMATCH);
        assert!(err.message.contains("pack-a:packIdentity"));
    }

    #[test]
    fn witness_payload_check_reports_hash_and_schema_errors() {
        let witnesses = ComposeWitnesses::<String, String, String, String, String> {
            witness_schema: COMPOSE_WITNESS_SCHEMA_VERSION + 1,
            conflict_mode: "semantic".to_string(),
            policy_digest: None,
            normalizer_version: None,
            conflicts: Vec::new(),
        };
        let payload = serde_json::to_vec(&witnesses).expect("serialize witnesses");

        let (parsed, errors) = verify_witnesses_payload::<
            ComposeWitnesses<String, String, String, String, String>,
        >("sha256:expected", &payload);
        assert!(parsed.is_some(), "payload should parse");
        assert!(
            errors
                .iter()
                .any(|e| e.code == verify_error_codes::HASH_MISMATCH),
            "expected hash mismatch error"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.code == verify_error_codes::WITNESS_SCHEMA_INVALID),
            "expected witness schema error"
        );
    }

    #[test]
    fn manifest_entry_binding_check_reports_hash_and_size_mismatch() {
        let errors = check_manifest_entry_binding(
            "pack-a",
            "resolvedJson",
            "/tmp/pack-a/resolved.json",
            "sha256:expected",
            999,
            br#"{}"#,
        );
        assert!(
            errors
                .iter()
                .any(|e| e.code == verify_error_codes::HASH_MISMATCH),
            "expected hash mismatch"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.code == verify_error_codes::SIZE_MISMATCH),
            "expected size mismatch"
        );
    }

    #[test]
    fn fold_pack_verify_outcome_uses_fallback_without_details() {
        let folded = fold_pack_verify_outcome::<(), _, _, _>(
            "pack-a",
            verify_error_codes::PACK_VERIFICATION_FAILED,
            vec!["boom-a", "boom-b"],
            &[],
            |_| "",
            |_| "",
        );
        assert_eq!(folded.len(), 2);
        assert!(
            folded
                .iter()
                .all(|e| e.code == verify_error_codes::PACK_VERIFICATION_FAILED),
            "all folded errors should use fallback code"
        );
        assert!(folded[0].message.contains("[pack-a] boom-a"));
        assert!(folded[1].message.contains("[pack-a] boom-b"));
    }

    #[test]
    fn fold_pack_verify_outcome_uses_detail_codes_when_present() {
        #[derive(Clone)]
        struct Detail {
            code: String,
            message: String,
        }

        let details = vec![
            Detail {
                code: "verify.hash_mismatch".to_string(),
                message: "hash mismatch".to_string(),
            },
            Detail {
                code: "verify.path_unsafe".to_string(),
                message: "unsafe path".to_string(),
            },
        ];
        let folded = fold_pack_verify_outcome(
            "pack-a",
            verify_error_codes::PACK_VERIFICATION_FAILED,
            vec!["ignored"],
            &details,
            |d| d.code.as_str(),
            |d| d.message.as_str(),
        );
        assert_eq!(folded.len(), 2);
        assert_eq!(folded[0].code, "verify.hash_mismatch");
        assert_eq!(folded[1].code, "verify.path_unsafe");
        assert!(folded[0].message.contains("[pack-a] hash mismatch"));
        assert!(folded[1].message.contains("[pack-a] unsafe path"));
    }

    #[test]
    fn prefix_pack_diagnostics_prefixes_messages_and_codes() {
        #[derive(Clone)]
        struct Detail {
            code: String,
            message: String,
        }
        let details = vec![
            Detail {
                code: "verify.missing".to_string(),
                message: "missing field".to_string(),
            },
            Detail {
                code: "verify.bad".to_string(),
                message: "bad value".to_string(),
            },
        ];
        let prefixed = prefix_pack_diagnostics(
            "pack-a",
            details,
            |d| d.code.as_str(),
            |d| d.message.clone(),
        );
        assert_eq!(prefixed.len(), 2);
        assert_eq!(prefixed[0].code, "verify.missing");
        assert_eq!(prefixed[1].code, "verify.bad");
        assert_eq!(prefixed[0].message, "[pack-a] missing field");
        assert_eq!(prefixed[1].message, "[pack-a] bad value");
    }

    #[test]
    fn verify_pack_with_callbacks_runs_validation_and_external_fold() {
        #[derive(Clone)]
        struct Entry {
            file: String,
            sha256: String,
            size: u64,
        }
        #[derive(Clone)]
        struct Identity {
            id: String,
            version: String,
            hash: String,
            signed: bool,
        }
        #[derive(Clone)]
        struct Detail {
            code: String,
            message: String,
        }

        let pack = ComposePackEntry {
            name: "pack-a".to_string(),
            dir: "/packs/pack-a".to_string(),
            pack_identity: Identity {
                id: "pack-a".to_string(),
                version: "1.0.0".to_string(),
                hash: "sha256:pack-a".to_string(),
                signed: false,
            },
            ctc_manifest: Entry {
                file: "ctc.manifest.json".to_string(),
                sha256: "sha256:expected".to_string(),
                size: 2,
            },
            ctc_witnesses: Entry {
                file: "ctc.witnesses.json".to_string(),
                sha256: "sha256:expected".to_string(),
                size: 2,
            },
            resolved_json: Entry {
                file: "resolved.json".to_string(),
                sha256: "sha256:expected".to_string(),
                size: 2,
            },
            authored_json: None,
        };

        let mut external_invoked = 0usize;
        let errors = verify_pack_with_callbacks(
            &pack,
            false,
            true,
            verify_error_codes::PACK_VERIFICATION_FAILED,
            |_label, entry| {
                Ok(PackEntryBytes {
                    display_path: format!("/tmp/{}", entry.file),
                    bytes: br#"{}"#.to_vec(),
                })
            },
            |entry| (entry.sha256.clone(), entry.size),
            |_payload| {
                Ok(Identity {
                    id: "pack-a".to_string(),
                    version: "1.0.0".to_string(),
                    hash: "sha256:pack-a".to_string(),
                    signed: false,
                })
            },
            |_inner| {
                vec![ComposeVerifyError {
                    code: "verify.synthetic".to_string(),
                    message: "[pack-a] synthetic".to_string(),
                }]
            },
            |pack| {
                (
                    pack.pack_identity.id.clone(),
                    pack.pack_identity.version.clone(),
                    pack.pack_identity.hash.clone(),
                )
            },
            |inner| (inner.id.clone(), inner.version.clone(), inner.hash.clone()),
            |inner| inner.signed,
            |_inner, _payload| Ok(()),
            || {
                external_invoked += 1;
                Ok(ExternalVerifyOutcome {
                    ok: false,
                    errors: vec!["boom".to_string()],
                    error_details: vec![Detail {
                        code: "verify.external".to_string(),
                        message: "external failed".to_string(),
                    }],
                })
            },
            |d| d.code.as_str(),
            |d| d.message.as_str(),
        );

        assert_eq!(external_invoked, 1);
        assert!(
            errors.iter().any(|e| e.code == "verify.synthetic"),
            "expected inner-validation diagnostics"
        );
        assert!(
            errors.iter().any(|e| e.code == "verify.external"),
            "expected folded external diagnostics"
        );
    }
}
