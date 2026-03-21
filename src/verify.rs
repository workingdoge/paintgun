use std::fs;
use std::path::Path;

use crate::allowlist::Allowlist;
use crate::cert::{
    CtcManifest, CtcWitnesses, ManifestEntry, RequiredArtifactBinding, RequiredArtifactKind,
    TrustStatus,
};
use crate::gate::{GateFailure, GateWitnesses};
use crate::ids::WitnessId;
use crate::kcir_v2::ProfileAnchors;
use crate::util::sha256_hex;

mod profile_binding;
pub use profile_binding::validate_manifest_profile_binding;
use profile_binding::{check_expected_profile_anchors, check_manifest_profile_binding};

pub mod error_codes {
    pub const UNCLASSIFIED: &str = "verify.unclassified";
    pub const MANIFEST_READ_ERROR: &str = "verify.manifest_read_error";
    pub const MANIFEST_PARSE_ERROR: &str = "verify.manifest_parse_error";
    pub const MANIFEST_FIELD_MISSING: &str = "verify.manifest_field_missing";
    pub const MANIFEST_FIELD_MISMATCH: &str = "verify.manifest_field_mismatch";
    pub const PATH_UNSAFE: &str = "verify.path_unsafe";
    pub const FILE_READ_ERROR: &str = "verify.file_read_error";
    pub const HASH_MISMATCH: &str = "verify.hash_mismatch";
    pub const SIGNATURE_REQUIRED: &str = "verify.signature_required";
    pub const SIGNATURE_INVALID: &str = "verify.signature_invalid";
    pub const KCIR_VERSION_MISSING: &str = "verify.kcir_version_missing";
    pub const KCIR_VERSION_MISMATCH: &str = "verify.kcir_version_mismatch";
    pub const PROFILE_UNSUPPORTED: &str = "verify.profile_unsupported";
    pub const WITNESSES_READ_ERROR: &str = "verify.witnesses_read_error";
    pub const WITNESSES_PARSE_ERROR: &str = "verify.witnesses_parse_error";
    pub const WITNESS_SCHEMA_INVALID: &str = "verify.witness_schema_invalid";
    pub const ALLOWLIST_INVALID: &str = "verify.allowlist_invalid";
    pub const ALLOWLIST_STALE_ENTRY: &str = "verify.allowlist_stale_entry";
    pub const COMPOSABILITY_FAILED: &str = "verify.composability_failed";
    pub const FULL_PROFILE_BINDING_MISSING: &str = "verify.full_profile_binding_missing";
    pub const FULL_PROFILE_ADMISSIBILITY_READ_ERROR: &str =
        "verify.full_profile_admissibility_read_error";
    pub const FULL_PROFILE_ADMISSIBILITY_HASH_MISMATCH: &str =
        "verify.full_profile_admissibility_hash_mismatch";
    pub const FULL_PROFILE_ADMISSIBILITY_PARSE_ERROR: &str =
        "verify.full_profile_admissibility_parse_error";
    pub const FULL_PROFILE_ADMISSIBILITY_INVALID: &str =
        "verify.full_profile_admissibility_invalid";
    pub const FULL_PROFILE_ADMISSIBILITY_REJECTED: &str =
        "verify.full_profile_admissibility_rejected";
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyError {
    pub code: String,
    pub message: String,
}

#[derive(Debug)]
pub struct VerifyReport {
    pub ok: bool,
    pub errors: Vec<String>,
    pub error_details: Vec<VerifyError>,
    pub notes: Vec<String>,
}

impl VerifyReport {
    pub fn new() -> Self {
        VerifyReport {
            ok: true,
            errors: Vec::new(),
            error_details: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn fail(&mut self, msg: impl Into<String>) {
        self.fail_code(error_codes::UNCLASSIFIED, msg);
    }

    pub fn fail_code(&mut self, code: &str, msg: impl Into<String>) {
        let message = msg.into();
        self.ok = false;
        self.errors.push(message.clone());
        self.error_details.push(VerifyError {
            code: code.to_string(),
            message,
        });
    }

    pub fn fail_error(&mut self, err: VerifyError) {
        self.ok = false;
        self.errors.push(err.message.clone());
        self.error_details.push(err);
    }

    pub fn note(&mut self, msg: impl Into<String>) {
        self.notes.push(msg.into());
    }
}

fn hash_entry(base: &Path, entry: &ManifestEntry) -> Result<(String, u64), VerifyError> {
    let root = base
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let p = crate::path_safety::resolve_existing_within(base, &entry.file, root).map_err(|e| {
        VerifyError {
            code: error_codes::PATH_UNSAFE.to_string(),
            message: format!("unsafe manifest path {}: {e}", entry.file),
        }
    })?;
    let bytes = fs::read(&p).map_err(|e| VerifyError {
        code: error_codes::FILE_READ_ERROR.to_string(),
        message: format!("failed to read {}: {e}", p.display()),
    })?;
    let size = bytes.len() as u64;
    let sha = format!("sha256:{}", sha256_hex(&bytes));
    Ok((sha, size))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyProfile {
    Core,
    Full,
}

#[derive(Clone, Debug, Default)]
struct RequiredArtifactSelection {
    ctc_witnesses: Option<ManifestEntry>,
    admissibility_witnesses: Option<ManifestEntry>,
}

fn select_required_artifact_entry(
    manifest: &CtcManifest,
    kind: RequiredArtifactKind,
    report: &mut VerifyReport,
) -> Option<ManifestEntry> {
    let matches: Vec<&RequiredArtifactBinding> = manifest
        .required_artifacts
        .iter()
        .filter(|binding| binding.kind == kind)
        .collect();
    if matches.len() > 1 {
        report.fail_code(
            error_codes::MANIFEST_FIELD_MISMATCH,
            format!(
                "manifest requiredArtifacts has duplicate '{}' entries",
                kind.as_str()
            ),
        );
    }
    matches.first().map(|binding| binding.entry.clone())
}

fn collect_required_artifact_bindings(
    manifest: &CtcManifest,
    profile: VerifyProfile,
    report: &mut VerifyReport,
) -> RequiredArtifactSelection {
    let ctc_witnesses =
        select_required_artifact_entry(manifest, RequiredArtifactKind::CtcWitnesses, report);
    let admissibility_witnesses = select_required_artifact_entry(
        manifest,
        RequiredArtifactKind::AdmissibilityWitnesses,
        report,
    );

    if profile == VerifyProfile::Full {
        if ctc_witnesses.is_none() {
            report.fail_code(
                error_codes::FULL_PROFILE_BINDING_MISSING,
                "full-profile verify requires requiredArtifacts entry 'ctcWitnesses'".to_string(),
            );
        }
        if admissibility_witnesses.is_none() {
            report.fail_code(
                error_codes::FULL_PROFILE_BINDING_MISSING,
                "full-profile verify requires requiredArtifacts entry 'admissibilityWitnesses'"
                    .to_string(),
            );
        }
        if let Some(entry) = ctc_witnesses.as_ref() {
            if entry.sha256 != manifest.witnesses_sha256 {
                report.fail_code(
                    error_codes::MANIFEST_FIELD_MISMATCH,
                    format!(
                        "requiredArtifacts.ctcWitnesses sha256 mismatch: expected witnessesSha256 {}, got {}",
                        manifest.witnesses_sha256, entry.sha256
                    ),
                );
            }
        }
        match (
            manifest.admissibility_witnesses_sha256.as_deref(),
            admissibility_witnesses.as_ref(),
        ) {
            (None, _) => report.fail_code(
                error_codes::FULL_PROFILE_BINDING_MISSING,
                "full-profile verify requires manifest admissibilityWitnessesSha256 binding"
                    .to_string(),
            ),
            (Some(expected), Some(entry)) if entry.sha256 != expected => report.fail_code(
                error_codes::MANIFEST_FIELD_MISMATCH,
                format!(
                    "requiredArtifacts.admissibilityWitnesses sha256 mismatch: expected admissibilityWitnessesSha256 {}, got {}",
                    expected, entry.sha256
                ),
            ),
            _ => {}
        }
    }

    RequiredArtifactSelection {
        ctc_witnesses,
        admissibility_witnesses,
    }
}

pub fn validate_manifest_required_artifacts(
    manifest: &CtcManifest,
    profile: VerifyProfile,
) -> Vec<VerifyError> {
    let mut report = VerifyReport::new();
    let _ = collect_required_artifact_bindings(manifest, profile, &mut report);
    report.error_details
}

#[derive(Clone, Debug)]
pub struct CtcVerifyOptions<'a> {
    pub witnesses_path: Option<&'a Path>,
    pub require_composable: bool,
    pub allowlist: Option<&'a Allowlist>,
    pub require_signed: bool,
    pub profile: VerifyProfile,
    pub admissibility_witnesses_path: Option<&'a Path>,
    pub expected_profile_anchors: Option<ProfileAnchors>,
}

impl<'a> Default for CtcVerifyOptions<'a> {
    fn default() -> Self {
        CtcVerifyOptions {
            witnesses_path: None,
            require_composable: false,
            allowlist: None,
            require_signed: false,
            profile: VerifyProfile::Core,
            admissibility_witnesses_path: None,
            expected_profile_anchors: None,
        }
    }
}

fn format_gate_sources(failure: &GateFailure) -> String {
    if failure.sources.is_empty() {
        return String::new();
    }
    let mut locs: Vec<String> = failure
        .sources
        .iter()
        .map(|s| format!("{}#{}", s.file_path, s.json_pointer))
        .collect();
    locs.sort();
    locs.dedup();
    format!(" [{}]", locs.join(", "))
}

/// Verify:
/// - input file hashes in the manifest match disk
/// - output file hashes in the manifest match disk (if present)
/// - witnesses file hash matches `witnessesSha256`
/// - (optional) witnesses arrays are empty ("must be composable")
pub fn verify_ctc(
    manifest_path: &Path,
    witnesses_path: Option<&Path>,
    require_composable: bool,
) -> VerifyReport {
    verify_ctc_with_options(
        manifest_path,
        CtcVerifyOptions {
            witnesses_path,
            require_composable,
            ..CtcVerifyOptions::default()
        },
    )
}

pub fn verify_ctc_with_allowlist(
    manifest_path: &Path,
    witnesses_path: Option<&Path>,
    require_composable: bool,
    allowlist: Option<&Allowlist>,
) -> VerifyReport {
    verify_ctc_with_options(
        manifest_path,
        CtcVerifyOptions {
            witnesses_path,
            require_composable,
            allowlist,
            ..CtcVerifyOptions::default()
        },
    )
}

pub fn verify_ctc_with_allowlist_and_signing(
    manifest_path: &Path,
    witnesses_path: Option<&Path>,
    require_composable: bool,
    allowlist: Option<&Allowlist>,
    require_signed: bool,
) -> VerifyReport {
    verify_ctc_with_options(
        manifest_path,
        CtcVerifyOptions {
            witnesses_path,
            require_composable,
            allowlist,
            require_signed,
            ..CtcVerifyOptions::default()
        },
    )
}

pub fn verify_ctc_with_options(
    manifest_path: &Path,
    options: CtcVerifyOptions<'_>,
) -> VerifyReport {
    let mut report = VerifyReport::new();

    let manifest_bytes = match fs::read(manifest_path) {
        Ok(b) => b,
        Err(e) => {
            report.fail_code(
                error_codes::MANIFEST_READ_ERROR,
                format!("failed to read manifest {}: {e}", manifest_path.display()),
            );
            return report;
        }
    };
    let manifest: CtcManifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(m) => m,
        Err(e) => {
            report.fail_code(
                error_codes::MANIFEST_PARSE_ERROR,
                format!(
                    "failed to parse manifest JSON {}: {e}",
                    manifest_path.display()
                ),
            );
            return report;
        }
    };
    if manifest.pack_identity.pack_id.trim().is_empty() {
        report.fail_code(
            error_codes::MANIFEST_FIELD_MISSING,
            "packIdentity.packId must be non-empty".to_string(),
        );
    }
    if manifest.pack_identity.pack_version.trim().is_empty() {
        report.fail_code(
            error_codes::MANIFEST_FIELD_MISSING,
            "packIdentity.packVersion must be non-empty".to_string(),
        );
    }
    if manifest.pack_identity.content_hash != manifest.outputs.resolved_json.sha256 {
        report.fail_code(
            error_codes::MANIFEST_FIELD_MISMATCH,
            format!(
                "packIdentity.contentHash mismatch: expected resolvedJson.sha256 {}, got {}",
                manifest.outputs.resolved_json.sha256, manifest.pack_identity.content_hash
            ),
        );
    }
    if options.require_signed && manifest.trust.status != TrustStatus::Signed {
        report.fail_code(
            error_codes::SIGNATURE_REQUIRED,
            "manifest trust.status must be 'signed'".to_string(),
        );
    }
    if manifest.trust.status == TrustStatus::Signed {
        if let Err(e) = crate::signing::verify_ctc_signature(manifest_path, &manifest) {
            report.fail_code(
                error_codes::SIGNATURE_INVALID,
                format!("signature verification failed: {e}"),
            );
        }
    }

    check_manifest_profile_binding(&manifest, &mut report);
    let required_artifacts =
        collect_required_artifact_bindings(&manifest, options.profile, &mut report);

    if let Some(expected_anchors) = options.expected_profile_anchors.as_ref() {
        check_expected_profile_anchors(&manifest, expected_anchors, &mut report);
    }

    let base = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let witnesses_path = options
        .witnesses_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| {
            required_artifacts
                .ctc_witnesses
                .as_ref()
                .map(|entry| base.join(&entry.file))
                .unwrap_or_else(|| base.join("ctc.witnesses.json"))
        });

    // Inputs
    {
        let (sha, size) = match hash_entry(base, &manifest.inputs.resolver_spec) {
            Ok(x) => x,
            Err(e) => {
                report.fail_error(e);
                ("".to_string(), 0)
            }
        };
        if sha != manifest.inputs.resolver_spec.sha256 || size != manifest.inputs.resolver_spec.size
        {
            report.fail_code(
                error_codes::HASH_MISMATCH,
                format!(
                    "resolver_spec hash mismatch: expected {} ({} bytes), got {} ({} bytes)",
                    manifest.inputs.resolver_spec.sha256,
                    manifest.inputs.resolver_spec.size,
                    sha,
                    size
                ),
            );
        }
    }

    for e in &manifest.inputs.token_docs {
        match hash_entry(base, e) {
            Ok((sha, size)) => {
                if sha != e.sha256 || size != e.size {
                    report.fail_code(
                        error_codes::HASH_MISMATCH,
                        format!(
                            "input hash mismatch for {}: expected {} ({} bytes), got {} ({} bytes)",
                            e.file, e.sha256, e.size, sha, size
                        ),
                    );
                }
            }
            Err(err) => report.fail_error(err),
        }
    }

    // Outputs
    let check_out_required = |label: &str, entry: &ManifestEntry, report: &mut VerifyReport| {
        match hash_entry(base, entry) {
            Ok((sha, size)) => {
                if sha != entry.sha256 || size != entry.size {
                    report.fail_code(
                        error_codes::HASH_MISMATCH,
                        format!(
                            "output hash mismatch for {label} {}: expected {} ({} bytes), got {} ({} bytes)",
                            entry.file, entry.sha256, entry.size, sha, size
                        ),
                    );
                }
            }
            Err(err) => report.fail_error(err),
        }
    };

    let check_out = |label: &str, me: &Option<ManifestEntry>, report: &mut VerifyReport| {
        if let Some(entry) = me {
            match hash_entry(base, entry) {
                Ok((sha, size)) => {
                    if sha != entry.sha256 || size != entry.size {
                        report.fail_code(
                            error_codes::HASH_MISMATCH,
                            format!(
                                "output hash mismatch for {label} {}: expected {} ({} bytes), got {} ({} bytes)",
                                entry.file, entry.sha256, entry.size, sha, size
                            ),
                        );
                    }
                }
                Err(err) => report.fail_error(err),
            }
        }
    };

    check_out_required(
        "resolved.json",
        &manifest.outputs.resolved_json,
        &mut report,
    );
    check_out("tokens.css", &manifest.outputs.tokens_css, &mut report);
    check_out("tokens.swift", &manifest.outputs.tokens_swift, &mut report);
    check_out(
        "tokens.kotlin",
        &manifest.outputs.tokens_kotlin,
        &mut report,
    );
    check_out("tokens.d.ts", &manifest.outputs.tokens_dts, &mut report);
    check_out(
        "authored.json",
        &manifest.outputs.authored_json,
        &mut report,
    );
    check_out(
        "validation.txt",
        &manifest.outputs.validation_txt,
        &mut report,
    );

    // Witnesses hash
    {
        if let Some(entry) = required_artifacts.ctc_witnesses.as_ref() {
            match hash_entry(base, entry) {
                Ok((sha, size)) => {
                    if sha != entry.sha256 || size != entry.size {
                        report.fail_code(
                            error_codes::HASH_MISMATCH,
                            format!(
                                "requiredArtifacts.ctcWitnesses hash mismatch for {}: expected {} ({} bytes), got {} ({} bytes)",
                                entry.file, entry.sha256, entry.size, sha, size
                            ),
                        );
                    }
                }
                Err(err) => report.fail_error(err),
            }
        }

        let wb = match fs::read(&witnesses_path) {
            Ok(b) => b,
            Err(e) => {
                report.fail_code(
                    error_codes::WITNESSES_READ_ERROR,
                    format!("failed to read witnesses {}: {e}", witnesses_path.display()),
                );
                return report;
            }
        };
        let sha = format!("sha256:{}", sha256_hex(&wb));
        if sha != manifest.witnesses_sha256 {
            report.fail_code(
                error_codes::HASH_MISMATCH,
                format!(
                    "witnesses hash mismatch: expected {}, got {}",
                    manifest.witnesses_sha256, sha
                ),
            );
        }

        let parsed_witnesses = match serde_json::from_slice::<CtcWitnesses>(&wb) {
            Ok(w) => {
                if let Err(e) = w.validate_schema_version() {
                    report.fail_code(error_codes::WITNESS_SCHEMA_INVALID, e);
                }
                Some(w)
            }
            Err(e) => {
                report.fail_code(
                    error_codes::WITNESSES_PARSE_ERROR,
                    format!(
                        "failed to parse witnesses JSON {}: {e}",
                        witnesses_path.display()
                    ),
                );
                None
            }
        };

        if options.require_composable || options.allowlist.is_some() {
            if let Some(w) = parsed_witnesses {
                let mut allowed_conflicts: std::collections::BTreeMap<WitnessId, Vec<String>> =
                    std::collections::BTreeMap::new();
                let mut allowed_bc: std::collections::BTreeMap<WitnessId, Vec<String>> =
                    std::collections::BTreeMap::new();

                if let Some(list) = options.allowlist {
                    for err in list.validate() {
                        report.fail_code(
                            error_codes::ALLOWLIST_INVALID,
                            format!("invalid allowlist: {err}"),
                        );
                    }

                    for (i, e) in list.conflicts.iter().enumerate() {
                        let mut matched = false;
                        for c in &w.conflicts {
                            if e.matches(c) {
                                matched = true;
                                allowed_conflicts
                                    .entry(c.witness_id.clone().into())
                                    .or_default()
                                    .push(e.reason.clone());
                            }
                        }
                        if !matched {
                            report.fail_code(
                                error_codes::ALLOWLIST_STALE_ENTRY,
                                format!(
                                    "stale allowlist entry conflicts[{i}] ({}) did not match any current conflict witness",
                                    e.describe()
                                ),
                            );
                        }
                    }

                    for (i, e) in list.bc_violations.iter().enumerate() {
                        let mut matched = false;
                        for b in &w.bc_violations {
                            if e.matches(b) {
                                matched = true;
                                allowed_bc
                                    .entry(b.witness_id.clone().into())
                                    .or_default()
                                    .push(e.reason.clone());
                            }
                        }
                        if !matched {
                            report.fail_code(
                                error_codes::ALLOWLIST_STALE_ENTRY,
                                format!(
                                    "stale allowlist entry bcViolations[{i}] ({}) did not match any current BC witness",
                                    e.describe()
                                ),
                            );
                        }
                    }

                    for (wid, reasons) in &allowed_conflicts {
                        let mut uniq = reasons.clone();
                        uniq.sort();
                        uniq.dedup();
                        report.note(format!("allowlisted conflict {wid}: {}", uniq.join(" | ")));
                    }
                    for (wid, reasons) in &allowed_bc {
                        let mut uniq = reasons.clone();
                        uniq.sort();
                        uniq.dedup();
                        report.note(format!(
                            "allowlisted bcViolation {wid}: {}",
                            uniq.join(" | ")
                        ));
                    }
                }

                if options.require_composable {
                    if !w.gaps.is_empty() {
                        report.fail_code(
                            error_codes::COMPOSABILITY_FAILED,
                            format!("composability failed: {} Kan gaps", w.gaps.len()),
                        );
                    }
                    let remaining_conflicts = w
                        .conflicts
                        .iter()
                        .filter(|c| !allowed_conflicts.contains_key(c.witness_id.as_str()))
                        .count();
                    if remaining_conflicts > 0 {
                        report.fail_code(
                            error_codes::COMPOSABILITY_FAILED,
                            format!(
                                "composability failed: {} Kan conflicts ({} allowlisted)",
                                remaining_conflicts,
                                allowed_conflicts.len()
                            ),
                        );
                    }
                    let remaining_bc = w
                        .bc_violations
                        .iter()
                        .filter(|b| !allowed_bc.contains_key(b.witness_id.as_str()))
                        .count();
                    if remaining_bc > 0 {
                        report.fail_code(
                            error_codes::COMPOSABILITY_FAILED,
                            format!(
                                "composability failed: {} BC violations ({} allowlisted)",
                                remaining_bc,
                                allowed_bc.len()
                            ),
                        );
                    }
                }
            }
        }
    }

    if options.profile == VerifyProfile::Full {
        let Some(admissibility_entry) = required_artifacts.admissibility_witnesses.as_ref() else {
            return report;
        };

        let admissibility_path = options
            .admissibility_witnesses_path
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| base.join(&admissibility_entry.file));

        let expected_admissibility_sha = match manifest.admissibility_witnesses_sha256.as_deref() {
            Some(v) => v,
            None => {
                return report;
            }
        };

        match hash_entry(base, admissibility_entry) {
            Ok((sha, size)) => {
                if sha != admissibility_entry.sha256 || size != admissibility_entry.size {
                    report.fail_code(
                        error_codes::FULL_PROFILE_ADMISSIBILITY_HASH_MISMATCH,
                        format!(
                            "requiredArtifacts.admissibilityWitnesses hash mismatch for {}: expected {} ({} bytes), got {} ({} bytes)",
                            admissibility_entry.file,
                            admissibility_entry.sha256,
                            admissibility_entry.size,
                            sha,
                            size
                        ),
                    );
                }
            }
            Err(err) => {
                report.fail_error(err);
                return report;
            }
        }

        let admissibility_bytes = match fs::read(&admissibility_path) {
            Ok(b) => b,
            Err(e) => {
                report.fail_code(
                    error_codes::FULL_PROFILE_ADMISSIBILITY_READ_ERROR,
                    format!(
                        "full-profile verify requires admissibility witnesses at {}: {e}",
                        admissibility_path.display()
                    ),
                );
                return report;
            }
        };
        let got_admissibility_sha = format!("sha256:{}", sha256_hex(&admissibility_bytes));
        if got_admissibility_sha != expected_admissibility_sha {
            report.fail_code(
                error_codes::FULL_PROFILE_ADMISSIBILITY_HASH_MISMATCH,
                format!(
                    "admissibility witnesses hash mismatch: expected {}, got {}",
                    expected_admissibility_sha, got_admissibility_sha
                ),
            );
        }

        match serde_json::from_slice::<GateWitnesses>(&admissibility_bytes) {
            Ok(gate) => {
                if let Err(e) = gate.validate() {
                    report.fail_code(
                        error_codes::FULL_PROFILE_ADMISSIBILITY_INVALID,
                        format!(
                            "invalid full-profile admissibility witnesses {}: {e}",
                            admissibility_path.display()
                        ),
                    );
                } else if gate.rejected() {
                    for f in &gate.failures {
                        report.fail_code(
                            error_codes::FULL_PROFILE_ADMISSIBILITY_REJECTED,
                            format!(
                                "full-profile admissibility verification failed: [{} {}] {}{}",
                                f.class_name,
                                f.law_ref,
                                f.message,
                                format_gate_sources(f)
                            ),
                        );
                    }
                }
            }
            Err(e) => {
                report.fail_code(
                    error_codes::FULL_PROFILE_ADMISSIBILITY_PARSE_ERROR,
                    format!(
                        "failed to parse full-profile admissibility witnesses {}: {e}",
                        admissibility_path.display()
                    ),
                );
            }
        }
    }

    report
}
