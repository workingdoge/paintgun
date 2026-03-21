use super::{error_codes, VerifyError, VerifyReport};
use crate::cert::CtcManifest;
use crate::kcir_v2::{
    kcir_profile_binding_for_scheme_and_wire, KcirProfileBinding, ProfileAnchors, KCIR_VERSION,
};

fn parse_anchor_root_bytes(raw: &str) -> Result<Vec<u8>, String> {
    let trimmed = raw.trim();
    let hex_part = if let Some(rest) = trimmed.strip_prefix("sha256:") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("0x") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("0X") {
        rest
    } else {
        trimmed
    };
    hex::decode(hex_part).map_err(|e| format!("invalid anchor root commitment {raw:?}: {e}"))
}

fn anchors_from_manifest_profile(
    profile: &KcirProfileBinding,
) -> Result<Option<ProfileAnchors>, String> {
    let Some(anchor) = profile.anchor.as_ref() else {
        return Ok(None);
    };
    let root_commitment = match anchor.root_commitment.as_ref() {
        Some(raw) => Some(parse_anchor_root_bytes(raw)?),
        None => None,
    };
    Ok(Some(ProfileAnchors {
        root_commitment,
        tree_epoch: anchor.tree_epoch,
        metadata: std::collections::BTreeMap::new(),
    }))
}

fn expected_anchor_fields_present(anchors: &ProfileAnchors) -> bool {
    anchors.root_commitment.is_some()
        || anchors.tree_epoch.is_some()
        || !anchors.metadata.is_empty()
}

pub(crate) fn check_manifest_profile_binding(manifest: &CtcManifest, report: &mut VerifyReport) {
    if manifest.kcir_version.trim().is_empty() {
        report.fail_code(
            error_codes::KCIR_VERSION_MISSING,
            "manifest kcirVersion missing".to_string(),
        );
    } else if manifest.kcir_version != KCIR_VERSION {
        report.fail_code(
            error_codes::KCIR_VERSION_MISMATCH,
            format!(
                "kcirVersion mismatch: expected {}, got {}",
                KCIR_VERSION, manifest.kcir_version
            ),
        );
    }

    let Some(profile) = manifest.profile.as_ref() else {
        report.fail_code(
            crate::kcir_v2::error_codes::PROFILE_MISMATCH,
            "manifest profile missing".to_string(),
        );
        return;
    };

    if profile.scheme_id.trim().is_empty() {
        report.fail_code(
            error_codes::MANIFEST_FIELD_MISSING,
            "manifest profile.schemeId missing".to_string(),
        );
    }
    if profile.params_hash.trim().is_empty() {
        report.fail_code(
            crate::kcir_v2::error_codes::PARAMS_HASH_MISMATCH,
            "manifest profile.paramsHash missing".to_string(),
        );
    }
    if profile.wire_format_id.trim().is_empty() {
        report.fail_code(
            error_codes::MANIFEST_FIELD_MISSING,
            "manifest profile.wireFormatId missing".to_string(),
        );
    }
    match profile.evidence_format_version.as_deref() {
        Some(v) if !v.trim().is_empty() => {}
        _ => report.fail_code(
            crate::kcir_v2::error_codes::EVIDENCE_MALFORMED,
            "manifest profile.evidenceFormatVersion missing".to_string(),
        ),
    }
    if profile.anchor.is_none() {
        report.fail_code(
            crate::kcir_v2::error_codes::ANCHOR_MISSING,
            "manifest profile.anchor missing".to_string(),
        );
    } else if let Some(root) = profile
        .anchor
        .as_ref()
        .and_then(|a| a.root_commitment.as_ref())
    {
        if let Err(e) = parse_anchor_root_bytes(root) {
            report.fail_code(
                crate::kcir_v2::error_codes::ANCHOR_MISMATCH,
                format!("invalid manifest profile.anchor.rootCommitment: {e}"),
            );
        }
    }

    let expected = match kcir_profile_binding_for_scheme_and_wire(
        profile.scheme_id.as_str(),
        profile.wire_format_id.as_str(),
    ) {
        Ok(v) => v,
        Err(e) => {
            report.fail_code(error_codes::PROFILE_UNSUPPORTED, e);
            return;
        }
    };
    if profile.params_hash != expected.params_hash {
        report.fail_code(
            crate::kcir_v2::error_codes::PARAMS_HASH_MISMATCH,
            format!(
                "profile.paramsHash mismatch: expected {}, got {}",
                expected.params_hash, profile.params_hash
            ),
        );
    }
    if let Some(expected_wire_version) = expected.wire_format_version.as_ref() {
        if profile.wire_format_version.as_deref() != Some(expected_wire_version.as_str()) {
            report.fail_code(
                error_codes::MANIFEST_FIELD_MISMATCH,
                format!(
                    "profile.wireFormatVersion mismatch: expected {:?}, got {:?}",
                    expected.wire_format_version, profile.wire_format_version
                ),
            );
        }
    }
    if let Some(expected_evidence_version) = expected.evidence_format_version.as_ref() {
        if profile.evidence_format_version.as_deref() != Some(expected_evidence_version.as_str()) {
            report.fail_code(
                crate::kcir_v2::error_codes::EVIDENCE_MALFORMED,
                format!(
                    "profile.evidenceFormatVersion mismatch: expected {:?}, got {:?}",
                    expected.evidence_format_version, profile.evidence_format_version
                ),
            );
        }
    }
}

pub fn validate_manifest_profile_binding(manifest: &CtcManifest) -> Vec<VerifyError> {
    let mut report = VerifyReport::new();
    check_manifest_profile_binding(manifest, &mut report);
    report.error_details
}

pub(crate) fn check_expected_profile_anchors(
    manifest: &CtcManifest,
    expected: &ProfileAnchors,
    report: &mut VerifyReport,
) {
    if !expected_anchor_fields_present(expected) {
        return;
    }

    let Some(profile) = manifest.profile.as_ref() else {
        report.fail_code(
            crate::kcir_v2::error_codes::ANCHOR_MISSING,
            "manifest profile missing while expected KCIR anchors were provided".to_string(),
        );
        return;
    };

    let parsed = match anchors_from_manifest_profile(profile) {
        Ok(v) => v,
        Err(e) => {
            report.fail_code(
                crate::kcir_v2::error_codes::ANCHOR_MISMATCH,
                format!("invalid manifest profile anchor: {e}"),
            );
            return;
        }
    };
    let Some(actual) = parsed else {
        report.fail_code(
            crate::kcir_v2::error_codes::ANCHOR_MISSING,
            "manifest profile anchor missing while expected KCIR anchors were provided".to_string(),
        );
        return;
    };

    if let Some(exp_root) = expected.root_commitment.as_ref() {
        if actual.root_commitment.as_ref() != Some(exp_root) {
            report.fail_code(
                crate::kcir_v2::error_codes::ANCHOR_MISMATCH,
                "manifest profile anchor rootCommitment mismatch".to_string(),
            );
        }
    }
    if let Some(exp_epoch) = expected.tree_epoch {
        if actual.tree_epoch != Some(exp_epoch) {
            report.fail_code(
                crate::kcir_v2::error_codes::ANCHOR_MISMATCH,
                format!(
                    "manifest profile anchor treeEpoch mismatch: expected {}, got {:?}",
                    exp_epoch, actual.tree_epoch
                ),
            );
        }
    }
    for (k, v) in &expected.metadata {
        let got = actual.metadata.get(k);
        if got != Some(v) {
            report.fail_code(
                crate::kcir_v2::error_codes::ANCHOR_MISMATCH,
                format!(
                    "manifest profile anchor metadata mismatch for key {}: expected {}, got {:?}",
                    k, v, got
                ),
            );
        }
    }
}
