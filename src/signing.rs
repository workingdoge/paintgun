use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::cert::{CtcManifest, TrustMetadata, TrustStatus};
use crate::compose::ComposeManifest;
use crate::util::sha256_hex;

pub const SIGNATURE_SCHEME: &str = "paintgun-detached-sha256-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetachedSignature {
    pub version: u32,
    pub scheme: String,
    #[serde(rename = "manifestKind")]
    pub manifest_kind: String,
    #[serde(rename = "claimsSha256")]
    pub claims_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

fn default_signature_path(manifest_path: &Path) -> PathBuf {
    let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let file = manifest_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("manifest.json");
    let sig_name = if let Some(base) = file.strip_suffix(".json") {
        format!("{base}.sig.json")
    } else {
        format!("{file}.sig.json")
    };
    manifest_dir.join(sig_name)
}

fn signature_path_for_manifest(manifest_path: &Path, signature_out: Option<&Path>) -> PathBuf {
    let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    match signature_out {
        Some(p) if p.is_absolute() => p.to_path_buf(),
        Some(p) => manifest_dir.join(p),
        None => default_signature_path(manifest_path),
    }
}

fn signature_file_field(manifest_path: &Path, signature_path: &Path) -> String {
    let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    match signature_path.strip_prefix(manifest_dir) {
        Ok(rel) => rel.to_string_lossy().replace('\\', "/"),
        Err(_) => signature_path.to_string_lossy().replace('\\', "/"),
    }
}

fn digest_json(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).expect("serialize signing claims");
    format!("sha256:{}", sha256_hex(&bytes))
}

fn ctc_claims(manifest: &CtcManifest) -> Value {
    json!({
        "kind": "ctc",
        "ctcVersion": manifest.ctc_version,
        "tool": manifest.tool,
        "spec": manifest.spec,
        "packIdentity": manifest.pack_identity,
        "profile": manifest.profile,
        "semantics": manifest.semantics,
        "resolverSpecSha256": manifest.inputs.resolver_spec.sha256,
        "resolvedSha256": manifest.outputs.resolved_json.sha256,
        "witnessesSha256": manifest.witnesses_sha256,
        "admissibilityWitnessesSha256": manifest.admissibility_witnesses_sha256,
    })
}

fn compose_claims(manifest: &ComposeManifest) -> Value {
    let pack_bindings: Vec<Value> = manifest
        .packs
        .iter()
        .map(|p| {
            json!({
                "name": p.name,
                "packIdentity": p.pack_identity,
                "ctcManifestSha256": p.ctc_manifest.sha256,
                "ctcWitnessesSha256": p.ctc_witnesses.sha256,
                "resolvedJsonSha256": p.resolved_json.sha256,
            })
        })
        .collect();
    json!({
        "kind": "compose",
        "composeVersion": manifest.compose_version,
        "tool": manifest.tool,
        "semantics": manifest.semantics,
        "packOrder": manifest.pack_order,
        "packs": pack_bindings,
        "witnessesSha256": manifest.witnesses_sha256,
    })
}

fn verify_trust_signed(trust: &TrustMetadata) -> Result<(), String> {
    if trust.status != TrustStatus::Signed {
        return Err("manifest trust.status is not 'signed'".to_string());
    }
    if trust.signature_scheme.as_deref() != Some(SIGNATURE_SCHEME) {
        return Err(format!(
            "unsupported signature scheme {:?} (expected {SIGNATURE_SCHEME})",
            trust.signature_scheme
        ));
    }
    if trust
        .signature_file
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        return Err("signed manifest is missing trust.signatureFile".to_string());
    }
    if trust
        .claims_sha256
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        return Err("signed manifest is missing trust.claimsSha256".to_string());
    }
    Ok(())
}

fn verify_signature_record(
    manifest_path: &Path,
    trust: &TrustMetadata,
    expected_kind: &str,
    expected_claims_sha256: &str,
) -> Result<(), String> {
    verify_trust_signed(trust)?;
    let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let root = manifest_dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let sig_rel = trust
        .signature_file
        .as_deref()
        .expect("signature file validated");
    let sig_path = crate::path_safety::resolve_existing_within(manifest_dir, sig_rel, root)
        .map_err(|e| format!("unsafe signature file path {sig_rel}: {e}"))?;

    let sig_bytes = fs::read(&sig_path)
        .map_err(|e| format!("failed to read signature file {}: {e}", sig_path.display()))?;
    let sig: DetachedSignature =
        serde_json::from_slice(&sig_bytes).map_err(|e| format!("invalid signature JSON: {e}"))?;

    if sig.version != 1 {
        return Err(format!(
            "unsupported signature version {} (expected 1)",
            sig.version
        ));
    }
    if sig.scheme != SIGNATURE_SCHEME {
        return Err(format!(
            "signature record scheme mismatch: expected {SIGNATURE_SCHEME}, got {}",
            sig.scheme
        ));
    }
    if sig.manifest_kind != expected_kind {
        return Err(format!(
            "signature record manifestKind mismatch: expected {}, got {}",
            expected_kind, sig.manifest_kind
        ));
    }
    if sig.claims_sha256 != expected_claims_sha256 {
        return Err(format!(
            "signature claimsSha256 mismatch: expected {}, got {}",
            expected_claims_sha256, sig.claims_sha256
        ));
    }
    if trust.claims_sha256.as_deref() != Some(expected_claims_sha256) {
        return Err(format!(
            "manifest trust.claimsSha256 mismatch: expected {}, got {:?}",
            expected_claims_sha256, trust.claims_sha256
        ));
    }
    if let Some(expected_signer) = trust.signer.as_deref() {
        if sig.signer.as_deref() != Some(expected_signer) {
            return Err(format!(
                "signature signer mismatch: expected {}, got {:?}",
                expected_signer, sig.signer
            ));
        }
    }
    Ok(())
}

pub fn verify_ctc_signature(manifest_path: &Path, manifest: &CtcManifest) -> Result<(), String> {
    let claims_sha = digest_json(&ctc_claims(manifest));
    verify_signature_record(manifest_path, &manifest.trust, "ctc", &claims_sha)
}

pub fn verify_compose_signature(
    manifest_path: &Path,
    manifest: &ComposeManifest,
) -> Result<(), String> {
    let claims_sha = digest_json(&compose_claims(manifest));
    verify_signature_record(manifest_path, &manifest.trust, "compose", &claims_sha)
}

fn write_signed_ctc_manifest(
    manifest_path: &Path,
    mut manifest: CtcManifest,
    signature_out: Option<&Path>,
    signer: Option<&str>,
) -> Result<PathBuf, String> {
    let sig_path = signature_path_for_manifest(manifest_path, signature_out);
    let claims_sha = digest_json(&ctc_claims(&manifest));

    let sig = DetachedSignature {
        version: 1,
        scheme: SIGNATURE_SCHEME.to_string(),
        manifest_kind: "ctc".to_string(),
        claims_sha256: claims_sha.clone(),
        signer: signer.map(|s| s.to_string()),
    };
    fs::write(
        &sig_path,
        serde_json::to_vec_pretty(&sig).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("failed to write signature {}: {e}", sig_path.display()))?;

    manifest.trust = TrustMetadata {
        status: TrustStatus::Signed,
        signature_scheme: Some(SIGNATURE_SCHEME.to_string()),
        signature_file: Some(signature_file_field(manifest_path, &sig_path)),
        signer: signer.map(|s| s.to_string()),
        claims_sha256: Some(claims_sha),
    };
    fs::write(
        manifest_path,
        serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("failed to write manifest {}: {e}", manifest_path.display()))?;
    Ok(sig_path)
}

fn write_signed_compose_manifest(
    manifest_path: &Path,
    mut manifest: ComposeManifest,
    signature_out: Option<&Path>,
    signer: Option<&str>,
) -> Result<PathBuf, String> {
    let sig_path = signature_path_for_manifest(manifest_path, signature_out);
    let claims_sha = digest_json(&compose_claims(&manifest));

    let sig = DetachedSignature {
        version: 1,
        scheme: SIGNATURE_SCHEME.to_string(),
        manifest_kind: "compose".to_string(),
        claims_sha256: claims_sha.clone(),
        signer: signer.map(|s| s.to_string()),
    };
    fs::write(
        &sig_path,
        serde_json::to_vec_pretty(&sig).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("failed to write signature {}: {e}", sig_path.display()))?;

    manifest.trust = TrustMetadata {
        status: TrustStatus::Signed,
        signature_scheme: Some(SIGNATURE_SCHEME.to_string()),
        signature_file: Some(signature_file_field(manifest_path, &sig_path)),
        signer: signer.map(|s| s.to_string()),
        claims_sha256: Some(claims_sha),
    };
    fs::write(
        manifest_path,
        serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("failed to write manifest {}: {e}", manifest_path.display()))?;
    Ok(sig_path)
}

pub fn sign_manifest_file(
    manifest_path: &Path,
    signature_out: Option<&Path>,
    signer: Option<&str>,
) -> Result<PathBuf, String> {
    let bytes = fs::read(manifest_path)
        .map_err(|e| format!("failed to read manifest {}: {e}", manifest_path.display()))?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| {
        format!(
            "failed to parse manifest JSON {}: {e}",
            manifest_path.display()
        )
    })?;

    if value.get("ctcVersion").is_some() {
        let manifest: CtcManifest =
            serde_json::from_value(value).map_err(|e| format!("invalid CTC manifest: {e}"))?;
        return write_signed_ctc_manifest(manifest_path, manifest, signature_out, signer);
    }
    if value.get("composeVersion").is_some() {
        let manifest: ComposeManifest =
            serde_json::from_value(value).map_err(|e| format!("invalid compose manifest: {e}"))?;
        return write_signed_compose_manifest(manifest_path, manifest, signature_out, signer);
    }

    Err(format!(
        "unsupported manifest type {} (expected ctcVersion or composeVersion)",
        manifest_path.display()
    ))
}
