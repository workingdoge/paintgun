use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use tbp::cert::{ConflictMode, CtcSemantics, ManifestEntry, PackIdentity, ToolInfo, TrustMetadata};
use tbp::compose::{
    error_codes as compose_error_codes, ComposeManifest, ComposePackEntry, ComposeSummary,
    ComposeWitnesses,
};

fn temp_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("tbp-{prefix}-{}-{ts}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", tbp::util::sha256_hex(bytes))
}

#[test]
fn verify_compose_format_json_emits_error_details() {
    let root = temp_dir("verify-compose-json");
    let dist = root.join("dist");
    fs::create_dir_all(&dist).expect("dist");

    let witnesses = ComposeWitnesses {
        witness_schema: 1,
        conflict_mode: ConflictMode::Semantic,
        policy_digest: Some("sha256:dummy".to_string()),
        normalizer_version: None,
        conflicts: Vec::new(),
    };
    let witness_bytes = serde_json::to_vec_pretty(&witnesses).expect("witnesses");
    fs::write(dist.join("compose.witnesses.json"), &witness_bytes).expect("write witnesses");

    let manifest = ComposeManifest {
        compose_version: "0.1".to_string(),
        tool: ToolInfo {
            name: "tbp-rs".to_string(),
            version: "0.1.0".to_string(),
        },
        trust: TrustMetadata::unsigned(),
        axes: BTreeMap::new(),
        pack_order: vec!["pack-a".to_string()],
        packs: vec![ComposePackEntry {
            name: "pack-a".to_string(),
            dir: "../pack-a".to_string(),
            pack_identity: PackIdentity {
                pack_id: "pack-a".to_string(),
                pack_version: "1.0.0".to_string(),
                content_hash: "sha256:pack".to_string(),
            },
            ctc_manifest: ManifestEntry {
                file: "ctc.manifest.json".to_string(),
                sha256: "sha256:x".to_string(),
                size: 1,
            },
            ctc_witnesses: ManifestEntry {
                file: "ctc.witnesses.json".to_string(),
                sha256: "sha256:y".to_string(),
                size: 1,
            },
            resolved_json: ManifestEntry {
                file: "resolved.json".to_string(),
                sha256: "sha256:z".to_string(),
                size: 1,
            },
            authored_json: None,
        }],
        semantics: CtcSemantics {
            eq_value_id: "dtcg-2025.10-typed-structural".to_string(),
            policy_digest: Some("sha256:dummy".to_string()),
            conflict_mode: ConflictMode::Semantic,
            normalizer_version: None,
        },
        native_api_versions: None,
        summary: ComposeSummary {
            packs: 1,
            contexts: 1,
            token_paths_union: 0,
            overlapping_token_paths: 0,
            conflicts: 0,
        },
        witnesses_sha256: sha256_prefixed(&witness_bytes),
    };
    let manifest_path = dist.join("compose.manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize compose manifest"),
    )
    .expect("write compose manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_tbp"))
        .arg("verify-compose")
        .arg(&manifest_path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run tbp verify-compose");
    assert!(
        !output.status.success(),
        "expected verify-compose to fail for unsafe pack dir"
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("parse json report");
    assert_eq!(report["kind"], "verify-compose");
    assert_eq!(report["ok"], false);
    assert_eq!(report["verify"]["ok"], false);

    let details = report["verify"]["errorDetails"]
        .as_array()
        .expect("errorDetails array");
    assert!(
        details
            .iter()
            .any(|e| e["code"] == compose_error_codes::PATH_UNSAFE),
        "expected PATH_UNSAFE in errorDetails, got:\n{}",
        stdout
    );
}
