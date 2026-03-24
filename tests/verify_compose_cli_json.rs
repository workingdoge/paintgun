use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use paintgun::cert::{
    ConflictMode, CtcSemantics, ManifestEntry, PackIdentity, ToolInfo, TrustMetadata,
};
use paintgun::compose::{
    error_codes as compose_error_codes, ComposeManifest, ComposePackEntry, ComposeSummary,
    ComposeWitnesses,
};

fn temp_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("paintgun-{prefix}-{}-{ts}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", paintgun::util::sha256_hex(bytes))
}

fn write_file(path: &Path, contents: &str) {
    let parent = path.parent().expect("parent");
    fs::create_dir_all(parent).expect("create parent");
    fs::write(path, contents).expect("write file");
}

fn create_source_tree(root: &Path, name: &str, value: i32) -> PathBuf {
    let src = root.join(name);
    let resolver = src.join(format!("{name}.resolver.json"));
    let token_doc = src.join("tokens/base.tokens.json");

    write_file(
        &token_doc,
        &format!(
            r#"{{
  "color": {{
    "brand": {{
      "$type": "number",
      "$value": {value}
    }}
  }}
}}"#
        ),
    );
    write_file(
        &resolver,
        &format!(
            r##"{{
  "name": "{name}",
  "version": "2025.10",
  "sets": {{
    "base": {{
      "sources": [
        {{ "$ref": "tokens/base.tokens.json" }}
      ]
    }}
  }},
  "modifiers": {{}},
  "resolutionOrder": [
    {{ "$ref": "#/sets/base" }}
  ]
}}"##
        ),
    );

    resolver
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn verify_compose_format_json_success_emits_contract_shape() {
    let root = temp_dir("verify-compose-json-success");
    let source_root = root.join("source");
    let bundle_root = root.join("bundle");
    let resolver_a = create_source_tree(&source_root, "pack-a", 1);
    let resolver_b = create_source_tree(&source_root, "pack-b", 2);
    let pack_a = bundle_root.join("pack-a");
    let pack_b = bundle_root.join("pack-b");
    let compose_out = bundle_root.join("dist-compose");

    let build_a = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("build")
        .arg(&resolver_a)
        .arg("--out")
        .arg(&pack_a)
        .arg("--target")
        .arg("swift")
        .output()
        .expect("run tbp build pack-a");
    assert_success(&build_a, "tbp build pack-a");

    let build_b = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("build")
        .arg(&resolver_b)
        .arg("--out")
        .arg(&pack_b)
        .arg("--target")
        .arg("swift")
        .output()
        .expect("run tbp build pack-b");
    assert_success(&build_b, "tbp build pack-b");

    let compose = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("compose")
        .arg(&pack_a)
        .arg(&pack_b)
        .arg("--out")
        .arg(&compose_out)
        .arg("--target")
        .arg("swift")
        .output()
        .expect("run tbp compose");
    assert_success(&compose, "tbp compose");

    let manifest_path = compose_out.join("compose.manifest.json");
    let output = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("verify-compose")
        .arg(&manifest_path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run tbp verify-compose");
    assert_success(&output, "tbp verify-compose --format json");

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse verify-compose json");
    assert_eq!(report["kind"], "verify-compose");
    assert_eq!(report["manifest"], manifest_path.to_string_lossy().as_ref());
    assert_eq!(report["ok"], true);
    assert_eq!(report["verify"]["ok"], true);
    assert_eq!(report["semantics"]["ok"], true);
    assert!(report["verify"]["errors"]
        .as_array()
        .expect("verify errors array")
        .is_empty());
    assert!(report["verify"]["errorDetails"]
        .as_array()
        .expect("verify errorDetails array")
        .is_empty());
    assert!(report["semantics"]["errors"]
        .as_array()
        .expect("semantics errors array")
        .is_empty());
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
            name: "paintgun".to_string(),
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

    let output = Command::new(env!("CARGO_BIN_EXE_paint"))
        .arg("verify-compose")
        .arg(&manifest_path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run paint verify-compose");
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
