use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use paintgun::verify::error_codes as verify_error_codes;

fn temp_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("paintgun-{prefix}-{}-{ts}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
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

fn build_pack(root: &Path, name: &str, value: i32) -> PathBuf {
    let resolver = create_source_tree(&root.join("source"), name, value);
    let out = root.join("bundle").join(name);
    let build = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("build")
        .arg(&resolver)
        .arg("--out")
        .arg(&out)
        .arg("--target")
        .arg("swift-tokens")
        .output()
        .expect("run tbp build");
    assert_success(&build, "tbp build");
    out.join("ctc.manifest.json")
}

#[test]
fn verify_format_json_success_emits_contract_shape() {
    let root = temp_dir("verify-json-success");
    let manifest_path = build_pack(&root, "pack-a", 1);

    let output = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("verify")
        .arg(&manifest_path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run tbp verify");
    assert_success(&output, "tbp verify --format json");

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse verify json");
    assert_eq!(report["kind"], "verify");
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
    assert!(report["verify"]["notes"]
        .as_array()
        .expect("verify notes array")
        .is_empty());
    assert!(report["semantics"]["errors"]
        .as_array()
        .expect("semantics errors array")
        .is_empty());
}

#[test]
fn verify_format_json_failure_preserves_error_code_and_exit_status() {
    let root = temp_dir("verify-json-failure");
    let manifest_path = build_pack(&root, "pack-a", 1);

    let output = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("verify")
        .arg(&manifest_path)
        .arg("--format")
        .arg("json")
        .arg("--require-signed")
        .output()
        .expect("run tbp verify");
    assert!(
        !output.status.success(),
        "expected verify --require-signed to fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse verify json");
    assert_eq!(report["kind"], "verify");
    assert_eq!(report["ok"], false);
    assert_eq!(report["verify"]["ok"], false);
    assert_eq!(report["semantics"]["ok"], true);

    let details = report["verify"]["errorDetails"]
        .as_array()
        .expect("errorDetails array");
    assert!(
        details
            .iter()
            .any(|e| e["code"] == verify_error_codes::SIGNATURE_REQUIRED),
        "expected SIGNATURE_REQUIRED in errorDetails, got:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
