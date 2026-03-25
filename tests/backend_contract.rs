use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

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

fn assert_relative_contract_path(path: &str) {
    let rel = Path::new(path);
    assert!(
        !rel.is_absolute(),
        "backend contract path must be relative, got {path}"
    );
    assert!(
        !rel.components().any(|c| matches!(c, Component::ParentDir)),
        "backend contract path must not escape output root, got {path}"
    );
}

#[test]
fn build_json_reports_backend_artifacts_and_manifest_compat_projection() {
    let root = temp_dir("backend-contract-build");
    let resolver = create_source_tree(&root.join("source"), "pack-a", 1);
    let out = root.join("dist");

    let build = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("build")
        .arg(&resolver)
        .arg("--out")
        .arg(&out)
        .arg("--target")
        .arg("swift-tokens")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run paint build");
    assert_success(&build, "paint build");

    let validation: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("validation.json")).expect("read validation"))
            .expect("parse validation.json");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(out.join("ctc.manifest.json")).expect("read ctc.manifest.json"),
    )
    .expect("parse ctc.manifest.json");

    let report_artifacts = validation["backendArtifacts"]
        .as_array()
        .expect("validation backendArtifacts array");
    assert!(
        report_artifacts
            .iter()
            .all(|artifact| artifact["backendId"] == "swift-tokens"),
        "expected canonical backend ids in validation.json, got:\n{}",
        serde_json::to_string_pretty(&validation).expect("serialize validation.json")
    );
    assert!(
        report_artifacts.iter().any(|artifact| {
            artifact["kind"] == "primaryTokenOutput" && artifact["file"] == "tokens.swift"
        }),
        "expected primaryTokenOutput tokens.swift in validation.json, got:\n{}",
        serde_json::to_string_pretty(&validation).expect("serialize validation.json")
    );
    for artifact in report_artifacts {
        assert_relative_contract_path(
            artifact["file"]
                .as_str()
                .expect("validation backend artifact file"),
        );
    }
    assert!(
        validation.get("nativeApiVersions").is_none(),
        "validation.json should not expose nativeApiVersions"
    );

    let manifest_artifacts = manifest["backendArtifacts"]
        .as_array()
        .expect("manifest backendArtifacts array");
    assert!(
        manifest_artifacts
            .iter()
            .all(|artifact| artifact["backendId"] == "swift-tokens"),
        "expected canonical backend ids in ctc.manifest.json, got:\n{}",
        serde_json::to_string_pretty(&manifest).expect("serialize ctc.manifest.json")
    );
    for artifact in manifest_artifacts {
        assert_relative_contract_path(
            artifact["file"]
                .as_str()
                .expect("manifest backend artifact file"),
        );
    }
    assert_eq!(
        manifest["nativeApiVersions"]["swift"],
        serde_json::Value::String("paintgun-swift-tokens/v1".to_string())
    );
}

#[test]
fn compose_json_reports_backend_artifacts_and_manifest_compat_projection() {
    let root = temp_dir("backend-contract-compose");
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
        .arg("swift-tokens")
        .output()
        .expect("run paint build pack-a");
    assert_success(&build_a, "paint build pack-a");

    let build_b = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("build")
        .arg(&resolver_b)
        .arg("--out")
        .arg(&pack_b)
        .arg("--target")
        .arg("swift-tokens")
        .output()
        .expect("run paint build pack-b");
    assert_success(&build_b, "paint build pack-b");

    let compose = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("compose")
        .arg(&pack_a)
        .arg(&pack_b)
        .arg("--out")
        .arg(&compose_out)
        .arg("--target")
        .arg("swift-tokens")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run paint compose");
    assert_success(&compose, "paint compose");

    let report: serde_json::Value = serde_json::from_slice(
        &fs::read(compose_out.join("compose.report.json")).expect("read compose.report.json"),
    )
    .expect("parse compose.report.json");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(compose_out.join("compose.manifest.json")).expect("read compose.manifest.json"),
    )
    .expect("parse compose.manifest.json");

    let report_artifacts = report["backendArtifacts"]
        .as_array()
        .expect("compose report backendArtifacts array");
    assert!(
        report_artifacts
            .iter()
            .all(|artifact| artifact["backendId"] == "swift-tokens"),
        "expected canonical backend ids in compose.report.json, got:\n{}",
        serde_json::to_string_pretty(&report).expect("serialize compose.report.json")
    );
    for artifact in report_artifacts {
        assert_relative_contract_path(
            artifact["file"]
                .as_str()
                .expect("compose report backend artifact file"),
        );
    }
    assert!(
        report.get("nativeApiVersions").is_none(),
        "compose.report.json should not expose nativeApiVersions"
    );

    let manifest_artifacts = manifest["backendArtifacts"]
        .as_array()
        .expect("compose manifest backendArtifacts array");
    assert!(
        manifest_artifacts
            .iter()
            .all(|artifact| artifact["backendId"] == "swift-tokens"),
        "expected canonical backend ids in compose.manifest.json, got:\n{}",
        serde_json::to_string_pretty(&manifest).expect("serialize compose.manifest.json")
    );
    for artifact in manifest_artifacts {
        assert_relative_contract_path(
            artifact["file"]
                .as_str()
                .expect("compose manifest backend artifact file"),
        );
    }
    assert_eq!(
        manifest["nativeApiVersions"]["swift"],
        serde_json::Value::String("paintgun-swift-tokens/v1".to_string())
    );
}
