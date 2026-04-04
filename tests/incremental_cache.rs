use std::fs;
use std::path::{Path, PathBuf};
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

fn write_policy(path: &Path, precision: u8) {
    write_file(
        path,
        &format!(
            r#"{{
  "float_precision": {precision},
  "duration": {{
    "prefer": "ms"
  }},
  "dimension": {{
    "rem_base_px": 16
  }},
  "css_color": "preserve-space"
}}"#
        ),
    );
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
fn build_reuses_incremental_cache_when_inputs_are_unchanged() {
    let root = temp_dir("incremental-build-hit");
    let resolver = create_source_tree(&root.join("source"), "pack-a", 1);
    let out = root.join("dist");

    let first = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("build")
        .arg(&resolver)
        .arg("--out")
        .arg(&out)
        .arg("--target")
        .arg("swift-tokens")
        .output()
        .expect("run first paint build");
    assert_success(&first, "first paint build");

    let second = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("build")
        .arg(&resolver)
        .arg("--out")
        .arg(&out)
        .arg("--target")
        .arg("swift-tokens")
        .output()
        .expect("run second paint build");
    assert_success(&second, "second paint build");

    let stderr = String::from_utf8(second.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("reused cached build outputs"),
        "expected cache hit note, got:\n{stderr}"
    );
    assert!(
        out.join(".paint/cache/build.json").exists(),
        "expected build cache metadata"
    );
}

#[test]
fn build_cache_invalidates_when_policy_changes() {
    let root = temp_dir("incremental-build-policy");
    let resolver = create_source_tree(&root.join("source"), "pack-a", 1);
    let out = root.join("dist");
    let policy_a = root.join("policy-a.json");
    let policy_b = root.join("policy-b.json");
    write_policy(&policy_a, 4);
    write_policy(&policy_b, 2);

    let first = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("build")
        .arg(&resolver)
        .arg("--out")
        .arg(&out)
        .arg("--target")
        .arg("swift-tokens")
        .arg("--policy")
        .arg(&policy_a)
        .output()
        .expect("run first paint build");
    assert_success(&first, "first paint build");

    let second = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("build")
        .arg(&resolver)
        .arg("--out")
        .arg(&out)
        .arg("--target")
        .arg("swift-tokens")
        .arg("--policy")
        .arg(&policy_b)
        .output()
        .expect("run second paint build");
    assert_success(&second, "second paint build");

    let stderr = String::from_utf8(second.stderr).expect("stderr utf8");
    assert!(
        !stderr.contains("reused cached build outputs"),
        "expected policy change to invalidate build cache, got:\n{stderr}"
    );
}

#[test]
fn compose_reuses_incremental_cache_when_inputs_are_unchanged() {
    let root = temp_dir("incremental-compose-hit");
    let source_root = root.join("source");
    let bundle_root = root.join("bundle");
    let resolver_a = create_source_tree(&source_root, "pack-a", 1);
    let resolver_b = create_source_tree(&source_root, "pack-b", 2);
    let pack_a = bundle_root.join("pack-a");
    let pack_b = bundle_root.join("pack-b");
    let compose_out = bundle_root.join("dist-compose");

    for (resolver, out) in [(&resolver_a, &pack_a), (&resolver_b, &pack_b)] {
        let build = Command::new(env!("CARGO_BIN_EXE_paint"))
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .arg("build")
            .arg(resolver)
            .arg("--out")
            .arg(out)
            .arg("--target")
            .arg("swift-tokens")
            .output()
            .expect("run paint build");
        assert_success(&build, "paint build");
    }

    let first = Command::new(env!("CARGO_BIN_EXE_paint"))
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
        .expect("run first paint compose");
    assert_success(&first, "first paint compose");

    let second = Command::new(env!("CARGO_BIN_EXE_paint"))
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
        .expect("run second paint compose");
    assert_success(&second, "second paint compose");

    let stderr = String::from_utf8(second.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("reused cached compose outputs"),
        "expected compose cache hit note, got:\n{stderr}"
    );
    assert!(
        compose_out.join(".paint/cache/compose.json").exists(),
        "expected compose cache metadata"
    );
    let report: serde_json::Value =
        serde_json::from_slice(&second.stdout).expect("parse cached compose.report.json");
    assert_eq!(report["backendArtifacts"][0]["backendId"], "swift-tokens");
}
