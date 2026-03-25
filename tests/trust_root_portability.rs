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

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn copy_dir_recursive(src: &Path, dest: &Path) {
    fs::create_dir_all(dest).expect("create dest dir");
    for entry in fs::read_dir(src).expect("read dir") {
        let entry = entry.expect("dir entry");
        let from = entry.path();
        let to = dest.join(entry.file_name());
        let file_type = entry.file_type().expect("file type");
        if file_type.is_dir() {
            copy_dir_recursive(&from, &to);
        } else {
            fs::copy(&from, &to).expect("copy file");
        }
    }
}

#[test]
fn build_stages_self_contained_inputs_for_external_output_roots() {
    let root = temp_dir("trust-root-pack");
    let resolver = create_source_tree(&root.join("source"), "pack-a", 1);
    let out = root.join("archive/pack-a");

    let build = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("build")
        .arg(&resolver)
        .arg("--out")
        .arg(&out)
        .arg("--target")
        .arg("swift-tokens")
        .output()
        .expect("run paint build");
    assert_success(&build, "paint build");

    let manifest_path = out.join("ctc.manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("parse manifest");

    assert_eq!(
        manifest["inputs"]["resolverSpec"]["file"],
        "inputs/pack-a.resolver.json"
    );
    assert_eq!(
        manifest["inputs"]["tokenDocs"][0]["file"],
        "inputs/tokens/base.tokens.json"
    );
    assert!(
        out.join("inputs/pack-a.resolver.json").exists(),
        "expected staged resolver bundle"
    );
    assert!(
        out.join("inputs/tokens/base.tokens.json").exists(),
        "expected staged token doc bundle"
    );

    let verify = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("verify")
        .arg(&manifest_path)
        .output()
        .expect("run paint verify");
    assert_success(&verify, "paint verify");

    let moved_root = root.join("moved");
    fs::rename(root.join("archive"), &moved_root).expect("move archive");
    let moved_manifest = moved_root.join("pack-a/ctc.manifest.json");

    let moved_verify = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("verify")
        .arg(&moved_manifest)
        .output()
        .expect("run moved paint verify");
    assert_success(&moved_verify, "paint verify after moving pack");
}

#[test]
fn compose_manifest_tracks_pack_dirs_relative_to_bundle_root() {
    let root = temp_dir("trust-root-compose");
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
        .output()
        .expect("run paint compose");
    assert_success(&compose, "paint compose");

    let compose_manifest_path = compose_out.join("compose.manifest.json");
    let compose_manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&compose_manifest_path).expect("read compose manifest"))
            .expect("parse compose manifest");
    let pack_dirs = compose_manifest["packs"]
        .as_array()
        .expect("packs array")
        .iter()
        .map(|entry| entry["dir"].as_str().expect("pack dir string").to_string())
        .collect::<Vec<_>>();
    assert!(
        pack_dirs.iter().any(|dir| dir == "../pack-a"),
        "expected relative pack-a dir, got {pack_dirs:?}"
    );
    assert!(
        pack_dirs.iter().any(|dir| dir == "../pack-b"),
        "expected relative pack-b dir, got {pack_dirs:?}"
    );

    let verify = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("verify-compose")
        .arg(&compose_manifest_path)
        .output()
        .expect("run paint verify-compose");
    assert_success(&verify, "paint verify-compose");

    let moved_bundle = root.join("bundle-moved");
    fs::rename(&bundle_root, &moved_bundle).expect("move bundle");
    let moved_manifest = moved_bundle.join("dist-compose/compose.manifest.json");
    let moved_verify = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("verify-compose")
        .arg(&moved_manifest)
        .output()
        .expect("run moved paint verify-compose");
    assert_success(&moved_verify, "paint verify-compose after moving bundle");

    let dist_only = root.join("dist-only");
    copy_dir_recursive(
        &moved_bundle.join("dist-compose"),
        &dist_only.join("dist-compose"),
    );
    let dist_only_manifest = dist_only.join("dist-compose/compose.manifest.json");
    let missing_bundle_verify = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("verify-compose")
        .arg(&dist_only_manifest)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run paint verify-compose");
    assert!(
        !missing_bundle_verify.status.success(),
        "expected dist-only compose bundle to fail"
    );
    let report: serde_json::Value =
        serde_json::from_slice(&missing_bundle_verify.stdout).expect("parse verify-compose json");
    let errors = report["verify"]["errors"]
        .as_array()
        .expect("verify errors array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();
    assert!(
        errors
            .iter()
            .any(|msg| msg.contains("unsafe pack dir ../pack-a")
                || msg.contains("unsafe pack dir ../pack-b")),
        "expected missing-pack-dir error, got {errors:?}"
    );
}
