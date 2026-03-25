use std::fs;
use std::path::PathBuf;
use std::process::Command;
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

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn example_resolver() -> PathBuf {
    repo_root().join("examples/charter-steel/charter-steel.resolver.json")
}

fn assert_nonpanic_failure(stderr: &str) {
    assert!(
        !stderr.contains("panicked at"),
        "expected CLI error, got panic backtrace:\n{}",
        stderr
    );
    assert!(
        !stderr.contains("thread 'main' panicked"),
        "expected CLI error, got panic backtrace:\n{}",
        stderr
    );
}

#[test]
fn build_invalid_resolver_json_fails_without_panic() {
    let root = temp_dir("build-invalid-resolver");
    let resolver = root.join("broken.resolver.json");
    fs::write(&resolver, "{").expect("write broken resolver");

    let output = Command::new(env!("CARGO_BIN_EXE_paint"))
        .arg("build")
        .arg(&resolver)
        .arg("--target")
        .arg("swift-tokens")
        .arg("--out")
        .arg(root.join("dist"))
        .output()
        .expect("run paint build");

    assert!(!output.status.success(), "expected build to fail");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("failed to parse resolver JSON"));
    assert_nonpanic_failure(&stderr);
}

#[test]
fn build_invalid_contracts_shape_fails_without_panic() {
    let root = temp_dir("build-invalid-contracts");
    let contracts = root.join("contracts.json");
    fs::write(&contracts, "[]").expect("write contracts");

    let output = Command::new(env!("CARGO_BIN_EXE_paint"))
        .arg("build")
        .arg(example_resolver())
        .arg("--contracts")
        .arg(&contracts)
        .arg("--out")
        .arg(root.join("dist"))
        .output()
        .expect("run paint build");

    assert!(!output.status.success(), "expected build to fail");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("top-level JSON value must be an object"));
    assert_nonpanic_failure(&stderr);
}

#[test]
fn build_missing_policy_file_fails_without_panic() {
    let root = temp_dir("build-missing-policy");
    let missing_policy = root.join("missing-policy.json");

    let output = Command::new(env!("CARGO_BIN_EXE_paint"))
        .arg("build")
        .arg(example_resolver())
        .arg("--target")
        .arg("swift-tokens")
        .arg("--policy")
        .arg(&missing_policy)
        .arg("--out")
        .arg(root.join("dist"))
        .output()
        .expect("run paint build");

    assert!(!output.status.success(), "expected build to fail");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("failed to read policy JSON"));
    assert_nonpanic_failure(&stderr);
}

#[test]
fn build_output_path_file_fails_without_panic() {
    let root = temp_dir("build-output-path");
    let out_path = root.join("not-a-dir");
    fs::write(&out_path, "occupied").expect("write output file");

    let output = Command::new(env!("CARGO_BIN_EXE_paint"))
        .arg("build")
        .arg(example_resolver())
        .arg("--target")
        .arg("swift-tokens")
        .arg("--out")
        .arg(&out_path)
        .output()
        .expect("run paint build");

    assert!(!output.status.success(), "expected build to fail");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("failed to create output directory"));
    assert_nonpanic_failure(&stderr);
}

#[test]
fn build_unknown_target_fails_via_registry_without_panic() {
    let root = temp_dir("build-unknown-target");

    let output = Command::new(env!("CARGO_BIN_EXE_paint"))
        .arg("build")
        .arg(example_resolver())
        .arg("--target")
        .arg("wat")
        .arg("--out")
        .arg(root.join("dist"))
        .output()
        .expect("run paint build");

    assert!(!output.status.success(), "expected build to fail");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("unknown --target wat"));
    assert!(stderr.contains("android-compose-tokens"));
    assert!(stderr.contains("css"));
    assert!(stderr.contains("kotlin"));
    assert!(stderr.contains("swift"));
    assert!(stderr.contains("swift-tokens"));
    assert!(stderr.contains("web-css-vars"));
    assert!(stderr.contains("web-tokens-ts"));
    assert_nonpanic_failure(&stderr);
}

#[test]
fn build_swift_alias_emits_canonical_backend_identity() {
    let root = temp_dir("build-swift-alias");
    let out = root.join("dist");

    let output = Command::new(env!("CARGO_BIN_EXE_paint"))
        .arg("build")
        .arg(example_resolver())
        .arg("--target")
        .arg("swift")
        .arg("--out")
        .arg(&out)
        .output()
        .expect("run paint build");

    assert!(
        output.status.success(),
        "expected swift alias build to succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let manifest_path = out.join("ctc.manifest.json");
    let manifest_bytes = fs::read(&manifest_path).expect("read ctc.manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("parse ctc.manifest.json");

    let backend_artifacts = manifest["backendArtifacts"]
        .as_array()
        .expect("backendArtifacts array");
    assert!(
        backend_artifacts
            .iter()
            .all(|artifact| artifact["backendId"] == "swift-tokens"),
        "expected canonical swift backend ids in manifest, got:\n{}",
        serde_json::to_string_pretty(&manifest).expect("serialize manifest for debug")
    );
}

#[test]
fn build_kotlin_alias_emits_android_backend_identity() {
    let root = temp_dir("build-kotlin-alias");
    let out = root.join("dist");

    let output = Command::new(env!("CARGO_BIN_EXE_paint"))
        .arg("build")
        .arg(example_resolver())
        .arg("--target")
        .arg("kotlin")
        .arg("--out")
        .arg(&out)
        .output()
        .expect("run paint build");

    assert!(
        output.status.success(),
        "expected alias build to succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let manifest_path = out.join("ctc.manifest.json");
    let manifest_bytes = fs::read(&manifest_path).expect("read ctc.manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("parse ctc.manifest.json");

    let backend_artifacts = manifest["backendArtifacts"]
        .as_array()
        .expect("backendArtifacts array");
    assert!(
        backend_artifacts
            .iter()
            .all(|artifact| artifact["backendId"] == "android-compose-tokens"),
        "expected canonical android backend ids in manifest, got:\n{}",
        serde_json::to_string_pretty(&manifest).expect("serialize manifest for debug")
    );
    assert!(
        out.join("android/build.gradle.kts").is_file(),
        "expected Android scaffold under canonical android/ path"
    );
}

#[test]
fn build_css_alias_emits_web_css_backend_identity() {
    let root = temp_dir("build-css-alias");
    let out = root.join("dist");

    let output = Command::new(env!("CARGO_BIN_EXE_paint"))
        .arg("build")
        .arg(example_resolver())
        .arg("--contracts")
        .arg(repo_root().join("examples/charter-steel/component-contracts.json"))
        .arg("--target")
        .arg("css")
        .arg("--out")
        .arg(&out)
        .output()
        .expect("run paint build");

    assert!(
        output.status.success(),
        "expected css alias build to succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let manifest_path = out.join("ctc.manifest.json");
    let manifest_bytes = fs::read(&manifest_path).expect("read ctc.manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("parse ctc.manifest.json");

    let backend_artifacts = manifest["backendArtifacts"]
        .as_array()
        .expect("backendArtifacts array");
    assert!(
        backend_artifacts
            .iter()
            .all(|artifact| artifact["backendId"] == "web-css-vars"),
        "expected canonical web-css backend ids in manifest, got:\n{}",
        serde_json::to_string_pretty(&manifest).expect("serialize manifest for debug")
    );
}

#[test]
fn build_web_tokens_backend_emits_web_package_artifacts() {
    let root = temp_dir("build-web-tokens");
    let out = root.join("dist");

    let output = Command::new(env!("CARGO_BIN_EXE_paint"))
        .arg("build")
        .arg(example_resolver())
        .arg("--target")
        .arg("web-tokens-ts")
        .arg("--out")
        .arg(&out)
        .output()
        .expect("run paint build");

    assert!(
        output.status.success(),
        "expected web tokens build to succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let manifest_path = out.join("ctc.manifest.json");
    let manifest_bytes = fs::read(&manifest_path).expect("read ctc.manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("parse ctc.manifest.json");

    let backend_artifacts = manifest["backendArtifacts"]
        .as_array()
        .expect("backendArtifacts array");
    assert!(
        backend_artifacts
            .iter()
            .all(|artifact| artifact["backendId"] == "web-tokens-ts"),
        "expected canonical web backend ids in manifest, got:\n{}",
        serde_json::to_string_pretty(&manifest).expect("serialize manifest for debug")
    );
    assert!(
        out.join("tokens.ts").is_file(),
        "expected typed web token source at the output root"
    );
    assert!(
        out.join("web/package.json").is_file(),
        "expected web token package scaffold under web/"
    );
}
