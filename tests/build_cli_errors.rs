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
        .arg("swift")
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
        .arg("swift")
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
        .arg("swift")
        .arg("--out")
        .arg(&out_path)
        .output()
        .expect("run paint build");

    assert!(!output.status.success(), "expected build to fail");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("failed to create output directory"));
    assert_nonpanic_failure(&stderr);
}
