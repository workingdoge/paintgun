use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

fn temp_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("paintgun-{prefix}-{}-{ts}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn build_writes_editor_diagnostics_projection_without_json_report_flag() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolver = root.join("examples/quickstart/failing.resolver.json");
    let out = temp_dir("diagnostics-cli");

    let output = Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("build")
        .arg(&resolver)
        .arg("--out")
        .arg(&out)
        .arg("--target")
        .arg("web-tokens-ts")
        .output()
        .expect("run paint build");
    assert!(
        output.status.success(),
        "paint build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let diagnostics_path = out.join("diagnostics.pack.json");
    assert!(
        diagnostics_path.exists(),
        "expected diagnostics.pack.json at {}",
        diagnostics_path.display()
    );
    let diagnostics: Value =
        serde_json::from_slice(&fs::read(&diagnostics_path).expect("read diagnostics.pack.json"))
            .expect("parse diagnostics.pack.json");
    assert_eq!(diagnostics["projectionKind"], "editorDiagnostics");
    assert_eq!(diagnostics["sourceReport"]["file"], "validation.json");

    assert!(
        !out.join("validation.json").exists(),
        "validation.json should still require --format json"
    );
}
