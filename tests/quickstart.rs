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

fn run_paint(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .output()
        .expect("run paint")
}

#[test]
fn quickstart_walkthrough_goes_from_gap_to_green() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let failing = root.join("examples/quickstart/failing.resolver.json");
    let fixed = root.join("examples/quickstart/fixed.resolver.json");
    let failing_out = temp_dir("quickstart-failing");
    let fixed_out = temp_dir("quickstart-fixed");

    let build_failing = run_paint(&[
        "build",
        failing.to_str().expect("failing path"),
        "--out",
        failing_out.to_str().expect("failing out"),
        "--target",
        "web-tokens-ts",
        "--format",
        "json",
    ]);
    assert!(
        build_failing.status.success(),
        "quickstart failing build should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build_failing.stdout),
        String::from_utf8_lossy(&build_failing.stderr)
    );
    assert!(
        failing_out.join("tokens.ts").exists(),
        "expected primary emitted artifact"
    );
    assert!(
        failing_out.join("ctc.manifest.json").exists(),
        "expected manifest artifact"
    );
    assert!(
        failing_out.join("validation.json").exists(),
        "expected machine-readable findings"
    );

    let verify_failing = run_paint(&[
        "verify",
        failing_out
            .join("ctc.manifest.json")
            .to_str()
            .expect("manifest path"),
        "--require-composable",
    ]);
    assert!(
        !verify_failing.status.success(),
        "expected failing quickstart verify"
    );
    let stderr = String::from_utf8(verify_failing.stderr).expect("verify stderr");
    assert!(
        stderr.contains("Kan gaps") || stderr.contains("gap"),
        "expected composability failure, got:\n{stderr}"
    );

    let validation: Value = serde_json::from_slice(
        &fs::read(failing_out.join("validation.json")).expect("read validation.json"),
    )
    .expect("parse validation.json");
    let witness_id = validation["findings"]
        .as_array()
        .and_then(|f| f.first())
        .and_then(|f| f["witnessId"].as_str())
        .expect("first witness id")
        .to_string();

    let explain = run_paint(&[
        "explain",
        &witness_id,
        "--witnesses",
        failing_out
            .join("ctc.witnesses.json")
            .to_str()
            .expect("witness path"),
    ]);
    assert!(
        explain.status.success(),
        "expected explain to succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&explain.stdout),
        String::from_utf8_lossy(&explain.stderr)
    );
    let explain_text = String::from_utf8(explain.stdout).expect("explain stdout");
    assert!(
        explain_text.contains("Finding: Missing definition"),
        "expected family-first explain output"
    );
    assert!(
        explain_text.contains("Technical kind: gap"),
        "expected gap technical kind"
    );
    assert!(
        explain_text.contains("Next action:"),
        "expected action guidance"
    );
    assert!(
        explain_text.contains("theme:dark"),
        "expected failing context summary"
    );
    assert!(
        explain_text.contains("/color/action/primary/$value"),
        "expected token-path location"
    );

    let build_fixed = run_paint(&[
        "build",
        fixed.to_str().expect("fixed path"),
        "--out",
        fixed_out.to_str().expect("fixed out"),
        "--target",
        "web-tokens-ts",
        "--format",
        "json",
    ]);
    assert!(
        build_fixed.status.success(),
        "quickstart fixed build should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build_fixed.stdout),
        String::from_utf8_lossy(&build_fixed.stderr)
    );

    let verify_fixed = run_paint(&[
        "verify",
        fixed_out
            .join("ctc.manifest.json")
            .to_str()
            .expect("fixed manifest path"),
        "--require-composable",
    ]);
    assert!(
        verify_fixed.status.success(),
        "expected fixed quickstart verify to succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&verify_fixed.stdout),
        String::from_utf8_lossy(&verify_fixed.stderr)
    );
}
