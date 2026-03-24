use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use tbp::cert::{analyze_composability, build_validation_report_json};
use tbp::resolver::{build_token_store, read_json_file, ResolverDoc};

fn temp_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("tbp-{prefix}-{}-{ts}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn annotate_report_emits_annotations_and_summary_notice() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture_root = root.join("examples/charter-steel");
    let resolver_path = fixture_root.join("charter-steel.resolver.json");

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store(&doc, &resolver_path).expect("token store");
    let analysis = analyze_composability(&doc, &store, &resolver_path).expect("analysis");
    let report = build_validation_report_json(&analysis);

    let temp = temp_dir("annotate-report");
    let report_path = temp.join("validation.json");
    fs::write(
        &report_path,
        serde_json::to_vec_pretty(&report).expect("serialize report"),
    )
    .expect("write report");

    let output = Command::new(env!("CARGO_BIN_EXE_tbp"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("annotate-report")
        .arg(&report_path)
        .arg("--file-root")
        .arg(&fixture_root)
        .arg("--max")
        .arg("1")
        .output()
        .expect("run annotate-report");
    assert!(
        output.status.success(),
        "annotate-report failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let lines = stdout.lines().collect::<Vec<_>>();
    assert!(
        lines.iter().any(|line| {
            line.starts_with("::error file=")
                || line.starts_with("::warning file=")
                || line.starts_with("::notice file=")
        }),
        "expected at least one GitHub annotation line, got:\n{stdout}"
    );
    assert!(
        lines.iter().any(|line| {
            line.starts_with("::notice title=tbp/report::reportKind=pack")
                && line.contains("conflictMode=semantic")
                && line.contains("emitted=1")
        }),
        "expected summary notice line, got:\n{stdout}"
    );
}

#[test]
fn annotate_report_invalid_json_exits_nonzero() {
    let temp = temp_dir("annotate-report-invalid");
    let report_path = temp.join("broken.json");
    fs::write(&report_path, "{").expect("write broken report");

    let output = Command::new(env!("CARGO_BIN_EXE_tbp"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("annotate-report")
        .arg(&report_path)
        .output()
        .expect("run annotate-report");
    assert!(
        !output.status.success(),
        "expected annotate-report to fail for invalid JSON"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("failed to parse"),
        "expected parse failure, got:\n{stderr}"
    );
}
