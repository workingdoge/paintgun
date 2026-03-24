use std::process::Command;

#[test]
fn paint_version_reports_public_binary_name() {
    let output = Command::new(env!("CARGO_BIN_EXE_paint"))
        .arg("--version")
        .output()
        .expect("run paint --version");

    assert!(
        output.status.success(),
        "--version should succeed, stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("paint "),
        "expected version output to start with public binary name, got: {stdout:?}"
    );
}
