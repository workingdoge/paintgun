use std::process::Command;

#[test]
fn top_level_version_flag_reports_package_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_tbp"))
        .arg("--version")
        .output()
        .expect("run tbp --version");

    assert!(output.status.success(), "expected --version to succeed");
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert_eq!(stdout.trim(), format!("tbp {}", env!("CARGO_PKG_VERSION")));
}
