use std::ffi::OsStr;
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

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_tbp<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(env!("CARGO_BIN_EXE_paint"))
        .args(args)
        .output()
        .expect("run tbp")
}

fn assert_success(output: &Output, label: &str) {
    if !output.status.success() {
        panic!(
            "{label} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn assert_json_ok(path: &Path) {
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(path).expect("read json")).expect("parse json");
    assert_eq!(value["ok"], true, "expected ok json in {}", path.display());
}

#[test]
fn external_adoption_example_runs_end_to_end() {
    let repo = repo_root();
    let example = repo.join("examples/adoption-starter");
    let contracts = example.join("component-contracts.json");
    let policy = example.join("policy.json");
    let core_resolver = example.join("core.resolver.json");
    let brand_resolver = example.join("brand.resolver.json");

    let root = temp_dir("adoption-example");
    let core_out = root.join("packs/core");
    let brand_out = root.join("packs/brand");
    let compose_out = root.join("compose");

    let build_core = run_tbp([
        OsStr::new("build"),
        core_resolver.as_os_str(),
        OsStr::new("--contracts"),
        contracts.as_os_str(),
        OsStr::new("--policy"),
        policy.as_os_str(),
        OsStr::new("--out"),
        core_out.as_os_str(),
        OsStr::new("--target"),
        OsStr::new("css"),
        OsStr::new("--format"),
        OsStr::new("json"),
    ]);
    assert_success(&build_core, "build core");

    let verify_core = run_tbp([
        OsStr::new("verify"),
        core_out.join("ctc.manifest.json").as_os_str(),
    ]);
    assert_success(&verify_core, "verify core");

    let sign_core = run_tbp([
        OsStr::new("sign"),
        core_out.join("ctc.manifest.json").as_os_str(),
        OsStr::new("--signer"),
        OsStr::new("ci@example"),
    ]);
    assert_success(&sign_core, "sign core");

    let verify_core_signed = run_tbp([
        OsStr::new("verify"),
        core_out.join("ctc.manifest.json").as_os_str(),
        OsStr::new("--require-signed"),
        OsStr::new("--format"),
        OsStr::new("json"),
    ]);
    assert_success(&verify_core_signed, "verify core signed");
    let core_verify_json = root.join("verify-core.json");
    fs::write(&core_verify_json, &verify_core_signed.stdout).expect("write verify core json");
    assert_json_ok(&core_verify_json);

    let build_brand = run_tbp([
        OsStr::new("build"),
        brand_resolver.as_os_str(),
        OsStr::new("--contracts"),
        contracts.as_os_str(),
        OsStr::new("--policy"),
        policy.as_os_str(),
        OsStr::new("--out"),
        brand_out.as_os_str(),
        OsStr::new("--target"),
        OsStr::new("css"),
        OsStr::new("--format"),
        OsStr::new("json"),
    ]);
    assert_success(&build_brand, "build brand");

    let verify_brand = run_tbp([
        OsStr::new("verify"),
        brand_out.join("ctc.manifest.json").as_os_str(),
    ]);
    assert_success(&verify_brand, "verify brand");

    let sign_brand = run_tbp([
        OsStr::new("sign"),
        brand_out.join("ctc.manifest.json").as_os_str(),
        OsStr::new("--signer"),
        OsStr::new("ci@example"),
    ]);
    assert_success(&sign_brand, "sign brand");

    let verify_brand_signed = run_tbp([
        OsStr::new("verify"),
        brand_out.join("ctc.manifest.json").as_os_str(),
        OsStr::new("--require-signed"),
        OsStr::new("--format"),
        OsStr::new("json"),
    ]);
    assert_success(&verify_brand_signed, "verify brand signed");
    let brand_verify_json = root.join("verify-brand.json");
    fs::write(&brand_verify_json, &verify_brand_signed.stdout).expect("write verify brand json");
    assert_json_ok(&brand_verify_json);

    let compose = run_tbp([
        OsStr::new("compose"),
        core_out.as_os_str(),
        brand_out.as_os_str(),
        OsStr::new("--out"),
        compose_out.as_os_str(),
        OsStr::new("--target"),
        OsStr::new("css"),
        OsStr::new("--contracts"),
        contracts.as_os_str(),
        OsStr::new("--policy"),
        policy.as_os_str(),
        OsStr::new("--format"),
        OsStr::new("json"),
    ]);
    assert_success(&compose, "compose");

    let sign_compose = run_tbp([
        OsStr::new("sign"),
        compose_out.join("compose.manifest.json").as_os_str(),
        OsStr::new("--signer"),
        OsStr::new("ci@example"),
    ]);
    assert_success(&sign_compose, "sign compose");

    let verify_compose = run_tbp([
        OsStr::new("verify-compose"),
        compose_out.join("compose.manifest.json").as_os_str(),
        OsStr::new("--require-signed"),
        OsStr::new("--require-packs-signed"),
        OsStr::new("--format"),
        OsStr::new("json"),
    ]);
    assert_success(&verify_compose, "verify compose");
    let compose_verify_json = root.join("verify-compose.json");
    fs::write(&compose_verify_json, &verify_compose.stdout).expect("write verify compose json");
    assert_json_ok(&compose_verify_json);

    assert!(core_out.join("ctc.manifest.sig.json").exists());
    assert!(brand_out.join("ctc.manifest.sig.json").exists());
    assert!(compose_out.join("compose.manifest.sig.json").exists());
    assert!(core_out.join("validation.json").exists());
    assert!(brand_out.join("validation.json").exists());
    assert!(compose_out.join("compose.report.json").exists());
}
