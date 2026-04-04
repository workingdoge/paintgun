use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use paintgun::allowlist::Allowlist;
use paintgun::artifact::write_resolved_json;
use paintgun::cert::{
    analyze_composability, build_ctc_manifest, render_validation_report, ConflictMode, CtcWitnesses,
};
use paintgun::policy::Policy;
use paintgun::resolver::{build_token_store, read_json_file, ResolverDoc};

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

fn run_paint<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .output()
        .expect("run paint")
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
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

fn build_charter_pack(out: &Path) {
    fs::create_dir_all(out).expect("create output dir");
    let resolver_path = repo_root().join("examples/charter-steel/charter-steel.resolver.json");

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store(&doc, &resolver_path).expect("token store");
    let analysis = analyze_composability(&doc, &store, &resolver_path).expect("analysis");

    let resolved_path = out.join("resolved.json");
    write_resolved_json(&resolved_path, &store).expect("write resolved");

    let validation_txt = render_validation_report(&store, &analysis);
    let validation_path = out.join("validation.txt");
    fs::write(&validation_path, validation_txt).expect("write validation");

    let witnesses_path = out.join("ctc.witnesses.json");
    let witnesses_bytes =
        serde_json::to_vec_pretty(&analysis.witnesses).expect("serialize witnesses");
    fs::write(&witnesses_path, &witnesses_bytes).expect("write witnesses");
    let witnesses_sha256 = format!("sha256:{}", paintgun::util::sha256_hex(&witnesses_bytes));

    let manifest = build_ctc_manifest(
        &doc,
        &resolver_path,
        &store,
        Some(&Policy::default()),
        ConflictMode::Semantic,
        &resolved_path,
        None,
        None,
        None,
        None,
        None,
        Some(&validation_path),
        Vec::new(),
        analysis.summary.clone(),
        witnesses_sha256,
    );
    let manifest_path = out.join("ctc.manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");
}

#[test]
fn fix_allowlist_writes_reviewable_stub_and_verify_consumes_it() {
    let root = temp_dir("fix-allowlist-file");
    let out = root.join("dist");
    let allowlist_path = root.join("ci").join("allowlist.json");

    build_charter_pack(&out);

    let output = run_paint([
        OsStr::new("fix-allowlist"),
        out.join("ctc.manifest.json").as_os_str(),
        OsStr::new("--out"),
        allowlist_path.as_os_str(),
    ]);
    assert_success(&output, "fix-allowlist --out");

    let allowlist_bytes = fs::read(&allowlist_path).expect("read generated allowlist");
    let allowlist: Allowlist =
        serde_json::from_slice(&allowlist_bytes).expect("parse generated allowlist");
    assert!(
        !allowlist.conflicts.is_empty(),
        "expected at least one generated conflict entry"
    );
    assert!(
        !allowlist.bc_violations.is_empty(),
        "expected at least one generated BC entry"
    );
    assert!(allowlist.conflicts.iter().all(|entry| {
        entry.witness_id.is_some()
            && entry.selector.is_none()
            && entry.reason.contains("reviewed justification")
    }));
    assert!(allowlist.bc_violations.iter().all(|entry| {
        entry.witness_id.is_some()
            && entry.selector.is_none()
            && entry.reason.contains("reviewed justification")
    }));

    let verify = run_paint([
        OsStr::new("verify"),
        out.join("ctc.manifest.json").as_os_str(),
        OsStr::new("--require-composable"),
        OsStr::new("--allowlist"),
        allowlist_path.as_os_str(),
    ]);
    assert!(
        !verify.status.success(),
        "expected verify to keep failing because gaps remain\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    let stderr = String::from_utf8(verify.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("Kan gaps"),
        "expected remaining gap failure, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("Kan conflicts ("),
        "generated allowlist should suppress conflict failure, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("BC violations ("),
        "generated allowlist should suppress BC failure, got:\n{stderr}"
    );
}

#[test]
fn fix_allowlist_selector_mode_can_generate_subset_to_stdout() {
    let root = temp_dir("fix-allowlist-selector");
    let out = root.join("dist");
    build_charter_pack(&out);

    let witnesses: CtcWitnesses = serde_json::from_slice(
        &fs::read(out.join("ctc.witnesses.json")).expect("read ctc.witnesses.json"),
    )
    .expect("parse ctc.witnesses.json");
    let conflict_id = witnesses.conflicts[0].witness_id.clone();
    let bc_id = witnesses.bc_violations[0].witness_id.clone();

    let output = run_paint([
        OsStr::new("fix-allowlist"),
        out.join("ctc.manifest.json").as_os_str(),
        OsStr::new("--matcher"),
        OsStr::new("selector"),
        OsStr::new("--witness-id"),
        OsStr::new(&conflict_id),
        OsStr::new("--witness-id"),
        OsStr::new(&bc_id),
    ]);
    assert_success(&output, "fix-allowlist selector stdout");

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let allowlist: Allowlist = serde_json::from_str(&stdout).expect("parse stdout allowlist");
    assert_eq!(allowlist.conflicts.len(), 1);
    assert_eq!(allowlist.bc_violations.len(), 1);
    assert!(
        allowlist.conflicts[0].witness_id.is_none() && allowlist.conflicts[0].selector.is_some(),
        "expected selector-based conflict entry, got:\n{stdout}"
    );
    assert!(
        allowlist.bc_violations[0].witness_id.is_none()
            && allowlist.bc_violations[0].selector.is_some(),
        "expected selector-based BC entry, got:\n{stdout}"
    );
}

#[test]
fn fix_allowlist_rejects_unknown_witness_ids_without_panic() {
    let root = temp_dir("fix-allowlist-unknown");
    let out = root.join("dist");
    build_charter_pack(&out);

    let output = run_paint([
        OsStr::new("fix-allowlist"),
        out.join("ctc.manifest.json").as_os_str(),
        OsStr::new("--witness-id"),
        OsStr::new("conflict-not-present"),
    ]);
    assert!(
        !output.status.success(),
        "expected fix-allowlist to fail for unknown witness id"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("did not match any current allowlistable"),
        "expected unknown witness id error, got:\n{stderr}"
    );
    assert_nonpanic_failure(&stderr);
}
