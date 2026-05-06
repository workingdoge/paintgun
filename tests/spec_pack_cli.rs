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

fn run_paint(args: &[&str], cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_paint"))
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("run paint")
}

fn write_fixture(root: &Path) -> PathBuf {
    let specs_dir = root.join("specs");
    fs::create_dir_all(&specs_dir).expect("create specs dir");
    fs::write(
        specs_dir.join("PLC-0000.md"),
        "# PLC-0000\n\nPacioli doctrine.\n",
    )
    .expect("write PLC-0000");
    fs::write(
        specs_dir.join("PLC-0001.md"),
        "# PLC-0001\n\nSemantic transition model.\n",
    )
    .expect("write PLC-0001");

    let manifest = root.join("atlas-spec-publication.json");
    fs::write(
        &manifest,
        r#"{
  "schema": "atlas.spec-publication.v1",
  "site": "fish/sites/aac",
  "sourceRoot": "specs",
  "series": [
    {
      "id": "plc",
      "title": "Pacioli",
      "documents": [
        {
          "id": "PLC-0000",
          "title": "Pacioli Kernel Doctrine",
          "status": "draft",
          "category": "doctrine",
          "path": "PLC-0000.md",
          "order": 0
        },
        {
          "id": "PLC-0001",
          "title": "Semantic State and Transition Model",
          "status": "draft",
          "category": "semantics",
          "path": "PLC-0001.md",
          "order": 1,
          "summary": "Semantic state rewrite meaning."
        }
      ]
    }
  ]
}
"#,
    )
    .expect("write manifest");
    manifest
}

#[test]
fn spec_pack_emits_and_verifies_self_contained_pack() {
    let root = temp_dir("spec-pack");
    let manifest = write_fixture(&root);
    let out = root.join("dist-spec");

    let build = run_paint(
        &[
            "spec-pack",
            manifest.to_str().expect("manifest path"),
            "--out",
            out.to_str().expect("out path"),
        ],
        &root,
    );
    assert!(
        build.status.success(),
        "spec-pack should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );

    assert!(out.join("spec.pack.json").exists());
    assert!(out.join("spec.index.json").exists());
    assert!(out.join("inputs/spec-publication.json").exists());
    assert!(out.join("sources/plc/PLC-0000.md").exists());
    assert!(out.join("sources/plc/PLC-0001.md").exists());

    let pack = fs::read_to_string(out.join("spec.pack.json")).expect("read pack manifest");
    assert!(pack.contains("\"schema\": \"paintgun.spec-pack.v1\""));
    assert!(pack.contains("\"publicationSchema\": \"atlas.spec-publication.v1\""));
    assert!(pack.contains("\"site\": \"fish/sites/aac\""));

    let verify = run_paint(
        &[
            "verify-spec-pack",
            out.join("spec.pack.json").to_str().expect("pack manifest"),
        ],
        &root,
    );
    assert!(
        verify.status.success(),
        "verify-spec-pack should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(String::from_utf8_lossy(&verify.stdout).contains("documents=2"));
}

#[test]
fn verify_spec_pack_rejects_tampered_packed_source() {
    let root = temp_dir("spec-pack-tamper");
    let manifest = write_fixture(&root);
    let out = root.join("dist-spec");

    let build = run_paint(
        &[
            "spec-pack",
            manifest.to_str().expect("manifest path"),
            "--out",
            out.to_str().expect("out path"),
        ],
        &root,
    );
    assert!(build.status.success(), "spec-pack should succeed");

    fs::write(out.join("sources/plc/PLC-0001.md"), "# Tampered\n").expect("tamper source copy");

    let verify = run_paint(
        &[
            "verify-spec-pack",
            out.join("spec.pack.json").to_str().expect("pack manifest"),
            "--format",
            "json",
        ],
        &root,
    );
    assert!(!verify.status.success(), "tampered pack should fail verify");
    let stdout = String::from_utf8_lossy(&verify.stdout);
    assert!(stdout.contains("\"ok\": false"));
    assert!(stdout.contains("hash/size mismatch"));
}

#[test]
fn spec_pack_rejects_source_paths_that_escape_manifest_root() {
    let root = temp_dir("spec-pack-escape");
    fs::create_dir_all(root.join("specs")).expect("create specs");
    fs::write(root.join("outside.md"), "# Outside\n").expect("write outside");
    let manifest = root.join("atlas-spec-publication.json");
    fs::write(
        &manifest,
        r#"{
  "schema": "atlas.spec-publication.v1",
  "site": "fish/sites/aac",
  "sourceRoot": "specs",
  "series": [
    {
      "id": "plc",
      "title": "Pacioli",
      "documents": [
        {
          "id": "PLC-0000",
          "title": "Pacioli Kernel Doctrine",
          "status": "draft",
          "category": "doctrine",
          "path": "../outside.md"
        }
      ]
    }
  ]
}
"#,
    )
    .expect("write manifest");

    let out = root.join("dist-spec");
    let build = run_paint(
        &[
            "spec-pack",
            manifest.to_str().expect("manifest path"),
            "--out",
            out.to_str().expect("out path"),
        ],
        &root,
    );
    assert!(!build.status.success(), "escaping source path should fail");
    assert!(String::from_utf8_lossy(&build.stderr).contains("path escapes trust root"));
}
