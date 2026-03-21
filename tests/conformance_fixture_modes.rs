use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct FixtureMeta {
    mode: String,
}

fn collect_meta_files(root: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(root).expect("read fixture directory");
    for entry in entries {
        let entry = entry.expect("read fixture entry");
        let path = entry.path();
        if path.is_dir() {
            collect_meta_files(&path, out);
            continue;
        }
        if path.file_name().and_then(|n| n.to_str()) == Some("meta.toml") {
            out.push(path);
        }
    }
}

#[test]
fn active_fixture_modes_are_v2_only() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/conformance/fixtures");
    let mut meta_files = Vec::new();
    collect_meta_files(&root, &mut meta_files);
    assert!(
        !meta_files.is_empty(),
        "expected at least one active fixture"
    );

    let allowed: BTreeSet<&str> = [
        "extends",
        "pipeline",
        "resolver",
        "admissibility-witness",
        "gate-analysis",
        "bidir-analysis",
        "kcir-v2-node",
        "core-verify-v2",
        "dsl-unique",
        "dsl-bag",
        "dsl-multibag",
    ]
    .into_iter()
    .collect();

    for meta_path in meta_files {
        let raw = fs::read_to_string(&meta_path).expect("read fixture meta");
        let meta: FixtureMeta = toml::from_str(&raw).expect("parse fixture meta");
        assert!(
            allowed.contains(meta.mode.as_str()),
            "unexpected active fixture mode {:?} in {}",
            meta.mode,
            meta_path.display()
        );
    }
}

#[test]
fn archived_fixture_modes_stay_legacy_only() {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/conformance/fixtures_archive_v1");
    let mut meta_files = Vec::new();
    collect_meta_files(&root, &mut meta_files);
    assert!(!meta_files.is_empty(), "expected archived v1 fixtures");

    let allowed: BTreeSet<&str> = [
        "kcir-node",
        "core-verify",
        "nf-obj",
        "nf-mor",
        "opcode-obj",
        "opcode-mor",
    ]
    .into_iter()
    .collect();

    for meta_path in meta_files {
        let raw = fs::read_to_string(&meta_path).expect("read archived fixture meta");
        let meta: FixtureMeta = toml::from_str(&raw).expect("parse archived fixture meta");
        assert!(
            allowed.contains(meta.mode.as_str()),
            "unexpected archived fixture mode {:?} in {}",
            meta.mode,
            meta_path.display()
        );
    }
}
