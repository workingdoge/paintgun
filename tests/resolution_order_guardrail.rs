use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

fn collect_files_recursive(root: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(root) {
        Ok(v) => v,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files_recursive(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn assert_resolution_order_object_entries(resolver: &Value, path: &Path) {
    let Some(order) = resolver.get("resolutionOrder") else {
        return;
    };
    let arr = order
        .as_array()
        .unwrap_or_else(|| panic!("{}: resolutionOrder must be an array", path.display()));
    for (idx, entry) in arr.iter().enumerate() {
        match entry {
            Value::Object(obj) => {
                assert!(
                    obj.get("$ref").and_then(|v| v.as_str()).is_some(),
                    "{}: resolutionOrder[{idx}] must contain string \"$ref\"",
                    path.display()
                );
                assert!(
                    obj.len() == 1,
                    "{}: resolutionOrder[{idx}] must only contain \"$ref\"",
                    path.display()
                );
            }
            Value::String(s) => panic!(
                "{}: resolutionOrder[{idx}] uses legacy string entry {s:?}; use {{\"$ref\":\"...\"}}",
                path.display()
            ),
            _ => panic!(
                "{}: resolutionOrder[{idx}] must be an object with \"$ref\"",
                path.display()
            ),
        }
    }
}

#[test]
fn repo_resolver_docs_use_object_resolution_order_entries() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut scanned = 0usize;

    // Guard real resolver docs under examples.
    let mut files = Vec::new();
    collect_files_recursive(&root.join("examples"), &mut files);
    for path in files {
        if path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.ends_with(".resolver.json"))
            != Some(true)
        {
            continue;
        }
        let bytes = fs::read(&path).unwrap_or_else(|e| {
            panic!("failed to read {}: {e}", path.display());
        });
        let value: Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to parse {}: {e}", path.display());
        });
        assert_resolution_order_object_entries(&value, &path);
        scanned += 1;
    }

    // Guard resolver conformance fixtures (those nest resolver under "resolver").
    let fixtures = root.join("tests/conformance/fixtures");
    let entries = fs::read_dir(&fixtures).expect("read conformance fixtures");
    for case in entries.flatten() {
        let case_path = case.path();
        if !case_path.is_dir() {
            continue;
        }
        let case_id = case_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if case_id == "resolver_resolution_order_string_entry_rejected" {
            // Deliberately invalid fixture that proves legacy entries are rejected.
            continue;
        }
        let input_path = case_path.join("input.json");
        if !input_path.exists() {
            continue;
        }
        let bytes = fs::read(&input_path).unwrap_or_else(|e| {
            panic!("failed to read {}: {e}", input_path.display());
        });
        let value: Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("failed to parse {}: {e}", input_path.display());
        });
        if let Some(resolver) = value.get("resolver") {
            assert_resolution_order_object_entries(resolver, &input_path);
            scanned += 1;
        }
    }

    assert!(
        scanned > 0,
        "expected to scan at least one resolver document"
    );
}
