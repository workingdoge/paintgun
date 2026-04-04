use std::fs;
use std::path::PathBuf;

use jsonschema::{Draft, JSONSchema};
use serde_json::Value;

fn catalog_schema() -> JSONSchema {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schema_path = root.join("schemas/system.catalog.schema.json");
    let schema_bytes = fs::read(&schema_path).expect("read catalog schema");
    let schema_json: Value = serde_json::from_slice(&schema_bytes).expect("parse catalog schema");
    JSONSchema::options()
        .with_draft(Draft::Draft7)
        .compile(&schema_json)
        .expect("compile catalog schema")
}

#[test]
fn generated_catalog_ir_matches_schema() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let catalog_path = root.join("examples/web-runtime-prototype/generated/system.catalog.json");
    let catalog_bytes = fs::read(&catalog_path).expect("read generated catalog");
    let catalog_json: Value =
        serde_json::from_slice(&catalog_bytes).expect("parse generated catalog");

    catalog_schema()
        .validate(&catalog_json)
        .unwrap_or_else(|errs| {
            panic!(
                "catalog IR schema errors:\n{}",
                errs.map(|e| e.to_string()).collect::<Vec<_>>().join("\n")
            )
        });

    let component = &catalog_json["catalogComponents"][0];
    assert!(
        component.get("tagName").is_none(),
        "catalog IR should remain design-tool-neutral and omit web-only tagName"
    );
    assert_eq!(component["artifactScope"], "system-wide");
}
