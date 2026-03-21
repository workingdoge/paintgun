use std::fs;
use std::path::PathBuf;

use jsonschema::{Draft, JSONSchema};
use serde_json::Value;

use tbp::cert::{analyze_composability, PACK_WITNESS_SCHEMA_VERSION};
use tbp::resolver::{build_token_store, read_json_file, ResolverDoc};

#[test]
fn witnesses_match_schema_v1() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolver_path = root.join("examples/charter-steel/charter-steel.resolver.json");

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store(&doc, &resolver_path).expect("token store");
    let analysis = analyze_composability(&doc, &store, &resolver_path).expect("ctc analysis");
    assert_eq!(
        analysis.witnesses.witness_schema, PACK_WITNESS_SCHEMA_VERSION,
        "pack witnesses should carry current schema version marker"
    );
    assert_eq!(
        analysis.witnesses.conflict_mode.to_string(),
        "semantic",
        "default witness conflict mode should be semantic"
    );
    assert!(
        analysis
            .witnesses
            .policy_digest
            .as_deref()
            .unwrap_or("")
            .starts_with("sha256:"),
        "witnesses should include policyDigest"
    );

    let witnesses_json = serde_json::to_value(&analysis.witnesses).expect("serialize witnesses");

    let schema_path = root.join("schemas/witness.schema.json");
    let schema_bytes = fs::read(&schema_path).expect("read schema file");
    let schema_json: Value = serde_json::from_slice(&schema_bytes).expect("parse schema json");

    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft7)
        .compile(&schema_json)
        .expect("compile schema");

    let errs: Vec<String> = match compiled.validate(&witnesses_json) {
        Ok(()) => Vec::new(),
        Err(iter) => iter.map(|e| e.to_string()).collect(),
    };

    assert!(
        errs.is_empty(),
        "witness schema validation failed ({} errors):\n{}",
        errs.len(),
        errs.join("\n")
    );
}
