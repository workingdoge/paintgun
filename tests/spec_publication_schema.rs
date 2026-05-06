use jsonschema::JSONSchema;

use paintgun::specpub::ATLAS_SPEC_PUBLICATION_SCHEMA_JSON;

#[test]
fn bundled_atlas_spec_publication_schema_accepts_manifest_shape() {
    let schema: serde_json::Value =
        serde_json::from_str(ATLAS_SPEC_PUBLICATION_SCHEMA_JSON).expect("parse atlas schema");
    let compiled = JSONSchema::compile(&schema).expect("compile atlas schema");
    let manifest = serde_json::json!({
        "schema": "atlas.spec-publication.v1",
        "site": "fish/sites/aac",
        "sourceRoot": ".",
        "series": [
            {
                "id": "plc",
                "title": "Pacioli Core Specification Stack",
                "documents": [
                    {
                        "id": "PLC-0000",
                        "title": "Pacioli Kernel Doctrine",
                        "status": "draft",
                        "category": "doctrine",
                        "path": "PLC-0000.md",
                        "order": 0,
                        "summary": "Constitutional doctrine."
                    }
                ]
            }
        ]
    });

    let result = compiled.validate(&manifest);
    assert!(result.is_ok(), "manifest should satisfy Atlas schema");
}

#[test]
fn bundled_atlas_spec_publication_schema_rejects_path_escape() {
    let schema: serde_json::Value =
        serde_json::from_str(ATLAS_SPEC_PUBLICATION_SCHEMA_JSON).expect("parse atlas schema");
    let compiled = JSONSchema::compile(&schema).expect("compile atlas schema");
    let manifest = serde_json::json!({
        "schema": "atlas.spec-publication.v1",
        "site": "fish/sites/aac",
        "sourceRoot": ".",
        "series": [
            {
                "id": "plc",
                "title": "Pacioli Core Specification Stack",
                "documents": [
                    {
                        "id": "PLC-0000",
                        "title": "Pacioli Kernel Doctrine",
                        "status": "draft",
                        "category": "doctrine",
                        "path": "../PLC-0000.md"
                    }
                ]
            }
        ]
    });

    let errors = compiled
        .validate(&manifest)
        .expect_err("path escape should fail Atlas schema")
        .collect::<Vec<_>>();
    assert!(
        errors
            .iter()
            .any(|error| error.instance_path.to_string().contains("/path")),
        "expected a path validation error, got: {errors:#?}"
    );
}
