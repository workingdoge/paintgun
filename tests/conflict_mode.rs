use std::path::PathBuf;

use serde_json::json;

use tbp::cert::{analyze_composability_with_mode, ConflictMode};
use tbp::policy::Policy;
use tbp::resolver::{build_token_store, ResolverDoc};

fn duration_conflict_doc() -> ResolverDoc {
    serde_json::from_value(json!({
        "version": "2025.10",
        "sets": {
            "foundation": {
                "sources": [{
                    "motion": {
                        "duration": {
                            "fast": {
                                "$type": "duration",
                                "$value": { "value": 250, "unit": "ms" }
                            }
                        }
                    }
                }]
            }
        },
        "modifiers": {
            "theme": {
                "contexts": {
                    "dark": {
                        "sources": [{
                            "motion": {
                                "duration": {
                                    "fast": {
                                        "$type": "duration",
                                        "$value": { "value": 1, "unit": "s" }
                                    }
                                }
                            }
                        }]
                    }
                }
            },
            "mode": {
                "contexts": {
                    "wellbeing": {
                        "sources": [{
                            "motion": {
                                "duration": {
                                    "fast": {
                                        "$type": "duration",
                                        "$value": { "value": 1000, "unit": "ms" }
                                    }
                                }
                            }
                        }]
                    }
                }
            }
        },
        "resolutionOrder": [
            { "$ref": "#/sets/foundation" },
            { "$ref": "#/modifiers/theme" },
            { "$ref": "#/modifiers/mode" }
        ]
    }))
    .expect("resolver doc")
}

#[test]
fn conflict_mode_normalized_can_resolve_semantic_duration_conflicts() {
    let doc = duration_conflict_doc();
    let resolver_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples/charter-steel/charter-steel.resolver.json");
    let store = build_token_store(&doc, &resolver_path).expect("token store");

    let default_policy = Policy::default();
    let semantic = analyze_composability_with_mode(
        &doc,
        &store,
        &resolver_path,
        ConflictMode::Semantic,
        &default_policy,
    )
    .expect("semantic analysis");

    let policy: Policy = serde_json::from_value(json!({
        "duration": { "prefer": "ms" }
    }))
    .expect("policy json");
    let normalized = analyze_composability_with_mode(
        &doc,
        &store,
        &resolver_path,
        ConflictMode::Normalized,
        &policy,
    )
    .expect("normalized analysis");

    let semantic_has = semantic
        .witnesses
        .conflicts
        .iter()
        .any(|w| w.token_path == "motion.duration.fast");
    let normalized_has = normalized
        .witnesses
        .conflicts
        .iter()
        .any(|w| w.token_path == "motion.duration.fast");

    assert!(
        semantic_has,
        "expected semantic conflict for duration normalization case"
    );
    assert!(
        !normalized_has,
        "normalized mode should suppress duration conflict when values normalize equally"
    );
}
