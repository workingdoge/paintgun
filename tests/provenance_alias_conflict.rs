use std::path::PathBuf;

use serde_json::json;

use tbp::cert::analyze_composability;
use tbp::resolver::{build_token_store, ResolverDoc};

#[test]
fn alias_derived_conflict_candidates_point_to_defining_leaves() {
    let doc_json = json!({
        "version": "2025.10",
        "sets": {},
        "modifiers": {
            "theme": {
                "contexts": {
                    "dark": [
                        {
                            "color": {
                                "$type": "number",
                                "sourceA": { "$value": 1 },
                                "surface": {
                                    "bg": { "$value": "{color.sourceA}" }
                                }
                            }
                        }
                    ]
                }
            },
            "mode": {
                "contexts": {
                    "wellbeing": [
                        {
                            "color": {
                                "$type": "number",
                                "sourceB": { "$value": 2 },
                                "surface": {
                                    "bg": { "$value": "{color.sourceB}" }
                                }
                            }
                        }
                    ]
                }
            }
        },
        "resolutionOrder": [
            { "$ref": "#/modifiers/theme" },
            { "$ref": "#/modifiers/mode" }
        ]
    });

    let doc: ResolverDoc = serde_json::from_value(doc_json).expect("resolver doc");
    let resolver_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples/charter-steel/charter-steel.resolver.json");
    let store = build_token_store(&doc, &resolver_path).expect("build token store");
    let analysis = analyze_composability(&doc, &store, &resolver_path).expect("ctc analysis");

    let witness = analysis
        .witnesses
        .conflicts
        .iter()
        .find(|w| w.token_path == "color.surface.bg")
        .expect("expected alias-derived conflict witness");

    let pointers: Vec<String> = witness
        .candidates
        .iter()
        .map(|c| c.json_pointer.clone())
        .collect();
    assert!(
        pointers.contains(&"/color/sourceA/$value".to_string()),
        "expected defining pointer for theme alias source, got: {:?}",
        pointers
    );
    assert!(
        pointers.contains(&"/color/sourceB/$value".to_string()),
        "expected defining pointer for mode alias source, got: {:?}",
        pointers
    );
}
