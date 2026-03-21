use std::collections::HashMap;
use std::path::PathBuf;

use serde_json::json;

use tbp::cert::build_explicit_index;
use tbp::provenance::TokenProvenance;
use tbp::resolver::{build_token_store, ResolverDoc};

fn build_explicit_base_map() -> HashMap<String, TokenProvenance> {
    let doc_json = json!({
        "version": "2025.10",
        "sets": {
            "foundation": {
                "sources": [
                    {
                        "color": {
                            "$type": "number",
                            "base": { "$value": 10 },
                            "alias1": { "$value": "{color.base}" },
                            "alias2": { "$value": "{color.alias1}" },
                            "baseGroup": {
                                "accent": { "$value": 11 }
                            },
                            "themeGroup": {
                                "$extends": "color.baseGroup"
                            },
                            "viaExtends": { "$value": "{color.themeGroup.accent}" },
                            "palette": {
                                "brand/blue~cool": { "$value": 1 },
                                "alias": { "$value": "{#/color/palette/brand~1blue~0cool}" }
                            }
                        },
                        "spacing": {
                            "scale": {
                                "$type": "dimension",
                                "$root": { "$value": { "value": 8, "unit": "px" } }
                            }
                        }
                    }
                ]
            }
        },
        "modifiers": {},
        "resolutionOrder": [{ "$ref": "#/sets/foundation" }]
    });

    let doc: ResolverDoc = serde_json::from_value(doc_json).expect("resolver doc");
    let resolver_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples/charter-steel/charter-steel.resolver.json");

    let store = build_token_store(&doc, &resolver_path).expect("build token store");
    let explicit =
        build_explicit_index(&doc, &store, &resolver_path).expect("build explicit index");
    explicit
        .get("(base)")
        .cloned()
        .expect("expected base explicit map")
}

#[test]
fn explicit_defs_preserve_escaped_json_pointer_segments() {
    let base = build_explicit_base_map();
    let prov = base
        .get("color.palette.brand/blue~cool")
        .expect("expected provenance for escaped token path");

    assert_eq!(
        prov.json_pointer.as_deref(),
        Some("/color/palette/brand~1blue~0cool/$value")
    );
}

#[test]
fn explicit_defs_preserve_root_value_pointer() {
    let base = build_explicit_base_map();
    let prov = base
        .get("spacing.scale")
        .expect("expected provenance for $root token");

    assert_eq!(
        prov.json_pointer.as_deref(),
        Some("/spacing/scale/$root/$value")
    );
}

#[test]
fn explicit_defs_follow_nested_alias_chain_to_defining_leaf() {
    let base = build_explicit_base_map();
    let prov = base
        .get("color.alias2")
        .expect("expected provenance for nested alias token");

    assert_eq!(prov.json_pointer.as_deref(), Some("/color/base/$value"));
}

#[test]
fn explicit_defs_follow_alias_through_extends_chain_to_defining_leaf() {
    let base = build_explicit_base_map();
    let prov = base
        .get("color.viaExtends")
        .expect("expected provenance for alias-through-extends token");

    assert_eq!(
        prov.json_pointer.as_deref(),
        Some("/color/baseGroup/accent/$value")
    );
}
