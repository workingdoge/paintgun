use std::fs;
use std::path::{Path, PathBuf};

use jsonschema::{Draft, JSONSchema};
use serde::Deserialize;
use serde_json::{json, Value};

use paintgun::analysis::{locality_failures, stability_failures, PartialAssignment};
use paintgun::cert::{analyze_composability, build_assignments, build_explicit_index};
use paintgun::contexts::partial_inputs;
use paintgun::dtcg::JValue;
use paintgun::kcir_v2::{
    DecodedNodeRefs, ProfileAnchors, WireCodec, DOMAIN_MOR_NF, DOMAIN_NODE, DOMAIN_OBJ_NF,
    DOMAIN_OPAQUE, LEGACY_FIXED32_WIRE_CODEC, LEN_PREFIXED_REF_WIRE_CODEC,
};
use paintgun::provenance::TokenProvenance;
use paintgun::resolver::{
    build_token_store, canonicalize_token, flatten, materialize, read_json_file, resolve_aliases,
    resolve_extends, Input, ResolverDoc, ResolverError,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum FixtureMode {
    Extends,
    Pipeline,
    Resolver,
    AdmissibilityWitness,
    GateAnalysis,
    BidirAnalysis,
    KcirV2Node,
    CoreVerifyV2,
    DslUnique,
    DslBag,
    DslMultibag,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum FixtureExpect {
    Ok,
    Error,
}

#[derive(Debug, Deserialize)]
struct FixtureMeta {
    mode: FixtureMode,
    expect: FixtureExpect,
    error_code: Option<String>,
    error_contains: Option<String>,
}

#[derive(Debug)]
enum FixtureRunError {
    Resolver(ResolverError),
    AdmissibilitySchema(String),
    Kcir(String),
    Core(String),
    Dsl(String),
}

impl std::fmt::Display for FixtureRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resolver(err) => write!(f, "{err}"),
            Self::AdmissibilitySchema(msg) => write!(f, "{msg}"),
            Self::Kcir(msg) => write!(f, "{msg}"),
            Self::Core(msg) => write!(f, "{msg}"),
            Self::Dsl(msg) => write!(f, "{msg}"),
        }
    }
}

fn fixture_error_code(err: &FixtureRunError) -> &'static str {
    match err {
        FixtureRunError::Resolver(inner) => match inner {
            ResolverError::ReadFile { .. } => "read_file",
            ResolverError::ParseJson { .. } => "parse_json",
            ResolverError::CircularExtends { .. } => "circular_extends",
            ResolverError::CircularAlias { .. } => "circular_alias",
            ResolverError::UnresolvedAlias { .. } => "unresolved_alias",
            ResolverError::UnsupportedAliasForm { .. } => "unsupported_alias_form",
            ResolverError::InvalidType { .. } => "invalid_type",
            ResolverError::UnsafePath { .. } => "unsafe_path",
            ResolverError::InvalidResolverRef { .. } => "invalid_resolver_ref",
            ResolverError::InvalidResolverInput { .. } => "invalid_resolver_input",
            ResolverError::CircularResolverRef { .. } => "circular_resolver_ref",
        },
        FixtureRunError::AdmissibilitySchema(_) => "invalid_admissibility_witness",
        FixtureRunError::Kcir(_) => "kcir_parse",
        FixtureRunError::Core(_) => "core_verify",
        FixtureRunError::Dsl(_) => "dsl_match",
    }
}

fn validate_admissibility_witness_value(input_json: Value) -> Result<Value, FixtureRunError> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schema_path = root.join("schemas/admissibility_witness.schema.json");
    let schema_text = fs::read_to_string(&schema_path).map_err(|e| {
        FixtureRunError::AdmissibilitySchema(format!(
            "failed to read admissibility witness schema: {e}"
        ))
    })?;
    let schema_json: Value = serde_json::from_str(&schema_text).map_err(|e| {
        FixtureRunError::AdmissibilitySchema(format!(
            "failed to parse admissibility witness schema JSON: {e}"
        ))
    })?;
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft7)
        .compile(&schema_json)
        .map_err(|e| {
            FixtureRunError::AdmissibilitySchema(format!("failed to compile schema: {e}"))
        })?;

    let errs: Vec<String> = match compiled.validate(&input_json) {
        Ok(()) => Vec::new(),
        Err(iter) => iter.map(|e| e.to_string()).collect(),
    };
    if errs.is_empty() {
        let failures = input_json
            .get("failures")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                FixtureRunError::AdmissibilitySchema(
                    "admissibility witness payload missing failures array".to_string(),
                )
            })?;
        let actual_keys: Vec<(String, String, String, String, String)> =
            failures.iter().map(gate_failure_sort_key).collect();
        let mut sorted_keys = actual_keys.clone();
        sorted_keys.sort();
        if actual_keys != sorted_keys {
            return Err(FixtureRunError::AdmissibilitySchema(
                "admissibility witness failures must be deterministically ordered by class, lawRef, tokenPath, context, witnessId".to_string(),
            ));
        }
        Ok(input_json)
    } else {
        Err(FixtureRunError::AdmissibilitySchema(format!(
            "admissibility witness schema validation failed ({} errors): {}",
            errs.len(),
            errs.join(" | ")
        )))
    }
}

fn gate_failure_sort_key(failure: &Value) -> (String, String, String, String, String) {
    let class = failure
        .get("class")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let law_ref = failure
        .get("lawRef")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let token_path = failure
        .get("tokenPath")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let context = failure
        .get("context")
        .map(|v| {
            if let Some(s) = v.as_str() {
                s.to_string()
            } else {
                serde_json::to_string(v).unwrap_or_default()
            }
        })
        .unwrap_or_default();
    let witness_id = failure
        .get("witnessId")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    (class, law_ref, token_path, context, witness_id)
}

fn validate_admissibility_witness(input: &JValue) -> Result<Value, FixtureRunError> {
    let mut input_json = serde_json::to_value(input)
        .map_err(|e| FixtureRunError::AdmissibilitySchema(e.to_string()))?;
    // DTCG JValue stores numbers as strings; Gate schema expects an integer witnessSchema.
    if let Some(obj) = input_json.as_object_mut() {
        if let Some(witness_schema) = obj.get_mut("witnessSchema") {
            if let Some(raw) = witness_schema.as_str() {
                if let Ok(parsed) = raw.parse::<u64>() {
                    *witness_schema = Value::Number(parsed.into());
                }
            }
        }
    }
    validate_admissibility_witness_value(input_json)
}

fn gate_source_from_provenance(prov: &TokenProvenance) -> Option<Value> {
    let mut obj = serde_json::Map::new();
    if !prov.source_id.is_empty() {
        obj.insert(
            "sourceId".to_string(),
            Value::String(prov.source_id.clone()),
        );
    }
    if let Some(v) = &prov.file_path {
        if !v.is_empty() {
            obj.insert("filePath".to_string(), Value::String(v.clone()));
        }
    }
    if let Some(v) = &prov.json_pointer {
        if !v.is_empty() {
            obj.insert("jsonPointer".to_string(), Value::String(v.clone()));
        }
    }
    if let Some(v) = &prov.file_hash {
        if !v.is_empty() {
            obj.insert("fileHash".to_string(), Value::String(v.clone()));
        }
    }
    if obj.is_empty() {
        None
    } else {
        Some(Value::Object(obj))
    }
}

fn gate_witness_from_analysis(
    analysis: &paintgun::cert::CtcAnalysis,
    assignments: &[PartialAssignment],
    axes: &std::collections::BTreeMap<String, Vec<String>>,
    contexts: &[Input],
) -> Result<Value, FixtureRunError> {
    let mut failures: Vec<Value> = Vec::new();

    for w in stability_failures(assignments, axes) {
        let mut failure = json!({
            "witnessId": format!(
                "stability:{}:{}:{}",
                w.token_path, w.context, w.kind.as_str()
            ),
            "class": "stability_failure",
            "lawRef": "GATE-3.1",
            "message": format!(
                "reindex composition does not commute for {} at {}:{},{}:{}",
                w.token_path, w.axis_a, w.value_a, w.axis_b, w.value_b
            ),
            "tokenPath": w.token_path,
            "context": w.context,
            "details": {
                "sourceWitnessType": "stability_check",
                "reason": w.kind.as_str(),
                "axisA": w.axis_a,
                "valueA": w.value_a,
                "axisB": w.axis_b,
                "valueB": w.value_b
            }
        });
        let sources: Vec<Value> = w
            .sources
            .iter()
            .filter_map(gate_source_from_provenance)
            .collect();
        if !sources.is_empty() {
            failure["sources"] = Value::Array(sources);
        }
        failures.push(failure);
    }

    for w in locality_failures(assignments, contexts) {
        let mut failure = json!({
            "witnessId": format!(
                "locality:{}:{}:{}:{}",
                w.token_path, w.context, w.restricted_context, w.kind.as_str()
            ),
            "class": "locality_failure",
            "lawRef": "GATE-3.2",
            "message": format!(
                "missing local restriction for {} from {} to {}",
                w.token_path, w.context, w.restricted_context
            ),
            "tokenPath": w.token_path,
            "context": w.context,
            "details": {
                "sourceWitnessType": "locality_check",
                "reason": w.kind.as_str(),
                "restrictedContext": w.restricted_context
            }
        });
        let sources: Vec<Value> = w
            .sources
            .iter()
            .filter_map(gate_source_from_provenance)
            .collect();
        if !sources.is_empty() {
            failure["sources"] = Value::Array(sources);
        }
        failures.push(failure);
    }

    for w in &analysis.witnesses.gaps {
        let mut failure = json!({
            "witnessId": w.witness_id,
            "class": "descent_failure",
            "lawRef": "GATE-3.3",
            "message": format!("no gluable candidate for {} at {}", w.token_path, w.target),
            "tokenPath": w.token_path,
            "context": w.target,
            "details": {
                "sourceWitnessType": "kan_gap",
                "authoredSources": w.authored_sources.len()
            }
        });
        let sources: Vec<Value> = w
            .authored_sources
            .iter()
            .map(|s| {
                json!({
                    "sourceId": s.source_id,
                    "filePath": s.file_path,
                    "jsonPointer": s.json_pointer,
                    "fileHash": s.file_hash
                })
            })
            .collect();
        if !sources.is_empty() {
            failure["sources"] = Value::Array(sources);
        }
        failures.push(failure);
    }

    for w in &analysis.witnesses.conflicts {
        let mut failure = json!({
            "witnessId": w.witness_id,
            "class": "glue_non_contractible",
            "lawRef": "GATE-3.4",
            "message": format!("non-unique glue for {} at {}", w.token_path, w.target),
            "tokenPath": w.token_path,
            "context": w.target,
            "details": {
                "sourceWitnessType": "kan_conflict",
                "candidateCount": w.candidates.len()
            }
        });
        let sources: Vec<Value> = w
            .candidates
            .iter()
            .map(|s| {
                json!({
                    "sourceId": s.source_id,
                    "filePath": s.file_path,
                    "jsonPointer": s.json_pointer,
                    "fileHash": s.file_hash
                })
            })
            .collect();
        if !sources.is_empty() {
            failure["sources"] = Value::Array(sources);
        }
        failures.push(failure);
    }

    for w in &analysis.witnesses.bc_violations {
        let mut sources: Vec<Value> = Vec::new();
        if let Some(src) = &w.left_source {
            if let Some(v) = gate_source_from_provenance(src) {
                sources.push(v);
            }
        }
        if let Some(src) = &w.right_source {
            if let Some(v) = gate_source_from_provenance(src) {
                if !sources.iter().any(|s| s == &v) {
                    sources.push(v);
                }
            }
        }

        let mut failure = json!({
            "witnessId": w.witness_id,
            "class": "adjoint_triple_coherence_failure",
            "lawRef": "GATE-3.5",
            "message": format!(
                "context-change coherence failed for {} at {}:{},{}:{}",
                w.token_path, w.axis_a, w.value_a, w.axis_b, w.value_b
            ),
            "tokenPath": w.token_path,
            "context": format!("{}:{},{}:{}", w.axis_a, w.value_a, w.axis_b, w.value_b),
            "details": {
                "sourceWitnessType": "bc_violation",
                "axisA": w.axis_a,
                "valueA": w.value_a,
                "axisB": w.axis_b,
                "valueB": w.value_b
            }
        });
        if !sources.is_empty() {
            failure["sources"] = Value::Array(sources);
        }
        failures.push(failure);
    }

    failures.sort_by(|a, b| gate_failure_sort_key(a).cmp(&gate_failure_sort_key(b)));
    Ok(json!({
        "witnessSchema": 1,
        "profile": "full",
        "result": if failures.is_empty() { "accepted" } else { "rejected" },
        "failures": failures
    }))
}

fn parse_hex_len(field: &str, s: &str, bytes: usize) -> Result<Vec<u8>, String> {
    let v = hex::decode(s).map_err(|e| format!("invalid hex in {field}: {e}"))?;
    if v.len() != bytes {
        return Err(format!(
            "{field} must be {bytes} bytes ({} hex chars), got {} bytes",
            bytes * 2,
            v.len()
        ));
    }
    Ok(v)
}

fn parse_hex32(field: &str, s: &str) -> Result<[u8; 32], String> {
    let v = parse_hex_len(field, s, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn required_str<'a>(obj: &'a serde_json::Map<String, Value>, key: &str) -> Result<&'a str, String> {
    obj.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or invalid string field {key}"))
}

fn required_u8(obj: &serde_json::Map<String, Value>, key: &str) -> Result<u8, String> {
    let v = obj.get(key).ok_or_else(|| format!("missing field {key}"))?;
    if let Some(n) = v.as_u64() {
        return u8::try_from(n).map_err(|_| format!("{key} out of range for u8: {n}"));
    }
    if let Some(s) = v.as_str() {
        let n = s
            .parse::<u64>()
            .map_err(|e| format!("{key} is not a valid integer: {e}"))?;
        return u8::try_from(n).map_err(|_| format!("{key} out of range for u8: {n}"));
    }
    Err(format!(
        "missing or invalid integer field {key} (accepts number or numeric string)"
    ))
}

fn parse_u8_value(v: &Value, field: &str) -> Result<u8, String> {
    if let Some(n) = v.as_u64() {
        return u8::try_from(n).map_err(|_| format!("{field} out of range for u8: {n}"));
    }
    if let Some(s) = v.as_str() {
        let n = s
            .parse::<u64>()
            .map_err(|e| format!("{field} is not a valid integer: {e}"))?;
        return u8::try_from(n).map_err(|_| format!("{field} out of range for u8: {n}"));
    }
    Err(format!(
        "{field} must be an integer (number or numeric string)"
    ))
}

fn parse_usize_value(v: &Value, field: &str) -> Result<usize, String> {
    if let Some(n) = v.as_u64() {
        return usize::try_from(n).map_err(|_| format!("{field} out of range for usize: {n}"));
    }
    if let Some(s) = v.as_str() {
        let n = s
            .parse::<u64>()
            .map_err(|e| format!("{field} is not a valid integer: {e}"))?;
        return usize::try_from(n).map_err(|_| format!("{field} out of range for usize: {n}"));
    }
    Err(format!(
        "{field} must be an integer (number or numeric string)"
    ))
}

fn parse_dsl_deps(
    root: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Vec<paintgun::dsl::DepShape>, String> {
    let deps_val = root
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{field} requires deps array"))?;
    let mut deps = Vec::with_capacity(deps_val.len());
    for (i, dep_v) in deps_val.iter().enumerate() {
        let dep = dep_v
            .as_object()
            .ok_or_else(|| format!("{field}[{i}] must be an object"))?;
        let sort = required_u8(dep, "sort")?;
        let opcode = required_u8(dep, "opcode")?;
        let mut meta = std::collections::BTreeMap::new();
        if let Some(m) = dep.get("meta") {
            let m_obj = m
                .as_object()
                .ok_or_else(|| format!("{field}[{i}].meta must be an object"))?;
            for (k, v) in m_obj {
                let s = v
                    .as_str()
                    .ok_or_else(|| format!("{field}[{i}].meta[{k}] must be a string"))?;
                meta.insert(k.clone(), s.to_string());
            }
        }
        deps.push(paintgun::dsl::DepShape { sort, opcode, meta });
    }
    Ok(deps)
}

fn parse_dsl_pred(value: Option<&Value>, field: &str) -> Result<paintgun::dsl::UniquePred, String> {
    let Some(v) = value else {
        return Ok(paintgun::dsl::UniquePred {
            sort: None,
            opcode: None,
            meta_eq: std::collections::BTreeMap::new(),
        });
    };
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{field} must be an object"))?;
    let sort = obj
        .get("sort")
        .map(|v| parse_u8_value(v, &format!("{field}.sort")))
        .transpose()?;
    let opcode = obj
        .get("opcode")
        .map(|v| parse_u8_value(v, &format!("{field}.opcode")))
        .transpose()?;
    let mut meta_eq = std::collections::BTreeMap::new();
    if let Some(meta_eq_v) = obj.get("metaEq") {
        let m = meta_eq_v
            .as_object()
            .ok_or_else(|| format!("{field}.metaEq must be an object"))?;
        for (k, v) in m {
            let s = v
                .as_str()
                .ok_or_else(|| format!("{field}.metaEq[{k}] must be string"))?;
            meta_eq.insert(k.clone(), s.to_string());
        }
    }
    Ok(paintgun::dsl::UniquePred {
        sort,
        opcode,
        meta_eq,
    })
}

fn parse_dsl_pos(value: Option<&Value>, field: &str) -> Result<paintgun::dsl::UniquePos, String> {
    let Some(v) = value else {
        return Ok(paintgun::dsl::UniquePos::Anywhere);
    };
    if let Some(s) = v.as_str() {
        return match s {
            "first" => Ok(paintgun::dsl::UniquePos::First),
            "last" => Ok(paintgun::dsl::UniquePos::Last),
            "anywhere" => Ok(paintgun::dsl::UniquePos::Anywhere),
            other => {
                if let Some(rest) = other.strip_prefix("suffix:") {
                    return Ok(paintgun::dsl::UniquePos::Index(
                        rest.parse::<usize>()
                            .map_err(|e| format!("{field} invalid suffix index {other:?}: {e}"))?,
                    ));
                }
                Ok(paintgun::dsl::UniquePos::Index(
                    other
                        .parse::<usize>()
                        .map_err(|e| format!("{field} unsupported pos {other:?}: {e}"))?,
                ))
            }
        };
    }
    if let Some(n) = v.as_u64() {
        return Ok(paintgun::dsl::UniquePos::Index(
            usize::try_from(n).map_err(|_| format!("{field} out of range: {n}"))?,
        ));
    }
    if let Some(arr) = v.as_array() {
        if arr.len() == 2 && arr[0].as_str() == Some("suffix") {
            let idx = parse_usize_value(&arr[1], &format!("{field}[1]"))?;
            return Ok(paintgun::dsl::UniquePos::Index(idx));
        }
    }
    Err(format!(
        "{field} must be first|last|anywhere|index|[\"suffix\",index]"
    ))
}

fn parse_dsl_key_selector(
    value: &Value,
    field: &str,
) -> Result<paintgun::dsl::KeySelector, String> {
    if let Some(s) = value.as_str() {
        return match s {
            "sort" => Ok(paintgun::dsl::KeySelector::Sort),
            "opcode" => Ok(paintgun::dsl::KeySelector::Opcode),
            _ => {
                if let Some(key) = s.strip_prefix("meta:") {
                    if key.is_empty() {
                        return Err(format!("{field} meta key cannot be empty"));
                    }
                    Ok(paintgun::dsl::KeySelector::Meta(key.to_string()))
                } else {
                    Err(format!(
                        "{field} must be sort|opcode|meta:<field>, got {s:?}"
                    ))
                }
            }
        };
    }
    let obj = value
        .as_object()
        .ok_or_else(|| format!("{field} must be a string or object"))?;
    if let Some(v) = obj.get("meta") {
        let key = v
            .as_str()
            .ok_or_else(|| format!("{field}.meta must be a string"))?;
        if key.is_empty() {
            return Err(format!("{field}.meta cannot be empty"));
        }
        return Ok(paintgun::dsl::KeySelector::Meta(key.to_string()));
    }
    if obj.contains_key("sort") {
        return Ok(paintgun::dsl::KeySelector::Sort);
    }
    if obj.contains_key("opcode") {
        return Ok(paintgun::dsl::KeySelector::Opcode);
    }
    Err(format!(
        "{field} object form must contain one of: meta|sort|opcode"
    ))
}

fn parse_dsl_expected_keys(value: &Value, field: &str) -> Result<Vec<String>, String> {
    let arr = value
        .as_array()
        .ok_or_else(|| format!("{field} must be an array"))?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        if let Some(s) = item.as_str() {
            out.push(s.to_string());
            continue;
        }
        if let Some(n) = item.as_u64() {
            out.push(n.to_string());
            continue;
        }
        return Err(format!("{field}[{i}] must be string or integer"));
    }
    Ok(out)
}

fn parse_dsl_expected_keys_spec(
    obj: &serde_json::Map<String, Value>,
    expected_keys_field: &str,
    expected_keys_from_binding_field: &str,
) -> Result<paintgun::dsl::ExpectedKeysSpec, String> {
    let has_literal = obj.contains_key(expected_keys_field);
    let has_from_binding = obj.contains_key(expected_keys_from_binding_field);
    if has_literal == has_from_binding {
        return Err(format!(
            "exactly one of {expected_keys_field} or {expected_keys_from_binding_field} is required"
        ));
    }

    if let Some(v) = obj.get(expected_keys_field) {
        let keys = parse_dsl_expected_keys(v, expected_keys_field)?;
        return Ok(paintgun::dsl::ExpectedKeysSpec::Literal(keys));
    }

    let from_obj = obj
        .get(expected_keys_from_binding_field)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{expected_keys_from_binding_field} must be an object"))?;
    let binding = required_str(from_obj, "binding")?.to_string();
    let key_selector = parse_dsl_key_selector(
        from_obj
            .get("keyOf")
            .ok_or_else(|| format!("{expected_keys_from_binding_field}.keyOf is required"))?,
        &format!("{expected_keys_from_binding_field}.keyOf"),
    )?;
    Ok(paintgun::dsl::ExpectedKeysSpec::FromBinding {
        binding,
        key_selector,
    })
}

fn parse_dsl_bag_mode(
    value: Option<&Value>,
    field: &str,
) -> Result<paintgun::dsl::BagMode, String> {
    let Some(v) = value else {
        return Ok(paintgun::dsl::BagMode::Unordered);
    };
    let s = v
        .as_str()
        .ok_or_else(|| format!("{field} must be ordered|unordered"))?;
    match s {
        "ordered" => Ok(paintgun::dsl::BagMode::Ordered),
        "unordered" => Ok(paintgun::dsl::BagMode::Unordered),
        _ => Err(format!("{field} must be ordered|unordered, got {s:?}")),
    }
}

fn parse_dsl_pool_k(
    value: Option<&Value>,
    field: &str,
) -> Result<Option<paintgun::dsl::PoolK>, String> {
    let Some(v) = value else {
        return Ok(None);
    };
    if let Some(s) = v.as_str() {
        if s == "all" {
            return Ok(Some(paintgun::dsl::PoolK::All));
        }
        let n = s
            .parse::<usize>()
            .map_err(|e| format!("{field} invalid integer string: {e}"))?;
        return Ok(Some(paintgun::dsl::PoolK::Count(n)));
    }
    if let Some(n) = v.as_u64() {
        return Ok(Some(paintgun::dsl::PoolK::Count(
            usize::try_from(n).map_err(|_| format!("{field} out of range: {n}"))?,
        )));
    }
    Err(format!("{field} must be integer or \"all\""))
}

fn parse_dsl_bindings(
    root: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<std::collections::BTreeMap<String, Vec<paintgun::dsl::DepShape>>, String> {
    let Some(v) = root.get(field) else {
        return Ok(std::collections::BTreeMap::new());
    };
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{field} must be an object map"))?;
    let mut out = std::collections::BTreeMap::new();
    for (name, deps_v) in obj {
        let deps_arr = deps_v
            .as_array()
            .ok_or_else(|| format!("{field}.{name} must be an array"))?;
        let mut deps = Vec::with_capacity(deps_arr.len());
        for (i, dep_v) in deps_arr.iter().enumerate() {
            let dep = dep_v
                .as_object()
                .ok_or_else(|| format!("{field}.{name}[{i}] must be an object"))?;
            let sort = required_u8(dep, "sort")?;
            let opcode = required_u8(dep, "opcode")?;
            let mut meta = std::collections::BTreeMap::new();
            if let Some(m) = dep.get("meta") {
                let m_obj = m
                    .as_object()
                    .ok_or_else(|| format!("{field}.{name}[{i}].meta must be an object"))?;
                for (k, v) in m_obj {
                    let s = v
                        .as_str()
                        .ok_or_else(|| format!("{field}.{name}[{i}].meta[{k}] must be a string"))?;
                    meta.insert(k.clone(), s.to_string());
                }
            }
            deps.push(paintgun::dsl::DepShape { sort, opcode, meta });
        }
        if out.insert(name.clone(), deps).is_some() {
            return Err(format!("duplicate binding name in {field}: {name:?}"));
        }
    }
    Ok(out)
}

fn kcir_v2_out_domain_for_sort(sort: u8) -> &'static str {
    match sort {
        paintgun::kcir_v2::SORT_OBJ => DOMAIN_OBJ_NF,
        paintgun::kcir_v2::SORT_MOR => DOMAIN_MOR_NF,
        _ => DOMAIN_OPAQUE,
    }
}

fn parse_hex_bytes(field: &str, s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| format!("invalid hex in {field}: {e}"))
}

fn parse_kcir_v2_profile_and_codec(
    input_obj: &serde_json::Map<String, Value>,
) -> Result<(String, String, [u8; 32], &'static dyn WireCodec), FixtureRunError> {
    let wire_format_id = required_str(input_obj, "wireFormatId")
        .map_err(FixtureRunError::Kcir)?
        .to_string();
    let scheme_id = required_str(input_obj, "schemeId")
        .map_err(FixtureRunError::Kcir)?
        .to_string();
    let params_hash = parse_hex32(
        "paramsHash",
        required_str(input_obj, "paramsHash").map_err(FixtureRunError::Kcir)?,
    )
    .map_err(FixtureRunError::Kcir)?;

    let wire_codec: &'static dyn WireCodec = match wire_format_id.as_str() {
        "kcir.wire.legacy-fixed32.v1" => &LEGACY_FIXED32_WIRE_CODEC,
        "kcir.wire.lenprefixed-ref.v1" => &LEN_PREFIXED_REF_WIRE_CODEC,
        other => {
            return Err(FixtureRunError::Kcir(format!(
                "unsupported wireFormatId: {other}"
            )))
        }
    };

    Ok((wire_format_id, scheme_id, params_hash, wire_codec))
}

fn parse_kcir_v2_node_bytes_from_input(
    input: &JValue,
) -> Result<(String, String, [u8; 32], &'static dyn WireCodec, Vec<u8>), FixtureRunError> {
    let input_json = serde_json::to_value(input).expect("serialize kcir-v2 fixture input to JSON");
    let input_obj = input_json
        .as_object()
        .ok_or_else(|| FixtureRunError::Kcir("kcir-v2-node input must be an object".to_string()))?;

    let (wire_format_id, scheme_id, params_hash, wire_codec) =
        parse_kcir_v2_profile_and_codec(input_obj)?;

    let node_bytes: Vec<u8> = if let Some(raw) =
        input_obj.get("nodeBytesHex").and_then(Value::as_str)
    {
        hex::decode(raw).map_err(|e| FixtureRunError::Kcir(format!("invalid nodeBytesHex: {e}")))?
    } else if let Some(node) = input_obj.get("node").and_then(Value::as_object) {
        let env_sig = parse_hex32(
            "node.envSig",
            required_str(node, "envSig").map_err(FixtureRunError::Kcir)?,
        )
        .map_err(FixtureRunError::Kcir)?;
        let uid = parse_hex32(
            "node.uid",
            required_str(node, "uid").map_err(FixtureRunError::Kcir)?,
        )
        .map_err(FixtureRunError::Kcir)?;
        let sort = required_u8(node, "sort").map_err(FixtureRunError::Kcir)?;
        let opcode = required_u8(node, "opcode").map_err(FixtureRunError::Kcir)?;
        let out_ref = parse_hex_bytes(
            "node.outRefHex",
            required_str(node, "outRefHex").map_err(FixtureRunError::Kcir)?,
        )
        .map_err(FixtureRunError::Kcir)?;
        let args = parse_hex_bytes(
            "node.argsHex",
            required_str(node, "argsHex").map_err(FixtureRunError::Kcir)?,
        )
        .map_err(FixtureRunError::Kcir)?;

        let dep_refs_v = node.get("depRefs").cloned().unwrap_or(Value::Array(vec![]));
        let dep_refs_arr = dep_refs_v
            .as_array()
            .ok_or_else(|| FixtureRunError::Kcir("node.depRefs must be an array".to_string()))?;
        let mut dep_refs = Vec::with_capacity(dep_refs_arr.len());
        for (idx, dep) in dep_refs_arr.iter().enumerate() {
            let dep_s = dep.as_str().ok_or_else(|| {
                FixtureRunError::Kcir(format!("node.depRefs[{idx}] must be a hex string"))
            })?;
            dep_refs.push(
                parse_hex_bytes(&format!("node.depRefs[{idx}]"), dep_s)
                    .map_err(FixtureRunError::Kcir)?,
            );
        }

        match wire_format_id.as_str() {
            "kcir.wire.legacy-fixed32.v1" => {
                if out_ref.len() != 32 {
                    return Err(FixtureRunError::Kcir(format!(
                        "node.outRefHex must be 32 bytes for legacy-fixed32, got {}",
                        out_ref.len()
                    )));
                }
                let mut out_h = [0u8; 32];
                out_h.copy_from_slice(&out_ref);
                let mut deps_h = Vec::with_capacity(dep_refs.len());
                for (idx, dep) in dep_refs.iter().enumerate() {
                    if dep.len() != 32 {
                        return Err(FixtureRunError::Kcir(format!(
                            "node.depRefs[{idx}] must be 32 bytes for legacy-fixed32, got {}",
                            dep.len()
                        )));
                    }
                    let mut dep_h = [0u8; 32];
                    dep_h.copy_from_slice(dep);
                    deps_h.push(dep_h);
                }
                paintgun::kcir_v2::KcirNode {
                    env_sig,
                    uid,
                    sort,
                    opcode,
                    out: out_h,
                    args,
                    deps: deps_h,
                }
                .encode()
            }
            "kcir.wire.lenprefixed-ref.v1" => {
                let decoded = DecodedNodeRefs {
                    env_sig,
                    uid,
                    sort,
                    opcode,
                    out_ref: paintgun::kcir_v2::Ref {
                        scheme_id: scheme_id.clone(),
                        params_hash,
                        domain: kcir_v2_out_domain_for_sort(sort).to_string(),
                        digest: out_ref,
                    },
                    args,
                    dep_refs: dep_refs
                        .into_iter()
                        .map(|digest| paintgun::kcir_v2::Ref {
                            scheme_id: scheme_id.clone(),
                            params_hash,
                            domain: DOMAIN_NODE.to_string(),
                            digest,
                        })
                        .collect(),
                };
                LEN_PREFIXED_REF_WIRE_CODEC
                    .encode_node_refs(&decoded)
                    .map_err(|e| FixtureRunError::Kcir(format!("{}: {}", e.code, e.message)))?
            }
            _ => unreachable!("unsupported wireFormatId handled above"),
        }
    } else {
        return Err(FixtureRunError::Kcir(
            "kcir-v2-node input must provide either nodeBytesHex or node".to_string(),
        ));
    };

    Ok((
        wire_format_id,
        scheme_id,
        params_hash,
        wire_codec,
        node_bytes,
    ))
}

fn parse_hex32_to_bytes_map(
    root: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<std::collections::BTreeMap<[u8; 32], Vec<u8>>, String> {
    let Some(v) = root.get(field) else {
        return Ok(std::collections::BTreeMap::new());
    };
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{field} must be an object map"))?;
    let mut out = std::collections::BTreeMap::new();
    for (k, v) in obj {
        let key = parse_hex32(&format!("{field}[{k}] key"), k)?;
        let bytes_hex = v
            .as_str()
            .ok_or_else(|| format!("{field}[{k}] value must be a hex string"))?;
        let bytes = hex::decode(bytes_hex)
            .map_err(|e| format!("{field}[{k}] value is not valid hex: {e}"))?;
        if out.insert(key, bytes).is_some() {
            return Err(format!("duplicate key in {field}: {k}"));
        }
    }
    Ok(out)
}

fn parse_core_cert_store_from_input(
    input: &JValue,
) -> Result<std::collections::BTreeMap<[u8; 32], Vec<u8>>, FixtureRunError> {
    let input_json = serde_json::to_value(input).expect("serialize core-verify fixture input");
    let root = input_json
        .as_object()
        .ok_or_else(|| FixtureRunError::Core("core-verify input must be an object".to_string()))?;
    parse_hex32_to_bytes_map(root, "certStore").map_err(FixtureRunError::Core)
}

fn parse_core_nf_store_from_input(
    input: &JValue,
    field: &str,
) -> Result<std::collections::BTreeMap<[u8; 32], Vec<u8>>, FixtureRunError> {
    let input_json = serde_json::to_value(input).expect("serialize core-verify fixture input");
    let root = input_json
        .as_object()
        .ok_or_else(|| FixtureRunError::Core("core-verify input must be an object".to_string()))?;
    parse_hex32_to_bytes_map(root, field).map_err(FixtureRunError::Core)
}

struct CoreVerifyV2FixtureStore<'a> {
    scheme_id: String,
    params_hash: [u8; 32],
    wire_codec: &'a dyn WireCodec,
    cert_store: &'a std::collections::BTreeMap<[u8; 32], Vec<u8>>,
    cert_evidence: &'a std::collections::BTreeMap<[u8; 32], Vec<u8>>,
    obj_store: &'a std::collections::BTreeMap<[u8; 32], Vec<u8>>,
    obj_evidence: &'a std::collections::BTreeMap<[u8; 32], Vec<u8>>,
    mor_store: &'a std::collections::BTreeMap<[u8; 32], Vec<u8>>,
    mor_evidence: &'a std::collections::BTreeMap<[u8; 32], Vec<u8>>,
}

impl CoreVerifyV2FixtureStore<'_> {
    fn digest_key(
        &self,
        reference: &paintgun::kcir_v2::Ref,
        expected_domain: &str,
    ) -> Option<[u8; 32]> {
        if reference.scheme_id != self.scheme_id {
            return None;
        }
        if reference.params_hash != self.params_hash {
            return None;
        }
        if reference.domain != expected_domain {
            return None;
        }
        self.wire_codec
            .contract_key_from_ref(reference, expected_domain)
            .ok()
    }
}

impl paintgun::kcir_v2::KcirRefStore for CoreVerifyV2FixtureStore<'_> {
    fn get_node(&self, reference: &paintgun::kcir_v2::Ref) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        let key = self.digest_key(reference, DOMAIN_NODE)?;
        let bytes = self.cert_store.get(&key)?.clone();
        let evidence = self.cert_evidence.get(&key).cloned();
        Some((bytes, evidence))
    }

    fn get_obj_nf(&self, reference: &paintgun::kcir_v2::Ref) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        let key = self.digest_key(reference, DOMAIN_OBJ_NF)?;
        let bytes = self.obj_store.get(&key)?.clone();
        let evidence = self.obj_evidence.get(&key).cloned();
        Some((bytes, evidence))
    }

    fn get_mor_nf(&self, reference: &paintgun::kcir_v2::Ref) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        let key = self.digest_key(reference, DOMAIN_MOR_NF)?;
        let bytes = self.mor_store.get(&key)?.clone();
        let evidence = self.mor_evidence.get(&key).cloned();
        Some((bytes, evidence))
    }
}

fn parse_core_v2_anchors_from_input(
    input: &JValue,
) -> Result<Option<ProfileAnchors>, FixtureRunError> {
    let input_json = serde_json::to_value(input).expect("serialize core-verify-v2 input");
    let root = input_json.as_object().ok_or_else(|| {
        FixtureRunError::Core("core-verify-v2 input must be an object".to_string())
    })?;
    let Some(anchors_v) = root.get("anchors") else {
        return Ok(None);
    };
    let anchors_obj = anchors_v
        .as_object()
        .ok_or_else(|| FixtureRunError::Core("anchors must be an object".to_string()))?;

    let root_commitment = anchors_obj
        .get("rootCommitment")
        .map(|v| {
            let s = v.as_str().ok_or_else(|| {
                FixtureRunError::Core("anchors.rootCommitment must be a hex string".to_string())
            })?;
            hex::decode(s).map_err(|e| {
                FixtureRunError::Core(format!("invalid anchors.rootCommitment hex: {e}"))
            })
        })
        .transpose()?;

    let tree_epoch = anchors_obj
        .get("treeEpoch")
        .map(|v| {
            if let Some(n) = v.as_u64() {
                return Ok(n);
            }
            if let Some(s) = v.as_str() {
                return s.parse::<u64>().map_err(|e| {
                    FixtureRunError::Core(format!("anchors.treeEpoch invalid integer string: {e}"))
                });
            }
            Err(FixtureRunError::Core(
                "anchors.treeEpoch must be an integer".to_string(),
            ))
        })
        .transpose()?;

    let mut metadata = std::collections::BTreeMap::new();
    if let Some(meta_v) = anchors_obj.get("metadata") {
        let meta_obj = meta_v.as_object().ok_or_else(|| {
            FixtureRunError::Core("anchors.metadata must be an object".to_string())
        })?;
        for (k, v) in meta_obj {
            let s = v.as_str().ok_or_else(|| {
                FixtureRunError::Core(format!("anchors.metadata[{k}] must be a string"))
            })?;
            metadata.insert(k.clone(), s.to_string());
        }
    }

    Ok(Some(ProfileAnchors {
        root_commitment,
        tree_epoch,
        metadata,
    }))
}

fn parse_hex32_array(arr_v: &Value, field: &str) -> Result<Vec<[u8; 32]>, FixtureRunError> {
    let arr = arr_v
        .as_array()
        .ok_or_else(|| FixtureRunError::Core(format!("{field} must be an array")))?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, v) in arr.iter().enumerate() {
        let s = v.as_str().ok_or_else(|| {
            FixtureRunError::Core(format!("{field}[{i}] must be a 64-char hex string"))
        })?;
        out.push(parse_hex32(&format!("{field}[{i}]"), s).map_err(FixtureRunError::Core)?);
    }
    Ok(out)
}

fn parse_u32_array(arr_v: &Value, field: &str) -> Result<Vec<u32>, FixtureRunError> {
    let arr = arr_v
        .as_array()
        .ok_or_else(|| FixtureRunError::Core(format!("{field} must be an array")))?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, v) in arr.iter().enumerate() {
        let n = if let Some(n) = v.as_u64() {
            n
        } else if let Some(s) = v.as_str() {
            s.parse::<u64>()
                .map_err(|e| FixtureRunError::Core(format!("{field}[{i}] invalid integer: {e}")))?
        } else {
            return Err(FixtureRunError::Core(format!(
                "{field}[{i}] must be an integer"
            )));
        };
        let n = u32::try_from(n).map_err(|_| {
            FixtureRunError::Core(format!("{field}[{i}] out of range for u32: {n}"))
        })?;
        out.push(n);
    }
    Ok(out)
}

fn parse_core_base_api_from_input(
    input: &JValue,
) -> Result<paintgun::kcir_v2::CoreBaseApi, FixtureRunError> {
    let input_json = serde_json::to_value(input).expect("serialize core-verify fixture input");
    let root = input_json
        .as_object()
        .ok_or_else(|| FixtureRunError::Core("core-verify input must be an object".to_string()))?;
    let Some(base_v) = root.get("baseApi") else {
        return Ok(paintgun::kcir_v2::CoreBaseApi::default());
    };
    let base = base_v
        .as_object()
        .ok_or_else(|| FixtureRunError::Core("baseApi must be an object".to_string()))?;
    let mut out = paintgun::kcir_v2::CoreBaseApi::default();

    if let Some(id_maps_v) = base.get("idMaps") {
        for id in parse_hex32_array(id_maps_v, "baseApi.idMaps")? {
            out.id_maps.insert(id);
        }
    }
    if let Some(covers_v) = base.get("validCovers") {
        for c in parse_hex32_array(covers_v, "baseApi.validCovers")? {
            out.valid_covers.insert(c);
        }
    }
    if let Some(cover_lens_v) = base.get("coverLens") {
        let arr = cover_lens_v.as_array().ok_or_else(|| {
            FixtureRunError::Core("baseApi.coverLens must be an array".to_string())
        })?;
        for (i, item) in arr.iter().enumerate() {
            let o = item.as_object().ok_or_else(|| {
                FixtureRunError::Core(format!("baseApi.coverLens[{i}] must be an object"))
            })?;
            let cover_sig = parse_hex32(
                &format!("baseApi.coverLens[{i}].coverSig"),
                required_str(o, "coverSig").map_err(FixtureRunError::Core)?,
            )
            .map_err(FixtureRunError::Core)?;
            let len_raw = o.get("len").ok_or_else(|| {
                FixtureRunError::Core(format!("baseApi.coverLens[{i}].len is required"))
            })?;
            let len = if let Some(n) = len_raw.as_u64() {
                n
            } else if let Some(s) = len_raw.as_str() {
                s.parse::<u64>().map_err(|e| {
                    FixtureRunError::Core(format!(
                        "baseApi.coverLens[{i}].len invalid integer: {e}"
                    ))
                })?
            } else {
                return Err(FixtureRunError::Core(format!(
                    "baseApi.coverLens[{i}].len must be an integer"
                )));
            };
            let len = u32::try_from(len).map_err(|_| {
                FixtureRunError::Core(format!(
                    "baseApi.coverLens[{i}].len out of range for u32: {len}"
                ))
            })?;
            out.cover_lengths.insert(cover_sig, len);
        }
    }
    if let Some(compose_v) = base.get("composeMaps") {
        let arr = compose_v.as_array().ok_or_else(|| {
            FixtureRunError::Core("baseApi.composeMaps must be an array".to_string())
        })?;
        for (i, item) in arr.iter().enumerate() {
            let o = item.as_object().ok_or_else(|| {
                FixtureRunError::Core(format!("baseApi.composeMaps[{i}] must be an object"))
            })?;
            let outer = parse_hex32(
                &format!("baseApi.composeMaps[{i}].outer"),
                required_str(o, "outer").map_err(FixtureRunError::Core)?,
            )
            .map_err(FixtureRunError::Core)?;
            let inner = parse_hex32(
                &format!("baseApi.composeMaps[{i}].inner"),
                required_str(o, "inner").map_err(FixtureRunError::Core)?,
            )
            .map_err(FixtureRunError::Core)?;
            let out_h = parse_hex32(
                &format!("baseApi.composeMaps[{i}].out"),
                required_str(o, "out").map_err(FixtureRunError::Core)?,
            )
            .map_err(FixtureRunError::Core)?;
            out.map_compositions.insert((outer, inner), out_h);
        }
    }
    if let Some(bc_allowed_v) = base.get("bcAllowedPairs") {
        let arr = bc_allowed_v.as_array().ok_or_else(|| {
            FixtureRunError::Core("baseApi.bcAllowedPairs must be an array".to_string())
        })?;
        for (i, item) in arr.iter().enumerate() {
            let o = item.as_object().ok_or_else(|| {
                FixtureRunError::Core(format!("baseApi.bcAllowedPairs[{i}] must be an object"))
            })?;
            let pull_id = parse_hex32(
                &format!("baseApi.bcAllowedPairs[{i}].pullId"),
                required_str(o, "pullId").map_err(FixtureRunError::Core)?,
            )
            .map_err(FixtureRunError::Core)?;
            let push_id = parse_hex32(
                &format!("baseApi.bcAllowedPairs[{i}].pushId"),
                required_str(o, "pushId").map_err(FixtureRunError::Core)?,
            )
            .map_err(FixtureRunError::Core)?;
            out.bc_allowed_pairs.insert((pull_id, push_id));
        }
    }
    if let Some(bc_square_v) = base.get("bcSquares") {
        let arr = bc_square_v.as_array().ok_or_else(|| {
            FixtureRunError::Core("baseApi.bcSquares must be an array".to_string())
        })?;
        for (i, item) in arr.iter().enumerate() {
            let o = item.as_object().ok_or_else(|| {
                FixtureRunError::Core(format!("baseApi.bcSquares[{i}] must be an object"))
            })?;
            let pull_id = parse_hex32(
                &format!("baseApi.bcSquares[{i}].pullId"),
                required_str(o, "pullId").map_err(FixtureRunError::Core)?,
            )
            .map_err(FixtureRunError::Core)?;
            let push_id = parse_hex32(
                &format!("baseApi.bcSquares[{i}].pushId"),
                required_str(o, "pushId").map_err(FixtureRunError::Core)?,
            )
            .map_err(FixtureRunError::Core)?;
            let f_prime = parse_hex32(
                &format!("baseApi.bcSquares[{i}].fPrime"),
                required_str(o, "fPrime").map_err(FixtureRunError::Core)?,
            )
            .map_err(FixtureRunError::Core)?;
            let p_prime = parse_hex32(
                &format!("baseApi.bcSquares[{i}].pPrime"),
                required_str(o, "pPrime").map_err(FixtureRunError::Core)?,
            )
            .map_err(FixtureRunError::Core)?;
            out.bc_squares
                .insert((push_id, pull_id), (f_prime, p_prime));
        }
    }
    if let Some(pull_cover_v) = base.get("pullCovers") {
        let arr = pull_cover_v.as_array().ok_or_else(|| {
            FixtureRunError::Core("baseApi.pullCovers must be an array".to_string())
        })?;
        for (i, item) in arr.iter().enumerate() {
            let o = item.as_object().ok_or_else(|| {
                FixtureRunError::Core(format!("baseApi.pullCovers[{i}] must be an object"))
            })?;
            let p_id = parse_hex32(
                &format!("baseApi.pullCovers[{i}].pId"),
                required_str(o, "pId").map_err(FixtureRunError::Core)?,
            )
            .map_err(FixtureRunError::Core)?;
            let u_sig = parse_hex32(
                &format!("baseApi.pullCovers[{i}].uSig"),
                required_str(o, "uSig").map_err(FixtureRunError::Core)?,
            )
            .map_err(FixtureRunError::Core)?;
            let w_sig = parse_hex32(
                &format!("baseApi.pullCovers[{i}].wSig"),
                required_str(o, "wSig").map_err(FixtureRunError::Core)?,
            )
            .map_err(FixtureRunError::Core)?;
            let map_w_to_u = parse_u32_array(
                o.get("mapWtoU").ok_or_else(|| {
                    FixtureRunError::Core(format!("baseApi.pullCovers[{i}].mapWtoU is required"))
                })?,
                &format!("baseApi.pullCovers[{i}].mapWtoU"),
            )?;
            let proj_ids = parse_hex32_array(
                o.get("projIds").ok_or_else(|| {
                    FixtureRunError::Core(format!("baseApi.pullCovers[{i}].projIds is required"))
                })?,
                &format!("baseApi.pullCovers[{i}].projIds"),
            )?;
            out.pull_covers.insert(
                (p_id, u_sig),
                paintgun::kcir_v2::PullCoverWitness {
                    w_sig,
                    map_w_to_u,
                    proj_ids,
                },
            );
        }
    }
    if let Some(enforce_v) = base.get("enforceCanonicalNf") {
        out.enforce_nf_canonicality = enforce_v.as_bool().ok_or_else(|| {
            FixtureRunError::Core("baseApi.enforceCanonicalNf must be a boolean".to_string())
        })?;
    }
    if let Some(adopt_v) = base.get("adoptPullAtomMor") {
        out.adopt_pull_atom_mor = adopt_v.as_bool().ok_or_else(|| {
            FixtureRunError::Core("baseApi.adoptPullAtomMor must be a boolean".to_string())
        })?;
    }
    Ok(out)
}

fn run_fixture_mode(
    mode: &FixtureMode,
    input: &JValue,
    case_dir: &Path,
) -> Result<Value, FixtureRunError> {
    #[derive(Debug, Deserialize)]
    struct ResolverFixtureInput {
        resolver: ResolverDoc,
        #[serde(default)]
        input: Input,
    }
    #[derive(Debug, Deserialize)]
    struct GateAnalysisFixtureInput {
        resolver: ResolverDoc,
    }

    match mode {
        FixtureMode::Extends => {
            let extended = resolve_extends(input).map_err(FixtureRunError::Resolver)?;
            Ok(serde_json::to_value(extended).expect("serialize JValue"))
        }
        FixtureMode::Pipeline => {
            let extended = resolve_extends(input).map_err(FixtureRunError::Resolver)?;
            let materialized = materialize(&extended, "fixture");
            let mut resolved = resolve_aliases(&materialized).map_err(|errs| {
                FixtureRunError::Resolver(
                    errs.into_iter().next().expect("non-empty alias error set"),
                )
            })?;
            resolved.sort_by(|a, b| a.path.cmp(&b.path));

            let mut out = Vec::with_capacity(resolved.len());
            for token in resolved {
                let canonical = canonicalize_token(&token).map_err(FixtureRunError::Resolver)?;
                out.push(json!({
                    "path": canonical.path,
                    "type": canonical.ty.to_string(),
                    "value": canonical.value,
                }));
            }
            Ok(Value::Array(out))
        }
        FixtureMode::Resolver => {
            let fixture: ResolverFixtureInput = serde_json::from_value(
                serde_json::to_value(input).expect("serialize fixture input"),
            )
            .map_err(|e| {
                FixtureRunError::Resolver(ResolverError::ParseJson {
                    path: "(fixture)".to_string(),
                    cause: e.to_string(),
                })
            })?;
            let tree = flatten(&fixture.resolver, &fixture.input, Path::new("."))
                .map_err(FixtureRunError::Resolver)?;
            Ok(serde_json::to_value(tree).expect("serialize JValue"))
        }
        FixtureMode::AdmissibilityWitness => validate_admissibility_witness(input),
        FixtureMode::GateAnalysis | FixtureMode::BidirAnalysis => {
            let fixture: GateAnalysisFixtureInput = serde_json::from_value(
                serde_json::to_value(input).expect("serialize fixture input"),
            )
            .map_err(|e| {
                FixtureRunError::Resolver(ResolverError::ParseJson {
                    path: "(fixture)".to_string(),
                    cause: e.to_string(),
                })
            })?;
            let resolver_path = case_dir.join("fixture.resolver.json");
            let store = build_token_store(&fixture.resolver, &resolver_path)
                .map_err(FixtureRunError::Resolver)?;
            let explicit = build_explicit_index(&fixture.resolver, &store, &resolver_path)
                .map_err(FixtureRunError::Resolver)?;
            let assignments = build_assignments(&store, &explicit);
            let contexts = partial_inputs(&store.axes);
            let analysis = analyze_composability(&fixture.resolver, &store, &resolver_path)
                .map_err(FixtureRunError::Resolver)?;
            let witness =
                gate_witness_from_analysis(&analysis, &assignments, &store.axes, &contexts)?;
            validate_admissibility_witness_value(witness)
        }
        FixtureMode::KcirV2Node => {
            let (wire_format_id, scheme_id, params_hash, wire_codec, node_bytes) =
                parse_kcir_v2_node_bytes_from_input(input)?;
            let parsed = wire_codec
                .decode_node_refs(&node_bytes, &scheme_id, params_hash)
                .map_err(|e| FixtureRunError::Kcir(format!("{}: {}", e.code, e.message)))?;

            if wire_format_id == LEN_PREFIXED_REF_WIRE_CODEC.wire_format_id() {
                let roundtrip = LEN_PREFIXED_REF_WIRE_CODEC
                    .encode_node_refs(&parsed)
                    .map_err(|e| FixtureRunError::Kcir(format!("{}: {}", e.code, e.message)))?;
                if roundtrip != node_bytes {
                    return Err(FixtureRunError::Kcir(
                        "KCIR v2 len-prefixed roundtrip mismatch after decode/encode".to_string(),
                    ));
                }
            }

            let dep_ref_hex: Vec<String> = parsed
                .dep_refs
                .iter()
                .map(|dep| hex::encode(&dep.digest))
                .collect();
            let dep_ref_lens: Vec<usize> =
                parsed.dep_refs.iter().map(|dep| dep.digest.len()).collect();
            let dep_ref_domains: Vec<String> = parsed
                .dep_refs
                .iter()
                .map(|dep| dep.domain.clone())
                .collect();

            Ok(json!({
                "wireFormatId": wire_format_id,
                "schemeId": scheme_id,
                "paramsHash": hex::encode(params_hash),
                "envSig": hex::encode(parsed.env_sig),
                "uid": hex::encode(parsed.uid),
                "sort": parsed.sort,
                "opcode": parsed.opcode,
                "outDomain": parsed.out_ref.domain,
                "outRefHex": hex::encode(&parsed.out_ref.digest),
                "outRefLen": parsed.out_ref.digest.len(),
                "argsHex": hex::encode(parsed.args),
                "depCount": parsed.dep_refs.len(),
                "depRefHex": dep_ref_hex,
                "depRefLens": dep_ref_lens,
                "depRefDomains": dep_ref_domains,
                "nodeBytesHex": hex::encode(node_bytes),
            }))
        }
        FixtureMode::CoreVerifyV2 => {
            let input_json = serde_json::to_value(input).expect("serialize core-verify-v2 input");
            let obj = input_json.as_object().ok_or_else(|| {
                FixtureRunError::Core("core-verify-v2 input must be an object".to_string())
            })?;
            let (wire_format_id, scheme_id, params_hash, wire_codec) =
                parse_kcir_v2_profile_and_codec(obj).map_err(|e| {
                    FixtureRunError::Core(format!("invalid v2 profile/wire metadata: {e}"))
                })?;
            let root_cert_id = parse_hex32(
                "rootCertId",
                required_str(obj, "rootCertId").map_err(FixtureRunError::Core)?,
            )
            .map_err(FixtureRunError::Core)?;
            let cert_store = parse_core_cert_store_from_input(input)?;
            let cert_evidence = parse_core_nf_store_from_input(input, "certEvidence")?;
            let obj_store = parse_core_nf_store_from_input(input, "objStore")?;
            let obj_evidence = parse_core_nf_store_from_input(input, "objEvidence")?;
            let mor_store = parse_core_nf_store_from_input(input, "morStore")?;
            let mor_evidence = parse_core_nf_store_from_input(input, "morEvidence")?;
            let anchors = parse_core_v2_anchors_from_input(input)?;
            let base_api = parse_core_base_api_from_input(input)?;
            let root_ref = paintgun::kcir_v2::Ref {
                scheme_id: scheme_id.clone(),
                params_hash,
                domain: DOMAIN_NODE.to_string(),
                digest: root_cert_id.to_vec(),
            };
            let ref_store = CoreVerifyV2FixtureStore {
                scheme_id: scheme_id.clone(),
                params_hash,
                wire_codec,
                cert_store: &cert_store,
                cert_evidence: &cert_evidence,
                obj_store: &obj_store,
                obj_evidence: &obj_evidence,
                mor_store: &mor_store,
                mor_evidence: &mor_evidence,
            };

            let verified = match scheme_id.as_str() {
                paintgun::kcir_v2::HASH_SCHEME_ID => {
                    let profile = paintgun::kcir_v2::HashProfile::new(params_hash);
                    paintgun::kcir_v2::verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors(
                        &root_ref,
                        &ref_store,
                        &base_api,
                        &profile,
                        wire_codec,
                        anchors.as_ref(),
                    )
                }
                paintgun::kcir_v2::MERKLE_SCHEME_ID => {
                    let profile = paintgun::kcir_v2::MerkleProfile::new(params_hash);
                    paintgun::kcir_v2::verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors(
                        &root_ref,
                        &ref_store,
                        &base_api,
                        &profile,
                        wire_codec,
                        anchors.as_ref(),
                    )
                }
                other => Err(paintgun::kcir_v2::KcirV2Error::new(
                    paintgun::kcir_v2::error_codes::PROFILE_MISMATCH,
                    format!("unsupported profile schemeId in core-verify-v2 fixture: {other}"),
                )),
            }
            .map_err(|e| FixtureRunError::Core(format!("{}: {}", e.code, e.message)))?;

            let nodes = verified
                .nodes
                .iter()
                .map(|n| {
                    json!({
                        "certRefHex": hex::encode(&n.cert_ref.digest),
                        "sort": n.sort,
                        "opcode": n.opcode,
                        "outDomain": n.out.domain,
                        "outRefHex": hex::encode(&n.out.digest),
                        "outRefLen": n.out.digest.len(),
                        "meta": n.meta,
                    })
                })
                .collect::<Vec<_>>();

            Ok(json!({
                "wireFormatId": wire_format_id,
                "schemeId": scheme_id,
                "paramsHash": hex::encode(params_hash),
                "rootCertRefHex": hex::encode(&verified.root_cert_ref.digest),
                "envSig": hex::encode(verified.env_sig),
                "uid": hex::encode(verified.uid),
                "nodesVerified": verified.nodes.len(),
                "objOverlayCount": verified.obj_overlay.len(),
                "morOverlayCount": verified.mor_overlay.len(),
                "nodes": nodes
            }))
        }
        FixtureMode::DslUnique => {
            let input_json = serde_json::to_value(input).expect("serialize dsl-unique input");
            let root = input_json.as_object().ok_or_else(|| {
                FixtureRunError::Dsl("dsl-unique input must be an object".to_string())
            })?;
            let deps = parse_dsl_deps(root, "deps").map_err(FixtureRunError::Dsl)?;

            let spec = root.get("spec").and_then(Value::as_object).ok_or_else(|| {
                FixtureRunError::Dsl("dsl-unique requires spec object".to_string())
            })?;
            let pred = parse_dsl_pred(spec.get("pred"), "dsl-unique spec.pred")
                .map_err(FixtureRunError::Dsl)?;
            let pos = parse_dsl_pos(spec.get("pos"), "dsl-unique spec.pos")
                .map_err(FixtureRunError::Dsl)?;
            let optional = spec
                .get("optional")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            let matched = paintgun::dsl::match_unique_spec(&deps, &pred, pos, optional)
                .map_err(FixtureRunError::Dsl)?;
            Ok(match matched {
                Some(m) => json!({
                    "matchedIndex": m.matched_index,
                    "matched": m.matched,
                    "remaining": m.remaining
                }),
                None => json!({
                    "matchedIndex": Value::Null,
                    "matched": Value::Null,
                    "remaining": deps
                }),
            })
        }
        FixtureMode::DslBag => {
            let input_json = serde_json::to_value(input).expect("serialize dsl-bag input");
            let root = input_json.as_object().ok_or_else(|| {
                FixtureRunError::Dsl("dsl-bag input must be an object".to_string())
            })?;
            let deps = parse_dsl_deps(root, "deps").map_err(FixtureRunError::Dsl)?;
            let bindings = parse_dsl_bindings(root, "bindings").map_err(FixtureRunError::Dsl)?;
            let spec = root
                .get("spec")
                .and_then(Value::as_object)
                .ok_or_else(|| FixtureRunError::Dsl("dsl-bag requires spec object".to_string()))?;
            let pred = parse_dsl_pred(spec.get("pred"), "dsl-bag spec.pred")
                .map_err(FixtureRunError::Dsl)?;
            let key_selector = parse_dsl_key_selector(
                spec.get("keyOf").ok_or_else(|| {
                    FixtureRunError::Dsl("dsl-bag spec.keyOf is required".to_string())
                })?,
                "dsl-bag spec.keyOf",
            )
            .map_err(FixtureRunError::Dsl)?;
            let expected_keys =
                parse_dsl_expected_keys_spec(spec, "expectedKeys", "expectedKeysFromBinding")
                    .map_err(FixtureRunError::Dsl)?;
            let mode = parse_dsl_bag_mode(spec.get("mode"), "dsl-bag spec.mode")
                .map_err(FixtureRunError::Dsl)?;
            let pos =
                parse_dsl_pos(spec.get("pos"), "dsl-bag spec.pos").map_err(FixtureRunError::Dsl)?;

            let matched = paintgun::dsl::match_bag_spec_with_bindings(
                &deps,
                &pred,
                &key_selector,
                &expected_keys,
                mode,
                pos,
                &bindings,
            )
            .map_err(FixtureRunError::Dsl)?;
            Ok(json!({
                "matchedIndices": matched.matched_indices,
                "matched": matched.matched,
                "remaining": matched.remaining
            }))
        }
        FixtureMode::DslMultibag => {
            let input_json = serde_json::to_value(input).expect("serialize dsl-multibag input");
            let root = input_json.as_object().ok_or_else(|| {
                FixtureRunError::Dsl("dsl-multibag input must be an object".to_string())
            })?;
            let deps = parse_dsl_deps(root, "deps").map_err(FixtureRunError::Dsl)?;
            let seed_bindings =
                parse_dsl_bindings(root, "bindings").map_err(FixtureRunError::Dsl)?;
            let spec = root.get("spec").and_then(Value::as_object).ok_or_else(|| {
                FixtureRunError::Dsl("dsl-multibag requires spec object".to_string())
            })?;
            let bags_val = spec.get("bags").and_then(Value::as_array).ok_or_else(|| {
                FixtureRunError::Dsl("dsl-multibag spec.bags is required".to_string())
            })?;
            let mut bags = Vec::with_capacity(bags_val.len());
            for (i, bag_v) in bags_val.iter().enumerate() {
                let bag = bag_v.as_object().ok_or_else(|| {
                    FixtureRunError::Dsl(format!("dsl-multibag spec.bags[{i}] must be an object"))
                })?;
                let name = required_str(bag, "name").map_err(FixtureRunError::Dsl)?;
                let pred = parse_dsl_pred(
                    bag.get("pred"),
                    &format!("dsl-multibag spec.bags[{i}].pred"),
                )
                .map_err(FixtureRunError::Dsl)?;
                let key_selector = parse_dsl_key_selector(
                    bag.get("keyOf").ok_or_else(|| {
                        FixtureRunError::Dsl(format!(
                            "dsl-multibag spec.bags[{i}].keyOf is required"
                        ))
                    })?,
                    &format!("dsl-multibag spec.bags[{i}].keyOf"),
                )
                .map_err(FixtureRunError::Dsl)?;
                let expected_keys =
                    parse_dsl_expected_keys_spec(bag, "expectedKeys", "expectedKeysFromBinding")
                        .map_err(FixtureRunError::Dsl)?;
                let mode = parse_dsl_bag_mode(
                    bag.get("mode"),
                    &format!("dsl-multibag spec.bags[{i}].mode"),
                )
                .map_err(FixtureRunError::Dsl)?;
                let bag_pos =
                    parse_dsl_pos(bag.get("pos"), &format!("dsl-multibag spec.bags[{i}].pos"))
                        .map_err(FixtureRunError::Dsl)?;
                bags.push(paintgun::dsl::BagRule {
                    name: name.to_string(),
                    expected_keys,
                    key_selector,
                    pred,
                    mode,
                    pos: bag_pos,
                });
            }

            let pool_pred = parse_dsl_pred(spec.get("poolPred"), "dsl-multibag spec.poolPred")
                .map_err(FixtureRunError::Dsl)?;
            let pool_pred_opt = if spec.contains_key("poolPred") {
                Some(pool_pred)
            } else {
                None
            };
            let pos = parse_dsl_pos(spec.get("pos"), "dsl-multibag spec.pos")
                .map_err(FixtureRunError::Dsl)?;
            let pool_k = parse_dsl_pool_k(spec.get("poolK"), "dsl-multibag spec.poolK")
                .map_err(FixtureRunError::Dsl)?;
            let consume_all = spec
                .get("consumeAll")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let domain_pred =
                parse_dsl_pred(spec.get("domainPred"), "dsl-multibag spec.domainPred")
                    .map_err(FixtureRunError::Dsl)?;
            let domain_pred_opt = if spec.contains_key("domainPred") {
                Some(domain_pred)
            } else {
                None
            };

            let matched = paintgun::dsl::match_multibag_spec(
                &deps,
                &bags,
                pool_pred_opt.as_ref(),
                pos,
                pool_k,
                consume_all,
                domain_pred_opt.as_ref(),
                Some(&seed_bindings),
            )
            .map_err(FixtureRunError::Dsl)?;
            Ok(json!({
                "poolIndices": matched.pool_indices,
                "matchedIndices": matched.matched_indices,
                "bindings": matched.bindings,
                "remaining": matched.remaining
            }))
        }
    }
}

fn pointer_escape(seg: &str) -> String {
    seg.replace('~', "~0").replace('/', "~1")
}

fn render_pointer(path: &[String]) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    format!("/{}", path.join("/"))
}

fn first_mismatch_pointer(expected: &Value, actual: &Value) -> Option<String> {
    fn go(expected: &Value, actual: &Value, path: &mut Vec<String>) -> Option<String> {
        match (expected, actual) {
            (Value::Object(a), Value::Object(b)) => {
                let mut keys: Vec<&str> = a.keys().map(String::as_str).collect();
                for key in b.keys().map(String::as_str) {
                    if !a.contains_key(key) {
                        keys.push(key);
                    }
                }
                keys.sort_unstable();
                keys.dedup();

                for key in keys {
                    path.push(pointer_escape(key));
                    let mismatch = match (a.get(key), b.get(key)) {
                        (Some(av), Some(bv)) => go(av, bv, path),
                        _ => Some(render_pointer(path)),
                    };
                    path.pop();
                    if mismatch.is_some() {
                        return mismatch;
                    }
                }
                None
            }
            (Value::Array(a), Value::Array(b)) => {
                if a.len() != b.len() {
                    return Some(render_pointer(path));
                }
                for (idx, (av, bv)) in a.iter().zip(b.iter()).enumerate() {
                    path.push(idx.to_string());
                    if let Some(p) = go(av, bv, path) {
                        path.pop();
                        return Some(p);
                    }
                    path.pop();
                }
                None
            }
            _ => {
                if expected == actual {
                    None
                } else {
                    Some(render_pointer(path))
                }
            }
        }
    }

    go(expected, actual, &mut Vec::new())
}

fn sorted_fixture_dirs(fixtures_root: &Path) -> Vec<PathBuf> {
    fn collect_case_dirs(root: &Path, out: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(root).expect("read fixtures directory");
        for entry in entries {
            let entry = entry.expect("read fixture entry");
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            // A fixture case is identified by the presence of `meta.toml`.
            // This allows profile subtrees such as:
            // tests/conformance/fixtures/{core,gate}/{golden,adversarial}/<case>
            if p.join("meta.toml").is_file() {
                out.push(p);
                continue;
            }
            collect_case_dirs(&p, out);
        }
    }

    let mut out = Vec::new();
    collect_case_dirs(fixtures_root, &mut out);
    out.sort();
    out
}

fn maybe_write_golden(path: &Path, actual: &Value, update: bool) -> Result<(), String> {
    if !update {
        return Err(format!(
            "missing or mismatched expected.json at {} (set TBP_UPDATE_GOLDENS=1 to update)",
            path.display()
        ));
    }

    let pretty = serde_json::to_string_pretty(actual).map_err(|e| e.to_string())?;
    fs::write(path, format!("{pretty}\n")).map_err(|e| e.to_string())?;
    Ok(())
}

fn run_one_fixture(case_dir: &Path, update_goldens: bool) -> Result<(), String> {
    let case_id = case_dir
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| format!("invalid fixture directory name: {}", case_dir.display()))?
        .to_string();

    let meta_path = case_dir.join("meta.toml");
    let input_path = case_dir.join("input.json");
    let expected_path = case_dir.join("expected.json");

    let meta_text = fs::read_to_string(&meta_path)
        .map_err(|e| format!("{case_id}: failed to read {}: {e}", meta_path.display()))?;
    let meta: FixtureMeta =
        toml::from_str(&meta_text).map_err(|e| format!("{case_id}: invalid meta.toml: {e}"))?;

    let input: JValue = read_json_file(&input_path)
        .map_err(|e| format!("{case_id}: failed to read input.json: {e}"))?;

    match meta.expect {
        FixtureExpect::Ok => {
            let actual = run_fixture_mode(&meta.mode, &input, case_dir).map_err(|e| {
                format!(
                    "{case_id}: expected success but got {} ({e})",
                    fixture_error_code(&e)
                )
            })?;

            let expected: Value = if expected_path.exists() {
                read_json_file(&expected_path)
                    .map_err(|e| format!("{case_id}: failed to read expected.json: {e}"))?
            } else {
                maybe_write_golden(&expected_path, &actual, update_goldens)
                    .map_err(|e| format!("{case_id}: {e}"))?;
                actual.clone()
            };

            if expected != actual {
                if update_goldens {
                    maybe_write_golden(&expected_path, &actual, true)
                        .map_err(|e| format!("{case_id}: {e}"))?;
                    return Ok(());
                }
                let ptr =
                    first_mismatch_pointer(&expected, &actual).unwrap_or_else(|| "/".to_string());
                return Err(format!(
                    "{case_id}: output mismatch at {ptr}\nexpected: {}\nactual: {}",
                    serde_json::to_string(&expected)
                        .unwrap_or_else(|_| "<serialize expected failed>".to_string()),
                    serde_json::to_string(&actual)
                        .unwrap_or_else(|_| "<serialize actual failed>".to_string())
                ));
            }

            Ok(())
        }
        FixtureExpect::Error => {
            let err = match run_fixture_mode(&meta.mode, &input, case_dir) {
                Ok(v) => {
                    return Err(format!(
                        "{case_id}: expected error but got success: {}",
                        serde_json::to_string(&v)
                            .unwrap_or_else(|_| "<serialize success failed>".to_string())
                    ))
                }
                Err(e) => e,
            };

            if let Some(expected_code) = meta.error_code.as_deref() {
                let actual_code = fixture_error_code(&err);
                if actual_code != expected_code {
                    return Err(format!(
                        "{case_id}: expected error_code={expected_code}, got {actual_code} ({err})"
                    ));
                }
            }

            if let Some(needle) = meta.error_contains.as_deref() {
                let msg = err.to_string();
                if !msg.contains(needle) {
                    return Err(format!(
                        "{case_id}: expected error to contain {needle:?}, got {msg:?}"
                    ));
                }
            }

            Ok(())
        }
    }
}

#[test]
fn conformance_fixtures() {
    let fixtures_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/conformance/fixtures");
    let cases = sorted_fixture_dirs(&fixtures_root);
    assert!(
        !cases.is_empty(),
        "no conformance fixtures found under {}",
        fixtures_root.display()
    );

    let update_goldens = std::env::var("TBP_UPDATE_GOLDENS").ok().as_deref() == Some("1");

    let mut failures = Vec::new();
    for case_dir in cases {
        if let Err(err) = run_one_fixture(&case_dir, update_goldens) {
            failures.push(err);
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} conformance fixture(s) failed:\n\n{}",
            failures.len(),
            failures.join("\n\n")
        );
    }
}
