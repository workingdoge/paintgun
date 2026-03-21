use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tbp_dtcg::{DtcgType, DtcgValue, JValue};

#[derive(Clone, Debug, Serialize)]
pub struct ResolverDoc {
    #[serde(default)]
    pub name: Option<String>,
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    pub sets: HashMap<String, ResolverSet>,
    pub modifiers: HashMap<String, ResolverModifier>,
    #[serde(rename = "resolutionOrder")]
    pub resolution_order: Vec<ResolverOrderRefObject>,
}

#[derive(Clone, Debug, Deserialize)]
struct RawResolverDoc {
    #[serde(default)]
    name: Option<String>,
    version: String,
    #[serde(default)]
    description: Option<String>,
    sets: HashMap<String, ResolverSet>,
    modifiers: HashMap<String, ResolverModifier>,
    #[serde(rename = "resolutionOrder")]
    resolution_order: Vec<JsonValue>,
}

impl<'de> Deserialize<'de> for ResolverDoc {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawResolverDoc::deserialize(deserializer)?;
        let mut resolution_order = Vec::with_capacity(raw.resolution_order.len());
        for (idx, entry) in raw.resolution_order.into_iter().enumerate() {
            let parsed = match entry {
                JsonValue::Object(mut obj) => {
                    let r = obj.remove("$ref").ok_or_else(|| {
                        serde::de::Error::custom(format!(
                            "resolutionOrder[{idx}] must include \"$ref\""
                        ))
                    })?;
                    let r = r.as_str().ok_or_else(|| {
                        serde::de::Error::custom(format!(
                            "resolutionOrder[{idx}].$ref must be a string"
                        ))
                    })?;
                    if !obj.is_empty() {
                        let mut keys: Vec<String> = obj.keys().cloned().collect();
                        keys.sort();
                        return Err(serde::de::Error::custom(format!(
                            "resolutionOrder[{idx}] has unsupported field(s): {}; only \"$ref\" is allowed",
                            keys.join(", ")
                        )));
                    }
                    ResolverOrderRefObject {
                        r#ref: r.to_string(),
                    }
                }
                JsonValue::String(_) => {
                    return Err(serde::de::Error::custom(format!(
                        "resolutionOrder[{idx}] must be an object like {{\"$ref\":\"#/...\"}}; legacy string entries are not supported"
                    )))
                }
                _ => {
                    return Err(serde::de::Error::custom(format!(
                        "resolutionOrder[{idx}] must be an object with a \"$ref\" string"
                    )))
                }
            };
            resolution_order.push(parsed);
        }

        Ok(ResolverDoc {
            name: raw.name,
            version: raw.version,
            description: raw.description,
            sets: raw.sets,
            modifiers: raw.modifiers,
            resolution_order,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverOrderRefObject {
    #[serde(rename = "$ref")]
    pub r#ref: String,
}

impl ResolverOrderRefObject {
    pub fn as_ref_str(&self) -> &str {
        self.r#ref.as_str()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResolverSet {
    #[serde(default)]
    pub description: Option<String>,
    pub sources: Vec<ResolverSource>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResolverModifier {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub default: Option<String>,
    pub contexts: HashMap<String, ResolverModifierContext>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResolverModifierContext {
    pub sources: Vec<ResolverSource>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResolverSource {
    #[serde(rename = "$ref")]
    pub r#ref: Option<String>,

    #[serde(flatten)]
    pub inline: BTreeMap<String, JValue>,
}

pub type Input = BTreeMap<String, String>;

#[derive(Clone, Debug)]
pub struct MaterializedToken {
    pub path: String,
    pub ty: DtcgType,
    pub value: DtcgValue,
    pub source: String,
}

#[derive(Clone, Debug)]
pub struct ResolvedToken {
    pub path: String,
    pub ty: DtcgType,
    pub value: DtcgValue,
    pub source: String,
}

#[derive(Clone, Debug)]
pub struct TokenStore {
    pub axes: BTreeMap<String, Vec<String>>,
    pub resolved_by_ctx: HashMap<String, Vec<ResolvedToken>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputSelectionError {
    UnknownAxis { axis: String, value: String },
    UnknownContextValue { axis: String, value: String },
}

pub fn axes_from_doc(doc: &ResolverDoc) -> BTreeMap<String, Vec<String>> {
    let mut axes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (mod_name, modifier) in &doc.modifiers {
        let mut vals: Vec<String> = modifier.contexts.keys().cloned().collect();
        vals.sort();
        axes.insert(mod_name.clone(), vals);
    }
    axes
}

pub fn validate_input_selection(
    doc: &ResolverDoc,
    input: &Input,
) -> Result<(), InputSelectionError> {
    for (axis, value) in input {
        let modifier = doc
            .modifiers
            .get(axis)
            .ok_or_else(|| InputSelectionError::UnknownAxis {
                axis: axis.clone(),
                value: value.clone(),
            })?;
        if !modifier.contexts.contains_key(value) {
            return Err(InputSelectionError::UnknownContextValue {
                axis: axis.clone(),
                value: value.clone(),
            });
        }
    }
    Ok(())
}

pub fn context_key(input: &Input) -> String {
    if input.is_empty() {
        return "(base)".to_string();
    }
    let mut entries: Vec<(&String, &String)> = input.iter().collect();
    entries.sort_by(|(a, _), (b, _)| a.cmp(b));
    entries
        .into_iter()
        .map(|(k, v)| format!("{k}:{v}"))
        .collect::<Vec<_>>()
        .join(",")
}

pub fn parse_context_key(key: &str) -> Input {
    if key == "(base)" {
        return BTreeMap::new();
    }
    let mut out = BTreeMap::new();
    for pair in key.split(',') {
        if let Some((k, v)) = pair.split_once(':') {
            out.insert(k.to_string(), v.to_string());
        }
    }
    out
}

pub fn dedup_inputs_for_axes(inputs: &[Input]) -> Vec<Input> {
    let mut out: Vec<Input> = inputs.to_vec();
    out.sort_by_key(context_key);
    out.dedup_by(|a, b| context_key(a) == context_key(b));
    out
}

impl TokenStore {
    pub fn tokens_at(&self, input: &Input) -> &[ResolvedToken] {
        self.resolved_by_ctx
            .get(&context_key(input))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn token_at(&self, path: &str, input: &Input) -> Option<&ResolvedToken> {
        self.tokens_at(input).iter().find(|t| t.path == path)
    }
}
