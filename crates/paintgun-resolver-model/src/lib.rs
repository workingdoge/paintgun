use std::collections::{BTreeMap, HashMap, HashSet};

use paintgun_dtcg::{DtcgType, DtcgValue, JValue};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Clone, Debug, Serialize)]
pub struct ResolverDoc {
    #[serde(default)]
    pub name: Option<String>,
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub sets: HashMap<String, ResolverSet>,
    #[serde(default)]
    pub modifiers: HashMap<String, ResolverModifier>,
    #[serde(rename = "resolutionOrder")]
    pub resolution_order: Vec<ResolverOrderEntry>,
    #[serde(skip_serializing)]
    pub inline_sets: HashMap<String, ResolverSet>,
    #[serde(skip_serializing)]
    pub inline_modifiers: HashMap<String, ResolverModifier>,
}

#[derive(Clone, Debug, Deserialize)]
struct RawResolverDoc {
    #[serde(default)]
    name: Option<String>,
    version: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    sets: HashMap<String, ResolverSet>,
    #[serde(default)]
    modifiers: HashMap<String, ResolverModifier>,
    #[serde(rename = "resolutionOrder")]
    resolution_order: Vec<JsonValue>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum ResolverOrderInlineType {
    #[serde(rename = "set")]
    Set,
    #[serde(rename = "modifier")]
    Modifier,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InlineResolverSet {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ResolverOrderInlineType,
    #[serde(flatten)]
    pub set: ResolverSet,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InlineResolverModifier {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ResolverOrderInlineType,
    #[serde(flatten)]
    pub modifier: ResolverModifier,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum ResolverOrderEntry {
    Ref(ResolverOrderRefObject),
    InlineSet(InlineResolverSet),
    InlineModifier(InlineResolverModifier),
}

fn decode_json_pointer_segment(seg: &str) -> Result<String, String> {
    let mut out = String::with_capacity(seg.len());
    let bytes = seg.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'~' {
            if i + 1 >= bytes.len() {
                return Err("dangling JSON Pointer escape '~'".to_string());
            }
            match bytes[i + 1] {
                b'0' => out.push('~'),
                b'1' => out.push('/'),
                other => return Err(format!("invalid JSON Pointer escape '~{}'", other as char)),
            }
            i += 2;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    Ok(out)
}

fn parse_resolver_pointer(pointer: &str) -> Option<(ResolverOrderInlineType, String)> {
    let stripped = pointer.strip_prefix("#/")?;
    let mut parts = stripped.split('/');
    let head = parts.next()?;
    let raw_name = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let name = decode_json_pointer_segment(raw_name).ok()?;
    match head {
        "sets" => Some((ResolverOrderInlineType::Set, name)),
        "modifiers" => Some((ResolverOrderInlineType::Modifier, name)),
        _ => None,
    }
}

impl ResolverOrderEntry {
    pub fn as_ref_str(&self) -> Option<&str> {
        match self {
            Self::Ref(entry) => Some(entry.as_ref_str()),
            Self::InlineSet(_) | Self::InlineModifier(_) => None,
        }
    }

    pub fn set_name(&self) -> Option<String> {
        match self {
            Self::Ref(entry) => match parse_resolver_pointer(entry.as_ref_str()) {
                Some((ResolverOrderInlineType::Set, name)) => Some(name),
                _ => None,
            },
            Self::InlineSet(entry) => Some(entry.name.clone()),
            Self::InlineModifier(_) => None,
        }
    }

    pub fn modifier_name(&self) -> Option<String> {
        match self {
            Self::Ref(entry) => match parse_resolver_pointer(entry.as_ref_str()) {
                Some((ResolverOrderInlineType::Modifier, name)) => Some(name),
                _ => None,
            },
            Self::InlineModifier(entry) => Some(entry.name.clone()),
            Self::InlineSet(_) => None,
        }
    }

    pub fn order_name(&self) -> Option<String> {
        match self {
            Self::Ref(entry) => parse_resolver_pointer(entry.as_ref_str()).map(|(_, name)| name),
            Self::InlineSet(entry) => Some(entry.name.clone()),
            Self::InlineModifier(entry) => Some(entry.name.clone()),
        }
    }

    pub fn inline_set(&self) -> Option<(&str, &ResolverSet)> {
        match self {
            Self::InlineSet(entry) => Some((entry.name.as_str(), &entry.set)),
            Self::Ref(_) | Self::InlineModifier(_) => None,
        }
    }

    pub fn inline_modifier(&self) -> Option<(&str, &ResolverModifier)> {
        match self {
            Self::InlineModifier(entry) => Some((entry.name.as_str(), &entry.modifier)),
            Self::Ref(_) | Self::InlineSet(_) => None,
        }
    }
}

impl<'de> Deserialize<'de> for ResolverDoc {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawResolverDoc::deserialize(deserializer)?;
        let mut resolution_order = Vec::with_capacity(raw.resolution_order.len());
        let mut inline_sets = HashMap::new();
        let mut inline_modifiers = HashMap::new();
        let mut seen_order_names = HashSet::new();
        for (idx, entry) in raw.resolution_order.into_iter().enumerate() {
            let parsed = match entry {
                JsonValue::Object(mut obj) => {
                    if let Some(r) = obj.remove("$ref") {
                        let r = r.as_str().ok_or_else(|| {
                            serde::de::Error::custom(format!(
                                "resolutionOrder[{idx}].$ref must be a string"
                            ))
                        })?;
                        ResolverOrderEntry::Ref(ResolverOrderRefObject {
                            r#ref: r.to_string(),
                            overrides: obj.into_iter().collect(),
                        })
                    } else {
                        let kind = obj
                            .get("type")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| {
                                serde::de::Error::custom(format!(
                                    "resolutionOrder[{idx}] must include either \"$ref\" or inline \"type\" and \"name\" fields"
                                ))
                            })?;
                        let name = obj
                            .get("name")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| {
                                serde::de::Error::custom(format!(
                                    "resolutionOrder[{idx}] inline entries must include string \"name\""
                                ))
                            })?
                            .to_string();

                        match kind {
                            "set" => {
                                let inline: InlineResolverSet = serde_json::from_value(
                                    JsonValue::Object(obj),
                                )
                                .map_err(|err| {
                                    serde::de::Error::custom(format!(
                                        "resolutionOrder[{idx}] is not a valid inline set: {err}"
                                    ))
                                })?;
                                inline_sets.insert(name.clone(), inline.set.clone());
                                ResolverOrderEntry::InlineSet(inline)
                            }
                            "modifier" => {
                                let inline: InlineResolverModifier = serde_json::from_value(
                                    JsonValue::Object(obj),
                                )
                                .map_err(|err| {
                                    serde::de::Error::custom(format!(
                                        "resolutionOrder[{idx}] is not a valid inline modifier: {err}"
                                    ))
                                })?;
                                inline_modifiers.insert(name.clone(), inline.modifier.clone());
                                ResolverOrderEntry::InlineModifier(inline)
                            }
                            other => {
                                return Err(serde::de::Error::custom(format!(
                                    "resolutionOrder[{idx}].type must be \"set\" or \"modifier\", got {other:?}"
                                )))
                            }
                        }
                    }
                }
                JsonValue::String(_) => {
                    return Err(serde::de::Error::custom(format!(
                        "resolutionOrder[{idx}] must be an object like {{\"$ref\":\"#/...\"}}; legacy string entries are not supported"
                    )))
                }
                _ => {
                    return Err(serde::de::Error::custom(format!(
                        "resolutionOrder[{idx}] must be a reference object or inline set/modifier object"
                    )))
                }
            };
            if let Some(name) = parsed.order_name() {
                if !seen_order_names.insert(name.clone()) {
                    return Err(serde::de::Error::custom(format!(
                        "resolutionOrder[{idx}] duplicates name {name:?}; names must be unique within resolutionOrder"
                    )));
                }
            }
            resolution_order.push(parsed);
        }

        Ok(ResolverDoc {
            name: raw.name,
            version: raw.version,
            description: raw.description,
            sets: raw.sets,
            modifiers: raw.modifiers,
            resolution_order,
            inline_sets,
            inline_modifiers,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverOrderRefObject {
    #[serde(rename = "$ref")]
    pub r#ref: String,
    #[serde(flatten)]
    pub overrides: BTreeMap<String, JsonValue>,
}

impl ResolverOrderRefObject {
    pub fn as_ref_str(&self) -> &str {
        self.r#ref.as_str()
    }
}

impl ResolverDoc {
    pub fn get_set(&self, name: &str) -> Option<&ResolverSet> {
        self.sets.get(name).or_else(|| self.inline_sets.get(name))
    }

    pub fn get_modifier(&self, name: &str) -> Option<&ResolverModifier> {
        self.modifiers
            .get(name)
            .or_else(|| self.inline_modifiers.get(name))
    }

    pub fn all_sets(&self) -> Vec<(&str, &ResolverSet)> {
        let mut names: Vec<&str> = self.sets.keys().map(String::as_str).collect();
        names.extend(self.inline_sets.keys().map(String::as_str));
        names.sort_unstable();
        names.dedup();
        names
            .into_iter()
            .filter_map(|name| self.get_set(name).map(|set| (name, set)))
            .collect()
    }

    pub fn all_modifiers(&self) -> Vec<(&str, &ResolverModifier)> {
        let mut names: Vec<&str> = self.modifiers.keys().map(String::as_str).collect();
        names.extend(self.inline_modifiers.keys().map(String::as_str));
        names.sort_unstable();
        names.dedup();
        names
            .into_iter()
            .filter_map(|name| self.get_modifier(name).map(|modifier| (name, modifier)))
            .collect()
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
    pub contexts: HashMap<String, Vec<ResolverSource>>,
}

pub type ResolverModifierContext = Vec<ResolverSource>;

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
    for (mod_name, modifier) in doc.all_modifiers() {
        let mut vals: Vec<String> = modifier.contexts.keys().cloned().collect();
        vals.sort();
        axes.insert(mod_name.to_string(), vals);
    }
    axes
}

pub fn validate_input_selection(
    doc: &ResolverDoc,
    input: &Input,
) -> Result<(), InputSelectionError> {
    for (axis, value) in input {
        let modifier = doc
            .get_modifier(axis)
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
