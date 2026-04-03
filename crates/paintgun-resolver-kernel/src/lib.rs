use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use paintgun_dtcg::{
    ColorComponent, ColorSpace, DimensionUnit, DtcgColor, DtcgDimension, DtcgDuration, DtcgType,
    DtcgValue, DurationUnit, JValue, NumLit,
};
use paintgun_resolver_model::{
    validate_input_selection, Input, InputSelectionError, MaterializedToken, ResolvedToken,
    ResolverDoc, ResolverModifier, ResolverOrderEntry, ResolverSource,
};
use serde::{de::DeserializeOwned, Serialize};

pub fn deep_merge(base: &JValue, overlay: &JValue) -> JValue {
    match (base, overlay) {
        (JValue::Object(a), JValue::Object(b)) => {
            let mut out = a.clone();
            for (k, vb) in b {
                if let Some(va) = out.get(k) {
                    out.insert(k.clone(), deep_merge(va, vb));
                } else {
                    out.insert(k.clone(), vb.clone());
                }
            }
            JValue::Object(out)
        }
        (_, other) => other.clone(),
    }
}

pub fn decode_json_pointer_segment(seg: &str) -> Result<String, String> {
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

pub fn parse_json_pointer(pointer: &str) -> Result<Vec<String>, String> {
    let stripped = pointer
        .strip_prefix("#/")
        .ok_or_else(|| "reference must start with '#/'".to_string())?;
    if stripped.is_empty() {
        return Err("reference must include at least one path segment".to_string());
    }
    stripped
        .split('/')
        .map(decode_json_pointer_segment)
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadFileError {
    ReadFile { path: String, cause: String },
    ParseJson { path: String, cause: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlattenError {
    CircularResolverRef {
        chain: Vec<String>,
    },
    InvalidResolverRef {
        reference: String,
        reason: String,
    },
    UnsafePath {
        path: String,
        reason: String,
    },
    ReadFile {
        path: String,
        cause: String,
    },
    ParseJson {
        path: String,
        cause: String,
    },
    InvalidResolverInput {
        axis: String,
        value: String,
        reason: String,
    },
    InvalidName {
        path: String,
        name: String,
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TokenNameError {
    InvalidName {
        path: String,
        name: String,
        reason: String,
    },
}

fn root_path_label(path: &str) -> String {
    if path.is_empty() {
        "(root)".to_string()
    } else {
        path.to_string()
    }
}

fn validate_token_name_segment(path: &str, name: &str) -> Result<(), TokenNameError> {
    if name.starts_with('$') {
        return Err(TokenNameError::InvalidName {
            path: root_path_label(path),
            name: name.to_string(),
            reason: "token and group names must not begin with '$'".to_string(),
        });
    }
    for ch in ['{', '}', '.'] {
        if name.contains(ch) {
            return Err(TokenNameError::InvalidName {
                path: root_path_label(path),
                name: name.to_string(),
                reason: format!("token and group names must not contain {ch:?}"),
            });
        }
    }
    Ok(())
}

fn is_allowed_token_property(name: &str) -> bool {
    matches!(
        name,
        "$value" | "$type" | "$description" | "$extensions" | "$deprecated"
    )
}

fn is_allowed_group_property(name: &str) -> bool {
    matches!(
        name,
        "$type" | "$description" | "$extensions" | "$deprecated" | "$extends" | "$root"
    )
}

fn unknown_reserved_property_reason() -> String {
    "unknown reserved property for DTCG 2025.10".to_string()
}

fn validate_token_tree_names(tree: &JValue) -> Result<(), TokenNameError> {
    fn go(node: &JValue, path: &str) -> Result<(), TokenNameError> {
        let obj = match node {
            JValue::Object(map) => map,
            _ => return Ok(()),
        };

        let is_token = obj.contains_key("$value");
        for (key, value) in obj {
            if key.starts_with('$') {
                let allowed = if is_token {
                    is_allowed_token_property(key)
                } else {
                    is_allowed_group_property(key)
                };
                if !allowed {
                    return Err(TokenNameError::InvalidName {
                        path: root_path_label(path),
                        name: key.clone(),
                        reason: unknown_reserved_property_reason(),
                    });
                }
                if key == "$root" {
                    go(value, path)?;
                }
                continue;
            }

            validate_token_name_segment(path, key)?;
            if let JValue::Object(_) = value {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                go(value, &child_path)?;
            }
        }

        Ok(())
    }

    go(tree, "")
}

fn map_input_selection_error(err: InputSelectionError) -> FlattenError {
    match err {
        InputSelectionError::UnknownAxis { axis, value } => FlattenError::InvalidResolverInput {
            axis,
            value,
            reason: "unknown modifier axis".to_string(),
        },
        InputSelectionError::UnknownContextValue { axis, value } => {
            FlattenError::InvalidResolverInput {
                axis,
                value,
                reason: "unknown modifier context value".to_string(),
            }
        }
        InputSelectionError::MissingRequiredAxis { axis } => FlattenError::InvalidResolverInput {
            axis,
            value: "(missing)".to_string(),
            reason: "missing required modifier input".to_string(),
        },
    }
}

pub fn load_source_with_refs<FResolvePath, FReadJson>(
    doc: &ResolverDoc,
    source: &ResolverSource,
    base_dir: &Path,
    ref_stack: &mut Vec<String>,
    resolve_existing_under: &FResolvePath,
    read_json_file: &FReadJson,
) -> Result<JValue, FlattenError>
where
    FResolvePath: Fn(&Path, &str) -> Result<PathBuf, String>,
    FReadJson: Fn(&Path) -> Result<JValue, LoadFileError>,
{
    let mut tree = if let Some(r) = &source.r#ref {
        if r.starts_with("#/") {
            if ref_stack.iter().any(|v| v == r) {
                let mut chain = ref_stack.clone();
                chain.push(r.clone());
                return Err(FlattenError::CircularResolverRef { chain });
            }
            ref_stack.push(r.clone());

            let segments =
                parse_json_pointer(r).map_err(|reason| FlattenError::InvalidResolverRef {
                    reference: r.clone(),
                    reason,
                })?;

            let resolved = match segments.as_slice() {
                [head, name] if head == "sets" => {
                    let set =
                        doc.sets
                            .get(name)
                            .ok_or_else(|| FlattenError::InvalidResolverRef {
                                reference: r.clone(),
                                reason: "points to unknown set".to_string(),
                            })?;
                    load_sources_with_refs(
                        doc,
                        &set.sources,
                        base_dir,
                        ref_stack,
                        resolve_existing_under,
                        read_json_file,
                    )?
                }
                [head, ..] if head == "modifiers" => {
                    return Err(FlattenError::InvalidResolverRef {
                        reference: r.clone(),
                        reason: "sources may not reference modifiers".to_string(),
                    });
                }
                [head, ..] if head == "resolutionOrder" => {
                    return Err(FlattenError::InvalidResolverRef {
                        reference: r.clone(),
                        reason: "sources may not reference resolutionOrder".to_string(),
                    });
                }
                _ => {
                    return Err(FlattenError::InvalidResolverRef {
                        reference: r.clone(),
                        reason: "sources may only reference '#/sets/<name>'".to_string(),
                    });
                }
            };

            ref_stack.pop();
            resolved
        } else {
            let p =
                resolve_existing_under(base_dir, r).map_err(|reason| FlattenError::UnsafePath {
                    path: r.clone(),
                    reason,
                })?;
            read_json_file(&p).map_err(|e| match e {
                LoadFileError::ReadFile { path, cause } => FlattenError::ReadFile { path, cause },
                LoadFileError::ParseJson { path, cause } => FlattenError::ParseJson { path, cause },
            })?
        }
    } else {
        JValue::Object(BTreeMap::new())
    };

    if source.r#ref.is_some() && !source.inline.is_empty() {
        let mut obj = match tree {
            JValue::Object(m) => m,
            _ => {
                return Err(FlattenError::InvalidResolverRef {
                    reference: source.r#ref.clone().unwrap_or_default(),
                    reason: "reference target must resolve to an object for overrides".to_string(),
                });
            }
        };
        for (k, v) in &source.inline {
            obj.insert(k.clone(), v.clone());
        }
        tree = JValue::Object(obj);
    }

    if source.r#ref.is_none() {
        let tree = JValue::Object(source.inline.clone());
        validate_token_tree_names(&tree).map_err(|err| match err {
            TokenNameError::InvalidName { path, name, reason } => {
                FlattenError::InvalidName { path, name, reason }
            }
        })?;
        return Ok(tree);
    }

    validate_token_tree_names(&tree).map_err(|err| match err {
        TokenNameError::InvalidName { path, name, reason } => {
            FlattenError::InvalidName { path, name, reason }
        }
    })?;
    Ok(tree)
}

fn load_sources_with_refs<FResolvePath, FReadJson>(
    doc: &ResolverDoc,
    sources: &[ResolverSource],
    base_dir: &Path,
    ref_stack: &mut Vec<String>,
    resolve_existing_under: &FResolvePath,
    read_json_file: &FReadJson,
) -> Result<JValue, FlattenError>
where
    FResolvePath: Fn(&Path, &str) -> Result<PathBuf, String>,
    FReadJson: Fn(&Path) -> Result<JValue, LoadFileError>,
{
    let mut merged = JValue::Object(BTreeMap::new());
    for s in sources {
        let tree = load_source_with_refs(
            doc,
            s,
            base_dir,
            ref_stack,
            resolve_existing_under,
            read_json_file,
        )?;
        merged = deep_merge(&merged, &tree);
    }
    Ok(merged)
}

pub fn load_source<FResolvePath, FReadJson>(
    doc: &ResolverDoc,
    source: &ResolverSource,
    base_dir: &Path,
    resolve_existing_under: &FResolvePath,
    read_json_file: &FReadJson,
) -> Result<JValue, FlattenError>
where
    FResolvePath: Fn(&Path, &str) -> Result<PathBuf, String>,
    FReadJson: Fn(&Path) -> Result<JValue, LoadFileError>,
{
    load_source_with_refs(
        doc,
        source,
        base_dir,
        &mut Vec::new(),
        resolve_existing_under,
        read_json_file,
    )
}

pub fn load_sources<FResolvePath, FReadJson>(
    doc: &ResolverDoc,
    sources: &[ResolverSource],
    base_dir: &Path,
    resolve_existing_under: &FResolvePath,
    read_json_file: &FReadJson,
) -> Result<JValue, FlattenError>
where
    FResolvePath: Fn(&Path, &str) -> Result<PathBuf, String>,
    FReadJson: Fn(&Path) -> Result<JValue, LoadFileError>,
{
    load_sources_with_refs(
        doc,
        sources,
        base_dir,
        &mut Vec::new(),
        resolve_existing_under,
        read_json_file,
    )
}

fn apply_resolution_order_overrides<T>(
    pointer: &str,
    kind: &str,
    base: &T,
    overrides: &BTreeMap<String, serde_json::Value>,
) -> Result<T, FlattenError>
where
    T: Clone + DeserializeOwned + Serialize,
{
    if overrides.is_empty() {
        return Ok(base.clone());
    }

    let mut value = serde_json::to_value(base).map_err(|err| FlattenError::InvalidResolverRef {
        reference: pointer.to_string(),
        reason: format!("failed to serialize referenced {kind}: {err}"),
    })?;
    let obj = value
        .as_object_mut()
        .ok_or_else(|| FlattenError::InvalidResolverRef {
            reference: pointer.to_string(),
            reason: format!("referenced {kind} must serialize as an object"),
        })?;
    for (key, value) in overrides {
        obj.insert(key.clone(), value.clone());
    }

    serde_json::from_value(value).map_err(|err| FlattenError::InvalidResolverRef {
        reference: pointer.to_string(),
        reason: format!("reference overrides do not produce a valid {kind}: {err}"),
    })
}

fn resolve_order_entry<FResolvePath, FReadJson>(
    doc: &ResolverDoc,
    entry: &ResolverOrderEntry,
    input: &Input,
    base_dir: &Path,
    resolve_existing_under: &FResolvePath,
    read_json_file: &FReadJson,
) -> Result<Option<JValue>, FlattenError>
where
    FResolvePath: Fn(&Path, &str) -> Result<PathBuf, String>,
    FReadJson: Fn(&Path) -> Result<JValue, LoadFileError>,
{
    fn resolve_modifier<FResolvePath, FReadJson>(
        doc: &ResolverDoc,
        mod_name: &str,
        modifier: &ResolverModifier,
        input: &Input,
        base_dir: &Path,
        resolve_existing_under: &FResolvePath,
        read_json_file: &FReadJson,
    ) -> Result<Option<JValue>, FlattenError>
    where
        FResolvePath: Fn(&Path, &str) -> Result<PathBuf, String>,
        FReadJson: Fn(&Path) -> Result<JValue, LoadFileError>,
    {
        let ctx_name = match input.get(mod_name) {
            Some(v) => v,
            None => match &modifier.default {
                Some(v) => v,
                None => return Ok(None),
            },
        };
        let ctx =
            modifier
                .contexts
                .get(ctx_name)
                .ok_or_else(|| FlattenError::InvalidResolverRef {
                    reference: format!("#/modifiers/{mod_name}"),
                    reason: format!("selected context value '{ctx_name}' does not exist"),
                })?;
        Ok(Some(load_sources(
            doc,
            ctx,
            base_dir,
            resolve_existing_under,
            read_json_file,
        )?))
    }

    match entry {
        ResolverOrderEntry::Ref(entry) => {
            let pointer = entry.as_ref_str();
            let segments =
                parse_json_pointer(pointer).map_err(|reason| FlattenError::InvalidResolverRef {
                    reference: pointer.to_string(),
                    reason,
                })?;
            match segments.as_slice() {
                [head, set_name] if head == "sets" => {
                    let set = doc
                        .sets
                        .get(set_name)
                        .ok_or_else(|| FlattenError::InvalidResolverRef {
                            reference: pointer.to_string(),
                            reason: "points to unknown set".to_string(),
                        })?;
                    let set = apply_resolution_order_overrides(
                        pointer,
                        "set",
                        set,
                        &entry.overrides,
                    )?;
                    Ok(Some(load_sources(
                        doc,
                        &set.sources,
                        base_dir,
                        resolve_existing_under,
                        read_json_file,
                    )?))
                }
                [head, mod_name] if head == "modifiers" => {
                    let modifier =
                        doc.modifiers
                            .get(mod_name)
                            .ok_or_else(|| FlattenError::InvalidResolverRef {
                                reference: pointer.to_string(),
                                reason: "points to unknown modifier".to_string(),
                            })?;
                    let modifier = apply_resolution_order_overrides(
                        pointer,
                        "modifier",
                        modifier,
                        &entry.overrides,
                    )?;
                    resolve_modifier(
                        doc,
                        mod_name,
                        &modifier,
                        input,
                        base_dir,
                        resolve_existing_under,
                        read_json_file,
                    )
                }
                _ => Err(FlattenError::InvalidResolverRef {
                    reference: pointer.to_string(),
                    reason:
                        "resolutionOrder entries must reference '#/sets/<name>' or '#/modifiers/<name>'"
                            .to_string(),
                }),
            }
        }
        ResolverOrderEntry::InlineSet(entry) => Ok(Some(load_sources(
            doc,
            &entry.set.sources,
            base_dir,
            resolve_existing_under,
            read_json_file,
        )?)),
        ResolverOrderEntry::InlineModifier(entry) => resolve_modifier(
            doc,
            &entry.name,
            &entry.modifier,
            input,
            base_dir,
            resolve_existing_under,
            read_json_file,
        ),
    }
}

fn flatten_impl<FResolvePath, FReadJson>(
    doc: &ResolverDoc,
    input: &Input,
    base_dir: &Path,
    resolve_existing_under: &FResolvePath,
    read_json_file: &FReadJson,
    validate_input: bool,
) -> Result<JValue, FlattenError>
where
    FResolvePath: Fn(&Path, &str) -> Result<PathBuf, String>,
    FReadJson: Fn(&Path) -> Result<JValue, LoadFileError>,
{
    if validate_input {
        validate_input_selection(doc, input).map_err(map_input_selection_error)?;
    }
    let mut merged = JValue::Object(BTreeMap::new());
    for entry in &doc.resolution_order {
        if let Some(tree) = resolve_order_entry(
            doc,
            entry,
            input,
            base_dir,
            resolve_existing_under,
            read_json_file,
        )? {
            merged = deep_merge(&merged, &tree);
        }
    }
    Ok(merged)
}

pub fn flatten<FResolvePath, FReadJson>(
    doc: &ResolverDoc,
    input: &Input,
    base_dir: &Path,
    resolve_existing_under: &FResolvePath,
    read_json_file: &FReadJson,
) -> Result<JValue, FlattenError>
where
    FResolvePath: Fn(&Path, &str) -> Result<PathBuf, String>,
    FReadJson: Fn(&Path) -> Result<JValue, LoadFileError>,
{
    flatten_impl(
        doc,
        input,
        base_dir,
        resolve_existing_under,
        read_json_file,
        true,
    )
}

pub fn flatten_unvalidated<FResolvePath, FReadJson>(
    doc: &ResolverDoc,
    input: &Input,
    base_dir: &Path,
    resolve_existing_under: &FResolvePath,
    read_json_file: &FReadJson,
) -> Result<JValue, FlattenError>
where
    FResolvePath: Fn(&Path, &str) -> Result<PathBuf, String>,
    FReadJson: Fn(&Path) -> Result<JValue, LoadFileError>,
{
    flatten_impl(
        doc,
        input,
        base_dir,
        resolve_existing_under,
        read_json_file,
        false,
    )
}

pub fn axes_relevant_to_tokens<FResolvePath, FReadJson>(
    doc: &ResolverDoc,
    base_dir: &Path,
    token_paths: &BTreeSet<String>,
    resolve_existing_under: &FResolvePath,
    read_json_file: &FReadJson,
) -> Result<BTreeSet<String>, FlattenError>
where
    FResolvePath: Fn(&Path, &str) -> Result<PathBuf, String>,
    FReadJson: Fn(&Path) -> Result<JValue, LoadFileError>,
{
    let mut out = BTreeSet::new();
    if token_paths.is_empty() {
        return Ok(out);
    }

    for (axis, modifier) in doc.all_modifiers() {
        let mut axis_relevant = false;
        for ctx in modifier.contexts.values() {
            let tree = load_sources(doc, ctx, base_dir, resolve_existing_under, read_json_file)?;
            let explicit = collect_explicit_token_paths(&tree);
            if explicit.iter().any(|p| token_paths.contains(p)) {
                axis_relevant = true;
                break;
            }
        }
        if axis_relevant {
            out.insert(axis.to_string());
        }
    }

    Ok(out)
}

pub fn lookup_path<'a>(root: &'a JValue, dot_path: &str) -> Option<&'a JValue> {
    let mut cur = root;
    for seg in dot_path.split('.') {
        cur = cur.as_object()?.get(seg)?;
    }
    Some(cur)
}

pub fn normalize_reference_literal(raw: &str) -> &str {
    let t = raw.trim();
    if let Some(inner) = t.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
        inner.trim()
    } else {
        t
    }
}

pub fn lookup_json_pointer<'a>(
    root: &'a JValue,
    pointer: &str,
) -> Result<Option<&'a JValue>, String> {
    if pointer == "#" {
        return Ok(Some(root));
    }
    let mut cur = root;
    for seg in parse_json_pointer(pointer)? {
        match cur {
            JValue::Object(map) => match map.get(&seg) {
                Some(next) => cur = next,
                None => return Ok(None),
            },
            _ => return Ok(None),
        }
    }
    Ok(Some(cur))
}

pub fn lookup_extends_target<'a>(
    root: &'a JValue,
    ext_path: &str,
) -> Result<Option<&'a JValue>, String> {
    if ext_path.starts_with('#') {
        return lookup_json_pointer(root, ext_path);
    }

    let path = normalize_reference_literal(ext_path);
    if path.starts_with('#') {
        lookup_json_pointer(root, path)
    } else {
        Ok(lookup_path(root, path))
    }
}

pub fn remove_key(mut obj: BTreeMap<String, JValue>, k: &str) -> BTreeMap<String, JValue> {
    obj.remove(k);
    obj
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtendsError {
    CircularExtends {
        chain: Vec<String>,
    },
    InvalidType {
        path: String,
        reason: String,
    },
    InvalidName {
        path: String,
        name: String,
        reason: String,
    },
}

fn lookup_extends_target_with_key<'a>(
    root: &'a JValue,
    raw_ref: &str,
) -> Result<(String, &'a JValue), String> {
    let normalized = normalize_reference_literal(raw_ref);
    if normalized.starts_with('#') {
        let target = lookup_json_pointer(root, normalized)?;
        let target =
            target.ok_or_else(|| format!("$extends refers to missing group: {raw_ref}"))?;
        let key = parse_json_pointer(normalized)
            .map(|segs| segs.join("."))
            .unwrap_or_else(|_| normalized.to_string());
        return Ok((key, target));
    }

    let target = lookup_path(root, normalized)
        .ok_or_else(|| format!("$extends refers to missing group: {raw_ref}"))?;
    Ok((normalized.to_string(), target))
}

fn resolve_extends_inner(
    root: &JValue,
    node: &JValue,
    path: &str,
    visiting: &mut Vec<String>,
    memo: &mut HashMap<String, JValue>,
) -> Result<JValue, ExtendsError> {
    if let Some(v) = memo.get(path) {
        return Ok(v.clone());
    }

    let obj = match node {
        JValue::Object(m) => m,
        _ => {
            memo.insert(path.to_string(), node.clone());
            return Ok(node.clone());
        }
    };

    if obj.contains_key("$value") {
        memo.insert(path.to_string(), node.clone());
        return Ok(node.clone());
    }

    let mut resolved_children: BTreeMap<String, JValue> = BTreeMap::new();
    for (k, v) in obj {
        if k.starts_with('$') {
            resolved_children.insert(k.clone(), v.clone());
            continue;
        }
        let child_path = if path.is_empty() {
            k.clone()
        } else {
            format!("{path}.{k}")
        };
        let vv = resolve_extends_inner(root, v, &child_path, visiting, memo)?;
        resolved_children.insert(k.clone(), vv);
    }

    if let Some(JValue::String(ext_path)) = obj.get("$extends") {
        if visiting.iter().any(|p| p == path) {
            let mut chain = visiting.clone();
            chain.push(path.to_string());
            return Err(ExtendsError::CircularExtends { chain });
        }
        visiting.push(path.to_string());

        let (target_path, target) =
            lookup_extends_target_with_key(root, ext_path).map_err(|reason| {
                ExtendsError::InvalidType {
                    path: path.to_string(),
                    reason,
                }
            })?;
        match target {
            JValue::Object(m) if !m.contains_key("$value") => {}
            _ => {
                return Err(ExtendsError::InvalidType {
                    path: path.to_string(),
                    reason: format!("$extends target must be a group object: {ext_path}"),
                });
            }
        }

        let resolved_target = resolve_extends_inner(root, target, &target_path, visiting, memo)?;
        let merged = deep_merge(&resolved_target, &JValue::Object(resolved_children));
        let merged_obj = match merged {
            JValue::Object(m) => JValue::Object(remove_key(m, "$extends")),
            other => other,
        };

        visiting.pop();
        memo.insert(path.to_string(), merged_obj.clone());
        return Ok(merged_obj);
    }

    let out = JValue::Object(remove_key(resolved_children, "$extends"));
    memo.insert(path.to_string(), out.clone());
    Ok(out)
}

pub fn resolve_extends(tree: &JValue) -> Result<JValue, ExtendsError> {
    validate_token_tree_names(tree).map_err(|err| match err {
        TokenNameError::InvalidName { path, name, reason } => {
            ExtendsError::InvalidName { path, name, reason }
        }
    })?;
    let mut memo: HashMap<String, JValue> = HashMap::new();
    resolve_extends_inner(tree, tree, "", &mut Vec::new(), &mut memo)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AliasError {
    CircularAlias {
        chain: Vec<String>,
    },
    UnresolvedAlias {
        path: String,
        r#ref: String,
    },
    UnsupportedAliasForm {
        path: String,
        r#ref: String,
        reason: String,
    },
    InvalidType {
        path: String,
        ty: DtcgType,
        reason: String,
    },
}

fn is_alias(s: &str) -> Option<&str> {
    let s = s.trim();
    if s.starts_with('{') && s.ends_with('}') {
        Some(&s[1..s.len() - 1])
    } else {
        None
    }
}

fn normalize_alias_ref(raw_ref: &str) -> Result<String, String> {
    let trimmed = raw_ref.trim();

    if !trimmed.starts_with('#') {
        return Ok(trimmed.to_string());
    }

    if trimmed == "#" {
        return Err("JSON Pointer alias cannot target document root".to_string());
    }

    let mut segments =
        parse_json_pointer(trimmed).map_err(|reason| format!("JSON Pointer alias {reason}"))?;

    if matches!(segments.last(), Some(s) if s == "$value") {
        segments.pop();
    }
    if matches!(segments.last(), Some(s) if s == "$root") {
        segments.pop();
    }

    if segments.is_empty() {
        return Err("JSON Pointer alias does not resolve to a token path".to_string());
    }
    if segments.iter().any(|s| s.starts_with('$')) {
        return Err(
            "JSON Pointer alias may only include '$value' or '$root' as the last segment"
                .to_string(),
        );
    }

    Ok(segments.join("."))
}

fn resolve_alias_target<'a>(
    current_path: &str,
    raw_ref: &str,
    token_index: &'a HashMap<String, MaterializedToken>,
    errors: &mut Vec<AliasError>,
) -> Option<&'a MaterializedToken> {
    let normalized = match normalize_alias_ref(raw_ref) {
        Ok(s) => s,
        Err(reason) => {
            errors.push(AliasError::UnsupportedAliasForm {
                path: current_path.to_string(),
                r#ref: raw_ref.to_string(),
                reason,
            });
            return None;
        }
    };

    match token_index.get(&normalized) {
        Some(t) => Some(t),
        None => {
            errors.push(AliasError::UnresolvedAlias {
                path: current_path.to_string(),
                r#ref: raw_ref.to_string(),
            });
            None
        }
    }
}

fn resolve_value_aliases(
    value: &DtcgValue,
    token_index: &HashMap<String, MaterializedToken>,
    resolved: &mut HashMap<String, ResolvedToken>,
    visiting: &mut Vec<String>,
    errors: &mut Vec<AliasError>,
) -> Option<DtcgValue> {
    match value {
        DtcgValue::Str(s) => {
            if let Some(r) = is_alias(s) {
                let current_path = visiting.last().cloned().unwrap_or_default();
                let target = resolve_alias_target(&current_path, r, token_index, errors)?;
                let t = resolve_token(target, token_index, resolved, visiting, errors)?;
                Some(t.value)
            } else {
                Some(value.clone())
            }
        }
        DtcgValue::Array(xs) => {
            let mut out = Vec::with_capacity(xs.len());
            for x in xs {
                out.push(resolve_value_aliases(
                    x,
                    token_index,
                    resolved,
                    visiting,
                    errors,
                )?);
            }
            Some(DtcgValue::Array(out))
        }
        DtcgValue::Object(m) => {
            let mut out = BTreeMap::new();
            for (k, v) in m {
                out.insert(
                    k.clone(),
                    resolve_value_aliases(v, token_index, resolved, visiting, errors)?,
                );
            }
            Some(DtcgValue::Object(out))
        }
        _ => Some(value.clone()),
    }
}

fn resolve_token(
    token: &MaterializedToken,
    token_index: &HashMap<String, MaterializedToken>,
    resolved: &mut HashMap<String, ResolvedToken>,
    visiting: &mut Vec<String>,
    errors: &mut Vec<AliasError>,
) -> Option<ResolvedToken> {
    if let Some(t) = resolved.get(&token.path) {
        return Some(t.clone());
    }

    if visiting.iter().any(|p| p == &token.path) {
        let mut chain = visiting.clone();
        chain.push(token.path.clone());
        errors.push(AliasError::CircularAlias { chain });
        return None;
    }
    visiting.push(token.path.clone());

    let (ty, value) = match &token.value {
        DtcgValue::Str(s) if is_alias(s).is_some() => {
            let r = is_alias(s).unwrap_or_default();
            let target = match resolve_alias_target(&token.path, r, token_index, errors) {
                Some(t) => t,
                None => {
                    visiting.pop();
                    return None;
                }
            };
            let resolved_target = resolve_token(target, token_index, resolved, visiting, errors)?;
            if token.ty != resolved_target.ty {
                errors.push(AliasError::InvalidType {
                    path: token.path.clone(),
                    ty: token.ty,
                    reason: format!(
                        "alias type mismatch: source type {} does not match target type {}",
                        token.ty, resolved_target.ty
                    ),
                });
                visiting.pop();
                return None;
            }
            (resolved_target.ty, resolved_target.value)
        }
        other => {
            let vv = resolve_value_aliases(other, token_index, resolved, visiting, errors)?;
            (token.ty, vv)
        }
    };

    let out = ResolvedToken {
        path: token.path.clone(),
        ty,
        value,
        source: token.source.clone(),
    };

    resolved.insert(token.path.clone(), out.clone());
    visiting.pop();
    Some(out)
}

pub fn resolve_aliases(
    tokens: &[MaterializedToken],
) -> Result<Vec<ResolvedToken>, Vec<AliasError>> {
    let token_index: HashMap<String, MaterializedToken> = tokens
        .iter()
        .cloned()
        .map(|t| (t.path.clone(), t))
        .collect();

    let mut resolved: HashMap<String, ResolvedToken> = HashMap::new();
    let mut errors: Vec<AliasError> = Vec::new();

    for t in tokens {
        let mut visiting = Vec::new();
        let _ = resolve_token(t, &token_index, &mut resolved, &mut visiting, &mut errors);
    }

    if !errors.is_empty() {
        Err(errors)
    } else {
        Ok(resolved.into_values().collect())
    }
}

fn parse_type(v: Option<&JValue>, fallback: Option<DtcgType>) -> Option<DtcgType> {
    match v {
        Some(JValue::String(s)) => match s.as_str() {
            "color" => Some(DtcgType::Color),
            "dimension" => Some(DtcgType::Dimension),
            "duration" => Some(DtcgType::Duration),
            "fontFamily" => Some(DtcgType::FontFamily),
            "fontWeight" => Some(DtcgType::FontWeight),
            "number" => Some(DtcgType::Number),
            "strokeStyle" => Some(DtcgType::StrokeStyle),
            "border" => Some(DtcgType::Border),
            "transition" => Some(DtcgType::Transition),
            "shadow" => Some(DtcgType::Shadow),
            "gradient" => Some(DtcgType::Gradient),
            "typography" => Some(DtcgType::Typography),
            "cubicBezier" => Some(DtcgType::CubicBezier),
            _ => fallback,
        },
        _ => fallback,
    }
}

pub fn materialize(tree: &JValue, source: &str) -> Vec<MaterializedToken> {
    fn go(
        node: &JValue,
        source: &str,
        prefix: &str,
        inherited: Option<DtcgType>,
        out: &mut Vec<MaterializedToken>,
    ) {
        let obj = match node {
            JValue::Object(m) => m,
            _ => return,
        };

        let group_type = parse_type(obj.get("$type"), inherited);

        if let Some(root) = obj.get("$root") {
            if let Some(root_obj) = root.as_object() {
                if let Some(v) = root_obj.get("$value") {
                    let ty = parse_type(root_obj.get("$type"), group_type)
                        .unwrap_or(DtcgType::Typography);
                    if !prefix.is_empty() {
                        out.push(MaterializedToken {
                            path: prefix.to_string(),
                            ty,
                            value: DtcgValue::from_jvalue(v),
                            source: source.to_string(),
                        });
                    }
                }
            }
        }

        for (k, v) in obj {
            if k.starts_with('$') {
                continue;
            }
            if !v.is_object() {
                continue;
            }
            let token_path = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            };

            let child_obj = match v.as_object() {
                Some(m) => m,
                None => continue,
            };
            if let Some(val_node) = child_obj.get("$value") {
                let ty =
                    parse_type(child_obj.get("$type"), group_type).unwrap_or(DtcgType::Typography);
                out.push(MaterializedToken {
                    path: token_path,
                    ty,
                    value: DtcgValue::from_jvalue(val_node),
                    source: source.to_string(),
                });
            } else {
                go(v, source, &token_path, group_type, out);
            }
        }
    }

    let mut out = Vec::new();
    go(tree, source, "", None, &mut out);
    out
}

pub fn collect_explicit_token_paths(tree: &JValue) -> HashSet<String> {
    fn go(node: &JValue, prefix: &str, out: &mut HashSet<String>) {
        let obj = match node {
            JValue::Object(m) => m,
            _ => return,
        };

        if let Some(JValue::Object(root_obj)) = obj.get("$root") {
            if root_obj.contains_key("$value") && !prefix.is_empty() {
                out.insert(prefix.to_string());
            }
        }

        for (k, v) in obj {
            if k.starts_with('$') {
                continue;
            }
            let child = match v {
                JValue::Object(m) => m,
                _ => continue,
            };
            let child_path = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            };
            if child.contains_key("$value") {
                out.insert(child_path);
            } else {
                go(v, &child_path, out);
            }
        }
    }

    let mut out = HashSet::new();
    go(tree, "", &mut out);
    out
}

pub fn collect_explicit_token_defs(tree: &JValue) -> HashMap<String, String> {
    fn esc(seg: &str) -> String {
        seg.replace('~', "~0").replace('/', "~1")
    }

    fn ptr_of(mut segs: Vec<String>) -> String {
        if segs.is_empty() {
            return "".to_string();
        }
        segs.insert(0, "".to_string());
        segs.join("/")
    }

    fn decode_json_pointer_segment_opt(seg: &str) -> Option<String> {
        let mut out = String::with_capacity(seg.len());
        let mut chars = seg.chars();
        while let Some(ch) = chars.next() {
            if ch != '~' {
                out.push(ch);
                continue;
            }
            match chars.next() {
                Some('0') => out.push('~'),
                Some('1') => out.push('/'),
                _ => return None,
            }
        }
        Some(out)
    }

    fn normalize_alias_ref(raw_ref: &str) -> Option<String> {
        let trimmed = raw_ref.trim();
        if trimmed.is_empty() {
            return None;
        }
        if !trimmed.starts_with('#') {
            return Some(trimmed.to_string());
        }
        let pointer = trimmed.strip_prefix("#/")?;
        let mut segments: Vec<String> = pointer
            .split('/')
            .map(decode_json_pointer_segment_opt)
            .collect::<Option<Vec<_>>>()?;
        if matches!(segments.last(), Some(s) if s == "$value") {
            segments.pop();
        }
        if matches!(segments.last(), Some(s) if s == "$root") {
            segments.pop();
        }
        if segments.is_empty() {
            return None;
        }
        Some(segments.join("."))
    }

    fn alias_target(value: &JValue) -> Option<String> {
        let s = match value {
            JValue::String(s) => s.as_str(),
            _ => return None,
        };
        let s = s.trim();
        if !(s.starts_with('{') && s.ends_with('}')) {
            return None;
        }
        normalize_alias_ref(&s[1..s.len() - 1])
    }

    fn rewritten_paths_via_extends(
        path: &str,
        extends_map: &HashMap<String, String>,
    ) -> Vec<String> {
        let segs: Vec<&str> = path.split('.').collect();
        let mut out = Vec::new();
        for i in (1..=segs.len()).rev() {
            let prefix = segs[..i].join(".");
            if let Some(ext) = extends_map.get(&prefix) {
                let suffix = segs[i..].join(".");
                if suffix.is_empty() {
                    out.push(ext.clone());
                } else {
                    out.push(format!("{ext}.{suffix}"));
                }
            }
        }
        out
    }

    fn resolve_defining_path(
        path: &str,
        defs: &HashMap<String, (String, JValue)>,
        extends_map: &HashMap<String, String>,
        visiting: &mut HashSet<String>,
    ) -> Option<String> {
        if !visiting.insert(path.to_string()) {
            return None;
        }

        if let Some((_ptr, value)) = defs.get(path) {
            if let Some(target) = alias_target(value) {
                if let Some(v) = resolve_defining_path(&target, defs, extends_map, visiting) {
                    return Some(v);
                }
            }
            return Some(path.to_string());
        }

        for candidate in rewritten_paths_via_extends(path, extends_map) {
            if let Some(v) = resolve_defining_path(&candidate, defs, extends_map, visiting) {
                return Some(v);
            }
        }

        None
    }

    fn go(
        node: &JValue,
        path: &mut Vec<String>,
        ptr: &mut Vec<String>,
        defs: &mut HashMap<String, (String, JValue)>,
        extends_map: &mut HashMap<String, String>,
    ) {
        let obj = match node {
            JValue::Object(m) => m,
            _ => return,
        };

        if let Some(JValue::String(ext)) = obj.get("$extends") {
            if !path.is_empty() {
                extends_map.insert(path.join("."), ext.clone());
            }
        }

        if let Some(JValue::Object(root_obj)) = obj.get("$root") {
            if root_obj.contains_key("$value") && !path.is_empty() {
                let token_path = path.join(".");
                let mut p = ptr.clone();
                p.push("$root".to_string());
                p.push("$value".to_string());
                if let Some(v) = root_obj.get("$value") {
                    defs.insert(token_path, (ptr_of(p), v.clone()));
                }
            }
        }

        for (k, v) in obj {
            if k.starts_with('$') {
                continue;
            }
            let child = match v {
                JValue::Object(m) => m,
                _ => continue,
            };

            path.push(k.clone());
            ptr.push(esc(k));

            if child.contains_key("$value") {
                let token_path = path.join(".");
                let mut p = ptr.clone();
                p.push("$value".to_string());
                if let Some(v) = child.get("$value") {
                    defs.insert(token_path, (ptr_of(p), v.clone()));
                }
            } else {
                go(v, path, ptr, defs, extends_map);
            }

            path.pop();
            ptr.pop();
        }
    }

    let mut defs: HashMap<String, (String, JValue)> = HashMap::new();
    let mut extends_map: HashMap<String, String> = HashMap::new();
    go(
        tree,
        &mut Vec::new(),
        &mut Vec::new(),
        &mut defs,
        &mut extends_map,
    );

    let mut out = HashMap::new();
    for (path, (ptr, _value)) in &defs {
        let mut visiting = HashSet::new();
        let final_ptr = resolve_defining_path(path, &defs, &extends_map, &mut visiting)
            .and_then(|p| defs.get(&p).map(|(resolved_ptr, _)| resolved_ptr.clone()))
            .unwrap_or_else(|| ptr.clone());
        out.insert(path.clone(), final_ptr);
    }

    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalizeError {
    InvalidType {
        path: String,
        ty: DtcgType,
        reason: String,
    },
}

fn as_object(value: &DtcgValue) -> Option<&BTreeMap<String, DtcgValue>> {
    match value {
        DtcgValue::Object(m) => Some(m),
        _ => None,
    }
}

fn as_str(value: &DtcgValue) -> Option<&str> {
    match value {
        DtcgValue::Str(s) => Some(s.as_str()),
        _ => None,
    }
}

fn parse_num(value: &DtcgValue) -> Option<NumLit> {
    match value {
        DtcgValue::Num(n) => Some(n.clone()),
        DtcgValue::Str(s) => Some(NumLit(s.clone())),
        _ => None,
    }
}

fn parse_f64(lit: &NumLit) -> Option<f64> {
    lit.0.parse::<f64>().ok()
}

fn invalid_type(path: String, ty: DtcgType, reason: String) -> CanonicalizeError {
    CanonicalizeError::InvalidType { path, ty, reason }
}

fn canonicalize_color(path: &str, value: &DtcgValue) -> Result<DtcgValue, CanonicalizeError> {
    let obj = as_object(value).ok_or_else(|| {
        invalid_type(
            path.to_string(),
            DtcgType::Color,
            "color value must be an object".to_string(),
        )
    })?;

    let cs = as_str(obj.get("colorSpace").ok_or_else(|| {
        invalid_type(
            path.to_string(),
            DtcgType::Color,
            "missing colorSpace".to_string(),
        )
    })?)
    .ok_or_else(|| {
        invalid_type(
            path.to_string(),
            DtcgType::Color,
            "colorSpace must be string".to_string(),
        )
    })?;

    let color_space = match cs {
        "srgb" => ColorSpace::Srgb,
        "srgb-linear" => ColorSpace::SrgbLinear,
        "hsl" => ColorSpace::Hsl,
        "hwb" => ColorSpace::Hwb,
        "lab" => ColorSpace::Lab,
        "lch" => ColorSpace::Lch,
        "oklab" => ColorSpace::Oklab,
        "oklch" => ColorSpace::Oklch,
        "display-p3" => ColorSpace::DisplayP3,
        "a98-rgb" => ColorSpace::A98Rgb,
        "prophoto-rgb" => ColorSpace::ProphotoRgb,
        "rec2020" => ColorSpace::Rec2020,
        "xyz-d65" => ColorSpace::XyzD65,
        "xyz-d50" => ColorSpace::XyzD50,
        _ => {
            return Err(invalid_type(
                path.to_string(),
                DtcgType::Color,
                format!("unsupported colorSpace: {cs}"),
            ))
        }
    };

    let comps_v = obj.get("components").ok_or_else(|| {
        invalid_type(
            path.to_string(),
            DtcgType::Color,
            "missing components".to_string(),
        )
    })?;

    let comps = match comps_v {
        DtcgValue::Array(xs) if xs.len() == 3 => xs,
        _ => {
            return Err(invalid_type(
                path.to_string(),
                DtcgType::Color,
                "components must be array of length 3".to_string(),
            ))
        }
    };

    let mut out_comps: [ColorComponent; 3] = [
        ColorComponent::None("none".to_string()),
        ColorComponent::None("none".to_string()),
        ColorComponent::None("none".to_string()),
    ];

    for (i, c) in comps.iter().enumerate() {
        let comp = match c {
            DtcgValue::Str(s) if s == "none" => ColorComponent::None("none".to_string()),
            _ => {
                let n = parse_num(c).ok_or_else(|| {
                    invalid_type(
                        format!("{path}.components[{i}]"),
                        DtcgType::Color,
                        "component must be number or \"none\"".to_string(),
                    )
                })?;

                let x = parse_f64(&n).ok_or_else(|| {
                    invalid_type(
                        format!("{path}.components[{i}]"),
                        DtcgType::Color,
                        "component is not a valid number".to_string(),
                    )
                })?;

                let (min, max_opt): (f64, Option<f64>) = match (color_space.as_css_ident(), i) {
                    (
                        "srgb" | "srgb-linear" | "display-p3" | "a98-rgb" | "prophoto-rgb"
                        | "rec2020" | "xyz-d65" | "xyz-d50",
                        _,
                    ) => (0.0, Some(1.0)),
                    ("hsl" | "hwb", 0) => (0.0, Some(360.0)),
                    ("hsl" | "hwb", _) => (0.0, Some(100.0)),
                    ("lab" | "lch", 0) => (0.0, Some(100.0)),
                    ("oklab" | "oklch", 0) => (0.0, Some(1.0)),
                    ("lab" | "oklab", _) => (f64::NEG_INFINITY, None),
                    ("lch" | "oklch", 1) => (0.0, None),
                    ("lch" | "oklch", 2) => (0.0, Some(360.0)),
                    _ => (f64::NEG_INFINITY, None),
                };

                if x < min {
                    return Err(invalid_type(
                        format!("{path}.components[{i}]"),
                        DtcgType::Color,
                        format!("component out of range (min {min})"),
                    ));
                }
                if let Some(max) = max_opt {
                    if x > max {
                        return Err(invalid_type(
                            format!("{path}.components[{i}]"),
                            DtcgType::Color,
                            format!("component out of range (max {max})"),
                        ));
                    }
                    if i == 0
                        && (color_space.as_css_ident() == "hsl"
                            || color_space.as_css_ident() == "hwb"
                            || color_space.as_css_ident() == "lch"
                            || color_space.as_css_ident() == "oklch")
                        && (x - 360.0).abs() < f64::EPSILON
                    {
                        return Err(invalid_type(
                            format!("{path}.components[{i}]"),
                            DtcgType::Color,
                            "hue must be in [0, 360)".to_string(),
                        ));
                    }
                }

                ColorComponent::Num(n)
            }
        };
        out_comps[i] = comp;
    }

    let alpha = match obj.get("alpha") {
        None => None,
        Some(v) => {
            let n = parse_num(v).ok_or_else(|| {
                invalid_type(
                    format!("{path}.alpha"),
                    DtcgType::Color,
                    "alpha must be number".to_string(),
                )
            })?;
            let x = parse_f64(&n).ok_or_else(|| {
                invalid_type(
                    format!("{path}.alpha"),
                    DtcgType::Color,
                    "alpha is not a valid number".to_string(),
                )
            })?;
            if !(0.0..=1.0).contains(&x) {
                return Err(invalid_type(
                    format!("{path}.alpha"),
                    DtcgType::Color,
                    "alpha must be in [0,1]".to_string(),
                ));
            }
            Some(n)
        }
    };

    let hex = match obj.get("hex") {
        None => None,
        Some(DtcgValue::Str(s)) => {
            if s.len() == 7 && s.starts_with('#') {
                Some(s.clone())
            } else {
                return Err(invalid_type(
                    format!("{path}.hex"),
                    DtcgType::Color,
                    "hex must be like #RRGGBB".to_string(),
                ));
            }
        }
        Some(_) => {
            return Err(invalid_type(
                format!("{path}.hex"),
                DtcgType::Color,
                "hex must be string".to_string(),
            ))
        }
    };

    Ok(DtcgValue::Color(DtcgColor {
        color_space,
        components: out_comps,
        alpha,
        hex,
    }))
}

fn canonicalize_dimension(path: &str, value: &DtcgValue) -> Result<DtcgValue, CanonicalizeError> {
    let obj = as_object(value).ok_or_else(|| {
        invalid_type(
            path.to_string(),
            DtcgType::Dimension,
            "dimension must be object".to_string(),
        )
    })?;

    let v = obj.get("value").ok_or_else(|| {
        invalid_type(
            path.to_string(),
            DtcgType::Dimension,
            "missing value".to_string(),
        )
    })?;

    let n = parse_num(v).ok_or_else(|| {
        invalid_type(
            format!("{path}.value"),
            DtcgType::Dimension,
            "value must be number".to_string(),
        )
    })?;

    let _ = parse_f64(&n).ok_or_else(|| {
        invalid_type(
            format!("{path}.value"),
            DtcgType::Dimension,
            "value is not a valid number".to_string(),
        )
    })?;

    let unit = match as_str(obj.get("unit").ok_or_else(|| {
        invalid_type(
            path.to_string(),
            DtcgType::Dimension,
            "missing unit".to_string(),
        )
    })?) {
        Some("px") => DimensionUnit::Px,
        Some("rem") => DimensionUnit::Rem,
        Some(u) => {
            return Err(invalid_type(
                format!("{path}.unit"),
                DtcgType::Dimension,
                format!("invalid unit: {u}"),
            ))
        }
        None => {
            return Err(invalid_type(
                format!("{path}.unit"),
                DtcgType::Dimension,
                "unit must be string".to_string(),
            ))
        }
    };

    Ok(DtcgValue::Dimension(DtcgDimension { value: n, unit }))
}

fn canonicalize_duration(path: &str, value: &DtcgValue) -> Result<DtcgValue, CanonicalizeError> {
    let obj = as_object(value).ok_or_else(|| {
        invalid_type(
            path.to_string(),
            DtcgType::Duration,
            "duration must be object".to_string(),
        )
    })?;

    let v = obj.get("value").ok_or_else(|| {
        invalid_type(
            path.to_string(),
            DtcgType::Duration,
            "missing value".to_string(),
        )
    })?;

    let n = parse_num(v).ok_or_else(|| {
        invalid_type(
            format!("{path}.value"),
            DtcgType::Duration,
            "value must be number".to_string(),
        )
    })?;

    let _ = parse_f64(&n).ok_or_else(|| {
        invalid_type(
            format!("{path}.value"),
            DtcgType::Duration,
            "value is not a valid number".to_string(),
        )
    })?;

    let unit = match as_str(obj.get("unit").ok_or_else(|| {
        invalid_type(
            path.to_string(),
            DtcgType::Duration,
            "missing unit".to_string(),
        )
    })?) {
        Some("ms") => DurationUnit::Ms,
        Some("s") => DurationUnit::S,
        Some(u) => {
            return Err(invalid_type(
                format!("{path}.unit"),
                DtcgType::Duration,
                format!("invalid unit: {u}"),
            ))
        }
        None => {
            return Err(invalid_type(
                format!("{path}.unit"),
                DtcgType::Duration,
                "unit must be string".to_string(),
            ))
        }
    };

    Ok(DtcgValue::Duration(DtcgDuration { value: n, unit }))
}

pub fn canonicalize_token(token: &ResolvedToken) -> Result<ResolvedToken, CanonicalizeError> {
    let value = match token.ty {
        DtcgType::Color => canonicalize_color(&token.path, &token.value)?,
        DtcgType::Dimension => canonicalize_dimension(&token.path, &token.value)?,
        DtcgType::Duration => canonicalize_duration(&token.path, &token.value)?,
        DtcgType::Number => match &token.value {
            DtcgValue::Num(_) => token.value.clone(),
            _ => {
                return Err(invalid_type(
                    token.path.clone(),
                    token.ty,
                    "number token must be numeric".to_string(),
                ))
            }
        },
        _ => token.value.clone(),
    };

    Ok(ResolvedToken {
        value,
        ..token.clone()
    })
}
