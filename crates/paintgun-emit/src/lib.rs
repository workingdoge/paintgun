use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use paintgun_dtcg::{
    ColorComponent, DtcgColor, DtcgDimension, DtcgDuration, DtcgType, DtcgValue, NumLit,
};
use paintgun_policy::{normalize_value, CssColorPolicy, Policy};

pub type Input = BTreeMap<String, String>;

pub const SWIFT_EMITTER_API_VERSION: &str = "paintgun-swift-tokens/v1";
pub const ANDROID_COMPOSE_EMITTER_API_VERSION: &str = "paintgun-android-compose-tokens/v1";
pub const KOTLIN_EMITTER_API_VERSION: &str = ANDROID_COMPOSE_EMITTER_API_VERSION;
pub const WEB_TOKENS_TS_API_VERSION: &str = "paintgun-web-tokens-ts/v1";

//──────────────────────────────────────────────────────────────────────────────
// Emitter abstraction
//──────────────────────────────────────────────────────────────────────────────

pub trait Emitter {
    type Output;

    fn color(&self, v: &DtcgColor, _path: &str) -> Self::Output;
    fn dimension(&self, v: &DtcgDimension, _path: &str) -> Self::Output;
    fn duration(&self, v: &DtcgDuration, _path: &str) -> Self::Output;
    fn number(&self, v: &NumLit, _path: &str) -> Self::Output;
    fn string(&self, v: &str, _path: &str) -> Self::Output;

    fn fallback(&self, v: &DtcgValue, _ty: DtcgType, _path: &str) -> Self::Output;
}

pub fn emit_value<E: Emitter>(e: &E, ty: DtcgType, value: &DtcgValue, path: &str) -> E::Output {
    match (ty, value) {
        (DtcgType::Color, DtcgValue::Color(c)) => e.color(c, path),
        (DtcgType::Dimension, DtcgValue::Dimension(d)) => e.dimension(d, path),
        (DtcgType::Duration, DtcgValue::Duration(d)) => e.duration(d, path),
        (DtcgType::Number, DtcgValue::Num(n)) => e.number(n, path),
        // Font-family wants quoting semantics
        (DtcgType::FontFamily, DtcgValue::Str(s)) => {
            // Emit as a single quoted family.
            e.string(&format!("\"{}\"", s), path)
        }
        (DtcgType::FontFamily, DtcgValue::Array(xs)) => {
            let mut out = Vec::new();
            for x in xs {
                if let DtcgValue::Str(s) = x {
                    out.push(format!("\"{}\"", s));
                }
            }
            e.string(&out.join(", "), path)
        }
        (DtcgType::FontWeight, DtcgValue::Num(n)) => e.number(n, path),
        (DtcgType::CubicBezier, DtcgValue::Array(xs)) => {
            let parts: Vec<String> = xs.iter().map(|v| v.to_canonical_json_string()).collect();
            e.string(&format!("cubic-bezier({})", parts.join(", ")), path)
        }
        // Default:
        _ => e.fallback(value, ty, path),
    }
}

//──────────────────────────────────────────────────────────────────────────────
// CSS emitter
//──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct CssEmitter {
    pub color_policy: CssColorPolicy,
}

impl Default for CssEmitter {
    fn default() -> Self {
        CssEmitter {
            color_policy: CssColorPolicy::PreserveSpace,
        }
    }
}

fn alpha_is_one(a: &NumLit) -> bool {
    match a.0.parse::<f64>() {
        Ok(x) => (x - 1.0).abs() < f64::EPSILON,
        Err(_) => a.0 == "1",
    }
}

impl CssEmitter {
    fn color_to_css(&self, v: &DtcgColor) -> String {
        if matches!(self.color_policy, CssColorPolicy::PreferHexIfPresent) {
            if let Some(hex) = &v.hex {
                return hex.clone();
            }
        }

        let comps = v
            .components
            .iter()
            .map(|c| match c {
                ColorComponent::None(_) => "none".to_string(),
                ColorComponent::Num(n) => n.0.clone(),
            })
            .collect::<Vec<_>>()
            .join(" ");

        let alpha = match &v.alpha {
            None => String::new(),
            Some(a) if alpha_is_one(a) => String::new(),
            Some(a) => format!(" / {}", a.0),
        };

        match v.color_space.as_css_ident() {
            "hsl" => format!("hsl({}{})", comps, alpha),
            "hwb" => format!("hwb({}{})", comps, alpha),
            "lab" => format!("lab({}{})", comps, alpha),
            "lch" => format!("lch({}{})", comps, alpha),
            "oklab" => format!("oklab({}{})", comps, alpha),
            "oklch" => format!("oklch({}{})", comps, alpha),
            other => format!("color({} {}{})", other, comps, alpha),
        }
    }
}

impl Emitter for CssEmitter {
    type Output = String;

    fn color(&self, v: &DtcgColor, _path: &str) -> Self::Output {
        self.color_to_css(v)
    }

    fn dimension(&self, v: &DtcgDimension, _path: &str) -> Self::Output {
        let unit = match v.unit {
            paintgun_dtcg::DimensionUnit::Px => "px",
            paintgun_dtcg::DimensionUnit::Rem => "rem",
        };
        format!("{}{}", v.value.0, unit)
    }

    fn duration(&self, v: &DtcgDuration, _path: &str) -> Self::Output {
        let unit = match v.unit {
            paintgun_dtcg::DurationUnit::Ms => "ms",
            paintgun_dtcg::DurationUnit::S => "s",
        };
        format!("{}{}", v.value.0, unit)
    }

    fn number(&self, v: &NumLit, _path: &str) -> Self::Output {
        v.0.clone()
    }

    fn string(&self, v: &str, _path: &str) -> Self::Output {
        v.to_string()
    }

    fn fallback(&self, v: &DtcgValue, _ty: DtcgType, _path: &str) -> Self::Output {
        match v {
            DtcgValue::Str(s) => s.clone(),
            _ => v.to_canonical_json_string(),
        }
    }
}

//──────────────────────────────────────────────────────────────────────────────
// Component contracts
//──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Deserialize)]
pub struct Contract {
    pub component: String,
    #[serde(default)]
    pub description: Option<String>,
    pub slots: HashMap<String, SlotDef>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SlotDef {
    pub token: String,
    pub property: String,
    #[serde(default)]
    pub fallback: Option<String>,
}

//──────────────────────────────────────────────────────────────────────────────
// Layer definitions (@layer + selectors)
//──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct LayerDef {
    pub name: String,
    pub input: Input,
    pub selector: String,
}

pub fn build_layer_defs_for_ordered_modifiers(
    mod_names: &[String],
    axes: &BTreeMap<String, Vec<String>>,
) -> Vec<LayerDef> {
    let mut layers = Vec::new();

    // Base
    layers.push(LayerDef {
        name: "base".to_string(),
        input: BTreeMap::new(),
        selector: "{tag}".to_string(),
    });

    // One layer per modifier context
    for mod_name in mod_names {
        let ctxs = axes.get(mod_name).cloned().unwrap_or_default();
        for ctx in ctxs {
            let mut input = BTreeMap::new();
            input.insert(mod_name.clone(), ctx.clone());
            layers.push(LayerDef {
                name: mod_name.clone(),
                input,
                selector: format!(":root[data-{mod_name}=\"{ctx}\"] {{tag}}"),
            });
        }
    }

    // Pairwise cross product layers
    if mod_names.len() >= 2 {
        for i in 0..mod_names.len() {
            for j in (i + 1)..mod_names.len() {
                let a = &mod_names[i];
                let b = &mod_names[j];
                let ctx_a = axes.get(a).cloned().unwrap_or_default();
                let ctx_b = axes.get(b).cloned().unwrap_or_default();
                for va in &ctx_a {
                    for vb in &ctx_b {
                        let mut input = BTreeMap::new();
                        input.insert(a.clone(), va.clone());
                        input.insert(b.clone(), vb.clone());
                        layers.push(LayerDef {
                            name: format!("{a}-{b}"),
                            input,
                            selector: format!(
                                ":root[data-{a}=\"{va}\"][data-{b}=\"{vb}\"] {{tag}}"
                            ),
                        });
                    }
                }
            }
        }
    }

    layers
}

/// Build layer definitions from an axes map, without requiring a full ResolverDoc.
///
/// This is used for multi-pack composition, where we may not have a single canonical
/// resolver spec, but we still want to emit CSS layers/selectors.
pub fn build_layer_defs_from_axes(axes: &BTreeMap<String, Vec<String>>) -> Vec<LayerDef> {
    let mut mod_names: Vec<String> = axes.keys().cloned().collect();
    mod_names.sort();
    build_layer_defs_for_ordered_modifiers(&mod_names, axes)
}

//──────────────────────────────────────────────────────────────────────────────
// CSS compilation
//──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Delta {
    pub property: String,
    pub value: String,
}

fn emit_layer_block(layer_name: &str, selector: &str, deltas: &[Delta]) -> Option<String> {
    if deltas.is_empty() {
        return None;
    }
    let props = deltas
        .iter()
        .map(|d| format!("    {}: {};", d.property, d.value))
        .collect::<Vec<_>>()
        .join("\n");

    Some(format!(
        "@layer {layer_name} {{\n  {selector} {{\n{props}\n  }}\n}}"
    ))
}

/// Compile a single component contract to CSS @layer blocks using precomputed layers.
///
/// Token lookup is injected via callback so this kernel stays independent of resolver/store
/// implementations.
pub fn compile_component_css_with_layers_lookup<Lookup>(
    contract: &Contract,
    policy: &Policy,
    emitter: &CssEmitter,
    layer_defs: &[LayerDef],
    mut lookup_token: Lookup,
) -> String
where
    Lookup: FnMut(&str, &Input) -> Option<(DtcgType, DtcgValue)>,
{
    let mut blocks: Vec<String> = Vec::new();
    let mut baseline: HashMap<String, (DtcgType, DtcgValue)> = HashMap::new();

    for layer in layer_defs {
        let mut current: HashMap<String, (DtcgType, DtcgValue)> = HashMap::new();

        for (_slot, def) in &contract.slots {
            if let Some((ty, value)) = lookup_token(&def.token, &layer.input) {
                let norm = normalize_value(policy, ty, &value);
                current.insert(def.property.clone(), (ty, norm));
            }
        }

        // Compute deltas on structured values.
        let mut deltas: Vec<Delta> = Vec::new();
        for (prop, (ty, v)) in &current {
            let changed = match baseline.get(prop) {
                None => true,
                Some((prev_ty, prev_v)) => prev_ty != ty || prev_v != v,
            };

            if changed {
                let css = emit_value(emitter, *ty, v, prop);
                deltas.push(Delta {
                    property: prop.clone(),
                    value: css,
                });
            }
        }

        if let Some(block) = emit_layer_block(
            &layer.name,
            &layer.selector.replace("{tag}", &contract.component),
            &deltas,
        ) {
            blocks.push(block);
        }

        // Update baseline
        for (k, tv) in current {
            baseline.insert(k, tv);
        }
    }

    format!("{}\n", blocks.join("\n\n"))
}

//──────────────────────────────────────────────────────────────────────────────
// Mobile targets (Swift / Kotlin)
//──────────────────────────────────────────────────────────────────────────────

fn escape_swift_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn escape_kotlin_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn kotlin_double_expr(raw: &str) -> String {
    format!("({raw}).toDouble()")
}

fn parse_num_lit(n: &NumLit) -> Option<f64> {
    n.0.parse::<f64>().ok()
}

fn parse_hex_rgb(hex: &str) -> Option<(u8, u8, u8)> {
    let s = hex.strip_prefix('#')?;
    if s.len() != 6 {
        return None;
    }
    let r = u8::from_str_radix(&s[0..2], 16).ok()?;
    let g = u8::from_str_radix(&s[2..4], 16).ok()?;
    let b = u8::from_str_radix(&s[4..6], 16).ok()?;
    Some((r, g, b))
}

fn enumerate_full_inputs(axes: &BTreeMap<String, Vec<String>>) -> Vec<Input> {
    let axis_names: Vec<String> = axes.keys().cloned().collect();
    let mut out: Vec<Input> = Vec::new();

    fn go(
        idx: usize,
        axis_names: &[String],
        axes: &BTreeMap<String, Vec<String>>,
        cur: &mut Input,
        out: &mut Vec<Input>,
    ) {
        if idx == axis_names.len() {
            out.push(cur.clone());
            return;
        }
        let a = &axis_names[idx];
        if let Some(vals) = axes.get(a) {
            for v in vals {
                cur.insert(a.clone(), v.clone());
                go(idx + 1, axis_names, axes, cur, out);
                cur.remove(a);
            }
        }
    }

    go(0, &axis_names, axes, &mut BTreeMap::new(), &mut out);
    out
}

pub fn stable_context_key(input: &Input) -> String {
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

#[derive(Clone, Debug)]
pub struct EmissionToken {
    pub path: String,
    pub ty: DtcgType,
    pub value: DtcgValue,
}

//──────────────────────────────────────────────────────────────────────────────
// Swift emitter
//──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct SwiftEmitter;

impl SwiftEmitter {
    fn color_expr(&self, v: &DtcgColor) -> Option<String> {
        // Prefer hex if present (works for any authored space).
        if let Some(hex) = &v.hex {
            if let Some((r8, g8, b8)) = parse_hex_rgb(hex) {
                let r = (r8 as f64) / 255.0;
                let g = (g8 as f64) / 255.0;
                let b = (b8 as f64) / 255.0;
                let a = v.alpha.as_ref().and_then(parse_num_lit).unwrap_or(1.0);
                return Some(format!(
                    "paintgunColor(red: {r}, green: {g}, blue: {b}, opacity: {a})"
                ));
            }
        }

        // Otherwise support numeric component colors.
        let mut comps: [f64; 3] = [0.0, 0.0, 0.0];
        for (i, c) in v.components.iter().enumerate() {
            match c {
                ColorComponent::Num(n) => {
                    comps[i] = parse_num_lit(n)?;
                }
                ColorComponent::None(_) => return None,
            }
        }
        let a = v.alpha.as_ref().and_then(parse_num_lit).unwrap_or(1.0);

        Some(format!(
            "paintgunColor(red: {r}, green: {g}, blue: {b}, opacity: {a})",
            r = comps[0],
            g = comps[1],
            b = comps[2],
            a = a
        ))
    }
}

impl Emitter for SwiftEmitter {
    type Output = String;

    fn color(&self, v: &DtcgColor, _path: &str) -> Self::Output {
        match self.color_expr(v) {
            Some(expr) => format!(".color({expr})"),
            None => format!(
                ".rawJson(\"{}\")",
                escape_swift_string(&DtcgValue::Color(v.clone()).to_canonical_json_string())
            ),
        }
    }

    fn dimension(&self, v: &DtcgDimension, _path: &str) -> Self::Output {
        let unit = match v.unit {
            paintgun_dtcg::DimensionUnit::Px => "px",
            paintgun_dtcg::DimensionUnit::Rem => "rem",
        };
        format!(".dimension({value}, unit: \"{unit}\")", value = v.value.0)
    }

    fn duration(&self, v: &DtcgDuration, _path: &str) -> Self::Output {
        let unit = match v.unit {
            paintgun_dtcg::DurationUnit::Ms => "ms",
            paintgun_dtcg::DurationUnit::S => "s",
        };
        format!(".duration({value}, unit: \"{unit}\")", value = v.value.0)
    }

    fn number(&self, v: &NumLit, _path: &str) -> Self::Output {
        format!(".number({})", v.0)
    }

    fn string(&self, v: &str, _path: &str) -> Self::Output {
        format!(".string(\"{}\")", escape_swift_string(v))
    }

    fn fallback(&self, v: &DtcgValue, _ty: DtcgType, _path: &str) -> Self::Output {
        format!(
            ".rawJson(\"{}\")",
            escape_swift_string(&v.to_canonical_json_string())
        )
    }
}

pub fn emit_store_swift_with_lookup<Lookup>(
    axes: &BTreeMap<String, Vec<String>>,
    policy: &Policy,
    mut tokens_for_context: Lookup,
) -> String
where
    Lookup: FnMut(&Input) -> Vec<EmissionToken>,
{
    let emitter = SwiftEmitter::default();
    let mut out = String::new();
    out.push_str("// Generated by Paintgun\n");
    out.push_str(&format!(
        "// Native API version: {}\n",
        SWIFT_EMITTER_API_VERSION
    ));
    out.push_str("#if canImport(SwiftUI)\n");
    out.push_str("import SwiftUI\n");
    out.push_str("public typealias PaintgunColor = Color\n");
    out.push_str("@inline(__always) private func paintgunColor(red: Double, green: Double, blue: Double, opacity: Double) -> PaintgunColor {\n");
    out.push_str("  Color(.sRGB, red: red, green: green, blue: blue, opacity: opacity)\n");
    out.push_str("}\n");
    out.push_str("#else\n");
    out.push_str("import Foundation\n");
    out.push_str("public struct PaintgunColor: Equatable {\n");
    out.push_str("  public let red: Double\n");
    out.push_str("  public let green: Double\n");
    out.push_str("  public let blue: Double\n");
    out.push_str("  public let opacity: Double\n");
    out.push_str("  public init(red: Double, green: Double, blue: Double, opacity: Double) {\n");
    out.push_str("    self.red = red\n");
    out.push_str("    self.green = green\n");
    out.push_str("    self.blue = blue\n");
    out.push_str("    self.opacity = opacity\n");
    out.push_str("  }\n");
    out.push_str("}\n");
    out.push_str("@inline(__always) private func paintgunColor(red: Double, green: Double, blue: Double, opacity: Double) -> PaintgunColor {\n");
    out.push_str("  PaintgunColor(red: red, green: green, blue: blue, opacity: opacity)\n");
    out.push_str("}\n");
    out.push_str("#endif\n\n");
    out.push_str("public enum PaintgunEmitterAPI {\n");
    out.push_str(&format!(
        "  public static let swiftVersion = \"{}\"\n",
        SWIFT_EMITTER_API_VERSION
    ));
    out.push_str("}\n\n");
    out.push_str("public enum PaintgunTokenValue {\n");
    out.push_str("  case color(PaintgunColor)\n");
    out.push_str("  case dimension(Double, unit: String)\n");
    out.push_str("  case duration(Double, unit: String)\n");
    out.push_str("  case number(Double)\n");
    out.push_str("  case string(String)\n");
    out.push_str("  case rawJson(String)\n");
    out.push_str("}\n\n");
    out.push_str("public struct PaintgunTokens {\n");
    out.push_str("  public static let values: [String: [String: PaintgunTokenValue]] = [\n");

    let mut contexts: Vec<(String, Input)> = enumerate_full_inputs(axes)
        .into_iter()
        .map(|i| (stable_context_key(&i), i))
        .collect();
    contexts.sort_by(|(a, _), (b, _)| a.cmp(b));

    for (ck, input) in contexts {
        let mut tokens_sorted = tokens_for_context(&input);
        tokens_sorted.sort_by(|a, b| a.path.cmp(&b.path));

        out.push_str(&format!("    \"{}\": [\n", escape_swift_string(&ck)));
        for t in tokens_sorted {
            let v = normalize_value(policy, t.ty, &t.value);
            let rendered = emit_value(&emitter, t.ty, &v, &t.path);
            out.push_str(&format!(
                "      \"{}\": {},\n",
                escape_swift_string(&t.path),
                rendered
            ));
        }
        out.push_str("    ],\n");
    }

    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

//──────────────────────────────────────────────────────────────────────────────
// Kotlin emitter
//──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct KotlinEmitter;

impl KotlinEmitter {
    fn color_expr(&self, v: &DtcgColor) -> Option<String> {
        let a = v
            .alpha
            .as_ref()
            .and_then(parse_num_lit)
            .unwrap_or(1.0)
            .clamp(0.0, 1.0);
        let a8 = (a * 255.0).round() as u8;

        if let Some(hex) = &v.hex {
            if let Some((r8, g8, b8)) = parse_hex_rgb(hex) {
                let argb: u32 =
                    ((a8 as u32) << 24) | ((r8 as u32) << 16) | ((g8 as u32) << 8) | (b8 as u32);
                return Some(format!("PaintgunColor(0x{:08X}u)", argb));
            }
        }

        // Support numeric component colors.
        let mut comps: [f64; 3] = [0.0, 0.0, 0.0];
        for (i, c) in v.components.iter().enumerate() {
            match c {
                ColorComponent::Num(n) => comps[i] = parse_num_lit(n)?,
                ColorComponent::None(_) => return None,
            }
        }
        let r8 = (comps[0].clamp(0.0, 1.0) * 255.0).round() as u8;
        let g8 = (comps[1].clamp(0.0, 1.0) * 255.0).round() as u8;
        let b8 = (comps[2].clamp(0.0, 1.0) * 255.0).round() as u8;
        let argb: u32 =
            ((a8 as u32) << 24) | ((r8 as u32) << 16) | ((g8 as u32) << 8) | (b8 as u32);
        return Some(format!("PaintgunColor(0x{:08X}u)", argb));

        #[allow(unreachable_code)]
        None
    }
}

impl Emitter for KotlinEmitter {
    type Output = String;

    fn color(&self, v: &DtcgColor, _path: &str) -> Self::Output {
        match self.color_expr(v) {
            Some(expr) => format!("TokenValue.ColorVal({expr})"),
            None => format!(
                "TokenValue.RawJson(\"{}\")",
                escape_kotlin_string(&DtcgValue::Color(v.clone()).to_canonical_json_string())
            ),
        }
    }

    fn dimension(&self, v: &DtcgDimension, _path: &str) -> Self::Output {
        let unit = match v.unit {
            paintgun_dtcg::DimensionUnit::Px => "px",
            paintgun_dtcg::DimensionUnit::Rem => "rem",
        };
        format!(
            "TokenValue.DimensionVal({value}, \"{unit}\")",
            value = kotlin_double_expr(&v.value.0)
        )
    }

    fn duration(&self, v: &DtcgDuration, _path: &str) -> Self::Output {
        let unit = match v.unit {
            paintgun_dtcg::DurationUnit::Ms => "ms",
            paintgun_dtcg::DurationUnit::S => "s",
        };
        format!(
            "TokenValue.DurationVal({value}, \"{unit}\")",
            value = kotlin_double_expr(&v.value.0)
        )
    }

    fn number(&self, v: &NumLit, _path: &str) -> Self::Output {
        format!("TokenValue.NumberVal({})", kotlin_double_expr(&v.0))
    }

    fn string(&self, v: &str, _path: &str) -> Self::Output {
        format!("TokenValue.StringVal(\"{}\")", escape_kotlin_string(v))
    }

    fn fallback(&self, v: &DtcgValue, _ty: DtcgType, _path: &str) -> Self::Output {
        format!(
            "TokenValue.RawJson(\"{}\")",
            escape_kotlin_string(&v.to_canonical_json_string())
        )
    }
}

pub fn emit_store_kotlin_with_lookup<Lookup>(
    axes: &BTreeMap<String, Vec<String>>,
    policy: &Policy,
    mut tokens_for_context: Lookup,
) -> String
where
    Lookup: FnMut(&Input) -> Vec<EmissionToken>,
{
    let emitter = KotlinEmitter::default();
    let mut out = String::new();
    out.push_str("// Generated by Paintgun\n");
    out.push_str(&format!(
        "// Native API version: {}\n",
        ANDROID_COMPOSE_EMITTER_API_VERSION
    ));
    out.push_str("package paintgun\n\n");
    out.push_str(&format!(
        "const val PAINTGUN_EMITTER_API_VERSION: String = \"{}\"\n\n",
        ANDROID_COMPOSE_EMITTER_API_VERSION
    ));
    out.push_str("data class PaintgunColor(val argb: UInt)\n\n");
    out.push_str("sealed class TokenValue {\n");
    out.push_str("  data class ColorVal(val value: PaintgunColor) : TokenValue()\n");
    out.push_str("  data class DimensionVal(val value: Double, val unit: String) : TokenValue()\n");
    out.push_str("  data class DurationVal(val value: Double, val unit: String) : TokenValue()\n");
    out.push_str("  data class NumberVal(val value: Double) : TokenValue()\n");
    out.push_str("  data class StringVal(val value: String) : TokenValue()\n");
    out.push_str("  data class RawJson(val value: String) : TokenValue()\n");
    out.push_str("}\n\n");
    out.push_str("object PaintgunTokens {\n");
    out.push_str("  val values: Map<String, Map<String, TokenValue>> = mapOf(\n");

    let mut contexts: Vec<(String, Input)> = enumerate_full_inputs(axes)
        .into_iter()
        .map(|i| (stable_context_key(&i), i))
        .collect();
    contexts.sort_by(|(a, _), (b, _)| a.cmp(b));

    for (ck, input) in contexts {
        let mut tokens_sorted = tokens_for_context(&input);
        tokens_sorted.sort_by(|a, b| a.path.cmp(&b.path));

        out.push_str(&format!(
            "    \"{}\" to mapOf(\n",
            escape_kotlin_string(&ck)
        ));
        for t in tokens_sorted {
            let v = normalize_value(policy, t.ty, &t.value);
            let rendered = emit_value(&emitter, t.ty, &v, &t.path);
            out.push_str(&format!(
                "      \"{}\" to {},\n",
                escape_kotlin_string(&t.path),
                rendered
            ));
        }
        out.push_str("    ),\n");
    }

    out.push_str("  )\n");
    out.push_str("}\n");
    out
}

fn write_utf8(path: &Path, content: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content.as_bytes())
}

fn swift_package_manifest() -> String {
    let mut out = String::new();
    out.push_str("// swift-tools-version: 5.9\n");
    out.push_str("import PackageDescription\n\n");
    out.push_str("let package = Package(\n");
    out.push_str("  name: \"PaintgunTokens\",\n");
    out.push_str("  products: [\n");
    out.push_str("    .library(name: \"PaintgunTokens\", targets: [\"PaintgunTokens\"])\n");
    out.push_str("  ],\n");
    out.push_str("  targets: [\n");
    out.push_str("    .target(name: \"PaintgunTokens\"),\n");
    out.push_str(
        "    .testTarget(name: \"PaintgunTokensTests\", dependencies: [\"PaintgunTokens\"])\n",
    );
    out.push_str("  ]\n");
    out.push_str(")\n");
    out
}

fn swift_test_file() -> String {
    let mut out = String::new();
    out.push_str("import XCTest\n");
    out.push_str("@testable import PaintgunTokens\n\n");
    out.push_str("final class PaintgunTokensTests: XCTestCase {\n");
    out.push_str("  func testValuesMapExists() {\n");
    out.push_str("    XCTAssertFalse(PaintgunTokens.values.isEmpty)\n");
    out.push_str("  }\n");
    out.push_str("}\n");
    out
}

pub fn emit_swift_package_scaffold(out_dir: &Path, swift_source: &str) -> std::io::Result<()> {
    let root = out_dir.join("swift");
    write_utf8(&root.join("Package.swift"), &swift_package_manifest())?;
    write_utf8(
        &root.join("Sources/PaintgunTokens/PaintgunTokens.swift"),
        swift_source,
    )?;
    write_utf8(
        &root.join("Tests/PaintgunTokensTests/PaintgunTokensTests.swift"),
        &swift_test_file(),
    )?;
    Ok(())
}

fn kotlin_settings_gradle() -> String {
    "rootProject.name = \"paintgun-android-compose-tokens\"\n".to_string()
}

fn kotlin_build_gradle() -> String {
    let mut out = String::new();
    out.push_str("plugins {\n");
    out.push_str("  kotlin(\"jvm\") version \"1.9.24\"\n");
    out.push_str("}\n\n");
    out.push_str("repositories {\n");
    out.push_str("  mavenCentral()\n");
    out.push_str("}\n\n");
    out.push_str("dependencies {\n");
    out.push_str("  testImplementation(kotlin(\"test\"))\n");
    out.push_str("}\n\n");
    out.push_str("tasks.test {\n");
    out.push_str("  useJUnitPlatform()\n");
    out.push_str("}\n\n");
    out.push_str("kotlin {\n");
    out.push_str("  jvmToolchain(17)\n");
    out.push_str("}\n");
    out
}

fn kotlin_test_file() -> String {
    let mut out = String::new();
    out.push_str("package paintgun\n\n");
    out.push_str("import kotlin.test.Test\n");
    out.push_str("import kotlin.test.assertTrue\n\n");
    out.push_str("class PaintgunTokensSmokeTest {\n");
    out.push_str("  @Test\n");
    out.push_str("  fun valuesMapExists() {\n");
    out.push_str("    assertTrue(PaintgunTokens.values.isNotEmpty())\n");
    out.push_str("  }\n");
    out.push_str("}\n");
    out
}

pub fn emit_kotlin_module_scaffold(out_dir: &Path, kotlin_source: &str) -> std::io::Result<()> {
    let root = out_dir.join("android");
    write_utf8(&root.join("settings.gradle.kts"), &kotlin_settings_gradle())?;
    write_utf8(&root.join("build.gradle.kts"), &kotlin_build_gradle())?;
    write_utf8(
        &root.join("src/main/kotlin/paintgun/PaintgunTokens.kt"),
        kotlin_source,
    )?;
    write_utf8(
        &root.join("src/test/kotlin/paintgun/PaintgunTokensSmokeTest.kt"),
        &kotlin_test_file(),
    )?;
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
struct WebTokensContextExport {
    context: String,
    input: Input,
    tokens: Vec<WebTokensTokenExport>,
}

#[derive(Clone, Debug, Serialize)]
struct WebTokensTokenExport {
    path: String,
    #[serde(rename = "type")]
    ty: String,
    value: DtcgValue,
}

#[derive(Clone, Debug, Serialize)]
struct WebTokensValueExport {
    #[serde(rename = "type")]
    ty: String,
    value: DtcgValue,
}

fn append_ts_const(out: &mut String, name: &str, value: &impl Serialize) {
    out.push_str("export const ");
    out.push_str(name);
    out.push_str(" = ");
    out.push_str(
        &serde_json::to_string_pretty(value).expect("web token package data should serialize"),
    );
    out.push_str(" as const;\n\n");
}

pub fn emit_store_web_tokens_ts_with_lookup<Lookup>(
    axes: &BTreeMap<String, Vec<String>>,
    policy: &Policy,
    mut tokens_for_context: Lookup,
) -> String
where
    Lookup: FnMut(&Input) -> Vec<EmissionToken>,
{
    let mut contexts: Vec<(String, Input)> = enumerate_full_inputs(axes)
        .into_iter()
        .map(|input| (stable_context_key(&input), input))
        .collect();
    contexts.sort_by(|(lhs, _), (rhs, _)| lhs.cmp(rhs));

    let mut context_exports = Vec::new();
    let mut values_by_context: BTreeMap<String, BTreeMap<String, WebTokensValueExport>> =
        BTreeMap::new();

    for (context_key, input) in contexts {
        let mut tokens_sorted = tokens_for_context(&input);
        tokens_sorted.sort_by(|lhs, rhs| lhs.path.cmp(&rhs.path));

        let mut token_exports = Vec::new();
        let mut context_values = BTreeMap::new();
        for token in tokens_sorted {
            let normalized = normalize_value(policy, token.ty, &token.value);
            let ty = token.ty.to_string();
            context_values.insert(
                token.path.clone(),
                WebTokensValueExport {
                    ty: ty.clone(),
                    value: normalized.clone(),
                },
            );
            token_exports.push(WebTokensTokenExport {
                path: token.path,
                ty,
                value: normalized,
            });
        }

        context_exports.push(WebTokensContextExport {
            context: context_key.clone(),
            input,
            tokens: token_exports,
        });
        values_by_context.insert(context_key, context_values);
    }

    let mut out = String::new();
    out.push_str("// Generated by Paintgun\n");
    out.push_str(&format!(
        "export const PAINTGUN_WEB_TOKENS_API_VERSION = \"{}\" as const;\n\n",
        WEB_TOKENS_TS_API_VERSION
    ));
    out.push_str("export const spec = \"DTCG 2025.10\" as const;\n\n");
    append_ts_const(&mut out, "axes", axes);
    append_ts_const(&mut out, "contexts", &context_exports);
    append_ts_const(&mut out, "valuesByContext", &values_by_context);
    out.push_str("export type PaintTokenContext = keyof typeof valuesByContext;\n");
    out.push_str(
        "export type PaintTokenMap<C extends PaintTokenContext = PaintTokenContext> = (typeof valuesByContext)[C];\n",
    );
    out.push_str(
        "export type PaintTokenPath<C extends PaintTokenContext = PaintTokenContext> = keyof PaintTokenMap<C>;\n",
    );
    out.push_str(
        "export type PaintTokenValue<C extends PaintTokenContext = PaintTokenContext> = PaintTokenMap<C>[PaintTokenPath<C>];\n",
    );
    out
}

fn web_tokens_package_manifest() -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"name\": \"paintgun-web-tokens\",\n");
    out.push_str("  \"private\": true,\n");
    out.push_str("  \"type\": \"module\",\n");
    out.push_str("  \"exports\": {\n");
    out.push_str("    \".\": \"./src/index.ts\"\n");
    out.push_str("  },\n");
    out.push_str("  \"types\": \"./src/index.ts\"\n");
    out.push_str("}\n");
    out
}

fn web_tokens_tsconfig() -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"compilerOptions\": {\n");
    out.push_str("    \"target\": \"ES2022\",\n");
    out.push_str("    \"module\": \"ES2022\",\n");
    out.push_str("    \"moduleResolution\": \"Bundler\",\n");
    out.push_str("    \"strict\": true,\n");
    out.push_str("    \"declaration\": true,\n");
    out.push_str("    \"noEmit\": true\n");
    out.push_str("  },\n");
    out.push_str("  \"include\": [\"src/**/*.ts\"]\n");
    out.push_str("}\n");
    out
}

fn web_tokens_test_file() -> String {
    let mut out = String::new();
    out.push_str("import { contexts, valuesByContext } from \"./index\";\n\n");
    out.push_str("const firstContext = contexts[0]?.context;\n");
    out.push_str("if (!firstContext) {\n");
    out.push_str("  throw new Error(\"expected at least one emitted token context\");\n");
    out.push_str("}\n");
    out.push_str("const tokens = valuesByContext[firstContext];\n");
    out.push_str("if (!tokens || Object.keys(tokens).length === 0) {\n");
    out.push_str("  throw new Error(\"expected emitted tokens for first context\");\n");
    out.push_str("}\n");
    out
}

pub fn emit_web_tokens_package_scaffold(
    out_dir: &Path,
    web_tokens_source: &str,
) -> std::io::Result<()> {
    let root = out_dir.join("web");
    write_utf8(&root.join("package.json"), &web_tokens_package_manifest())?;
    write_utf8(&root.join("tsconfig.json"), &web_tokens_tsconfig())?;
    write_utf8(&root.join("src/index.ts"), web_tokens_source)?;
    write_utf8(&root.join("src/index.test.ts"), &web_tokens_test_file())?;
    Ok(())
}

//──────────────────────────────────────────────────────────────────────────────
// TypeScript declarations for component contracts
//──────────────────────────────────────────────────────────────────────────────

fn pascal_case(s: &str) -> String {
    let mut out = String::new();
    for seg in s.split(|c: char| !c.is_ascii_alphanumeric()) {
        if seg.is_empty() {
            continue;
        }
        let mut chars = seg.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            for c in chars {
                out.push(c.to_ascii_lowercase());
            }
        }
    }
    out
}

/// Emit a `tokens.d.ts` file matching the component-contracts schema.
pub fn emit_tokens_d_ts(contracts: &[Contract]) -> String {
    use std::collections::BTreeSet;

    let mut out = String::new();
    out.push_str("// Generated by Paintgun\n\n");

    // Stable order by component name.
    let mut cs = contracts.to_vec();
    cs.sort_by(|a, b| a.component.cmp(&b.component));

    for c in &cs {
        let iface = format!("{}Tokens", pascal_case(&c.component));
        out.push_str(&format!("export interface {iface} {{\n"));

        let mut props: BTreeSet<String> = BTreeSet::new();
        for def in c.slots.values() {
            props.insert(def.property.clone());
        }
        for p in props {
            out.push_str(&format!(
                "  readonly \"{}\": string\n",
                p.replace('"', "\\\"")
            ));
        }
        out.push_str("}\n\n");
    }

    out.push_str("export type TokensByComponent = {\n");
    for c in &cs {
        let iface = format!("{}Tokens", pascal_case(&c.component));
        out.push_str(&format!(
            "  readonly \"{}\": {iface}\n",
            c.component.replace('"', "\\\"")
        ));
    }
    out.push_str("}\n");

    out
}

#[cfg(test)]
mod tests {
    use super::{emit_value, CssEmitter};
    use paintgun_dtcg::{ColorComponent, ColorSpace, DtcgColor, DtcgType, DtcgValue, NumLit};
    use paintgun_policy::CssColorPolicy;

    fn sample_color(color_space: ColorSpace) -> DtcgColor {
        DtcgColor {
            color_space,
            components: [
                ColorComponent::Num(NumLit("0.97".to_string())),
                ColorComponent::Num(NumLit("0.005".to_string())),
                ColorComponent::Num(NumLit("250".to_string())),
            ],
            alpha: None,
            hex: Some("#f5f6f8".to_string()),
        }
    }

    #[test]
    fn css_emitter_uses_direct_functions_for_lab_like_spaces() {
        let emitter = CssEmitter {
            color_policy: CssColorPolicy::PreserveSpace,
        };

        for (space, expected) in [
            (ColorSpace::Lab, "lab(0.97 0.005 250)"),
            (ColorSpace::Lch, "lch(0.97 0.005 250)"),
            (ColorSpace::Oklab, "oklab(0.97 0.005 250)"),
            (ColorSpace::Oklch, "oklch(0.97 0.005 250)"),
        ] {
            let color = sample_color(space);
            let rendered = emit_value(
                &emitter,
                DtcgType::Color,
                &DtcgValue::Color(color),
                "color.test",
            );
            assert_eq!(rendered, expected);
        }
    }

    #[test]
    fn css_emitter_keeps_color_function_for_predefined_color_spaces() {
        let emitter = CssEmitter {
            color_policy: CssColorPolicy::PreserveSpace,
        };

        for (space, expected) in [
            (ColorSpace::Srgb, "color(srgb 0.97 0.005 250)"),
            (ColorSpace::SrgbLinear, "color(srgb-linear 0.97 0.005 250)"),
            (ColorSpace::DisplayP3, "color(display-p3 0.97 0.005 250)"),
            (ColorSpace::XyzD65, "color(xyz-d65 0.97 0.005 250)"),
        ] {
            let color = sample_color(space);
            let rendered = emit_value(
                &emitter,
                DtcgType::Color,
                &DtcgValue::Color(color),
                "color.test",
            );
            assert_eq!(rendered, expected);
        }
    }

    #[test]
    fn css_emitter_prefers_hex_when_policy_requests_it() {
        let emitter = CssEmitter {
            color_policy: CssColorPolicy::PreferHexIfPresent,
        };
        let color = sample_color(ColorSpace::Oklch);
        let rendered = emit_value(
            &emitter,
            DtcgType::Color,
            &DtcgValue::Color(color),
            "color.test",
        );
        assert_eq!(rendered, "#f5f6f8");
    }
}
