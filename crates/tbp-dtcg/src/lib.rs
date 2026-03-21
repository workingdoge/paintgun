use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

//──────────────────────────────────────────────────────────────────────────────
// Raw numeric literal (preserve JSON lexeme where possible)
//──────────────────────────────────────────────────────────────────────────────

/// A numeric literal preserved as text.
///
/// We accept either a JSON number (`0.70`) or a JSON string (`"0.70"`).
/// In both cases we store the unquoted lexeme (`0.70`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct NumLit(pub String);

impl<'de> Deserialize<'de> for NumLit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        let s = raw.get();
        // If it was a JSON string, RawValue includes quotes.
        if let Some(stripped) = s.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
            Ok(NumLit(stripped.to_string()))
        } else {
            Ok(NumLit(s.to_string()))
        }
    }
}

//──────────────────────────────────────────────────────────────────────────────
// A JSON-ish AST that preserves numbers as NumLit
//──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum JValue {
    Null(()),
    Bool(bool),
    Number(NumLit),
    String(String),
    Array(Vec<JValue>),
    Object(BTreeMap<String, JValue>),
}

impl JValue {
    fn from_serde(v: serde_json::Value) -> JValue {
        match v {
            serde_json::Value::Null => JValue::Null(()),
            serde_json::Value::Bool(b) => JValue::Bool(b),
            serde_json::Value::Number(n) => JValue::Number(NumLit(n.to_string())),
            serde_json::Value::String(s) => JValue::String(s),
            serde_json::Value::Array(xs) => {
                JValue::Array(xs.into_iter().map(JValue::from_serde).collect())
            }
            serde_json::Value::Object(m) => {
                let mut out = BTreeMap::new();
                for (k, v) in m {
                    out.insert(k, JValue::from_serde(v));
                }
                JValue::Object(out)
            }
        }
    }
}

impl<'de> Deserialize<'de> for JValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = serde_json::Value::deserialize(deserializer)?;
        Ok(JValue::from_serde(v))
    }
}

impl JValue {
    pub fn as_object(&self) -> Option<&BTreeMap<String, JValue>> {
        match self {
            JValue::Object(m) => Some(m),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&JValue> {
        self.as_object()?.get(key)
    }

    pub fn is_object(&self) -> bool {
        matches!(self, JValue::Object(_))
    }

    pub fn is_array(&self) -> bool {
        matches!(self, JValue::Array(_))
    }

    pub fn is_string(&self) -> bool {
        matches!(self, JValue::String(_))
    }

    pub fn is_number(&self) -> bool {
        matches!(self, JValue::Number(_))
    }
}

//──────────────────────────────────────────────────────────────────────────────
// DTCG types (2025.10)
//──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DtcgType {
    Color,
    Dimension,
    Duration,
    FontFamily,
    FontWeight,
    Number,
    StrokeStyle,
    Border,
    Transition,
    Shadow,
    Gradient,
    Typography,
    CubicBezier,
}

//──────────────────────────────────────────────────────────────────────────────
// Typed value wrapper (type + structured value)
//──────────────────────────────────────────────────────────────────────────────

/// A DTCG value paired with its declared `$type`.
///
/// This matters for analysis and composability:
/// two values with the same JSON representation can still be semantically
/// different if their types differ (e.g. `number` vs `fontWeight`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedValue {
    pub ty: DtcgType,
    pub value: DtcgValue,
}

impl TypedValue {
    /// Canonical JSON for hashing / certificates.
    ///
    /// We keep it explicit and stable rather than relying on serde derives.
    pub fn to_canonical_json_string(&self) -> String {
        // NOTE: this intentionally returns a *JSON object string*, not a JSON string literal.
        // Keep it stable and explicit.
        format!(
            r#"{{"type":"{}","value":{}}}"#,
            self.ty,
            self.value.to_canonical_json_string()
        )
    }
}

impl fmt::Display for DtcgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DtcgType::*;
        let s = match self {
            Color => "color",
            Dimension => "dimension",
            Duration => "duration",
            FontFamily => "fontFamily",
            FontWeight => "fontWeight",
            Number => "number",
            StrokeStyle => "strokeStyle",
            Border => "border",
            Transition => "transition",
            Shadow => "shadow",
            Gradient => "gradient",
            Typography => "typography",
            CubicBezier => "cubicBezier",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for DtcgType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use DtcgType::*;
        match s {
            "color" => Ok(Color),
            "dimension" => Ok(Dimension),
            "duration" => Ok(Duration),
            "fontFamily" => Ok(FontFamily),
            "fontWeight" => Ok(FontWeight),
            "number" => Ok(Number),
            "strokeStyle" => Ok(StrokeStyle),
            "border" => Ok(Border),
            "transition" => Ok(Transition),
            "shadow" => Ok(Shadow),
            "gradient" => Ok(Gradient),
            "typography" => Ok(Typography),
            "cubicBezier" => Ok(CubicBezier),
            other => Err(format!("unknown DTCG type: {other}")),
        }
    }
}

//──────────────────────────────────────────────────────────────────────────────
// Structured value types
//──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ColorSpace {
    Srgb,
    SrgbLinear,
    Hsl,
    Hwb,
    Lab,
    Lch,
    Oklab,
    Oklch,
    DisplayP3,
    A98Rgb,
    ProphotoRgb,
    Rec2020,
    XyzD65,
    XyzD50,
}

impl ColorSpace {
    pub fn as_css_ident(&self) -> &'static str {
        use ColorSpace::*;
        match self {
            Srgb => "srgb",
            SrgbLinear => "srgb-linear",
            Hsl => "hsl",
            Hwb => "hwb",
            Lab => "lab",
            Lch => "lch",
            Oklab => "oklab",
            Oklch => "oklch",
            DisplayP3 => "display-p3",
            A98Rgb => "a98-rgb",
            ProphotoRgb => "prophoto-rgb",
            Rec2020 => "rec2020",
            XyzD65 => "xyz-d65",
            XyzD50 => "xyz-d50",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ColorComponent {
    /// The literal string "none".
    None(String),
    /// Numeric component preserved as text.
    Num(NumLit),
}

impl ColorComponent {
    pub fn is_none(&self) -> bool {
        matches!(self, ColorComponent::None(s) if s == "none")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DtcgColor {
    #[serde(rename = "colorSpace")]
    pub color_space: ColorSpace,
    pub components: [ColorComponent; 3],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpha: Option<NumLit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DimensionUnit {
    Px,
    Rem,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DtcgDimension {
    pub value: NumLit,
    pub unit: DimensionUnit,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DurationUnit {
    Ms,
    S,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DtcgDuration {
    pub value: NumLit,
    pub unit: DurationUnit,
}

//──────────────────────────────────────────────────────────────────────────────
// Universal DTCG value (typed normal form for analysis + emission)
//──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DtcgValue {
    Null(()),
    Bool(bool),
    Num(NumLit),
    Str(String),
    Array(Vec<DtcgValue>),
    Object(BTreeMap<String, DtcgValue>),

    // Canonical typed variants (post-validation)
    Color(DtcgColor),
    Dimension(DtcgDimension),
    Duration(DtcgDuration),
}

impl DtcgValue {
    /// Convert a preserved JSON AST into a DTCG value tree.
    pub fn from_jvalue(v: &JValue) -> DtcgValue {
        match v {
            JValue::Null(x) => DtcgValue::Null(*x),
            JValue::Bool(b) => DtcgValue::Bool(*b),
            JValue::Number(n) => DtcgValue::Num(n.clone()),
            JValue::String(s) => DtcgValue::Str(s.clone()),
            JValue::Array(xs) => DtcgValue::Array(xs.iter().map(DtcgValue::from_jvalue).collect()),
            JValue::Object(m) => {
                let mut out = BTreeMap::new();
                for (k, vv) in m {
                    out.insert(k.clone(), DtcgValue::from_jvalue(vv));
                }
                DtcgValue::Object(out)
            }
        }
    }

    /// Pretty-ish JSON for reports.
    pub fn to_canonical_json_string(&self) -> String {
        // Because we use BTreeMap, serde_json serialization is stable.
        serde_json::to_string(self).unwrap_or_else(|_| "null".to_string())
    }
}
