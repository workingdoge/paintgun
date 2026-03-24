use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use paintgun_dtcg::{
    ColorComponent, DimensionUnit, DtcgColor, DtcgDimension, DtcgDuration, DtcgType, DtcgValue,
    DurationUnit, NumLit,
};

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Policy controls *normalization* of the free algebra (Res) before emission.
///
/// Intuition:
/// - Kan/BC analysis runs on the *raw* resolved values (authored intent).
/// - Emission targets may want a normalized representation (rounding, unit preferences).
///
/// This is the "policy as endomorphism" step: normalize_P : Res → Res.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// If set, round all numeric literals to this many decimal places during normalization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub float_precision: Option<u8>,

    /// Dimension normalization rules.
    #[serde(default)]
    pub dimension: DimensionPolicy,

    /// Duration normalization rules.
    #[serde(default)]
    pub duration: DurationPolicy,

    /// Color normalization rules.
    #[serde(default)]
    pub color: ColorPolicy,

    /// CSS emission preferences (does not affect analysis).
    #[serde(default)]
    pub css_color: CssColorPolicy,

    /// Optional KCIR profile expectations for verification-time policy checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kcir: Option<KcirPolicy>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            float_precision: None,
            dimension: DimensionPolicy::default(),
            duration: DurationPolicy::default(),
            color: ColorPolicy::default(),
            css_color: CssColorPolicy::default(),
            kcir: None,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KcirPolicy {
    #[serde(rename = "schemeId", skip_serializing_if = "Option::is_none")]
    pub scheme_id: Option<String>,
    #[serde(rename = "paramsHash", skip_serializing_if = "Option::is_none")]
    pub params_hash: Option<String>,
    #[serde(rename = "wireFormatId", skip_serializing_if = "Option::is_none")]
    pub wire_format_id: Option<String>,
    #[serde(
        rename = "anchorRootCommitment",
        skip_serializing_if = "Option::is_none"
    )]
    pub anchor_root_commitment: Option<String>,
    #[serde(rename = "anchorTreeEpoch", skip_serializing_if = "Option::is_none")]
    pub anchor_tree_epoch: Option<u64>,
}

/// CSS-specific emission strategy for colors.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CssColorPolicy {
    /// Emit the authored color space syntax (`color(space …)` / `hsl(...)` / `hwb(...)`).
    PreserveSpace,
    /// If the DTCG color has a `hex` field, emit it as `#RRGGBB`.
    PreferHexIfPresent,
}

impl Default for CssColorPolicy {
    fn default() -> Self {
        CssColorPolicy::PreserveSpace
    }
}

impl Policy {
    /// A stable identifier for the policy, suitable for embedding in manifests.
    pub fn id(&self) -> String {
        // Struct field order is stable; we rely on serde_json's deterministic struct encoding.
        // (If you later add maps here, prefer BTreeMap for stable ordering.)
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        format!("sha256:{}", sha256_hex(&bytes))
    }

    /// Convenience wrapper: normalize a value in the resolved IR.
    pub fn normalize(&self, ty: DtcgType, value: &DtcgValue) -> DtcgValue {
        normalize_value(self, ty, value)
    }
}

/// Return a stable digest for embedding in certificates/manifests.
pub fn policy_digest(policy: &Policy) -> String {
    policy.id()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DimensionPolicy {
    /// If set, prefer this output unit. Conversion only happens when possible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefer: Option<DimensionUnit>,

    /// Base for converting `rem` to `px` (px per 1rem).
    /// Only used when `prefer = px` and the input is in `rem`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rem_base_px: Option<f64>,
}

impl Default for DimensionPolicy {
    fn default() -> Self {
        Self {
            prefer: None,
            rem_base_px: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurationPolicy {
    /// If set, prefer this output unit. Conversion happens when possible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefer: Option<DurationUnit>,
}

impl Default for DurationPolicy {
    fn default() -> Self {
        Self { prefer: None }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColorPolicy {
    /// Drop the optional `hex` field during normalization.
    #[serde(default)]
    pub drop_hex: bool,
}

impl Default for ColorPolicy {
    fn default() -> Self {
        Self { drop_hex: false }
    }
}

//──────────────────────────────────────────────────────────────────────────────
// Normalization (endomorphism on Res)
//──────────────────────────────────────────────────────────────────────────────

fn parse_f64(n: &NumLit) -> Option<f64> {
    n.0.parse::<f64>().ok()
}

fn format_f64(x: f64, precision: u8) -> String {
    // Fixed precision; strip trailing zeros and trailing dot.
    let s = format!("{x:.p$}", p = precision as usize);
    let s = s.trim_end_matches('0').trim_end_matches('.').to_string();
    if s.is_empty() {
        "0".to_string()
    } else {
        s
    }
}

fn round_num(policy: &Policy, n: &NumLit) -> NumLit {
    match policy.float_precision {
        None => n.clone(),
        Some(p) => match parse_f64(n) {
            None => n.clone(),
            Some(x) => NumLit(format_f64(x, p)),
        },
    }
}

fn normalize_color(policy: &Policy, c: &DtcgColor) -> DtcgColor {
    let mut out = c.clone();
    for comp in &mut out.components {
        if let ColorComponent::Num(n) = comp {
            *n = round_num(policy, n);
        }
    }
    if let Some(a) = &out.alpha {
        out.alpha = Some(round_num(policy, a));
    }
    if policy.color.drop_hex {
        out.hex = None;
    }
    out
}

fn normalize_dimension(policy: &Policy, d: &DtcgDimension) -> DtcgDimension {
    let mut out = d.clone();
    out.value = round_num(policy, &out.value);

    if let Some(prefer) = policy.dimension.prefer.as_ref() {
        match (&out.unit, prefer) {
            (DimensionUnit::Rem, DimensionUnit::Px) => {
                if let Some(base) = policy.dimension.rem_base_px {
                    if let Some(x) = parse_f64(&out.value) {
                        let px = x * base;
                        out.value = match policy.float_precision {
                            None => NumLit(px.to_string()),
                            Some(p) => NumLit(format_f64(px, p)),
                        };
                        out.unit = DimensionUnit::Px;
                    }
                }
            }
            _ => {}
        }
    }

    out
}

fn normalize_duration(policy: &Policy, d: &DtcgDuration) -> DtcgDuration {
    let mut out = d.clone();
    out.value = round_num(policy, &out.value);

    if let Some(prefer) = policy.duration.prefer.as_ref() {
        match (&out.unit, prefer) {
            (DurationUnit::S, DurationUnit::Ms) => {
                if let Some(x) = parse_f64(&out.value) {
                    let ms = x * 1000.0;
                    out.value = match policy.float_precision {
                        None => NumLit(ms.to_string()),
                        Some(p) => NumLit(format_f64(ms, p)),
                    };
                    out.unit = DurationUnit::Ms;
                }
            }
            (DurationUnit::Ms, DurationUnit::S) => {
                if let Some(x) = parse_f64(&out.value) {
                    let s = x / 1000.0;
                    out.value = match policy.float_precision {
                        None => NumLit(s.to_string()),
                        Some(p) => NumLit(format_f64(s, p)),
                    };
                    out.unit = DurationUnit::S;
                }
            }
            _ => {}
        }
    }

    out
}

/// Normalize a typed DTCG value according to `policy`.
///
/// This is *not* type validation; it assumes the value has already been canonicalized.
pub fn normalize_value(policy: &Policy, ty: DtcgType, value: &DtcgValue) -> DtcgValue {
    match (ty, value) {
        (DtcgType::Color, DtcgValue::Color(c)) => DtcgValue::Color(normalize_color(policy, c)),
        (DtcgType::Dimension, DtcgValue::Dimension(d)) => {
            DtcgValue::Dimension(normalize_dimension(policy, d))
        }
        (DtcgType::Duration, DtcgValue::Duration(d)) => {
            DtcgValue::Duration(normalize_duration(policy, d))
        }
        (DtcgType::Number, DtcgValue::Num(n)) => DtcgValue::Num(round_num(policy, n)),
        // For other types, recurse shallowly to normalize embedded numbers.
        (_, DtcgValue::Array(xs)) => {
            DtcgValue::Array(xs.iter().map(|v| normalize_value(policy, ty, v)).collect())
        }
        (_, DtcgValue::Object(m)) => {
            let mut out = std::collections::BTreeMap::new();
            for (k, v) in m {
                out.insert(k.clone(), normalize_value(policy, ty, v));
            }
            DtcgValue::Object(out)
        }
        _ => value.clone(),
    }
}
