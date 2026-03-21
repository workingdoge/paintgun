use serde::{Deserialize, Serialize};

use crate::dtcg::{DtcgType, DtcgValue};

/// Provenance metadata for a token value.
///
/// This is intentionally *lightweight* but actionable:
/// - which logical resolver source it came from (set/modifier)
/// - pack identity (when composing from vendored packs)
/// - which file carried the explicit `$value` (stable relative path + hash)
/// - an approximate JSON Pointer derived from the token path
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenProvenance {
    /// Logical source identifier (e.g. "base" or "modifier:theme/dark").
    #[serde(rename = "sourceId")]
    pub source_id: String,

    /// Layer identifier used in resolution ordering (e.g. `set:base`, `modifier:theme/dark`).
    #[serde(rename = "resolutionLayerId", skip_serializing_if = "Option::is_none")]
    pub resolution_layer_id: Option<String>,

    /// Rank in resolver `resolutionOrder`, when applicable (0-based).
    #[serde(rename = "resolutionRank", skip_serializing_if = "Option::is_none")]
    pub resolution_rank: Option<u64>,

    /// Optional pack id, when sources were vendored under `vendor/<pack>/...`.
    #[serde(rename = "packId", skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,

    /// Optional pack version (best-effort parse from vendored path naming).
    #[serde(rename = "packVersion", skip_serializing_if = "Option::is_none")]
    pub pack_version: Option<String>,

    /// Optional pack content hash (best-effort parse from vendored path naming).
    #[serde(rename = "packHash", skip_serializing_if = "Option::is_none")]
    pub pack_hash: Option<String>,

    /// Stable relative path to the source file carrying the explicit value.
    #[serde(rename = "filePath", skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,

    /// Hash of the source file bytes.
    #[serde(rename = "fileHash", skip_serializing_if = "Option::is_none")]
    pub file_hash: Option<String>,

    /// Approximate JSON pointer to the `$value` location.
    ///
    /// We derive this from the token path, so it is stable even if the file
    /// contains additional metadata.
    #[serde(rename = "jsonPointer", skip_serializing_if = "Option::is_none")]
    pub json_pointer: Option<String>,
}

/// A typed token value paired with provenance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthoredValue {
    #[serde(rename = "type")]
    pub ty: DtcgType,
    pub value: DtcgValue,
    pub provenance: TokenProvenance,
}

impl AuthoredValue {
    pub fn new(ty: DtcgType, value: DtcgValue, provenance: TokenProvenance) -> Self {
        AuthoredValue {
            ty,
            value,
            provenance,
        }
    }
}
