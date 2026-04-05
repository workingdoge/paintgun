use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::util::sha256_bytes;

mod compat;

/// KCIR node payload used by v2 tests/fixtures.
///
/// This mirrors the fixed32 KCIR node wire shape but remains a v2-owned type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KcirNode {
    pub env_sig: [u8; 32],
    pub uid: [u8; 32],
    pub sort: u8,
    pub opcode: u8,
    pub out: [u8; 32],
    pub args: Vec<u8>,
    pub deps: Vec<[u8; 32]>,
}

impl KcirNode {
    pub fn encode(&self) -> Vec<u8> {
        compat::KernelNode::from(self).encode()
    }

    pub fn cert_id(&self) -> [u8; 32] {
        cert_id(&self.encode())
    }
}

impl From<compat::KernelNode> for KcirNode {
    fn from(value: compat::KernelNode) -> Self {
        Self {
            env_sig: value.env_sig,
            uid: value.uid,
            sort: value.sort,
            opcode: value.opcode,
            out: value.out,
            args: value.args,
            deps: value.deps,
        }
    }
}

impl From<&KcirNode> for compat::KernelNode {
    fn from(value: &KcirNode) -> Self {
        Self {
            env_sig: value.env_sig,
            uid: value.uid,
            sort: value.sort,
            opcode: value.opcode,
            out: value.out,
            args: value.args.clone(),
            deps: value.deps.clone(),
        }
    }
}

impl From<KcirNode> for compat::KernelNode {
    fn from(value: KcirNode) -> Self {
        Self::from(&value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PullCoverWitness {
    pub w_sig: [u8; 32],
    pub map_w_to_u: Vec<u32>,
    pub proj_ids: Vec<[u8; 32]>,
}

impl From<compat::KernelPullCoverWitness> for PullCoverWitness {
    fn from(value: compat::KernelPullCoverWitness) -> Self {
        Self {
            w_sig: value.w_sig,
            map_w_to_u: value.map_w_to_u,
            proj_ids: value.proj_ids,
        }
    }
}

impl From<&PullCoverWitness> for compat::KernelPullCoverWitness {
    fn from(value: &PullCoverWitness) -> Self {
        Self {
            w_sig: value.w_sig,
            map_w_to_u: value.map_w_to_u.clone(),
            proj_ids: value.proj_ids.clone(),
        }
    }
}

impl From<PullCoverWitness> for compat::KernelPullCoverWitness {
    fn from(value: PullCoverWitness) -> Self {
        Self::from(&value)
    }
}

/// Backend hooks used by v2 verification entrypoints.
pub trait KcirBackend {
    fn digest_node(&self, node_bytes: &[u8]) -> [u8; 32] {
        cert_id(node_bytes)
    }

    fn digest_obj_nf(&self, env_sig: &[u8; 32], uid: &[u8; 32], obj_bytes: &[u8]) -> [u8; 32] {
        h_obj(env_sig, uid, obj_bytes)
    }

    fn digest_mor_nf(&self, env_sig: &[u8; 32], uid: &[u8; 32], mor_bytes: &[u8]) -> [u8; 32] {
        h_mor(env_sig, uid, mor_bytes)
    }

    fn is_id_map(&self, _map_id: &[u8; 32]) -> bool {
        false
    }

    fn compose_maps(&self, _outer: &[u8; 32], _inner: &[u8; 32]) -> Option<[u8; 32]> {
        None
    }

    fn bc_square(&self, _push_id: &[u8; 32], _pull_id: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
        None
    }

    fn bc_allowed(&self, _pull_id: &[u8; 32], _push_id: &[u8; 32]) -> bool {
        false
    }

    fn has_bc_policy(&self) -> bool {
        false
    }

    fn validate_cover(&self, _cover_sig: &[u8; 32]) -> Option<bool> {
        None
    }

    fn cover_len(&self, _cover_sig: &[u8; 32]) -> Option<u32> {
        None
    }

    fn pull_cover(&self, _p_id: &[u8; 32], _u_sig: &[u8; 32]) -> Option<PullCoverWitness> {
        None
    }

    fn adopt_pull_atom_mor(&self) -> bool {
        false
    }

    fn enforce_nf_canonicality(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CoreBaseApi {
    pub id_maps: BTreeSet<[u8; 32]>,
    pub map_compositions: BTreeMap<([u8; 32], [u8; 32]), [u8; 32]>,
    pub bc_squares: BTreeMap<([u8; 32], [u8; 32]), ([u8; 32], [u8; 32])>,
    pub bc_allowed_pairs: BTreeSet<([u8; 32], [u8; 32])>,
    pub adopt_pull_atom_mor: bool,
    pub enforce_nf_canonicality: bool,
    pub valid_covers: BTreeSet<[u8; 32]>,
    pub cover_lengths: BTreeMap<[u8; 32], u32>,
    pub pull_covers: BTreeMap<([u8; 32], [u8; 32]), PullCoverWitness>,
}

impl CoreBaseApi {
    pub fn is_id_map(&self, map_id: &[u8; 32]) -> bool {
        self.id_maps.contains(map_id)
    }

    pub fn compose_maps(&self, outer: &[u8; 32], inner: &[u8; 32]) -> Option<[u8; 32]> {
        self.map_compositions.get(&(*outer, *inner)).copied()
    }

    pub fn bc_square(
        &self,
        push_id: &[u8; 32],
        pull_id: &[u8; 32],
    ) -> Option<([u8; 32], [u8; 32])> {
        self.bc_squares.get(&(*push_id, *pull_id)).copied()
    }

    pub fn bc_allowed(&self, pull_id: &[u8; 32], push_id: &[u8; 32]) -> bool {
        self.bc_allowed_pairs.contains(&(*pull_id, *push_id))
            || self.bc_squares.contains_key(&(*push_id, *pull_id))
    }

    pub fn validate_cover(&self, cover_sig: &[u8; 32]) -> Option<bool> {
        if self.valid_covers.is_empty() {
            None
        } else {
            Some(self.valid_covers.contains(cover_sig))
        }
    }

    pub fn cover_len(&self, cover_sig: &[u8; 32]) -> Option<u32> {
        self.cover_lengths.get(cover_sig).copied()
    }

    pub fn pull_cover(&self, p_id: &[u8; 32], u_sig: &[u8; 32]) -> Option<PullCoverWitness> {
        self.pull_covers.get(&(*p_id, *u_sig)).cloned()
    }
}

impl KcirBackend for CoreBaseApi {
    fn is_id_map(&self, map_id: &[u8; 32]) -> bool {
        self.id_maps.contains(map_id)
    }

    fn compose_maps(&self, outer: &[u8; 32], inner: &[u8; 32]) -> Option<[u8; 32]> {
        self.map_compositions.get(&(*outer, *inner)).copied()
    }

    fn bc_square(&self, push_id: &[u8; 32], pull_id: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
        self.bc_squares.get(&(*push_id, *pull_id)).copied()
    }

    fn bc_allowed(&self, pull_id: &[u8; 32], push_id: &[u8; 32]) -> bool {
        self.bc_allowed_pairs.contains(&(*pull_id, *push_id))
            || self.bc_squares.contains_key(&(*push_id, *pull_id))
    }

    fn has_bc_policy(&self) -> bool {
        !self.bc_allowed_pairs.is_empty() || !self.bc_squares.is_empty()
    }

    fn validate_cover(&self, cover_sig: &[u8; 32]) -> Option<bool> {
        if self.valid_covers.is_empty() {
            None
        } else {
            Some(self.valid_covers.contains(cover_sig))
        }
    }

    fn cover_len(&self, cover_sig: &[u8; 32]) -> Option<u32> {
        self.cover_lengths.get(cover_sig).copied()
    }

    fn pull_cover(&self, p_id: &[u8; 32], u_sig: &[u8; 32]) -> Option<PullCoverWitness> {
        self.pull_covers.get(&(*p_id, *u_sig)).cloned()
    }

    fn adopt_pull_atom_mor(&self) -> bool {
        self.adopt_pull_atom_mor
    }

    fn enforce_nf_canonicality(&self) -> bool {
        self.enforce_nf_canonicality
    }
}

pub const HASH_SCHEME_ID: &str = "hash";
pub const MERKLE_SCHEME_ID: &str = "merkle";
pub const DOMAIN_NODE: &str = "kcir.node";
pub const DOMAIN_OBJ_NF: &str = "kcir.obj_nf";
pub const DOMAIN_MOR_NF: &str = "kcir.mor_nf";
pub const DOMAIN_OPAQUE: &str = "kcir.opaque";
pub const KCIR_VERSION: &str = "2";
pub const WIRE_FORMAT_LEGACY_FIXED32_V1: &str = "kcir.wire.legacy-fixed32.v1";
pub const WIRE_FORMAT_LENPREFIXED_REF_V1: &str = "kcir.wire.lenprefixed-ref.v1";
pub const WIRE_FORMAT_VERSION_V1: &str = "1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KcirProfileAnchor {
    #[serde(rename = "rootCommitment", skip_serializing_if = "Option::is_none")]
    pub root_commitment: Option<String>,
    #[serde(rename = "treeEpoch", skip_serializing_if = "Option::is_none")]
    pub tree_epoch: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KcirProfileBinding {
    #[serde(rename = "schemeId")]
    pub scheme_id: String,
    #[serde(rename = "paramsHash")]
    pub params_hash: String,
    #[serde(rename = "wireFormatId")]
    pub wire_format_id: String,
    #[serde(rename = "wireFormatVersion", skip_serializing_if = "Option::is_none")]
    pub wire_format_version: Option<String>,
    #[serde(
        rename = "evidenceFormatVersion",
        skip_serializing_if = "Option::is_none"
    )]
    pub evidence_format_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor: Option<KcirProfileAnchor>,
}

pub fn kcir_profile_binding_for_scheme_and_wire(
    scheme_id: &str,
    wire_format_id: &str,
) -> Result<KcirProfileBinding, String> {
    let params_hash = match scheme_id {
        HASH_SCHEME_ID => format!("sha256:{}", hex::encode(HashProfile::default_params_hash())),
        MERKLE_SCHEME_ID => format!(
            "sha256:{}",
            hex::encode(MerkleProfile::default_params_hash())
        ),
        other => return Err(format!("unsupported profile schemeId: {other}")),
    };
    let wire_format_version = wire_format_version_for_id(wire_format_id)
        .ok_or_else(|| format!("unsupported profile wireFormatId: {wire_format_id}"))?;

    Ok(KcirProfileBinding {
        scheme_id: scheme_id.to_string(),
        params_hash,
        wire_format_id: wire_format_id.to_string(),
        wire_format_version: Some(wire_format_version.to_string()),
        evidence_format_version: Some("1".to_string()),
        anchor: Some(KcirProfileAnchor {
            root_commitment: None,
            tree_epoch: None,
        }),
    })
}

pub fn default_kcir_profile_binding() -> KcirProfileBinding {
    kcir_profile_binding_for_scheme_and_wire(HASH_SCHEME_ID, WIRE_FORMAT_LEGACY_FIXED32_V1)
        .expect("default hash profile binding")
}

pub fn default_kcir_merkle_profile_binding() -> KcirProfileBinding {
    kcir_profile_binding_for_scheme_and_wire(MERKLE_SCHEME_ID, WIRE_FORMAT_LEGACY_FIXED32_V1)
        .expect("default merkle profile binding")
}

pub const SORT_COVER: u8 = compat::SORT_COVER;
pub const SORT_MAP: u8 = compat::SORT_MAP;
pub const SORT_OBJ: u8 = compat::SORT_OBJ;
pub const SORT_MOR: u8 = compat::SORT_MOR;

pub const O_UNIT: u8 = compat::O_UNIT;
pub const O_PRIM: u8 = compat::O_PRIM;
pub const O_MKTENSOR: u8 = compat::O_MKTENSOR;
pub const O_PULL: u8 = compat::O_PULL;

pub const M_ID: u8 = compat::M_ID;
pub const M_MKTENSOR: u8 = compat::M_MKTENSOR;
pub const M_MKCOMP: u8 = compat::M_MKCOMP;
pub const M_PULL: u8 = compat::M_PULL;

pub const C_PULLCOVER: u8 = compat::C_PULLCOVER;
pub const M_BC_FPRIME: u8 = compat::M_BC_FPRIME;
pub const M_BC_GPRIME: u8 = compat::M_BC_GPRIME;

pub mod error_codes {
    pub const PARSE_ERROR: &str = "kcir_v2.parse_error";
    pub const ENV_UID_MISMATCH: &str = "kcir_v2.env_uid_mismatch";
    pub const DEP_CYCLE: &str = "kcir_v2.dep_cycle";
    pub const UNSUPPORTED_SORT: &str = "kcir_v2.unsupported_sort";
    pub const UNSUPPORTED_OPCODE: &str = "kcir_v2.unsupported_opcode";
    pub const CONTRACT_VIOLATION: &str = "kcir_v2.contract_violation";

    pub const PROFILE_MISMATCH: &str = "kcir_v2.profile_mismatch";
    pub const PARAMS_HASH_MISMATCH: &str = "kcir_v2.params_hash_mismatch";
    pub const DOMAIN_MISMATCH: &str = "kcir_v2.domain_mismatch";
    pub const DIGEST_MISMATCH: &str = "kcir_v2.digest_mismatch";
    pub const EVIDENCE_MALFORMED: &str = "kcir_v2.evidence_malformed";
    pub const EVIDENCE_INVALID: &str = "kcir_v2.evidence_invalid";
    pub const ANCHOR_MISMATCH: &str = "kcir_v2.anchor_mismatch";
    pub const ANCHOR_MISSING: &str = "kcir_v2.anchor_missing";

    pub const STORE_MISSING_NODE: &str = "kcir_v2.store_missing_node";
    pub const STORE_MISSING_OBJ_NF: &str = "kcir_v2.store_missing_obj_nf";
    pub const STORE_MISSING_MOR_NF: &str = "kcir_v2.store_missing_mor_nf";
    pub const DATA_UNAVAILABLE: &str = "kcir_v2.data_unavailable";

    pub const OBJ_NF_NONCANONICAL: &str = "kcir_v2.obj_nf_noncanonical";
    pub const MOR_NF_NONCANONICAL: &str = "kcir_v2.mor_nf_noncanonical";
}

pub fn h_obj(env_sig: &[u8; 32], uid: &[u8; 32], obj_bytes: &[u8]) -> [u8; 32] {
    compat::h_obj(env_sig, uid, obj_bytes)
}

pub fn h_mor(env_sig: &[u8; 32], uid: &[u8; 32], mor_bytes: &[u8]) -> [u8; 32] {
    compat::h_mor(env_sig, uid, mor_bytes)
}

pub fn cert_id(node_bytes: &[u8]) -> [u8; 32] {
    compat::cert_id(node_bytes)
}

pub fn parse_node_bytes(node_bytes: &[u8]) -> Result<KcirNode, String> {
    compat::parse_node_bytes(node_bytes).map(Into::into)
}

pub fn node_obj_prim(env_sig: [u8; 32], uid: [u8; 32], prim_id: [u8; 32]) -> KcirNode {
    compat::node_obj_prim(env_sig, uid, prim_id).into()
}

pub fn node_obj_mktensor(env_sig: [u8; 32], uid: [u8; 32], factors: Vec<[u8; 32]>) -> KcirNode {
    compat::node_obj_mktensor(env_sig, uid, factors).into()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KcirV2Error {
    pub code: String,
    pub message: String,
}

impl KcirV2Error {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }
}

impl fmt::Display for KcirV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for KcirV2Error {}

fn classify_legacy_core_error(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.contains("dependency cycle") {
        return error_codes::DEP_CYCLE;
    }
    if lower.contains("envsig mismatch") || lower.contains("uid mismatch") {
        return error_codes::ENV_UID_MISMATCH;
    }
    if lower.contains("unsupported kcir sort") {
        return error_codes::UNSUPPORTED_SORT;
    }
    if lower.contains("unsupported") && lower.contains("opcode") {
        return error_codes::UNSUPPORTED_OPCODE;
    }
    if lower.contains("missing kcir root node bytes")
        || lower.contains("missing kcir node bytes")
        || lower.contains("missing kcir node")
    {
        return error_codes::STORE_MISSING_NODE;
    }
    if lower.contains("missing objnf") {
        return error_codes::STORE_MISSING_OBJ_NF;
    }
    if lower.contains("missing mornf") {
        return error_codes::STORE_MISSING_MOR_NF;
    }
    if lower.contains("certid mismatch")
        || lower.contains("digest mismatch")
        || lower.contains("hash mismatch")
    {
        return error_codes::DIGEST_MISMATCH;
    }
    if lower.contains("non-canonical objnf") {
        return error_codes::OBJ_NF_NONCANONICAL;
    }
    if lower.contains("non-canonical mornf") {
        return error_codes::MOR_NF_NONCANONICAL;
    }
    if lower.contains("failed to parse")
        || lower.contains("parse ")
        || lower.contains("payload is empty")
        || lower.contains("trailing bytes")
        || lower.contains("varint")
    {
        return error_codes::PARSE_ERROR;
    }
    error_codes::CONTRACT_VIOLATION
}

/// Profile-pinned verification anchors.
///
/// This shape is intentionally minimal and profile-agnostic:
/// profile implementations can interpret these fields as needed and/or ignore
/// them (e.g., hash profile).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileAnchors {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_commitment: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

/// Wire codec abstraction for profile-specific Ref/node encoding.
///
/// Most core verification is now Ref-native, but transitional helpers remain for
/// legacy 32-byte contract-key projections used by residual bridge paths.
pub trait WireCodec {
    fn wire_format_id(&self) -> &str;

    fn encode_ref_for_domain(&self, reference: &Ref, domain: &str) -> Result<Vec<u8>, KcirV2Error>;

    fn decode_ref_for_domain(
        &self,
        encoded: &[u8],
        scheme_id: &str,
        params_hash: [u8; 32],
        domain: &str,
    ) -> Result<Ref, KcirV2Error>;

    fn legacy_digest_from_ref(
        &self,
        reference: &Ref,
        domain: &str,
    ) -> Result<[u8; 32], KcirV2Error> {
        let encoded = self.encode_ref_for_domain(reference, domain)?;
        if encoded.len() != 32 {
            return Err(KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!(
                    "wire codec {} expected 32-byte legacy digest for {}, got {} bytes",
                    self.wire_format_id(),
                    domain,
                    encoded.len()
                ),
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&encoded);
        Ok(out)
    }

    /// Transitional projection used by current opcode-contract verifiers.
    ///
    /// This is the 32-byte key space consumed by existing KCIR contract logic.
    /// Default behavior matches legacy fixed32 wire assumptions.
    fn contract_key_from_ref(
        &self,
        reference: &Ref,
        domain: &str,
    ) -> Result<[u8; 32], KcirV2Error> {
        self.legacy_digest_from_ref(reference, domain)
    }

    fn ref_from_legacy_digest(
        &self,
        scheme_id: &str,
        params_hash: [u8; 32],
        domain: &str,
        digest: [u8; 32],
    ) -> Result<Ref, KcirV2Error> {
        self.decode_ref_for_domain(&digest, scheme_id, params_hash, domain)
    }

    /// Inverse of `contract_key_from_ref` for contexts that still decode
    /// 32-byte contract keys from KCIR node payloads.
    fn ref_from_contract_key(
        &self,
        scheme_id: &str,
        params_hash: [u8; 32],
        domain: &str,
        key: [u8; 32],
    ) -> Result<Ref, KcirV2Error> {
        self.ref_from_legacy_digest(scheme_id, params_hash, domain, key)
    }

    fn decode_node_refs(
        &self,
        node_bytes: &[u8],
        scheme_id: &str,
        params_hash: [u8; 32],
    ) -> Result<DecodedNodeRefs, KcirV2Error> {
        let parsed = parse_node_bytes(node_bytes).map_err(|message| {
            KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!("failed to parse KCIR node bytes: {message}"),
            )
        })?;
        let out_ref = self.ref_from_contract_key(
            scheme_id,
            params_hash,
            out_domain_for_sort(parsed.sort),
            parsed.out,
        )?;
        let dep_refs = parsed
            .deps
            .iter()
            .map(|dep| self.ref_from_contract_key(scheme_id, params_hash, DOMAIN_NODE, *dep))
            .collect::<Result<Vec<_>, KcirV2Error>>()?;
        Ok(DecodedNodeRefs {
            env_sig: parsed.env_sig,
            uid: parsed.uid,
            sort: parsed.sort,
            opcode: parsed.opcode,
            out_ref,
            args: parsed.args,
            dep_refs,
        })
    }
}

/// Legacy fixed-width digest-only wire codec.
///
/// - `out` refs are encoded as raw 32-byte digests.
/// - `deps` refs are encoded as repeated raw 32-byte digests.
#[derive(Clone, Debug, Default)]
pub struct LegacyFixed32WireCodec;

impl WireCodec for LegacyFixed32WireCodec {
    fn wire_format_id(&self) -> &str {
        WIRE_FORMAT_LEGACY_FIXED32_V1
    }

    fn encode_ref_for_domain(&self, reference: &Ref, domain: &str) -> Result<Vec<u8>, KcirV2Error> {
        if reference.domain != domain {
            return Err(KcirV2Error::new(
                error_codes::DOMAIN_MISMATCH,
                format!(
                    "domain mismatch: expected {}, got {}",
                    domain, reference.domain
                ),
            ));
        }
        let digest = reference.digest32()?;
        Ok(digest.to_vec())
    }

    fn decode_ref_for_domain(
        &self,
        encoded: &[u8],
        scheme_id: &str,
        params_hash: [u8; 32],
        domain: &str,
    ) -> Result<Ref, KcirV2Error> {
        if encoded.len() != 32 {
            return Err(KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!(
                    "legacy fixed32 codec expects 32-byte ref encoding, got {} bytes",
                    encoded.len()
                ),
            ));
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(encoded);
        Ok(Ref {
            scheme_id: scheme_id.to_string(),
            params_hash,
            domain: domain.to_string(),
            digest: digest.to_vec(),
        })
    }
}

pub static LEGACY_FIXED32_WIRE_CODEC: LegacyFixed32WireCodec = LegacyFixed32WireCodec;

/// Length-prefixed ref wire codec.
///
/// Node layout:
/// - envSig: 32 bytes
/// - uid: 32 bytes
/// - sort: u8
/// - opcode: u8
/// - outRef: varint(len) || ref-bytes
/// - args: varint(len) || args-bytes
/// - deps: varint(count) || (varint(len) || ref-bytes){count}
///
/// Contract-key projection remains transitional and deterministic:
/// - requires at least 32 digest bytes
/// - uses the first 32 digest bytes as the legacy contract key
#[derive(Clone, Debug, Default)]
pub struct LenPrefixedRefWireCodec;

impl LenPrefixedRefWireCodec {
    fn read_len_prefixed(
        bytes: &[u8],
        cursor: &mut usize,
        field: &str,
    ) -> Result<Vec<u8>, KcirV2Error> {
        let len_u64 = dec_varint_contract(bytes, cursor, field)?;
        let len = usize::try_from(len_u64).map_err(|_| {
            KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!("{field} length out of range: {len_u64}"),
            )
        })?;
        let end = cursor.checked_add(len).ok_or_else(|| {
            KcirV2Error::new(error_codes::PARSE_ERROR, format!("{field} length overflow"))
        })?;
        if end > bytes.len() {
            return Err(KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!(
                    "{field} length {} runs past end of KCIR node ({} bytes total)",
                    len,
                    bytes.len()
                ),
            ));
        }
        let out = bytes[*cursor..end].to_vec();
        *cursor = end;
        Ok(out)
    }

    pub fn encode_node_refs(&self, node: &DecodedNodeRefs) -> Result<Vec<u8>, KcirV2Error> {
        let mut out = Vec::new();
        out.extend_from_slice(&node.env_sig);
        out.extend_from_slice(&node.uid);
        out.push(node.sort);
        out.push(node.opcode);

        let out_encoded =
            self.encode_ref_for_domain(&node.out_ref, out_domain_for_sort(node.sort))?;
        enc_varint_u64(out_encoded.len() as u64, &mut out);
        out.extend_from_slice(&out_encoded);

        enc_varint_u64(node.args.len() as u64, &mut out);
        out.extend_from_slice(&node.args);

        enc_varint_u64(node.dep_refs.len() as u64, &mut out);
        for (idx, dep_ref) in node.dep_refs.iter().enumerate() {
            let dep_encoded = self
                .encode_ref_for_domain(dep_ref, DOMAIN_NODE)
                .map_err(|e| {
                    KcirV2Error::new(
                        e.code.as_str(),
                        format!("failed to encode dep[{idx}] reference: {}", e.message),
                    )
                })?;
            enc_varint_u64(dep_encoded.len() as u64, &mut out);
            out.extend_from_slice(&dep_encoded);
        }
        Ok(out)
    }
}

impl WireCodec for LenPrefixedRefWireCodec {
    fn wire_format_id(&self) -> &str {
        WIRE_FORMAT_LENPREFIXED_REF_V1
    }

    fn encode_ref_for_domain(&self, reference: &Ref, domain: &str) -> Result<Vec<u8>, KcirV2Error> {
        if reference.domain != domain {
            return Err(KcirV2Error::new(
                error_codes::DOMAIN_MISMATCH,
                format!(
                    "domain mismatch: expected {}, got {}",
                    domain, reference.domain
                ),
            ));
        }
        Ok(reference.digest.clone())
    }

    fn decode_ref_for_domain(
        &self,
        encoded: &[u8],
        scheme_id: &str,
        params_hash: [u8; 32],
        domain: &str,
    ) -> Result<Ref, KcirV2Error> {
        Ok(Ref {
            scheme_id: scheme_id.to_string(),
            params_hash,
            domain: domain.to_string(),
            digest: encoded.to_vec(),
        })
    }

    fn contract_key_from_ref(
        &self,
        reference: &Ref,
        domain: &str,
    ) -> Result<[u8; 32], KcirV2Error> {
        if reference.domain != domain {
            return Err(KcirV2Error::new(
                error_codes::DOMAIN_MISMATCH,
                format!(
                    "domain mismatch: expected {}, got {}",
                    domain, reference.domain
                ),
            ));
        }
        if reference.digest.len() < 32 {
            return Err(KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!(
                    "len-prefixed codec needs at least 32 digest bytes for contract key projection, got {}",
                    reference.digest.len()
                ),
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&reference.digest[0..32]);
        Ok(out)
    }

    fn decode_node_refs(
        &self,
        node_bytes: &[u8],
        scheme_id: &str,
        params_hash: [u8; 32],
    ) -> Result<DecodedNodeRefs, KcirV2Error> {
        if node_bytes.len() < 66 {
            return Err(KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!(
                    "len-prefixed node requires at least 66 bytes, got {}",
                    node_bytes.len()
                ),
            ));
        }

        let mut cursor = 0usize;
        let mut env_sig = [0u8; 32];
        env_sig.copy_from_slice(&node_bytes[cursor..cursor + 32]);
        cursor += 32;

        let mut uid = [0u8; 32];
        uid.copy_from_slice(&node_bytes[cursor..cursor + 32]);
        cursor += 32;

        let sort = node_bytes[cursor];
        cursor += 1;
        let opcode = node_bytes[cursor];
        cursor += 1;

        let out_encoded =
            Self::read_len_prefixed(node_bytes, &mut cursor, "len-prefixed node outRef")?;
        let out_ref = self.decode_ref_for_domain(
            &out_encoded,
            scheme_id,
            params_hash,
            out_domain_for_sort(sort),
        )?;

        let args = Self::read_len_prefixed(node_bytes, &mut cursor, "len-prefixed node args")?;

        let deps_len_u64 =
            dec_varint_contract(node_bytes, &mut cursor, "len-prefixed node depsLen")?;
        let deps_len = usize::try_from(deps_len_u64).map_err(|_| {
            KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!("len-prefixed node depsLen out of range: {deps_len_u64}"),
            )
        })?;

        let mut dep_refs = Vec::with_capacity(deps_len);
        for idx in 0..deps_len {
            let dep_encoded = Self::read_len_prefixed(
                node_bytes,
                &mut cursor,
                &format!("len-prefixed node deps[{idx}]"),
            )?;
            let dep_ref =
                self.decode_ref_for_domain(&dep_encoded, scheme_id, params_hash, DOMAIN_NODE)?;
            dep_refs.push(dep_ref);
        }

        if cursor != node_bytes.len() {
            return Err(KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!(
                    "len-prefixed node has trailing bytes: parsed {} of {}",
                    cursor,
                    node_bytes.len()
                ),
            ));
        }

        Ok(DecodedNodeRefs {
            env_sig,
            uid,
            sort,
            opcode,
            out_ref,
            args,
            dep_refs,
        })
    }
}

pub static LEN_PREFIXED_REF_WIRE_CODEC: LenPrefixedRefWireCodec = LenPrefixedRefWireCodec;

static SUPPORTED_WIRE_FORMAT_IDS: [&str; 2] = [
    WIRE_FORMAT_LEGACY_FIXED32_V1,
    WIRE_FORMAT_LENPREFIXED_REF_V1,
];

pub fn supported_wire_format_ids() -> &'static [&'static str] {
    &SUPPORTED_WIRE_FORMAT_IDS
}

pub fn wire_codec_for_id(wire_format_id: &str) -> Option<&'static dyn WireCodec> {
    match wire_format_id {
        WIRE_FORMAT_LEGACY_FIXED32_V1 => Some(&LEGACY_FIXED32_WIRE_CODEC),
        WIRE_FORMAT_LENPREFIXED_REF_V1 => Some(&LEN_PREFIXED_REF_WIRE_CODEC),
        _ => None,
    }
}

pub fn wire_format_version_for_id(wire_format_id: &str) -> Option<&'static str> {
    if wire_codec_for_id(wire_format_id).is_some() {
        Some(WIRE_FORMAT_VERSION_V1)
    } else {
        None
    }
}

/// KCIR v2 commitment reference.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Ref {
    pub scheme_id: String,
    pub params_hash: [u8; 32],
    pub domain: String,
    pub digest: Vec<u8>,
}

impl Ref {
    pub fn digest32(&self) -> Result<[u8; 32], KcirV2Error> {
        if self.digest.len() != 32 {
            return Err(KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!("expected 32-byte digest, got {} bytes", self.digest.len()),
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.digest);
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedNodeRefs {
    pub env_sig: [u8; 32],
    pub uid: [u8; 32],
    pub sort: u8,
    pub opcode: u8,
    pub out_ref: Ref,
    pub args: Vec<u8>,
    pub dep_refs: Vec<Ref>,
}

pub trait VerifierProfile {
    fn scheme_id(&self) -> &str;
    fn params_hash(&self) -> [u8; 32];
    fn verify_ref(
        &self,
        reference: &Ref,
        payload_bytes: &[u8],
        evidence: Option<&[u8]>,
        domain: &str,
    ) -> Result<(), KcirV2Error>;

    fn verify_ref_with_anchors(
        &self,
        reference: &Ref,
        payload_bytes: &[u8],
        evidence: Option<&[u8]>,
        anchors: Option<&ProfileAnchors>,
        domain: &str,
    ) -> Result<(), KcirV2Error> {
        let _ = anchors;
        self.verify_ref(reference, payload_bytes, evidence, domain)
    }
}

/// Ref-keyed core store contract aligned with KCIR v2.
pub trait KcirRefStore {
    fn get_node(&self, reference: &Ref) -> Option<(Vec<u8>, Option<Vec<u8>>)>;
    fn get_obj_nf(&self, reference: &Ref) -> Option<(Vec<u8>, Option<Vec<u8>>)>;
    fn get_mor_nf(&self, reference: &Ref) -> Option<(Vec<u8>, Option<Vec<u8>>)>;
}

/// In-memory adapter from legacy digest-keyed maps to the v2 Ref store contract.
pub struct InMemoryDigestRefStore<'a> {
    pub scheme_id: String,
    pub params_hash: [u8; 32],
    pub wire_codec: &'a dyn WireCodec,
    pub cert_store: &'a BTreeMap<[u8; 32], Vec<u8>>,
    pub obj_store: &'a BTreeMap<[u8; 32], Vec<u8>>,
    pub mor_store: &'a BTreeMap<[u8; 32], Vec<u8>>,
}

impl<'a> InMemoryDigestRefStore<'a> {
    pub fn new(
        scheme_id: String,
        params_hash: [u8; 32],
        cert_store: &'a BTreeMap<[u8; 32], Vec<u8>>,
        obj_store: &'a BTreeMap<[u8; 32], Vec<u8>>,
        mor_store: &'a BTreeMap<[u8; 32], Vec<u8>>,
    ) -> Self {
        Self::new_with_codec(
            scheme_id,
            params_hash,
            &LEGACY_FIXED32_WIRE_CODEC,
            cert_store,
            obj_store,
            mor_store,
        )
    }

    pub fn new_with_codec(
        scheme_id: String,
        params_hash: [u8; 32],
        wire_codec: &'a dyn WireCodec,
        cert_store: &'a BTreeMap<[u8; 32], Vec<u8>>,
        obj_store: &'a BTreeMap<[u8; 32], Vec<u8>>,
        mor_store: &'a BTreeMap<[u8; 32], Vec<u8>>,
    ) -> Self {
        Self {
            scheme_id,
            params_hash,
            wire_codec,
            cert_store,
            obj_store,
            mor_store,
        }
    }

    fn digest_key(&self, reference: &Ref, expected_domain: &str) -> Option<[u8; 32]> {
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

impl KcirRefStore for InMemoryDigestRefStore<'_> {
    fn get_node(&self, reference: &Ref) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        let key = self.digest_key(reference, DOMAIN_NODE)?;
        self.cert_store.get(&key).cloned().map(|v| (v, None))
    }

    fn get_obj_nf(&self, reference: &Ref) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        let key = self.digest_key(reference, DOMAIN_OBJ_NF)?;
        self.obj_store.get(&key).cloned().map(|v| (v, None))
    }

    fn get_mor_nf(&self, reference: &Ref) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        let key = self.digest_key(reference, DOMAIN_MOR_NF)?;
        self.mor_store.get(&key).cloned().map(|v| (v, None))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashProfile {
    params_hash: [u8; 32],
}

impl HashProfile {
    pub fn new(params_hash: [u8; 32]) -> Self {
        Self { params_hash }
    }

    pub fn params_hash(&self) -> [u8; 32] {
        self.params_hash
    }

    pub fn default_params_hash() -> [u8; 32] {
        // Canonicalized profile parameter payload for hash profile (v1-compat).
        sha256_bytes(
            b"kcir.v2.profile.hash;v=1;kcir.node=KCIRNode;kcir.obj_nf=ObjNF;kcir.mor_nf=MorNF",
        )
    }

    pub fn hash_ref_from_digest(&self, domain: &str, digest: [u8; 32]) -> Ref {
        hash_ref_from_digest(domain, digest, self.params_hash)
    }

    fn digest_payload(&self, domain: &str, payload_bytes: &[u8]) -> Result<[u8; 32], KcirV2Error> {
        let tag = domain_tag(domain)?;
        let mut buf = Vec::with_capacity(tag.len() + payload_bytes.len());
        buf.extend_from_slice(tag);
        buf.extend_from_slice(payload_bytes);
        Ok(sha256_bytes(&buf))
    }
}

impl Default for HashProfile {
    fn default() -> Self {
        Self::new(Self::default_params_hash())
    }
}

impl VerifierProfile for HashProfile {
    fn scheme_id(&self) -> &str {
        HASH_SCHEME_ID
    }

    fn params_hash(&self) -> [u8; 32] {
        self.params_hash
    }

    fn verify_ref(
        &self,
        reference: &Ref,
        payload_bytes: &[u8],
        evidence: Option<&[u8]>,
        domain: &str,
    ) -> Result<(), KcirV2Error> {
        if reference.scheme_id != self.scheme_id() {
            return Err(KcirV2Error::new(
                error_codes::PROFILE_MISMATCH,
                format!(
                    "profile mismatch: expected scheme {}, got {}",
                    self.scheme_id(),
                    reference.scheme_id
                ),
            ));
        }
        if reference.params_hash != self.params_hash {
            return Err(KcirV2Error::new(
                error_codes::PARAMS_HASH_MISMATCH,
                "params hash mismatch",
            ));
        }
        if reference.domain != domain {
            return Err(KcirV2Error::new(
                error_codes::DOMAIN_MISMATCH,
                format!(
                    "domain mismatch: expected {}, got {}",
                    domain, reference.domain
                ),
            ));
        }
        if evidence.is_some_and(|e| !e.is_empty()) {
            return Err(KcirV2Error::new(
                error_codes::EVIDENCE_INVALID,
                "hash profile does not accept evidence payload",
            ));
        }

        let expected = self.digest_payload(domain, payload_bytes)?;
        let got = reference.digest32()?;
        if got != expected {
            return Err(KcirV2Error::new(
                error_codes::DIGEST_MISMATCH,
                format!(
                    "digest mismatch for domain {}: expected {}, got {}",
                    domain,
                    hex::encode(expected),
                    hex::encode(got)
                ),
            ));
        }
        Ok(())
    }
}

fn merkle_malformed(message: impl Into<String>) -> KcirV2Error {
    KcirV2Error::new(error_codes::EVIDENCE_MALFORMED, message.into())
}

fn enc_varint_u64(mut n: u64, out: &mut Vec<u8>) {
    while n >= 0x80 {
        out.push(((n as u8) & 0x7F) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

fn dec_varint_u64(bytes: &[u8], cursor: &mut usize, field: &str) -> Result<u64, KcirV2Error> {
    let mut out: u64 = 0;
    let mut shift = 0u32;
    let mut steps = 0usize;
    loop {
        if *cursor >= bytes.len() {
            return Err(merkle_malformed(format!(
                "truncated varint for {field} at byte offset {}",
                *cursor
            )));
        }
        let b = bytes[*cursor];
        *cursor += 1;
        steps += 1;
        if steps > 10 {
            return Err(merkle_malformed(format!("overlong varint for {field}")));
        }
        let chunk = (b & 0x7F) as u64;
        if shift >= 64 || chunk.checked_shl(shift).is_none() {
            return Err(merkle_malformed(format!("varint overflow for {field}")));
        }
        out |= chunk << shift;
        if (b & 0x80) == 0 {
            return Ok(out);
        }
        shift += 7;
    }
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    enc_varint_u64(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

fn read_digest32(bytes: &[u8], cursor: &mut usize, field: &str) -> Result<[u8; 32], KcirV2Error> {
    if *cursor + 32 > bytes.len() {
        return Err(merkle_malformed(format!(
            "truncated {field}: need 32 bytes at offset {} (len={})",
            *cursor,
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[*cursor..*cursor + 32]);
    *cursor += 32;
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MerkleDirection {
    Left,
    Right,
}

impl MerkleDirection {
    fn as_u8(self) -> u8 {
        match self {
            MerkleDirection::Left => 0,
            MerkleDirection::Right => 1,
        }
    }

    fn from_u8(raw: u8) -> Result<Self, KcirV2Error> {
        match raw {
            0 => Ok(MerkleDirection::Left),
            1 => Ok(MerkleDirection::Right),
            _ => Err(merkle_malformed(format!(
                "invalid Merkle direction tag {raw} (expected 0 or 1)"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofStep {
    pub direction: MerkleDirection,
    #[serde(rename = "siblingHash")]
    pub sibling_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleEvidence {
    #[serde(rename = "leafHash")]
    pub leaf_hash: [u8; 32],
    pub proof: Vec<MerkleProofStep>,
    pub root: [u8; 32],
}

impl MerkleEvidence {
    pub const FORMAT_VERSION: u8 = 1;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 5 + (self.proof.len() * 33) + 32);
        out.push(Self::FORMAT_VERSION);
        out.extend_from_slice(&self.leaf_hash);
        enc_varint_u64(self.proof.len() as u64, &mut out);
        for step in &self.proof {
            out.push(step.direction.as_u8());
            out.extend_from_slice(&step.sibling_hash);
        }
        out.extend_from_slice(&self.root);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KcirV2Error> {
        if bytes.is_empty() {
            return Err(merkle_malformed("missing Merkle evidence payload"));
        }
        let mut cursor = 0usize;
        let version = bytes[cursor];
        cursor += 1;
        if version != Self::FORMAT_VERSION {
            return Err(merkle_malformed(format!(
                "unsupported Merkle evidence version {version} (expected {})",
                Self::FORMAT_VERSION
            )));
        }

        let leaf_hash = read_digest32(bytes, &mut cursor, "leaf_hash")?;
        let proof_len = dec_varint_u64(bytes, &mut cursor, "proof_len")? as usize;
        let mut proof = Vec::with_capacity(proof_len);
        for idx in 0..proof_len {
            if cursor >= bytes.len() {
                return Err(merkle_malformed(format!(
                    "truncated proof direction at index {idx}"
                )));
            }
            let direction = MerkleDirection::from_u8(bytes[cursor])?;
            cursor += 1;
            let sibling_hash = read_digest32(bytes, &mut cursor, "proof sibling_hash")?;
            proof.push(MerkleProofStep {
                direction,
                sibling_hash,
            });
        }
        let root = read_digest32(bytes, &mut cursor, "root")?;
        if cursor != bytes.len() {
            return Err(merkle_malformed(format!(
                "trailing Merkle evidence bytes: parsed {}, total {}",
                cursor,
                bytes.len()
            )));
        }

        Ok(Self {
            leaf_hash,
            proof,
            root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProfile {
    params_hash: [u8; 32],
}

impl MerkleProfile {
    pub fn new(params_hash: [u8; 32]) -> Self {
        Self { params_hash }
    }

    pub fn params_hash(&self) -> [u8; 32] {
        self.params_hash
    }

    pub fn default_params_hash() -> [u8; 32] {
        sha256_bytes(
            b"kcir.v2.profile.merkle;v=1;hash=sha256;leaf=KCIRMerkleLeaf+len(domain)+len(scheme)+params_hash+len(payload)+payload;node=KCIRMerkleNode+direction+left+right;direction=0:left,1:right",
        )
    }

    pub fn leaf_hash(&self, domain: &str, payload_bytes: &[u8]) -> Result<[u8; 32], KcirV2Error> {
        merkle_leaf_hash(domain, self.scheme_id(), self.params_hash, payload_bytes)
    }

    pub fn ref_for_payload(&self, domain: &str, payload_bytes: &[u8]) -> Result<Ref, KcirV2Error> {
        Ok(merkle_ref_from_digest(
            domain,
            self.leaf_hash(domain, payload_bytes)?,
            self.params_hash,
        ))
    }

    pub fn root_from_leaf(leaf_hash: [u8; 32], proof: &[MerkleProofStep]) -> [u8; 32] {
        let mut current = leaf_hash;
        for step in proof {
            current = merkle_parent_hash(step.direction, current, step.sibling_hash);
        }
        current
    }

    pub fn evidence_for_payload(
        &self,
        domain: &str,
        payload_bytes: &[u8],
        proof: Vec<MerkleProofStep>,
    ) -> Result<MerkleEvidence, KcirV2Error> {
        let leaf_hash = self.leaf_hash(domain, payload_bytes)?;
        let root = Self::root_from_leaf(leaf_hash, &proof);
        Ok(MerkleEvidence {
            leaf_hash,
            proof,
            root,
        })
    }

    fn verify_ref_internal(
        &self,
        reference: &Ref,
        payload_bytes: &[u8],
        evidence: Option<&[u8]>,
        anchors: Option<&ProfileAnchors>,
        domain: &str,
    ) -> Result<(), KcirV2Error> {
        if reference.scheme_id != self.scheme_id() {
            return Err(KcirV2Error::new(
                error_codes::PROFILE_MISMATCH,
                format!(
                    "profile mismatch: expected scheme {}, got {}",
                    self.scheme_id(),
                    reference.scheme_id
                ),
            ));
        }
        if reference.params_hash != self.params_hash {
            return Err(KcirV2Error::new(
                error_codes::PARAMS_HASH_MISMATCH,
                "params hash mismatch",
            ));
        }
        if reference.domain != domain {
            return Err(KcirV2Error::new(
                error_codes::DOMAIN_MISMATCH,
                format!(
                    "domain mismatch: expected {}, got {}",
                    domain, reference.domain
                ),
            ));
        }

        let expected_leaf = self.leaf_hash(domain, payload_bytes)?;
        let digest = reference.digest32()?;
        if digest != expected_leaf {
            return Err(KcirV2Error::new(
                error_codes::DIGEST_MISMATCH,
                format!(
                    "digest mismatch for domain {}: expected {}, got {}",
                    domain,
                    hex::encode(expected_leaf),
                    hex::encode(digest)
                ),
            ));
        }

        let evidence_bytes = evidence.ok_or_else(|| {
            KcirV2Error::new(
                error_codes::EVIDENCE_MALFORMED,
                "merkle profile requires evidence payload",
            )
        })?;
        let parsed = MerkleEvidence::decode(evidence_bytes)?;

        if parsed.leaf_hash != expected_leaf {
            return Err(KcirV2Error::new(
                error_codes::EVIDENCE_INVALID,
                format!(
                    "evidence leaf hash mismatch: expected {}, got {}",
                    hex::encode(expected_leaf),
                    hex::encode(parsed.leaf_hash)
                ),
            ));
        }

        let recomputed_root = Self::root_from_leaf(parsed.leaf_hash, &parsed.proof);
        if recomputed_root != parsed.root {
            return Err(KcirV2Error::new(
                error_codes::EVIDENCE_INVALID,
                format!(
                    "invalid Merkle proof root: expected {}, got {}",
                    hex::encode(parsed.root),
                    hex::encode(recomputed_root)
                ),
            ));
        }

        let anchors = anchors.ok_or_else(|| {
            KcirV2Error::new(
                error_codes::ANCHOR_MISSING,
                "merkle profile requires verifier anchors",
            )
        })?;
        let expected_root = anchors.root_commitment.as_ref().ok_or_else(|| {
            KcirV2Error::new(
                error_codes::ANCHOR_MISSING,
                "merkle profile requires anchors.root_commitment",
            )
        })?;
        if anchors.tree_epoch.is_none() {
            return Err(KcirV2Error::new(
                error_codes::ANCHOR_MISSING,
                "merkle profile requires anchors.tree_epoch",
            ));
        }
        if expected_root.len() != 32 {
            return Err(KcirV2Error::new(
                error_codes::ANCHOR_MISMATCH,
                format!(
                    "anchors.root_commitment must be 32 bytes, got {} bytes",
                    expected_root.len()
                ),
            ));
        }
        if expected_root.as_slice() != parsed.root.as_slice() {
            return Err(KcirV2Error::new(
                error_codes::ANCHOR_MISMATCH,
                format!(
                    "anchor root mismatch: expected {}, got {}",
                    hex::encode(expected_root),
                    hex::encode(parsed.root)
                ),
            ));
        }
        Ok(())
    }
}

impl Default for MerkleProfile {
    fn default() -> Self {
        Self::new(Self::default_params_hash())
    }
}

impl VerifierProfile for MerkleProfile {
    fn scheme_id(&self) -> &str {
        MERKLE_SCHEME_ID
    }

    fn params_hash(&self) -> [u8; 32] {
        self.params_hash
    }

    fn verify_ref(
        &self,
        reference: &Ref,
        payload_bytes: &[u8],
        evidence: Option<&[u8]>,
        domain: &str,
    ) -> Result<(), KcirV2Error> {
        self.verify_ref_internal(reference, payload_bytes, evidence, None, domain)
    }

    fn verify_ref_with_anchors(
        &self,
        reference: &Ref,
        payload_bytes: &[u8],
        evidence: Option<&[u8]>,
        anchors: Option<&ProfileAnchors>,
        domain: &str,
    ) -> Result<(), KcirV2Error> {
        self.verify_ref_internal(reference, payload_bytes, evidence, anchors, domain)
    }
}

fn merkle_leaf_hash(
    domain: &str,
    scheme_id: &str,
    params_hash: [u8; 32],
    payload_bytes: &[u8],
) -> Result<[u8; 32], KcirV2Error> {
    if !matches!(
        domain,
        DOMAIN_NODE | DOMAIN_OBJ_NF | DOMAIN_MOR_NF | DOMAIN_OPAQUE
    ) {
        return Err(KcirV2Error::new(
            error_codes::DOMAIN_MISMATCH,
            format!("unknown merkle-profile domain: {domain}"),
        ));
    }

    let mut buf = Vec::with_capacity(16 + domain.len() + scheme_id.len() + payload_bytes.len());
    buf.extend_from_slice(b"KCIRMerkleLeaf");
    append_len_prefixed(&mut buf, domain.as_bytes());
    append_len_prefixed(&mut buf, scheme_id.as_bytes());
    buf.extend_from_slice(&params_hash);
    append_len_prefixed(&mut buf, payload_bytes);
    Ok(sha256_bytes(&buf))
}

fn merkle_parent_hash(
    direction: MerkleDirection,
    current_hash: [u8; 32],
    sibling_hash: [u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(14 + 1 + 64);
    buf.extend_from_slice(b"KCIRMerkleNode");
    buf.push(direction.as_u8());
    match direction {
        MerkleDirection::Left => {
            buf.extend_from_slice(&sibling_hash);
            buf.extend_from_slice(&current_hash);
        }
        MerkleDirection::Right => {
            buf.extend_from_slice(&current_hash);
            buf.extend_from_slice(&sibling_hash);
        }
    }
    sha256_bytes(&buf)
}

fn domain_tag(domain: &str) -> Result<&'static [u8], KcirV2Error> {
    match domain {
        DOMAIN_NODE => Ok(b"KCIRNode"),
        DOMAIN_OBJ_NF => Ok(b"ObjNF"),
        DOMAIN_MOR_NF => Ok(b"MorNF"),
        other => Err(KcirV2Error::new(
            error_codes::DOMAIN_MISMATCH,
            format!("unknown hash-profile domain tag: {other}"),
        )),
    }
}

fn hash_profile_nf_payload(env_sig: &[u8; 32], uid: &[u8; 32], nf_bytes: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64 + nf_bytes.len());
    payload.extend_from_slice(env_sig);
    payload.extend_from_slice(uid);
    payload.extend_from_slice(nf_bytes);
    payload
}

pub fn hash_ref_from_digest(domain: &str, digest: [u8; 32], params_hash: [u8; 32]) -> Ref {
    Ref {
        scheme_id: HASH_SCHEME_ID.to_string(),
        params_hash,
        domain: domain.to_string(),
        digest: digest.to_vec(),
    }
}

pub fn merkle_ref_from_digest(domain: &str, digest: [u8; 32], params_hash: [u8; 32]) -> Ref {
    Ref {
        scheme_id: MERKLE_SCHEME_ID.to_string(),
        params_hash,
        domain: domain.to_string(),
        digest: digest.to_vec(),
    }
}

pub fn hash_cert_ref(node_bytes: &[u8], params_hash: [u8; 32]) -> Ref {
    hash_ref_from_digest(DOMAIN_NODE, cert_id(node_bytes), params_hash)
}

pub fn hash_obj_ref(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    obj_bytes: &[u8],
    params_hash: [u8; 32],
) -> Ref {
    hash_ref_from_digest(DOMAIN_OBJ_NF, h_obj(env_sig, uid, obj_bytes), params_hash)
}

pub fn hash_mor_ref(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    mor_bytes: &[u8],
    params_hash: [u8; 32],
) -> Ref {
    hash_ref_from_digest(DOMAIN_MOR_NF, h_mor(env_sig, uid, mor_bytes), params_hash)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreVerifiedNodeRef {
    pub cert_ref: Ref,
    pub sort: u8,
    pub opcode: u8,
    pub out: Ref,
    pub meta: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DepRecordRef {
    sort: u8,
    opcode: u8,
    out: Ref,
    meta: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreVerifyResultRef {
    pub root_cert_ref: Ref,
    pub env_sig: [u8; 32],
    pub uid: [u8; 32],
    pub nodes: Vec<CoreVerifiedNodeRef>,
    pub obj_overlay: BTreeMap<Ref, Vec<u8>>,
    pub mor_overlay: BTreeMap<Ref, Vec<u8>>,
}

fn out_domain_for_sort(sort: u8) -> &'static str {
    match sort {
        SORT_OBJ => DOMAIN_OBJ_NF,
        SORT_MOR => DOMAIN_MOR_NF,
        _ => DOMAIN_OPAQUE,
    }
}

fn dec_varint_contract(bytes: &[u8], cursor: &mut usize, field: &str) -> Result<u64, KcirV2Error> {
    let mut out: u64 = 0;
    let mut shift = 0u32;
    let mut steps = 0usize;
    loop {
        if *cursor >= bytes.len() {
            return Err(KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!("truncated varint for {field} at byte offset {}", *cursor),
            ));
        }
        let b = bytes[*cursor];
        *cursor += 1;
        steps += 1;
        if steps > 10 {
            return Err(KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!("overlong varint for {field}"),
            ));
        }
        let chunk = (b & 0x7F) as u64;
        if shift >= 64 || chunk.checked_shl(shift).is_none() {
            return Err(KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!("varint overflow for {field}"),
            ));
        }
        out |= chunk << shift;
        if (b & 0x80) == 0 {
            return Ok(out);
        }
        shift += 7;
    }
}

fn dec_list_u32_contract(bytes: &[u8], field: &str) -> Result<(Vec<u32>, usize), KcirV2Error> {
    let mut cursor = 0usize;
    let len = dec_varint_contract(bytes, &mut cursor, field)? as usize;
    let mut out = Vec::with_capacity(len);
    for idx in 0..len {
        let v = dec_varint_contract(bytes, &mut cursor, &format!("{field}[{idx}]"))?;
        let vv = u32::try_from(v).map_err(|_| {
            KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!("{field}[{idx}] out of range: {v}"),
            )
        })?;
        out.push(vv);
    }
    Ok((out, cursor))
}

fn dec_list_b32_contract(bytes: &[u8], field: &str) -> Result<(Vec<[u8; 32]>, usize), KcirV2Error> {
    let mut cursor = 0usize;
    let len = dec_varint_contract(bytes, &mut cursor, field)? as usize;
    let total_bytes = len
        .checked_mul(32)
        .ok_or_else(|| KcirV2Error::new(error_codes::PARSE_ERROR, format!("{field} overflow")))?;
    if cursor + total_bytes > bytes.len() {
        return Err(KcirV2Error::new(
            error_codes::PARSE_ERROR,
            format!(
                "{field} length {} runs past end of payload ({} bytes total)",
                len,
                bytes.len()
            ),
        ));
    }
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        out.push(h);
    }
    Ok((out, cursor))
}

fn contract_key_for_ref(
    wire_codec: &dyn WireCodec,
    reference: &Ref,
    label: &str,
) -> Result<[u8; 32], KcirV2Error> {
    wire_codec
        .contract_key_from_ref(reference, &reference.domain)
        .map_err(|e| {
            KcirV2Error::new(
                error_codes::DATA_UNAVAILABLE,
                format!(
                    "wire codec {} cannot project contract key for {}: {}",
                    wire_codec.wire_format_id(),
                    label,
                    e.message
                ),
            )
        })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PullCoverWitnessRef {
    w_sig: Ref,
    w_sig_key: [u8; 32],
    map_w_to_u: Vec<u32>,
    proj_id_keys: Vec<[u8; 32]>,
}

struct RefMapCoverBackend<'a> {
    backend: &'a dyn KcirBackend,
    wire_codec: &'a dyn WireCodec,
    profile_scheme_id: &'a str,
    profile_params_hash: [u8; 32],
}

impl<'a> RefMapCoverBackend<'a> {
    fn new(
        backend: &'a dyn KcirBackend,
        wire_codec: &'a dyn WireCodec,
        profile_scheme_id: &'a str,
        profile_params_hash: [u8; 32],
    ) -> Self {
        Self {
            backend,
            wire_codec,
            profile_scheme_id,
            profile_params_hash,
        }
    }

    fn key_for_ref(&self, reference: &Ref, label: &str) -> Result<[u8; 32], KcirV2Error> {
        contract_key_for_ref(self.wire_codec, reference, label)
    }

    fn opaque_ref_from_key(&self, key: [u8; 32], label: &str) -> Result<Ref, KcirV2Error> {
        self.wire_codec
            .ref_from_contract_key(
                self.profile_scheme_id,
                self.profile_params_hash,
                DOMAIN_OPAQUE,
                key,
            )
            .map_err(|e| {
                KcirV2Error::new(
                    error_codes::DATA_UNAVAILABLE,
                    format!(
                        "wire codec {} cannot lift contract key for {}: {}",
                        self.wire_codec.wire_format_id(),
                        label,
                        e.message
                    ),
                )
            })
    }

    fn refs_equal_by_key(
        &self,
        left: &Ref,
        left_label: &str,
        right: &Ref,
        right_label: &str,
    ) -> Result<bool, KcirV2Error> {
        let left_key = self.key_for_ref(left, left_label)?;
        let right_key = self.key_for_ref(right, right_label)?;
        Ok(left_key == right_key)
    }

    fn bc_square_from_keys(
        &self,
        push_id: [u8; 32],
        pull_id: [u8; 32],
    ) -> Result<Option<(Ref, Ref)>, KcirV2Error> {
        let Some((f_prime, p_prime)) = self.backend.bc_square(&push_id, &pull_id) else {
            return Ok(None);
        };
        let f_prime_ref = self.opaque_ref_from_key(f_prime, "MAP BC fPrime")?;
        let p_prime_ref = self.opaque_ref_from_key(p_prime, "MAP BC gPrime")?;
        Ok(Some((f_prime_ref, p_prime_ref)))
    }

    fn validate_cover_ref(&self, cover_ref: &Ref) -> Result<Option<bool>, KcirV2Error> {
        let cover_key = self.key_for_ref(cover_ref, "COVER validateCover input")?;
        Ok(self.backend.validate_cover(&cover_key))
    }

    fn cover_len_ref(&self, cover_ref: &Ref) -> Result<Option<u32>, KcirV2Error> {
        let cover_key = self.key_for_ref(cover_ref, "COVER coverLen input")?;
        Ok(self.backend.cover_len(&cover_key))
    }

    fn pull_cover_from_keys(
        &self,
        p_id: [u8; 32],
        u_sig: [u8; 32],
    ) -> Result<Option<PullCoverWitnessRef>, KcirV2Error> {
        let Some(witness) = self.backend.pull_cover(&p_id, &u_sig) else {
            return Ok(None);
        };
        let w_sig_ref = self.opaque_ref_from_key(witness.w_sig, "C_PULLCOVER witness wSig")?;
        let _proj_refs = witness
            .proj_ids
            .iter()
            .enumerate()
            .map(|(idx, key)| {
                self.opaque_ref_from_key(*key, &format!("C_PULLCOVER witness projIds[{idx}]"))
            })
            .collect::<Result<Vec<_>, KcirV2Error>>()?;
        Ok(Some(PullCoverWitnessRef {
            w_sig: w_sig_ref,
            w_sig_key: witness.w_sig,
            map_w_to_u: witness.map_w_to_u,
            proj_id_keys: witness.proj_ids,
        }))
    }
}

fn verify_map_opcode_contract_ref(
    node: &DecodedNodeRefs,
    deps: &[CoreVerifiedNodeRef],
    hooks: &RefMapCoverBackend<'_>,
) -> Result<BTreeMap<String, String>, KcirV2Error> {
    if node.sort != SORT_MAP {
        return Err(KcirV2Error::new(
            error_codes::CONTRACT_VIOLATION,
            format!(
                "MAP opcode contract requires sort=0x02, got 0x{:02x}",
                node.sort
            ),
        ));
    }
    match node.opcode {
        0x01 => {
            if !deps.is_empty() {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    "M_LITERAL expects no deps".to_string(),
                ));
            }
            if node.args.len() != 32 {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!(
                        "M_LITERAL expects 32-byte mapId args, got {} bytes",
                        node.args.len()
                    ),
                ));
            }
            let mut map_id = [0u8; 32];
            map_id.copy_from_slice(&node.args);
            let map_ref = hooks.opaque_ref_from_key(map_id, "M_LITERAL expected out")?;
            if !hooks.refs_equal_by_key(
                &node.out_ref,
                "M_LITERAL out",
                &map_ref,
                "M_LITERAL expected out",
            )? {
                let out = hooks.key_for_ref(&node.out_ref, "M_LITERAL out")?;
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!(
                        "M_LITERAL out mismatch: expected {}, got {}",
                        hex::encode(map_id),
                        hex::encode(out)
                    ),
                ));
            }
            let mut meta = BTreeMap::new();
            meta.insert("mapId".to_string(), hex::encode(map_id));
            Ok(meta)
        }
        M_BC_FPRIME | M_BC_GPRIME => {
            if !node.args.is_empty() {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!("MAP BC opcode 0x{:02x} expects empty args", node.opcode),
                ));
            }
            if deps.len() != 2 {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!(
                        "MAP BC opcode 0x{:02x} expects exactly 2 MAP deps, got {}",
                        node.opcode,
                        deps.len()
                    ),
                ));
            }
            if deps.iter().any(|d| d.sort != SORT_MAP) {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!(
                        "MAP BC opcode 0x{:02x} deps must all be MAP sort",
                        node.opcode
                    ),
                ));
            }
            let pull_id = hooks.key_for_ref(&deps[0].out, "MAP BC pull dep")?;
            let push_id = hooks.key_for_ref(&deps[1].out, "MAP BC push dep")?;
            let (f_prime, p_prime) =
                hooks
                    .bc_square_from_keys(push_id, pull_id)?
                    .ok_or_else(|| {
                        KcirV2Error::new(
                            error_codes::CONTRACT_VIOLATION,
                            format!(
                        "MAP BC opcode 0x{:02x} missing BaseApi.bcSquare for push={} pull={}",
                        node.opcode,
                        hex::encode(push_id),
                        hex::encode(pull_id)
                    ),
                        )
                    })?;
            let exp_out_ref = if node.opcode == M_BC_FPRIME {
                f_prime
            } else {
                p_prime
            };
            if !hooks.refs_equal_by_key(
                &node.out_ref,
                "MAP BC out",
                &exp_out_ref,
                "MAP BC expected out",
            )? {
                let out = hooks.key_for_ref(&node.out_ref, "MAP BC out")?;
                let exp_out = hooks.key_for_ref(&exp_out_ref, "MAP BC expected out")?;
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!(
                        "MAP BC opcode 0x{:02x} out mismatch: expected {}, got {}",
                        node.opcode,
                        hex::encode(exp_out),
                        hex::encode(out)
                    ),
                ));
            }
            let mut meta = BTreeMap::new();
            meta.insert("pullId".to_string(), hex::encode(pull_id));
            meta.insert("pushId".to_string(), hex::encode(push_id));
            Ok(meta)
        }
        other => Err(KcirV2Error::new(
            error_codes::UNSUPPORTED_OPCODE,
            format!("unsupported MAP opcode for this verifier slice: 0x{other:02x}"),
        )),
    }
}

fn verify_cover_opcode_contract_ref(
    node: &DecodedNodeRefs,
    deps: &[CoreVerifiedNodeRef],
    hooks: &RefMapCoverBackend<'_>,
) -> Result<BTreeMap<String, String>, KcirV2Error> {
    if node.sort != SORT_COVER {
        return Err(KcirV2Error::new(
            error_codes::CONTRACT_VIOLATION,
            format!(
                "COVER opcode contract requires sort=0x01, got 0x{:02x}",
                node.sort
            ),
        ));
    }
    match node.opcode {
        0x01 => {
            if !deps.is_empty() {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    "C_LITERAL expects no deps".to_string(),
                ));
            }
            if node.args.len() != 32 {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!(
                        "C_LITERAL expects 32-byte coverSig args, got {} bytes",
                        node.args.len()
                    ),
                ));
            }
            let mut cover_sig = [0u8; 32];
            cover_sig.copy_from_slice(&node.args);
            let cover_ref = hooks.opaque_ref_from_key(cover_sig, "C_LITERAL expected out")?;
            if !hooks.refs_equal_by_key(
                &node.out_ref,
                "C_LITERAL out",
                &cover_ref,
                "C_LITERAL expected out",
            )? {
                let out = hooks.key_for_ref(&node.out_ref, "C_LITERAL out")?;
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!(
                        "C_LITERAL out mismatch: expected {}, got {}",
                        hex::encode(cover_sig),
                        hex::encode(out)
                    ),
                ));
            }
            let valid = hooks.validate_cover_ref(&cover_ref)?.ok_or_else(|| {
                KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!(
                        "C_LITERAL requires BaseApi.validateCover hook for {}",
                        hex::encode(cover_sig)
                    ),
                )
            })?;
            if !valid {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!(
                        "C_LITERAL cover validation failed for {}",
                        hex::encode(cover_sig)
                    ),
                ));
            }
            let mut meta = BTreeMap::new();
            meta.insert("coverSig".to_string(), hex::encode(cover_sig));
            Ok(meta)
        }
        0x02 => {
            if deps.len() != 2 {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!("C_PULLCOVER expects exactly 2 deps, got {}", deps.len()),
                ));
            }
            let has_map = deps.iter().any(|d| d.sort == SORT_MAP);
            let has_cover = deps.iter().any(|d| d.sort == SORT_COVER);
            if !(has_map && has_cover) {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    "C_PULLCOVER deps must include one MAP dep and one COVER dep".to_string(),
                ));
            }
            let (map_dep, cover_dep) = if deps[0].sort == SORT_MAP {
                (&deps[0], &deps[1])
            } else {
                (&deps[1], &deps[0])
            };
            let (map_w_to_u, used1) = dec_list_u32_contract(&node.args, "C_PULLCOVER mapWtoU")?;
            let (proj_ids, used2) =
                dec_list_b32_contract(&node.args[used1..], "C_PULLCOVER projIds")?;
            if used1 + used2 != node.args.len() {
                return Err(KcirV2Error::new(
                    error_codes::PARSE_ERROR,
                    "C_PULLCOVER args contain trailing bytes".to_string(),
                ));
            }
            if map_w_to_u.len() != proj_ids.len() {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!(
                        "C_PULLCOVER args mismatch: mapWtoU len {} != projIds len {}",
                        map_w_to_u.len(),
                        proj_ids.len()
                    ),
                ));
            }
            let map_dep_out = hooks.key_for_ref(&map_dep.out, "C_PULLCOVER map dep")?;
            let u_sig = hooks.key_for_ref(&cover_dep.out, "C_PULLCOVER cover dep")?;
            let node_out = hooks.key_for_ref(&node.out_ref, "C_PULLCOVER out")?;
            let cover_len = hooks.cover_len_ref(&cover_dep.out)?.ok_or_else(|| {
                KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!(
                        "C_PULLCOVER missing BaseApi.coverLen for uSig={}",
                        hex::encode(u_sig)
                    ),
                )
            })?;
            for (idx, w_to_u) in map_w_to_u.iter().enumerate() {
                if *w_to_u >= cover_len {
                    return Err(KcirV2Error::new(
                        error_codes::CONTRACT_VIOLATION,
                        format!(
                            "C_PULLCOVER mapWtoU[{idx}]={} out of range for coverLen(uSig)={}",
                            w_to_u, cover_len
                        ),
                    ));
                }
            }
            let wit = hooks
                .pull_cover_from_keys(map_dep_out, u_sig)?
                .ok_or_else(|| {
                    KcirV2Error::new(
                        error_codes::CONTRACT_VIOLATION,
                        format!(
                            "C_PULLCOVER missing BaseApi.pullCover for pId={} uSig={}",
                            hex::encode(map_dep_out),
                            hex::encode(u_sig)
                        ),
                    )
                })?;
            if !hooks.refs_equal_by_key(
                &node.out_ref,
                "C_PULLCOVER out",
                &wit.w_sig,
                "C_PULLCOVER expected out",
            )? {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!(
                        "C_PULLCOVER out mismatch: expected {}, got {}",
                        hex::encode(wit.w_sig_key),
                        hex::encode(node_out)
                    ),
                ));
            }
            if map_w_to_u != wit.map_w_to_u {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    "C_PULLCOVER mapWtoU args mismatch against BaseApi.pullCover".to_string(),
                ));
            }
            if proj_ids != wit.proj_id_keys {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    "C_PULLCOVER projIds args mismatch against BaseApi.pullCover".to_string(),
                ));
            }
            let mut meta = BTreeMap::new();
            meta.insert("pId".to_string(), hex::encode(map_dep_out));
            meta.insert("uSig".to_string(), hex::encode(u_sig));
            meta.insert("wSig".to_string(), hex::encode(node_out));
            meta.insert("coverSig".to_string(), hex::encode(node_out));
            meta.insert(
                "mapWtoU".to_string(),
                map_w_to_u
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
            meta.insert(
                "projIds".to_string(),
                proj_ids
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>()
                    .join(","),
            );
            Ok(meta)
        }
        other => Err(KcirV2Error::new(
            error_codes::UNSUPPORTED_OPCODE,
            format!("unsupported COVER opcode for this verifier slice: 0x{other:02x}"),
        )),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DepRecordKey {
    sort: u8,
    opcode: u8,
    out: [u8; 32],
    meta: BTreeMap<String, String>,
}

impl DepRecordKey {
    fn as_dep_shape(&self) -> crate::dsl::DepShape {
        crate::dsl::DepShape {
            sort: self.sort,
            opcode: self.opcode,
            meta: self.meta.clone(),
        }
    }
}

fn dep_records_key_from_ref(
    dep_records: &[DepRecordRef],
    wire_codec: &dyn WireCodec,
) -> Result<Vec<DepRecordKey>, KcirV2Error> {
    dep_records
        .iter()
        .enumerate()
        .map(|(idx, dep)| {
            Ok(DepRecordKey {
                sort: dep.sort,
                opcode: dep.opcode,
                out: contract_key_for_ref(
                    wire_codec,
                    &dep.out,
                    &format!("dependency out ref[{idx}]"),
                )?,
                meta: dep.meta.clone(),
            })
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObjOpcodeVerifyResultRef {
    meta: BTreeMap<String, String>,
    overlay_obj_bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MorOpcodeVerifyResultRef {
    meta: BTreeMap<String, String>,
    overlay_mor_bytes: Option<Vec<u8>>,
}

fn enc_list_b32_contract(items: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + items.len() * 32);
    enc_varint_u64(items.len() as u64, &mut out);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

fn enforce_nf_canonicality_ref(backend: Option<&dyn KcirBackend>) -> bool {
    backend.is_some_and(KcirBackend::enforce_nf_canonicality)
}

fn adopt_pull_atom_mor_ref(backend: Option<&dyn KcirBackend>) -> bool {
    backend.is_some_and(KcirBackend::adopt_pull_atom_mor)
}

fn digest_obj_with_backend_ref(
    backend: Option<&dyn KcirBackend>,
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    obj_bytes: &[u8],
) -> [u8; 32] {
    if let Some(backend) = backend {
        backend.digest_obj_nf(env_sig, uid, obj_bytes)
    } else {
        h_obj(env_sig, uid, obj_bytes)
    }
}

fn digest_mor_with_backend_ref(
    backend: Option<&dyn KcirBackend>,
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    mor_bytes: &[u8],
) -> [u8; 32] {
    if let Some(backend) = backend {
        backend.digest_mor_nf(env_sig, uid, mor_bytes)
    } else {
        h_mor(env_sig, uid, mor_bytes)
    }
}

fn mor_endpoints_ref(m: &compat::MorNf) -> ([u8; 32], [u8; 32]) {
    match m {
        compat::MorNf::Id { src_h } => (*src_h, *src_h),
        compat::MorNf::Comp { src_h, tgt_h, .. } => (*src_h, *tgt_h),
        compat::MorNf::PullAtom { src_h, tgt_h, .. } => (*src_h, *tgt_h),
        compat::MorNf::PushAtom { src_h, tgt_h, .. } => (*src_h, *tgt_h),
        compat::MorNf::TensorAtom { src_h, tgt_h, .. } => (*src_h, *tgt_h),
        compat::MorNf::GlueAtom { src_h, tgt_h, .. } => (*src_h, *tgt_h),
    }
}

fn validate_mor_nf_canonical_ref(
    parsed: &compat::MorNf,
    mor_store: &dyn compat::MorNfStore,
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    enforce_hash: bool,
    hash_backend: Option<&dyn KcirBackend>,
    adopt_pull_atom_mor: bool,
) -> Result<(), String> {
    match parsed {
        compat::MorNf::Comp {
            src_h,
            tgt_h,
            parts,
        } => {
            if parts.len() <= 1 {
                return Err(format!(
                    "non-canonical MorNF Comp has {} part(s); canonical form requires len >= 2",
                    parts.len()
                ));
            }
            let mut all_parts_loaded = true;
            let mut part_endpoints = Vec::with_capacity(parts.len());
            for (idx, part_h) in parts.iter().enumerate() {
                let Some(part_bytes) = mor_store.mor_nf_bytes(part_h) else {
                    all_parts_loaded = false;
                    continue;
                };
                let part_nf = if enforce_hash {
                    let parsed =
                        compat::parse_mor_nf_bytes_with_options(&part_bytes, adopt_pull_atom_mor)?;
                    let got = digest_mor_with_backend_ref(hash_backend, env_sig, uid, &part_bytes);
                    if &got != part_h {
                        return Err(format!(
                            "MorNF hash mismatch: expected {}, got {}",
                            hex::encode(part_h),
                            hex::encode(got)
                        ));
                    }
                    parsed
                } else {
                    compat::parse_mor_nf_bytes_with_options(&part_bytes, adopt_pull_atom_mor)?
                };
                match part_nf {
                    compat::MorNf::Id { .. } => {
                        return Err(format!(
                            "non-canonical MorNF Comp contains Id part at index {idx}"
                        ));
                    }
                    compat::MorNf::Comp { .. } => {
                        return Err(format!(
                            "non-canonical MorNF Comp contains nested Comp part at index {idx}"
                        ));
                    }
                    other => {
                        part_endpoints.push(mor_endpoints_ref(&other));
                    }
                }
            }
            if all_parts_loaded && !part_endpoints.is_empty() {
                let exp_src = part_endpoints
                    .first()
                    .map(|(s, _)| *s)
                    .expect("non-empty checked");
                let exp_tgt = part_endpoints
                    .last()
                    .map(|(_, t)| *t)
                    .expect("non-empty checked");
                if *src_h != exp_src {
                    return Err(format!(
                        "non-canonical MorNF Comp srcH mismatch with first part src: expected {}, got {}",
                        hex::encode(exp_src),
                        hex::encode(src_h)
                    ));
                }
                if *tgt_h != exp_tgt {
                    return Err(format!(
                        "non-canonical MorNF Comp tgtH mismatch with last part tgt: expected {}, got {}",
                        hex::encode(exp_tgt),
                        hex::encode(tgt_h)
                    ));
                }
                for idx in 0..part_endpoints.len().saturating_sub(1) {
                    let left_tgt = part_endpoints[idx].1;
                    let right_src = part_endpoints[idx + 1].0;
                    if left_tgt != right_src {
                        return Err(format!(
                            "non-canonical MorNF Comp chain mismatch at idx {} -> {}: left tgt={} right src={}",
                            idx,
                            idx + 1,
                            hex::encode(left_tgt),
                            hex::encode(right_src)
                        ));
                    }
                }
            }
            Ok(())
        }
        compat::MorNf::PullAtom { inner_h, .. } => {
            if let Some(inner_bytes) = mor_store.mor_nf_bytes(inner_h) {
                let inner_nf = if enforce_hash {
                    let parsed =
                        compat::parse_mor_nf_bytes_with_options(&inner_bytes, adopt_pull_atom_mor)?;
                    let got = digest_mor_with_backend_ref(hash_backend, env_sig, uid, &inner_bytes);
                    if &got != inner_h {
                        return Err(format!(
                            "MorNF hash mismatch: expected {}, got {}",
                            hex::encode(inner_h),
                            hex::encode(got)
                        ));
                    }
                    parsed
                } else {
                    compat::parse_mor_nf_bytes_with_options(&inner_bytes, adopt_pull_atom_mor)?
                };
                if matches!(inner_nf, compat::MorNf::PullAtom { .. }) {
                    return Err(format!(
                        "non-canonical MorNF PullAtom nests PullAtom at innerH={}",
                        hex::encode(inner_h)
                    ));
                }
            }
            Ok(())
        }
        compat::MorNf::PushAtom { inner_h, .. } => {
            if let Some(inner_bytes) = mor_store.mor_nf_bytes(inner_h) {
                let inner_nf = if enforce_hash {
                    let parsed =
                        compat::parse_mor_nf_bytes_with_options(&inner_bytes, adopt_pull_atom_mor)?;
                    let got = digest_mor_with_backend_ref(hash_backend, env_sig, uid, &inner_bytes);
                    if &got != inner_h {
                        return Err(format!(
                            "MorNF hash mismatch: expected {}, got {}",
                            hex::encode(inner_h),
                            hex::encode(got)
                        ));
                    }
                    parsed
                } else {
                    compat::parse_mor_nf_bytes_with_options(&inner_bytes, adopt_pull_atom_mor)?
                };
                if matches!(inner_nf, compat::MorNf::PushAtom { .. }) {
                    return Err(format!(
                        "non-canonical MorNF PushAtom nests PushAtom at innerH={}",
                        hex::encode(inner_h)
                    ));
                }
            }
            Ok(())
        }
        compat::MorNf::TensorAtom { parts, .. } if parts.len() <= 1 => Err(format!(
            "non-canonical MorNF TensorAtom has {} part(s); canonical form requires len >= 2",
            parts.len()
        )),
        _ => Ok(()),
    }
}

fn parse_mor_nf_from_store_ref(
    mor_store: &dyn compat::MorNfStore,
    key: &[u8; 32],
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    enforce_hash: bool,
    hash_backend: Option<&dyn KcirBackend>,
    enforce_canonical: bool,
    adopt_pull_atom_mor: bool,
    label: &str,
) -> Result<compat::MorNf, String> {
    let mor_bytes = mor_store
        .mor_nf_bytes(key)
        .ok_or_else(|| format!("{label} requires morStore entry for {}", hex::encode(key)))?;
    let parsed = if enforce_hash {
        let parsed = compat::parse_mor_nf_bytes_with_options(&mor_bytes, adopt_pull_atom_mor)
            .map_err(|e| {
                format!(
                    "{label} morStore entry {} is not valid MorNF: {e}",
                    hex::encode(key)
                )
            })?;
        let got = digest_mor_with_backend_ref(hash_backend, env_sig, uid, &mor_bytes);
        if &got != key {
            return Err(format!(
                "{label} morStore entry {} failed hash/parse validation: MorNF hash mismatch: expected {}, got {}",
                hex::encode(key),
                hex::encode(key),
                hex::encode(got)
            ));
        }
        parsed
    } else {
        compat::parse_mor_nf_bytes_with_options(&mor_bytes, adopt_pull_atom_mor).map_err(|e| {
            format!(
                "{label} morStore entry {} is not valid MorNF: {e}",
                hex::encode(key)
            )
        })?
    };
    if enforce_canonical {
        validate_mor_nf_canonical_ref(
            &parsed,
            mor_store,
            env_sig,
            uid,
            enforce_hash,
            hash_backend,
            adopt_pull_atom_mor,
        )
        .map_err(|e| {
            format!(
                "{label} morStore entry {} canonicality validation failed: {e}",
                hex::encode(key)
            )
        })?;
    }
    Ok(parsed)
}

fn canonical_obj_tensor_out_ref(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    factors: &[[u8; 32]],
    hash_backend: Option<&dyn KcirBackend>,
) -> ([u8; 32], Option<Vec<u8>>) {
    match factors.len() {
        0 => {
            let obj_bytes = vec![0x01];
            (
                digest_obj_with_backend_ref(hash_backend, env_sig, uid, &obj_bytes),
                Some(obj_bytes),
            )
        }
        1 => (factors[0], None),
        _ => {
            let args = enc_list_b32_contract(factors);
            let mut obj_bytes = Vec::with_capacity(1 + args.len());
            obj_bytes.push(0x03);
            obj_bytes.extend_from_slice(&args);
            (
                digest_obj_with_backend_ref(hash_backend, env_sig, uid, &obj_bytes),
                Some(obj_bytes),
            )
        }
    }
}

fn canonicalize_comp_parts_ref(
    parts: &[[u8; 32]],
    mor_store: &dyn compat::MorNfStore,
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    enforce_hash: bool,
    hash_backend: Option<&dyn KcirBackend>,
    enforce_canonical: bool,
    adopt_pull_atom_mor: bool,
    label: &str,
) -> Result<Vec<[u8; 32]>, String> {
    let mut out = Vec::new();
    for part in parts {
        if mor_store.mor_nf_bytes(part).is_some() {
            match parse_mor_nf_from_store_ref(
                mor_store,
                part,
                env_sig,
                uid,
                enforce_hash,
                hash_backend,
                enforce_canonical,
                adopt_pull_atom_mor,
                label,
            )? {
                compat::MorNf::Id { .. } => {}
                compat::MorNf::Comp { parts: inner, .. } => out.extend(inner),
                _ => out.push(*part),
            }
        } else {
            out.push(*part);
        }
    }
    Ok(out)
}

fn parse_mor_args_src_tgt_parts_ref(
    args: &[u8],
    label: &str,
) -> Result<([u8; 32], [u8; 32], Vec<[u8; 32]>), String> {
    if args.len() < 64 {
        return Err(format!(
            "{label} expects at least 64-byte src/tgt args, got {} bytes",
            args.len()
        ));
    }
    let mut src_h = [0u8; 32];
    src_h.copy_from_slice(&args[0..32]);
    let mut tgt_h = [0u8; 32];
    tgt_h.copy_from_slice(&args[32..64]);
    let (parts, used) =
        dec_list_b32_contract(&args[64..], &format!("{label} parts")).map_err(|e| e.message)?;
    if 64 + used != args.len() {
        return Err(format!("{label} args contain trailing bytes"));
    }
    Ok((src_h, tgt_h, parts))
}

fn verify_obj_opcode_contract_ref_non_pull(
    node: &DecodedNodeRefs,
    deps: &[CoreVerifiedNodeRef],
    backend: &dyn KcirBackend,
    wire_codec: &dyn WireCodec,
) -> Result<ObjOpcodeVerifyResultRef, KcirV2Error> {
    if node.sort != SORT_OBJ {
        return Err(KcirV2Error::new(
            error_codes::CONTRACT_VIOLATION,
            format!(
                "OBJ opcode contract requires sort=0x03, got 0x{:02x}",
                node.sort
            ),
        ));
    }
    if node.opcode == O_PULL {
        return Err(KcirV2Error::new(
            error_codes::UNSUPPORTED_OPCODE,
            "O_PULL is not handled by ref-native OBJ non-pull verifier".to_string(),
        ));
    }
    if !deps.is_empty() {
        return Err(KcirV2Error::new(
            error_codes::CONTRACT_VIOLATION,
            format!(
                "OBJ non-pull opcode 0x{:02x} expects no deps, got {}",
                node.opcode,
                deps.len()
            ),
        ));
    }

    match node.opcode {
        O_UNIT => {
            if !node.args.is_empty() {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    "O_UNIT expects empty args".to_string(),
                ));
            }
            let obj_bytes = vec![0x01];
            let exp_out = backend.digest_obj_nf(&node.env_sig, &node.uid, &obj_bytes);
            let out = contract_key_for_ref(wire_codec, &node.out_ref, "O_UNIT out")?;
            if out != exp_out {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!(
                        "O_UNIT out mismatch: expected {}, got {}",
                        hex::encode(exp_out),
                        hex::encode(out)
                    ),
                ));
            }
            Ok(ObjOpcodeVerifyResultRef {
                meta: compat::obj_opcode_meta_to_dep_meta(&compat::ObjOpcodeMeta::Unit),
                overlay_obj_bytes: Some(obj_bytes),
            })
        }
        O_PRIM => {
            if node.args.len() != 32 {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!(
                        "O_PRIM expects 32-byte primId args, got {} bytes",
                        node.args.len()
                    ),
                ));
            }
            let mut prim_id = [0u8; 32];
            prim_id.copy_from_slice(&node.args);
            let mut obj_bytes = Vec::with_capacity(33);
            obj_bytes.push(0x02);
            obj_bytes.extend_from_slice(&prim_id);
            let exp_out = backend.digest_obj_nf(&node.env_sig, &node.uid, &obj_bytes);
            let out = contract_key_for_ref(wire_codec, &node.out_ref, "O_PRIM out")?;
            if out != exp_out {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!(
                        "O_PRIM out mismatch: expected {}, got {}",
                        hex::encode(exp_out),
                        hex::encode(out)
                    ),
                ));
            }
            Ok(ObjOpcodeVerifyResultRef {
                meta: compat::obj_opcode_meta_to_dep_meta(&compat::ObjOpcodeMeta::Prim { prim_id }),
                overlay_obj_bytes: Some(obj_bytes),
            })
        }
        O_MKTENSOR => {
            let (factors, used) = dec_list_b32_contract(&node.args, "O_MKTENSOR factors")?;
            if used != node.args.len() {
                return Err(KcirV2Error::new(
                    error_codes::PARSE_ERROR,
                    "O_MKTENSOR args contain trailing bytes".to_string(),
                ));
            }
            let (exp_out, overlay_obj_bytes) = match factors.len() {
                0 => {
                    let obj_bytes = vec![0x01];
                    (
                        backend.digest_obj_nf(&node.env_sig, &node.uid, &obj_bytes),
                        Some(obj_bytes),
                    )
                }
                1 => (factors[0], None),
                _ => {
                    let mut obj_bytes = Vec::with_capacity(1 + node.args.len());
                    obj_bytes.push(0x03);
                    obj_bytes.extend_from_slice(&node.args);
                    (
                        backend.digest_obj_nf(&node.env_sig, &node.uid, &obj_bytes),
                        Some(obj_bytes),
                    )
                }
            };
            let out = contract_key_for_ref(wire_codec, &node.out_ref, "O_MKTENSOR out")?;
            if out != exp_out {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!(
                        "O_MKTENSOR out mismatch: expected {}, got {}",
                        hex::encode(exp_out),
                        hex::encode(out)
                    ),
                ));
            }
            Ok(ObjOpcodeVerifyResultRef {
                meta: compat::obj_opcode_meta_to_dep_meta(&compat::ObjOpcodeMeta::MkTensor {
                    factors,
                }),
                overlay_obj_bytes,
            })
        }
        other => Err(KcirV2Error::new(
            error_codes::UNSUPPORTED_OPCODE,
            format!("unsupported OBJ opcode for ref-native non-pull verifier: 0x{other:02x}"),
        )),
    }
}

fn verify_mor_opcode_contract_ref_id(
    node: &DecodedNodeRefs,
    deps: &[CoreVerifiedNodeRef],
    backend: &dyn KcirBackend,
    wire_codec: &dyn WireCodec,
) -> Result<MorOpcodeVerifyResultRef, KcirV2Error> {
    if node.sort != SORT_MOR {
        return Err(KcirV2Error::new(
            error_codes::CONTRACT_VIOLATION,
            format!(
                "MOR opcode contract requires sort=0x04, got 0x{:02x}",
                node.sort
            ),
        ));
    }
    if node.opcode != M_ID {
        return Err(KcirV2Error::new(
            error_codes::UNSUPPORTED_OPCODE,
            format!(
                "only M_ID is handled by ref-native MOR verifier in this slice, got 0x{:02x}",
                node.opcode
            ),
        ));
    }
    if !deps.is_empty() {
        return Err(KcirV2Error::new(
            error_codes::CONTRACT_VIOLATION,
            format!("M_ID expects no deps, got {}", deps.len()),
        ));
    }
    if node.args.len() != 32 {
        return Err(KcirV2Error::new(
            error_codes::CONTRACT_VIOLATION,
            format!(
                "M_ID expects 32-byte srcH args, got {} bytes",
                node.args.len()
            ),
        ));
    }
    let mut src_h = [0u8; 32];
    src_h.copy_from_slice(&node.args);
    let mut mor_bytes = Vec::with_capacity(33);
    mor_bytes.push(0x11);
    mor_bytes.extend_from_slice(&src_h);
    let exp_out = backend.digest_mor_nf(&node.env_sig, &node.uid, &mor_bytes);
    let out = contract_key_for_ref(wire_codec, &node.out_ref, "M_ID out")?;
    if out != exp_out {
        return Err(KcirV2Error::new(
            error_codes::CONTRACT_VIOLATION,
            format!(
                "M_ID out mismatch: expected {}, got {}",
                hex::encode(exp_out),
                hex::encode(out)
            ),
        ));
    }
    Ok(MorOpcodeVerifyResultRef {
        meta: compat::mor_opcode_meta_to_dep_meta(&compat::MorOpcodeMeta::Id { src_h }),
        overlay_mor_bytes: Some(mor_bytes),
    })
}

fn verify_mor_opcode_contract_ref_non_pull(
    node: &DecodedNodeRefs,
    deps: &[CoreVerifiedNodeRef],
    backend: &dyn KcirBackend,
    wire_codec: &dyn WireCodec,
    mor_lookup: &dyn compat::MorNfStore,
) -> Result<MorOpcodeVerifyResultRef, KcirV2Error> {
    if node.sort != SORT_MOR {
        return Err(KcirV2Error::new(
            error_codes::CONTRACT_VIOLATION,
            format!(
                "MOR opcode contract requires sort=0x04, got 0x{:02x}",
                node.sort
            ),
        ));
    }
    if node.opcode == M_PULL {
        return Err(KcirV2Error::new(
            error_codes::UNSUPPORTED_OPCODE,
            "M_PULL is not handled by ref-native MOR non-pull verifier".to_string(),
        ));
    }

    match node.opcode {
        M_ID => verify_mor_opcode_contract_ref_id(node, deps, backend, wire_codec),
        M_MKTENSOR => {
            if !deps.is_empty() {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!("M_MKTENSOR expects no deps, got {}", deps.len()),
                ));
            }
            let (src_h, tgt_h, parts) = parse_mor_args_src_tgt_parts_ref(&node.args, "M_MKTENSOR")
                .map_err(|message| {
                    KcirV2Error::new(classify_legacy_core_error(&message), message)
                })?;
            let can_check_endpoints = parts
                .iter()
                .all(|part| mor_lookup.mor_nf_bytes(part).is_some());
            if can_check_endpoints {
                let mut src_factors = Vec::with_capacity(parts.len());
                let mut tgt_factors = Vec::with_capacity(parts.len());
                for part in &parts {
                    let parsed = parse_mor_nf_from_store_ref(
                        mor_lookup,
                        part,
                        &node.env_sig,
                        &node.uid,
                        true,
                        Some(backend),
                        enforce_nf_canonicality_ref(Some(backend)),
                        adopt_pull_atom_mor_ref(Some(backend)),
                        "M_MKTENSOR endpoint check",
                    )
                    .map_err(|message| {
                        KcirV2Error::new(classify_legacy_core_error(&message), message)
                    })?;
                    let (s, t) = mor_endpoints_ref(&parsed);
                    src_factors.push(s);
                    tgt_factors.push(t);
                }
                let (exp_src_h, _) = canonical_obj_tensor_out_ref(
                    &node.env_sig,
                    &node.uid,
                    &src_factors,
                    Some(backend),
                );
                let (exp_tgt_h, _) = canonical_obj_tensor_out_ref(
                    &node.env_sig,
                    &node.uid,
                    &tgt_factors,
                    Some(backend),
                );
                if src_h != exp_src_h {
                    return Err(KcirV2Error::new(
                        error_codes::CONTRACT_VIOLATION,
                        format!(
                            "M_MKTENSOR srcH mismatch with tensor(part.src): expected {}, got {}",
                            hex::encode(exp_src_h),
                            hex::encode(src_h)
                        ),
                    ));
                }
                if tgt_h != exp_tgt_h {
                    return Err(KcirV2Error::new(
                        error_codes::CONTRACT_VIOLATION,
                        format!(
                            "M_MKTENSOR tgtH mismatch with tensor(part.tgt): expected {}, got {}",
                            hex::encode(exp_tgt_h),
                            hex::encode(tgt_h)
                        ),
                    ));
                }
            }
            let mut mor_bytes = Vec::with_capacity(1 + node.args.len());
            mor_bytes.push(0x18);
            mor_bytes.extend_from_slice(&node.args);
            let exp_out =
                digest_mor_with_backend_ref(Some(backend), &node.env_sig, &node.uid, &mor_bytes);
            let out = contract_key_for_ref(wire_codec, &node.out_ref, "M_MKTENSOR out")?;
            if out != exp_out {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!(
                        "M_MKTENSOR out mismatch: expected {}, got {}",
                        hex::encode(exp_out),
                        hex::encode(out)
                    ),
                ));
            }
            Ok(MorOpcodeVerifyResultRef {
                meta: compat::mor_opcode_meta_to_dep_meta(&compat::MorOpcodeMeta::MkTensor {
                    src_h,
                    tgt_h,
                    parts,
                }),
                overlay_mor_bytes: Some(mor_bytes),
            })
        }
        M_MKCOMP => {
            if !deps.is_empty() {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!("M_MKCOMP expects no deps, got {}", deps.len()),
                ));
            }
            let (src_h, tgt_h, parts) = parse_mor_args_src_tgt_parts_ref(&node.args, "M_MKCOMP")
                .map_err(|message| {
                    KcirV2Error::new(classify_legacy_core_error(&message), message)
                })?;
            let canonical_parts = canonicalize_comp_parts_ref(
                &parts,
                mor_lookup,
                &node.env_sig,
                &node.uid,
                true,
                Some(backend),
                enforce_nf_canonicality_ref(Some(backend)),
                adopt_pull_atom_mor_ref(Some(backend)),
                "M_MKCOMP canonicalization",
            )
            .map_err(|message| KcirV2Error::new(classify_legacy_core_error(&message), message))?;
            let can_check_endpoints = !canonical_parts.is_empty()
                && canonical_parts
                    .iter()
                    .all(|part| mor_lookup.mor_nf_bytes(part).is_some());
            if can_check_endpoints {
                let mut part_endpoints = Vec::with_capacity(canonical_parts.len());
                for part in &canonical_parts {
                    let parsed = parse_mor_nf_from_store_ref(
                        mor_lookup,
                        part,
                        &node.env_sig,
                        &node.uid,
                        true,
                        Some(backend),
                        enforce_nf_canonicality_ref(Some(backend)),
                        adopt_pull_atom_mor_ref(Some(backend)),
                        "M_MKCOMP endpoint check",
                    )
                    .map_err(|message| {
                        KcirV2Error::new(classify_legacy_core_error(&message), message)
                    })?;
                    part_endpoints.push(mor_endpoints_ref(&parsed));
                }
                for idx in 0..part_endpoints.len().saturating_sub(1) {
                    let left_tgt = part_endpoints[idx].1;
                    let right_src = part_endpoints[idx + 1].0;
                    if left_tgt != right_src {
                        return Err(KcirV2Error::new(
                            error_codes::CONTRACT_VIOLATION,
                            format!(
                                "M_MKCOMP part chain mismatch at idx {} -> {}: left tgt={} right src={}",
                                idx,
                                idx + 1,
                                hex::encode(left_tgt),
                                hex::encode(right_src)
                            ),
                        ));
                    }
                }
                let exp_src_h = part_endpoints
                    .first()
                    .map(|(s, _)| *s)
                    .expect("non-empty checked");
                let exp_tgt_h = part_endpoints
                    .last()
                    .map(|(_, t)| *t)
                    .expect("non-empty checked");
                if src_h != exp_src_h {
                    return Err(KcirV2Error::new(
                        error_codes::CONTRACT_VIOLATION,
                        format!(
                            "M_MKCOMP srcH mismatch with comp(part.src): expected {}, got {}",
                            hex::encode(exp_src_h),
                            hex::encode(src_h)
                        ),
                    ));
                }
                if tgt_h != exp_tgt_h {
                    return Err(KcirV2Error::new(
                        error_codes::CONTRACT_VIOLATION,
                        format!(
                            "M_MKCOMP tgtH mismatch with comp(part.tgt): expected {}, got {}",
                            hex::encode(exp_tgt_h),
                            hex::encode(tgt_h)
                        ),
                    ));
                }
            }
            let (canonical_parts, exp_out, overlay_mor_bytes) = match canonical_parts.len() {
                0 => {
                    if src_h != tgt_h {
                        return Err(KcirV2Error::new(
                            error_codes::CONTRACT_VIOLATION,
                            format!(
                                "M_MKCOMP canonical 0-part case requires srcH == tgtH; got src={} tgt={}",
                                hex::encode(src_h),
                                hex::encode(tgt_h)
                            ),
                        ));
                    }
                    let mut mor_bytes = Vec::with_capacity(33);
                    mor_bytes.push(0x11);
                    mor_bytes.extend_from_slice(&src_h);
                    (
                        Vec::new(),
                        digest_mor_with_backend_ref(
                            Some(backend),
                            &node.env_sig,
                            &node.uid,
                            &mor_bytes,
                        ),
                        Some(mor_bytes),
                    )
                }
                1 => (canonical_parts.clone(), canonical_parts[0], None),
                _ => {
                    let args = enc_list_b32_contract(&canonical_parts);
                    let mut mor_bytes = Vec::with_capacity(1 + 64 + args.len());
                    mor_bytes.push(0x13);
                    mor_bytes.extend_from_slice(&src_h);
                    mor_bytes.extend_from_slice(&tgt_h);
                    mor_bytes.extend_from_slice(&args);
                    (
                        canonical_parts.clone(),
                        digest_mor_with_backend_ref(
                            Some(backend),
                            &node.env_sig,
                            &node.uid,
                            &mor_bytes,
                        ),
                        Some(mor_bytes),
                    )
                }
            };
            let out = contract_key_for_ref(wire_codec, &node.out_ref, "M_MKCOMP out")?;
            if out != exp_out {
                return Err(KcirV2Error::new(
                    error_codes::CONTRACT_VIOLATION,
                    format!(
                        "M_MKCOMP out mismatch: expected {}, got {}",
                        hex::encode(exp_out),
                        hex::encode(out)
                    ),
                ));
            }
            Ok(MorOpcodeVerifyResultRef {
                meta: compat::mor_opcode_meta_to_dep_meta(&compat::MorOpcodeMeta::MkComp {
                    src_h,
                    tgt_h,
                    parts: canonical_parts,
                }),
                overlay_mor_bytes,
            })
        }
        other => Err(KcirV2Error::new(
            error_codes::UNSUPPORTED_OPCODE,
            format!("unsupported MOR opcode for ref-native non-pull verifier: 0x{other:02x}"),
        )),
    }
}

fn ensure_dep_alignment_len_ref(
    dep_len: usize,
    deps: &[DepRecordKey],
    label: &str,
) -> Result<(), String> {
    if dep_len != deps.len() {
        return Err(format!(
            "{label} dependency metadata count mismatch: node has {} dep cert ids, verifier received {} dep records",
            dep_len,
            deps.len()
        ));
    }
    Ok(())
}

fn match_unique_role_ref(
    deps: &[DepRecordKey],
    pred: &crate::dsl::UniquePred,
    role_name: &str,
) -> Result<(DepRecordKey, Vec<DepRecordKey>), String> {
    let shapes = deps
        .iter()
        .map(DepRecordKey::as_dep_shape)
        .collect::<Vec<_>>();
    let matched =
        crate::dsl::match_unique_spec(&shapes, pred, crate::dsl::UniquePos::Anywhere, false)
            .map_err(|e| format!("role {role_name:?} match failed: {e}"))?;
    let Some(m) = matched else {
        return Err(format!("role {role_name:?} required match missing"));
    };
    let mut remaining = Vec::with_capacity(deps.len().saturating_sub(1));
    for (idx, dep) in deps.iter().enumerate() {
        if idx != m.matched_index {
            remaining.push(dep.clone());
        }
    }
    Ok((deps[m.matched_index].clone(), remaining))
}

fn parse_pull_args_ref(args: &[u8], label: &str) -> Result<([u8; 32], [u8; 32], u8), String> {
    if args.len() != 65 {
        return Err(format!(
            "{label} expects args pId(32)||inH(32)||stepTag(1), got {} bytes",
            args.len()
        ));
    }
    let mut p_id = [0u8; 32];
    p_id.copy_from_slice(&args[0..32]);
    let mut in_h = [0u8; 32];
    in_h.copy_from_slice(&args[32..64]);
    Ok((p_id, in_h, args[64]))
}

fn parse_csv_u32_ref(raw: &str, field: &str) -> Result<Vec<u32>, String> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for (idx, part) in raw.split(',').map(str::trim).enumerate() {
        if part.is_empty() {
            return Err(format!("{field}[{idx}] is empty"));
        }
        let v = part
            .parse::<u64>()
            .map_err(|e| format!("{field}[{idx}] invalid integer: {e}"))?;
        let vv = u32::try_from(v).map_err(|_| format!("{field}[{idx}] out of range: {v}"))?;
        out.push(vv);
    }
    Ok(out)
}

fn parse_csv_hex32_ref(raw: &str, field: &str) -> Result<Vec<[u8; 32]>, String> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for (idx, part) in raw.split(',').map(str::trim).enumerate() {
        if part.is_empty() {
            return Err(format!("{field}[{idx}] is empty"));
        }
        let bytes = hex::decode(part).map_err(|e| format!("{field}[{idx}] invalid hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "{field}[{idx}] must be 32 bytes (64 hex chars), got {} bytes",
                bytes.len()
            ));
        }
        let mut v = [0u8; 32];
        v.copy_from_slice(&bytes);
        out.push(v);
    }
    Ok(out)
}

fn parse_optional_dep_meta_hex32_ref(
    dep: &DepRecordKey,
    field: &str,
    label: &str,
) -> Result<Option<[u8; 32]>, String> {
    let Some(raw) = dep.meta.get(field) else {
        return Ok(None);
    };
    let bytes =
        hex::decode(raw).map_err(|e| format!("{label} dep meta.{field} invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "{label} dep meta.{field} must be 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(Some(out))
}

#[derive(Clone, Debug, Default)]
struct ObjPullDepMetaRef {
    p_id: Option<[u8; 32]>,
    in_obj_h: Option<[u8; 32]>,
}

impl ObjPullDepMetaRef {
    fn parse(dep: &DepRecordKey, label: &str) -> Result<Self, String> {
        Ok(Self {
            p_id: parse_optional_dep_meta_hex32_ref(dep, "pId", label)?,
            in_obj_h: parse_optional_dep_meta_hex32_ref(dep, "inObjH", label)?,
        })
    }

    fn require_p_id(&self, label: &str) -> Result<[u8; 32], String> {
        self.p_id
            .ok_or_else(|| format!("{label} dep requires meta.pId"))
    }

    fn require_in_obj_h(&self, label: &str) -> Result<[u8; 32], String> {
        self.in_obj_h
            .ok_or_else(|| format!("{label} dep requires meta.inObjH"))
    }
}

#[derive(Clone, Debug, Default)]
struct MorPullDepMetaRef {
    p_id: Option<[u8; 32]>,
    in_mor_h: Option<[u8; 32]>,
}

impl MorPullDepMetaRef {
    fn parse(dep: &DepRecordKey, label: &str) -> Result<Self, String> {
        Ok(Self {
            p_id: parse_optional_dep_meta_hex32_ref(dep, "pId", label)?,
            in_mor_h: parse_optional_dep_meta_hex32_ref(dep, "inMorH", label)?,
        })
    }
}

#[derive(Clone, Debug)]
struct CoverProjectionMetaRef {
    map_w_to_u: Vec<u32>,
    proj_ids: Vec<[u8; 32]>,
}

fn parse_cover_projection_meta_ref(
    cover_dep: &DepRecordKey,
    label: &str,
) -> Result<CoverProjectionMetaRef, String> {
    let map_w_to_u_raw = cover_dep
        .meta
        .get("mapWtoU")
        .ok_or_else(|| format!("{label} cover dep requires meta.mapWtoU"))?;
    let proj_ids_raw = cover_dep
        .meta
        .get("projIds")
        .ok_or_else(|| format!("{label} cover dep requires meta.projIds"))?;
    let map_w_to_u = parse_csv_u32_ref(map_w_to_u_raw, &format!("{label} mapWtoU"))?;
    let proj_ids = parse_csv_hex32_ref(proj_ids_raw, &format!("{label} projIds"))?;
    if proj_ids.len() != map_w_to_u.len() {
        return Err(format!(
            "{label} cover meta mismatch: projIds len {} != mapWtoU len {}",
            proj_ids.len(),
            map_w_to_u.len()
        ));
    }
    Ok(CoverProjectionMetaRef {
        map_w_to_u,
        proj_ids,
    })
}

fn expected_glue_keys_ref(
    cover_meta: &CoverProjectionMetaRef,
    locals_u: &[[u8; 32]],
    label: &str,
) -> Result<Vec<String>, String> {
    let mut expected = Vec::with_capacity(cover_meta.proj_ids.len());
    for (idx, proj) in cover_meta.proj_ids.iter().enumerate() {
        let u_idx = usize::try_from(cover_meta.map_w_to_u[idx])
            .map_err(|_| format!("{label} mapWtoU[{idx}] conversion overflow"))?;
        if u_idx >= locals_u.len() {
            return Err(format!(
                "{label} mapWtoU[{idx}]={} out of bounds for localsU len {}",
                cover_meta.map_w_to_u[idx],
                locals_u.len()
            ));
        }
        expected.push(format!(
            "{}:{}",
            hex::encode(proj),
            hex::encode(locals_u[u_idx])
        ));
    }
    Ok(expected)
}

#[derive(Copy, Clone, Debug)]
enum PullGlueMetaKindRef {
    Obj,
    Mor,
}

fn pull_dep_glue_key_ref(
    dep: &DepRecordKey,
    kind: PullGlueMetaKindRef,
    label: &str,
) -> Result<Option<String>, String> {
    match kind {
        PullGlueMetaKindRef::Obj => {
            let meta = ObjPullDepMetaRef::parse(dep, label)?;
            Ok(match (meta.p_id, meta.in_obj_h) {
                (Some(p), Some(i)) => Some(format!("{}:{}", hex::encode(p), hex::encode(i))),
                _ => None,
            })
        }
        PullGlueMetaKindRef::Mor => {
            let meta = MorPullDepMetaRef::parse(dep, label)?;
            Ok(match (meta.p_id, meta.in_mor_h) {
                (Some(p), Some(i)) => Some(format!("{}:{}", hex::encode(p), hex::encode(i))),
                _ => None,
            })
        }
    }
}

fn match_pull_glue_locals_ref(
    rem: &[DepRecordKey],
    sort: u8,
    opcode: u8,
    meta_kind: PullGlueMetaKindRef,
    expected_keys: &[String],
    label: &str,
) -> Result<Vec<[u8; 32]>, String> {
    let mut rem_shapes = Vec::with_capacity(rem.len());
    for dep in rem {
        let mut shape = dep.as_dep_shape();
        if let Some(glue_key) = pull_dep_glue_key_ref(dep, meta_kind, label)? {
            shape.meta.insert("glueKey".to_string(), glue_key);
        }
        rem_shapes.push(shape);
    }
    let role_locals = crate::dsl::UniquePred {
        sort: Some(sort),
        opcode: Some(opcode),
        meta_eq: BTreeMap::new(),
    };
    let bag = crate::dsl::match_bag_spec(
        &rem_shapes,
        &role_locals,
        &crate::dsl::KeySelector::Meta("glueKey".to_string()),
        expected_keys,
        crate::dsl::BagMode::Unordered,
        crate::dsl::UniquePos::Anywhere,
    )
    .map_err(|e| format!("{label} locals role match failed: {e}"))?;
    if !bag.remaining.is_empty() {
        return Err(format!(
            "{label} has unexpected extra deps after locals match: {}",
            bag.remaining.len()
        ));
    }
    Ok(bag
        .matched_indices
        .iter()
        .map(|idx| rem[*idx].out)
        .collect::<Vec<_>>())
}

fn hex_keys_ref(keys: &[[u8; 32]]) -> Vec<String> {
    keys.iter().map(hex::encode).collect()
}

fn classify_mor_pull_step_ref(
    p_id: &[u8; 32],
    in_mor_h: &[u8; 32],
    mor_store: &dyn compat::MorNfStore,
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    base_api: Option<&dyn KcirBackend>,
) -> Result<Option<u8>, String> {
    if let Some(api) = base_api {
        if api.is_id_map(p_id) {
            return Ok(Some(0x00));
        }
    }

    if mor_store.mor_nf_bytes(in_mor_h).is_none() {
        return Ok(None);
    }
    let nf = parse_mor_nf_from_store_ref(
        mor_store,
        in_mor_h,
        env_sig,
        uid,
        base_api.is_some(),
        base_api,
        enforce_nf_canonicality_ref(base_api),
        adopt_pull_atom_mor_ref(base_api),
        "M_PULL prelude",
    )?;
    let step = match nf {
        compat::MorNf::Id { .. } => 0x01,
        compat::MorNf::Comp { .. } => 0x02,
        compat::MorNf::PullAtom { .. } => 0x04,
        compat::MorNf::GlueAtom { .. } => 0x03,
        compat::MorNf::PushAtom { f_id, .. } => {
            if base_api.is_some_and(|api| api.bc_allowed(p_id, &f_id)) {
                0x05
            } else {
                0x07
            }
        }
        compat::MorNf::TensorAtom { .. } => 0x06,
    };
    Ok(Some(step))
}

fn mk_pull_atom_out_ref(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    p_id: [u8; 32],
    in_mor_h: [u8; 32],
    mor_store: &dyn compat::MorNfStore,
    base_api: Option<&dyn KcirBackend>,
) -> Result<([u8; 32], Option<Vec<u8>>), String> {
    if base_api.is_some_and(|api| api.is_id_map(&p_id)) {
        return Ok((in_mor_h, None));
    }

    let parsed = parse_mor_nf_from_store_ref(
        mor_store,
        &in_mor_h,
        env_sig,
        uid,
        base_api.is_some(),
        base_api,
        enforce_nf_canonicality_ref(base_api),
        adopt_pull_atom_mor_ref(base_api),
        "M_PULL.WRAP/FUSE",
    )?;

    if let compat::MorNf::PullAtom {
        src_h,
        tgt_h,
        p_id: inner_p,
        inner_h,
    } = parsed
    {
        let api = base_api
            .ok_or_else(|| "M_PULL.FUSE_PULLATOM requires BaseApi.composeMaps hook".to_string())?;
        let composed = api.compose_maps(&p_id, &inner_p).ok_or_else(|| {
            format!(
                "M_PULL.FUSE_PULLATOM missing composeMaps entry for outer={} inner={}",
                hex::encode(p_id),
                hex::encode(inner_p)
            )
        })?;
        if api.is_id_map(&composed) {
            return Ok((inner_h, None));
        }
        let mut mor_bytes = Vec::with_capacity(129);
        mor_bytes.push(0x16);
        mor_bytes.extend_from_slice(&src_h);
        mor_bytes.extend_from_slice(&tgt_h);
        mor_bytes.extend_from_slice(&composed);
        mor_bytes.extend_from_slice(&inner_h);
        return Ok((
            digest_mor_with_backend_ref(base_api, env_sig, uid, &mor_bytes),
            Some(mor_bytes),
        ));
    }

    let (src_h, tgt_h) = mor_endpoints_ref(&parsed);
    let mut mor_bytes = Vec::with_capacity(129);
    mor_bytes.push(0x16);
    mor_bytes.extend_from_slice(&src_h);
    mor_bytes.extend_from_slice(&tgt_h);
    mor_bytes.extend_from_slice(&p_id);
    mor_bytes.extend_from_slice(&in_mor_h);
    Ok((
        digest_mor_with_backend_ref(base_api, env_sig, uid, &mor_bytes),
        Some(mor_bytes),
    ))
}

fn validate_obj_nf_canonical_ref(
    parsed: &compat::ObjNf,
    obj_store: &dyn compat::ObjNfStore,
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    enforce_hash: bool,
    hash_backend: Option<&dyn KcirBackend>,
) -> Result<(), String> {
    match parsed {
        compat::ObjNf::Tensor(factors) if factors.len() <= 1 => Err(format!(
            "non-canonical ObjNF Tensor has {} factor(s); canonical form requires len >= 2",
            factors.len()
        )),
        compat::ObjNf::PullSpine { base_h, .. } => {
            if let Some(base_bytes) = obj_store.obj_nf_bytes(base_h) {
                let base_nf = if enforce_hash {
                    let parsed = compat::parse_obj_nf_bytes(&base_bytes)?;
                    let got = digest_obj_with_backend_ref(hash_backend, env_sig, uid, &base_bytes);
                    if &got != base_h {
                        return Err(format!(
                            "ObjNF hash mismatch: expected {}, got {}",
                            hex::encode(base_h),
                            hex::encode(got)
                        ));
                    }
                    parsed
                } else {
                    compat::parse_obj_nf_bytes(&base_bytes)?
                };
                if matches!(base_nf, compat::ObjNf::PullSpine { .. }) {
                    return Err(format!(
                        "non-canonical ObjNF PullSpine nests PullSpine at baseH={}",
                        hex::encode(base_h)
                    ));
                }
            }
            Ok(())
        }
        compat::ObjNf::PushSpine { base_h, .. } => {
            if let Some(base_bytes) = obj_store.obj_nf_bytes(base_h) {
                let base_nf = if enforce_hash {
                    let parsed = compat::parse_obj_nf_bytes(&base_bytes)?;
                    let got = digest_obj_with_backend_ref(hash_backend, env_sig, uid, &base_bytes);
                    if &got != base_h {
                        return Err(format!(
                            "ObjNF hash mismatch: expected {}, got {}",
                            hex::encode(base_h),
                            hex::encode(got)
                        ));
                    }
                    parsed
                } else {
                    compat::parse_obj_nf_bytes(&base_bytes)?
                };
                if matches!(base_nf, compat::ObjNf::PushSpine { .. }) {
                    return Err(format!(
                        "non-canonical ObjNF PushSpine nests PushSpine at baseH={}",
                        hex::encode(base_h)
                    ));
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn parse_obj_nf_from_store_ref(
    obj_store: &dyn compat::ObjNfStore,
    key: &[u8; 32],
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    enforce_hash: bool,
    hash_backend: Option<&dyn KcirBackend>,
    enforce_canonical: bool,
    label: &str,
) -> Result<compat::ObjNf, String> {
    let obj_bytes = obj_store
        .obj_nf_bytes(key)
        .ok_or_else(|| format!("{label} requires objStore entry for {}", hex::encode(key)))?;
    let parsed = if enforce_hash {
        let parsed = compat::parse_obj_nf_bytes(&obj_bytes).map_err(|e| {
            format!(
                "{label} objStore entry {} is not valid ObjNF: {e}",
                hex::encode(key)
            )
        })?;
        let got = digest_obj_with_backend_ref(hash_backend, env_sig, uid, &obj_bytes);
        if &got != key {
            return Err(format!(
                "{label} objStore entry {} failed hash/parse validation: ObjNF hash mismatch: expected {}, got {}",
                hex::encode(key),
                hex::encode(key),
                hex::encode(got)
            ));
        }
        parsed
    } else {
        compat::parse_obj_nf_bytes(&obj_bytes).map_err(|e| {
            format!(
                "{label} objStore entry {} is not valid ObjNF: {e}",
                hex::encode(key)
            )
        })?
    };
    if enforce_canonical {
        validate_obj_nf_canonical_ref(&parsed, obj_store, env_sig, uid, enforce_hash, hash_backend)
            .map_err(|e| {
                format!(
                    "{label} objStore entry {} canonicality validation failed: {e}",
                    hex::encode(key)
                )
            })?;
    }
    Ok(parsed)
}

fn classify_obj_pull_step_ref(
    p_id: &[u8; 32],
    in_obj_h: &[u8; 32],
    obj_store: &dyn compat::ObjNfStore,
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    base_api: Option<&dyn KcirBackend>,
) -> Result<Option<u8>, String> {
    if let Some(api) = base_api {
        if api.is_id_map(p_id) {
            return Ok(Some(0x00));
        }
    }

    if obj_store.obj_nf_bytes(in_obj_h).is_none() {
        return Ok(None);
    }
    let nf = parse_obj_nf_from_store_ref(
        obj_store,
        in_obj_h,
        env_sig,
        uid,
        base_api.is_some(),
        base_api,
        enforce_nf_canonicality_ref(base_api),
        "O_PULL prelude",
    )?;
    let step = match nf {
        compat::ObjNf::Unit => 0x01,
        compat::ObjNf::Tensor(_) => 0x02,
        compat::ObjNf::Glue { .. } => 0x03,
        compat::ObjNf::PullSpine { .. } => 0x04,
        compat::ObjNf::PushSpine { f_id, .. } => {
            if base_api.is_some_and(|api| api.bc_allowed(p_id, &f_id)) {
                0x05
            } else {
                0x06
            }
        }
        compat::ObjNf::Prim(_) => 0x06,
    };
    Ok(Some(step))
}

fn mk_pull_spine_out_ref(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    p_id: [u8; 32],
    in_obj_h: [u8; 32],
    obj_store: &dyn compat::ObjNfStore,
    base_api: Option<&dyn KcirBackend>,
) -> Result<([u8; 32], Option<Vec<u8>>), String> {
    if base_api.is_some_and(|api| api.is_id_map(&p_id)) {
        return Ok((in_obj_h, None));
    }

    if obj_store.obj_nf_bytes(&in_obj_h).is_some() {
        let parsed = parse_obj_nf_from_store_ref(
            obj_store,
            &in_obj_h,
            env_sig,
            uid,
            base_api.is_some(),
            base_api,
            enforce_nf_canonicality_ref(base_api),
            "O_PULL.WRAP/FUSE",
        )?;
        if let compat::ObjNf::PullSpine {
            p_id: inner_p,
            base_h,
        } = parsed
        {
            let api = base_api.ok_or_else(|| {
                "O_PULL.FUSE_PULLSPINE requires BaseApi.composeMaps hook".to_string()
            })?;
            let composed = api.compose_maps(&p_id, &inner_p).ok_or_else(|| {
                format!(
                    "O_PULL.FUSE_PULLSPINE missing composeMaps entry for outer={} inner={}",
                    hex::encode(p_id),
                    hex::encode(inner_p)
                )
            })?;
            if api.is_id_map(&composed) {
                return Ok((base_h, None));
            }
            let mut obj_bytes = Vec::with_capacity(65);
            obj_bytes.push(0x04);
            obj_bytes.extend_from_slice(&composed);
            obj_bytes.extend_from_slice(&base_h);
            return Ok((
                digest_obj_with_backend_ref(base_api, env_sig, uid, &obj_bytes),
                Some(obj_bytes),
            ));
        }
    }

    let mut obj_bytes = Vec::with_capacity(65);
    obj_bytes.push(0x04);
    obj_bytes.extend_from_slice(&p_id);
    obj_bytes.extend_from_slice(&in_obj_h);
    Ok((
        digest_obj_with_backend_ref(base_api, env_sig, uid, &obj_bytes),
        Some(obj_bytes),
    ))
}

fn verify_obj_pull_opcode_contract_core_ref(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    out: [u8; 32],
    args: &[u8],
    dep_len: usize,
    deps: &[DepRecordKey],
    obj_store: &dyn compat::ObjNfStore,
    base_api: Option<&dyn KcirBackend>,
) -> Result<ObjOpcodeVerifyResultRef, String> {
    ensure_dep_alignment_len_ref(dep_len, deps, "OBJ opcode contract")?;

    let (p_id, in_obj_h, step_tag) = parse_pull_args_ref(args, "O_PULL")?;
    if let Some(exp_step) =
        classify_obj_pull_step_ref(&p_id, &in_obj_h, obj_store, env_sig, uid, base_api)?
    {
        if step_tag != exp_step {
            return Err(format!(
                "O_PULL stepTag mismatch: expected 0x{exp_step:02x}, got 0x{step_tag:02x}"
            ));
        }
    }
    match step_tag {
        0x00 => {
            if !deps.is_empty() {
                return Err("O_PULL.ID expects no deps".to_string());
            }
            if out != in_obj_h {
                return Err(format!(
                    "O_PULL.ID out mismatch: expected {}, got {}",
                    hex::encode(in_obj_h),
                    hex::encode(out)
                ));
            }
            Ok(ObjOpcodeVerifyResultRef {
                meta: compat::obj_opcode_meta_to_dep_meta(&compat::ObjOpcodeMeta::PullId {
                    p_id,
                    in_obj_h,
                    step_tag,
                }),
                overlay_obj_bytes: None,
            })
        }
        0x01 => {
            if !deps.is_empty() {
                return Err("O_PULL.UNIT expects no deps".to_string());
            }
            let obj_bytes = vec![0x01];
            let exp_out = digest_obj_with_backend_ref(base_api, env_sig, uid, &obj_bytes);
            if out != exp_out {
                return Err(format!(
                    "O_PULL.UNIT out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(out)
                ));
            }
            Ok(ObjOpcodeVerifyResultRef {
                meta: compat::obj_opcode_meta_to_dep_meta(&compat::ObjOpcodeMeta::PullUnit {
                    p_id,
                    in_obj_h,
                    step_tag,
                }),
                overlay_obj_bytes: Some(obj_bytes),
            })
        }
        0x04 | 0x06 => {
            if !deps.is_empty() {
                return Err(format!("O_PULL stepTag=0x{step_tag:02x} expects no deps"));
            }
            let (exp_out, overlay_obj_bytes) =
                mk_pull_spine_out_ref(env_sig, uid, p_id, in_obj_h, obj_store, base_api)?;
            if out != exp_out {
                return Err(format!(
                    "O_PULL stepTag=0x{step_tag:02x} out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(out)
                ));
            }
            Ok(ObjOpcodeVerifyResultRef {
                meta: compat::obj_opcode_meta_to_dep_meta(&compat::ObjOpcodeMeta::PullWrap {
                    p_id,
                    in_obj_h,
                    step_tag,
                }),
                overlay_obj_bytes,
            })
        }
        0x02 => {
            let role_mk = crate::dsl::UniquePred {
                sort: Some(SORT_OBJ),
                opcode: Some(O_MKTENSOR),
                meta_eq: BTreeMap::new(),
            };
            let (mk_dep, rem) = match_unique_role_ref(deps, &role_mk, "mk")?;
            let in_obj_nf = parse_obj_nf_from_store_ref(
                obj_store,
                &in_obj_h,
                env_sig,
                uid,
                base_api.is_some(),
                base_api,
                enforce_nf_canonicality_ref(base_api),
                "O_PULL.TENSOR",
            )?;
            let expected_keys = match in_obj_nf {
                compat::ObjNf::Unit => Vec::new(),
                compat::ObjNf::Tensor(factors) => hex_keys_ref(&factors),
                other => {
                    return Err(format!(
                        "O_PULL.TENSOR requires inObjH to reference ObjNF Unit/Tensor, got {other:?}"
                    ));
                }
            };
            let mut factor_meta = BTreeMap::new();
            factor_meta.insert("pId".to_string(), hex::encode(p_id));
            let role_factors = crate::dsl::UniquePred {
                sort: Some(SORT_OBJ),
                opcode: Some(O_PULL),
                meta_eq: factor_meta,
            };
            let rem_shapes = rem.iter().map(DepRecordKey::as_dep_shape).collect::<Vec<_>>();
            let bag = crate::dsl::match_bag_spec(
                &rem_shapes,
                &role_factors,
                &crate::dsl::KeySelector::Meta("inObjH".to_string()),
                &expected_keys,
                crate::dsl::BagMode::Unordered,
                crate::dsl::UniquePos::Anywhere,
            )
            .map_err(|e| format!("O_PULL.TENSOR factors role match failed: {e}"))?;
            if !bag.remaining.is_empty() {
                return Err(format!(
                    "O_PULL.TENSOR has unexpected extra deps after factors match: {}",
                    bag.remaining.len()
                ));
            }
            let pulled_factors = bag
                .matched_indices
                .iter()
                .map(|idx| rem[*idx].out)
                .collect::<Vec<_>>();
            let (mk_exp_out, _) = canonical_obj_tensor_out_ref(env_sig, uid, &pulled_factors, base_api);
            if mk_dep.out != mk_exp_out {
                return Err(format!(
                    "O_PULL.TENSOR mk out mismatch: expected {}, got {}",
                    hex::encode(mk_exp_out),
                    hex::encode(mk_dep.out)
                ));
            }
            if let Some(raw) = mk_dep.meta.get("factors") {
                let mk_factors = parse_csv_hex32_ref(raw, "O_PULL.TENSOR mk.meta.factors")?;
                if mk_factors != pulled_factors {
                    return Err("O_PULL.TENSOR mk.meta.factors mismatch with pulled factors".to_string());
                }
            }
            if out != mk_dep.out {
                return Err(format!(
                    "O_PULL.TENSOR out mismatch: expected {}, got {}",
                    hex::encode(mk_dep.out),
                    hex::encode(out)
                ));
            }
            Ok(ObjOpcodeVerifyResultRef {
                meta: compat::obj_opcode_meta_to_dep_meta(&compat::ObjOpcodeMeta::PullTensor {
                    p_id,
                    in_obj_h,
                    step_tag,
                    mk_out: mk_dep.out,
                    pulled_factors,
                }),
                overlay_obj_bytes: None,
            })
        }
        0x03 => {
            let in_obj_nf = parse_obj_nf_from_store_ref(
                obj_store,
                &in_obj_h,
                env_sig,
                uid,
                base_api.is_some(),
                base_api,
                enforce_nf_canonicality_ref(base_api),
                "O_PULL.GLUE",
            )?;
            let (u_sig, locals_u) = match in_obj_nf {
                compat::ObjNf::Glue { w_sig, locals } => (w_sig, locals),
                other => {
                    return Err(format!(
                        "O_PULL.GLUE requires inObjH to reference ObjNF Glue, got {other:?}"
                    ));
                }
            };
            let role_cover = crate::dsl::UniquePred {
                sort: Some(SORT_COVER),
                opcode: Some(C_PULLCOVER),
                meta_eq: BTreeMap::new(),
            };
            let (cover_dep, rem) = match_unique_role_ref(deps, &role_cover, "cover")?;
            let cover_meta = parse_cover_projection_meta_ref(&cover_dep, "O_PULL.GLUE")?;
            let expected_keys = expected_glue_keys_ref(&cover_meta, &locals_u, "O_PULL.GLUE")?;
            let pulled_locals = match_pull_glue_locals_ref(
                &rem,
                SORT_OBJ,
                O_PULL,
                PullGlueMetaKindRef::Obj,
                &expected_keys,
                "O_PULL.GLUE",
            )?;
            let args = enc_list_b32_contract(&pulled_locals);
            let mut obj_bytes = Vec::with_capacity(1 + 32 + args.len());
            obj_bytes.push(0x06);
            obj_bytes.extend_from_slice(&cover_dep.out);
            obj_bytes.extend_from_slice(&args);
            let exp_out = digest_obj_with_backend_ref(base_api, env_sig, uid, &obj_bytes);
            if out != exp_out {
                return Err(format!(
                    "O_PULL.GLUE out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(out)
                ));
            }
            if u_sig == cover_dep.out {
                // no-op: reference retained via meta/provenance; equality not required by contract
            }
            Ok(ObjOpcodeVerifyResultRef {
                meta: compat::obj_opcode_meta_to_dep_meta(&compat::ObjOpcodeMeta::PullGlue {
                    p_id,
                    in_obj_h,
                    step_tag,
                    cover_out: cover_dep.out,
                    pulled_locals,
                }),
                overlay_obj_bytes: Some(obj_bytes),
            })
        }
        0x05 => {
            let role_fprime = crate::dsl::UniquePred {
                sort: Some(SORT_MAP),
                opcode: Some(M_BC_FPRIME),
                meta_eq: BTreeMap::new(),
            };
            let role_gprime = crate::dsl::UniquePred {
                sort: Some(SORT_MAP),
                opcode: Some(M_BC_GPRIME),
                meta_eq: BTreeMap::new(),
            };
            let role_base_pull = crate::dsl::UniquePred {
                sort: Some(SORT_OBJ),
                opcode: Some(O_PULL),
                meta_eq: BTreeMap::new(),
            };

            let (f_prime_dep, rem1) = match_unique_role_ref(deps, &role_fprime, "fPrime")?;
            let (g_prime_dep, rem2) = match_unique_role_ref(&rem1, &role_gprime, "gPrime")?;
            let (base_pull_dep, rem3) = match_unique_role_ref(&rem2, &role_base_pull, "basePull")?;
            if !rem3.is_empty() {
                return Err(format!(
                    "O_PULL.BC_PUSH has unexpected extra deps after role match: {}",
                    rem3.len()
                ));
            }
            let base_pull_meta = ObjPullDepMetaRef::parse(&base_pull_dep, "O_PULL.BC_PUSH basePull")?;
            if obj_store.obj_nf_bytes(&in_obj_h).is_some() {
                let in_nf = parse_obj_nf_from_store_ref(
                    obj_store,
                    &in_obj_h,
                    env_sig,
                    uid,
                    base_api.is_some(),
                    base_api,
                    enforce_nf_canonicality_ref(base_api),
                    "O_PULL.BC_PUSH",
                )?;
                let (f_id, base_h) = match in_nf {
                    compat::ObjNf::PushSpine { f_id, base_h } => (f_id, base_h),
                    other => {
                        return Err(format!(
                            "O_PULL.BC_PUSH requires inObjH to reference ObjNF PushSpine, got {other:?}"
                        ));
                    }
                };

                if let Some(base_pull_in) = base_pull_meta.in_obj_h {
                    if base_pull_in != base_h {
                        return Err(format!(
                            "O_PULL.BC_PUSH basePull meta.inObjH mismatch: expected {}, got {}",
                            hex::encode(base_h),
                            hex::encode(base_pull_in)
                        ));
                    }
                }

                if let Some(api) = base_api {
                    if api.has_bc_policy() && !api.bc_allowed(&p_id, &f_id) {
                        return Err(format!(
                            "O_PULL.BC_PUSH requires BCAllowed for pull={} push={}",
                            hex::encode(p_id),
                            hex::encode(f_id)
                        ));
                    }
                    if let Some((f_prime, p_prime)) = api.bc_square(&f_id, &p_id) {
                        if f_prime_dep.out != f_prime {
                            return Err(format!(
                                "O_PULL.BC_PUSH fPrime out mismatch: expected {}, got {}",
                                hex::encode(f_prime),
                                hex::encode(f_prime_dep.out)
                            ));
                        }
                        if g_prime_dep.out != p_prime {
                            return Err(format!(
                                "O_PULL.BC_PUSH gPrime out mismatch: expected {}, got {}",
                                hex::encode(p_prime),
                                hex::encode(g_prime_dep.out)
                            ));
                        }
                        if let Some(base_pull_pid) = base_pull_meta.p_id {
                            if base_pull_pid != p_prime {
                                return Err(format!(
                                    "O_PULL.BC_PUSH basePull meta.pId mismatch: expected {}, got {}",
                                    hex::encode(p_prime),
                                    hex::encode(base_pull_pid)
                                ));
                            }
                        }
                    }
                }
            }

            let mut obj_bytes = Vec::with_capacity(65);
            obj_bytes.push(0x05);
            obj_bytes.extend_from_slice(&f_prime_dep.out);
            obj_bytes.extend_from_slice(&base_pull_dep.out);
            let exp_out = digest_obj_with_backend_ref(base_api, env_sig, uid, &obj_bytes);
            if out != exp_out {
                return Err(format!(
                    "O_PULL.BC_PUSH out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(out)
                ));
            }

            Ok(ObjOpcodeVerifyResultRef {
                meta: compat::obj_opcode_meta_to_dep_meta(&compat::ObjOpcodeMeta::PullBcPush {
                    p_id,
                    in_obj_h,
                    step_tag,
                    f_prime_out: f_prime_dep.out,
                    g_prime_out: g_prime_dep.out,
                    base_pull_out: base_pull_dep.out,
                }),
                overlay_obj_bytes: Some(obj_bytes),
            })
        }
        _ => Err(format!(
            "O_PULL stepTag 0x{step_tag:02x} is unsupported in this verifier slice (supported: 0x00 ID, 0x01 UNIT, 0x02 TENSOR, 0x03 GLUE, 0x04 FUSE_PULLSPINE, 0x05 BC_PUSH, 0x06 WRAP)"
        )),
    }
}

fn verify_mor_pull_opcode_contract_core_ref(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    out: [u8; 32],
    args: &[u8],
    dep_len: usize,
    deps: &[DepRecordKey],
    mor_store: &dyn compat::MorNfStore,
    base_api: Option<&dyn KcirBackend>,
) -> Result<MorOpcodeVerifyResultRef, String> {
    ensure_dep_alignment_len_ref(dep_len, deps, "MOR opcode contract")?;

    let (p_id, in_mor_h, step_tag) = parse_pull_args_ref(args, "M_PULL")?;
    let pull_atom_enabled = adopt_pull_atom_mor_ref(base_api);
    if !pull_atom_enabled && (step_tag == 0x04 || step_tag == 0x07) {
        return Err(
            "M_PULL stepTag 0x04/0x07 (FUSE_PULLATOM/WRAP) requires MorNF PullAtom (tag 0x16), which is not adopted in this profile"
                .to_string(),
        );
    }
    let exp_step = classify_mor_pull_step_ref(&p_id, &in_mor_h, mor_store, env_sig, uid, base_api)?;
    if !pull_atom_enabled && exp_step == Some(0x07) {
        return Err(
            "M_PULL stepTag 0x04/0x07 (FUSE_PULLATOM/WRAP) requires MorNF PullAtom (tag 0x16), which is not adopted in this profile"
                .to_string(),
        );
    }
    if let Some(exp_step) = exp_step {
        if step_tag != exp_step {
            return Err(format!(
                "M_PULL stepTag mismatch: expected 0x{exp_step:02x}, got 0x{step_tag:02x}"
            ));
        }
    }
    match step_tag {
        0x00 => {
            if !deps.is_empty() {
                return Err("M_PULL.ID expects no deps".to_string());
            }
            if out != in_mor_h {
                return Err(format!(
                    "M_PULL.ID out mismatch: expected {}, got {}",
                    hex::encode(in_mor_h),
                    hex::encode(out)
                ));
            }
            Ok(MorOpcodeVerifyResultRef {
                meta: compat::mor_opcode_meta_to_dep_meta(&compat::MorOpcodeMeta::PullId {
                    p_id,
                    in_mor_h,
                    step_tag,
                }),
                overlay_mor_bytes: None,
            })
        }
        0x01 => {
            let in_nf = parse_mor_nf_from_store_ref(
                mor_store,
                &in_mor_h,
                env_sig,
                uid,
                base_api.is_some(),
                base_api,
                enforce_nf_canonicality_ref(base_api),
                adopt_pull_atom_mor_ref(base_api),
                "M_PULL.IDMOR",
            )?;
            let src_h = match in_nf {
                compat::MorNf::Id { src_h } => src_h,
                other => {
                    return Err(format!(
                        "M_PULL.IDMOR requires inMorH to reference MorNF Id, got {other:?}"
                    ));
                }
            };
            let role_src_pull = crate::dsl::UniquePred {
                sort: Some(SORT_OBJ),
                opcode: Some(O_PULL),
                meta_eq: BTreeMap::new(),
            };
            let (src_pull_dep, rem) = match_unique_role_ref(deps, &role_src_pull, "srcPull")?;
            if !rem.is_empty() {
                return Err(format!(
                    "M_PULL.IDMOR has unexpected extra deps after role match: {}",
                    rem.len()
                ));
            }
            let src_pull_meta = ObjPullDepMetaRef::parse(&src_pull_dep, "M_PULL.IDMOR srcPull")?;
            let src_pull_p = src_pull_meta.require_p_id("M_PULL.IDMOR srcPull")?;
            if src_pull_p != p_id {
                return Err(format!(
                    "M_PULL.IDMOR srcPull meta.pId mismatch: expected {}, got {}",
                    hex::encode(p_id),
                    hex::encode(src_pull_p)
                ));
            }
            let src_pull_in = src_pull_meta.require_in_obj_h("M_PULL.IDMOR srcPull")?;
            if src_pull_in != src_h {
                return Err(format!(
                    "M_PULL.IDMOR srcPull meta.inObjH mismatch: expected {}, got {}",
                    hex::encode(src_h),
                    hex::encode(src_pull_in)
                ));
            }
            let mut mor_bytes = Vec::with_capacity(33);
            mor_bytes.push(0x11);
            mor_bytes.extend_from_slice(&src_pull_dep.out);
            let exp_out = digest_mor_with_backend_ref(base_api, env_sig, uid, &mor_bytes);
            if out != exp_out {
                return Err(format!(
                    "M_PULL.IDMOR out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(out)
                ));
            }
            Ok(MorOpcodeVerifyResultRef {
                meta: compat::mor_opcode_meta_to_dep_meta(&compat::MorOpcodeMeta::PullIdMor {
                    p_id,
                    in_mor_h,
                    step_tag,
                    pulled_src_out: src_pull_dep.out,
                }),
                overlay_mor_bytes: Some(mor_bytes),
            })
        }
        0x04 | 0x07 => {
            if !deps.is_empty() {
                return Err(format!("M_PULL stepTag=0x{step_tag:02x} expects no deps"));
            }
            let (exp_out, overlay_mor_bytes) =
                mk_pull_atom_out_ref(env_sig, uid, p_id, in_mor_h, mor_store, base_api)?;
            if out != exp_out {
                return Err(format!(
                    "M_PULL stepTag=0x{step_tag:02x} out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(out)
                ));
            }
            Ok(MorOpcodeVerifyResultRef {
                meta: compat::mor_opcode_meta_to_dep_meta(&compat::MorOpcodeMeta::PullWrap {
                    p_id,
                    in_mor_h,
                    step_tag,
                }),
                overlay_mor_bytes,
            })
        }
        0x02 | 0x06 => {
            let mk_opcode = if step_tag == 0x02 {
                M_MKCOMP
            } else {
                M_MKTENSOR
            };
            let role_mk = crate::dsl::UniquePred {
                sort: Some(SORT_MOR),
                opcode: Some(mk_opcode),
                meta_eq: BTreeMap::new(),
            };
            let (mk_dep, rem) = match_unique_role_ref(deps, &role_mk, "mk")?;
            let in_mor_nf = parse_mor_nf_from_store_ref(
                mor_store,
                &in_mor_h,
                env_sig,
                uid,
                base_api.is_some(),
                base_api,
                enforce_nf_canonicality_ref(base_api),
                adopt_pull_atom_mor_ref(base_api),
                if step_tag == 0x02 {
                    "M_PULL.COMP"
                } else {
                    "M_PULL.TENSOR"
                },
            )?;
            let expected_keys = match (&in_mor_nf, step_tag) {
                (compat::MorNf::Id { .. }, 0x02) => Vec::new(),
                (compat::MorNf::Comp { parts, .. }, 0x02) => hex_keys_ref(parts),
                (compat::MorNf::TensorAtom { parts, .. }, 0x06) => hex_keys_ref(parts),
                (other, 0x02) => {
                    return Err(format!(
                        "M_PULL.COMP requires inMorH to reference MorNF Id/Comp, got {other:?}"
                    ));
                }
                (other, 0x06) => {
                    return Err(format!(
                        "M_PULL.TENSOR requires inMorH to reference MorNF TensorAtom, got {other:?}"
                    ));
                }
                _ => unreachable!("step tag guarded above"),
            };
            let mut part_meta = BTreeMap::new();
            part_meta.insert("pId".to_string(), hex::encode(p_id));
            let role_parts = crate::dsl::UniquePred {
                sort: Some(SORT_MOR),
                opcode: Some(M_PULL),
                meta_eq: part_meta,
            };
            let rem_shapes = rem.iter().map(DepRecordKey::as_dep_shape).collect::<Vec<_>>();
            let bag = crate::dsl::match_bag_spec(
                &rem_shapes,
                &role_parts,
                &crate::dsl::KeySelector::Meta("inMorH".to_string()),
                &expected_keys,
                crate::dsl::BagMode::Unordered,
                crate::dsl::UniquePos::Anywhere,
            )
            .map_err(|e| format!("M_PULL parts role match failed: {e}"))?;
            if !bag.remaining.is_empty() {
                return Err(format!(
                    "M_PULL stepTag=0x{step_tag:02x} has unexpected extra deps after parts match: {}",
                    bag.remaining.len()
                ));
            }
            let mut pulled_parts = Vec::with_capacity(bag.matched_indices.len());
            let mut part_endpoints = Vec::with_capacity(bag.matched_indices.len());
            for idx in &bag.matched_indices {
                let dep = &rem[*idx];
                let parsed = parse_mor_nf_from_store_ref(
                    mor_store,
                    &dep.out,
                    env_sig,
                    uid,
                    base_api.is_some(),
                    base_api,
                    enforce_nf_canonicality_ref(base_api),
                    adopt_pull_atom_mor_ref(base_api),
                    "M_PULL part dep",
                )?;
                pulled_parts.push(dep.out);
                part_endpoints.push(mor_endpoints_ref(&parsed));
            }
            if step_tag == 0x02 {
                let raw_pulled_parts = pulled_parts.clone();
                pulled_parts = canonicalize_comp_parts_ref(
                    &pulled_parts,
                    mor_store,
                    env_sig,
                    uid,
                    base_api.is_some(),
                    base_api,
                    enforce_nf_canonicality_ref(base_api),
                    adopt_pull_atom_mor_ref(base_api),
                    "M_PULL.COMP canonicalization",
                )?;
                if pulled_parts.is_empty() && !part_endpoints.is_empty() {
                    let src_h = part_endpoints
                        .first()
                        .map(|(s, _)| *s)
                        .expect("non-empty checked");
                    let tgt_h = part_endpoints
                        .last()
                        .map(|(_, t)| *t)
                        .expect("non-empty checked");
                    if src_h != tgt_h {
                        pulled_parts = raw_pulled_parts;
                    }
                }
            }

            let (exp_out, overlay_mor_bytes, meta) = if step_tag == 0x02 {
                let (exp_out, overlay_mor_bytes) = if pulled_parts.is_empty() {
                    let (src_h, tgt_h) = if part_endpoints.is_empty() {
                        mor_endpoints_ref(&in_mor_nf)
                    } else {
                        (
                            part_endpoints
                                .first()
                                .map(|(s, _)| *s)
                                .expect("non-empty checked"),
                            part_endpoints
                                .last()
                                .map(|(_, t)| *t)
                                .expect("non-empty checked"),
                        )
                    };
                    if src_h != tgt_h {
                        return Err(format!(
                            "M_PULL.COMP zero-part canonical case requires srcH == tgtH; got src={} tgt={}",
                            hex::encode(src_h),
                            hex::encode(tgt_h)
                        ));
                    }
                    let mut mor_bytes = Vec::with_capacity(33);
                    mor_bytes.push(0x11);
                    mor_bytes.extend_from_slice(&src_h);
                    (
                        digest_mor_with_backend_ref(base_api, env_sig, uid, &mor_bytes),
                        Some(mor_bytes),
                    )
                } else {
                    let src_h = part_endpoints
                        .first()
                        .map(|(s, _)| *s)
                        .expect("non-empty checked");
                    let tgt_h = part_endpoints
                        .last()
                        .map(|(_, t)| *t)
                        .expect("non-empty checked");
                    match pulled_parts.len() {
                        1 => (pulled_parts[0], None),
                        _ => {
                            let args = enc_list_b32_contract(&pulled_parts);
                            let mut mor_bytes = Vec::with_capacity(1 + 64 + args.len());
                            mor_bytes.push(0x13);
                            mor_bytes.extend_from_slice(&src_h);
                            mor_bytes.extend_from_slice(&tgt_h);
                            mor_bytes.extend_from_slice(&args);
                            (
                                digest_mor_with_backend_ref(base_api, env_sig, uid, &mor_bytes),
                                Some(mor_bytes),
                            )
                        }
                    }
                };
                (
                    exp_out,
                    overlay_mor_bytes,
                    compat::MorOpcodeMeta::PullComp {
                        p_id,
                        in_mor_h,
                        step_tag,
                        mk_out: mk_dep.out,
                        pulled_parts: pulled_parts.clone(),
                    },
                )
            } else {
                let src_factors = part_endpoints.iter().map(|(s, _)| *s).collect::<Vec<_>>();
                let tgt_factors = part_endpoints.iter().map(|(_, t)| *t).collect::<Vec<_>>();
                let (src_ten, _) = canonical_obj_tensor_out_ref(env_sig, uid, &src_factors, base_api);
                let (tgt_ten, _) = canonical_obj_tensor_out_ref(env_sig, uid, &tgt_factors, base_api);
                let args = enc_list_b32_contract(&pulled_parts);
                let mut mor_bytes = Vec::with_capacity(1 + 64 + args.len());
                mor_bytes.push(0x18);
                mor_bytes.extend_from_slice(&src_ten);
                mor_bytes.extend_from_slice(&tgt_ten);
                mor_bytes.extend_from_slice(&args);
                (
                    digest_mor_with_backend_ref(base_api, env_sig, uid, &mor_bytes),
                    Some(mor_bytes),
                    compat::MorOpcodeMeta::PullTensor {
                        p_id,
                        in_mor_h,
                        step_tag,
                        mk_out: mk_dep.out,
                        pulled_parts: pulled_parts.clone(),
                    },
                )
            };
            if mk_dep.out != exp_out {
                return Err(format!(
                    "M_PULL stepTag=0x{step_tag:02x} mk out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(mk_dep.out)
                ));
            }
            if let Some(raw) = mk_dep.meta.get("parts") {
                let mk_parts = parse_csv_hex32_ref(raw, "M_PULL mk.meta.parts")?;
                if mk_parts != pulled_parts {
                    return Err(format!(
                        "M_PULL stepTag=0x{step_tag:02x} mk.meta.parts mismatch with pulled parts"
                    ));
                }
            }
            if out != mk_dep.out {
                return Err(format!(
                    "M_PULL stepTag=0x{step_tag:02x} out mismatch: expected {}, got {}",
                    hex::encode(mk_dep.out),
                    hex::encode(out)
                ));
            }
            Ok(MorOpcodeVerifyResultRef {
                meta: compat::mor_opcode_meta_to_dep_meta(&meta),
                overlay_mor_bytes,
            })
        }
        0x03 => {
            let in_mor_nf = parse_mor_nf_from_store_ref(
                mor_store,
                &in_mor_h,
                env_sig,
                uid,
                base_api.is_some(),
                base_api,
                enforce_nf_canonicality_ref(base_api),
                adopt_pull_atom_mor_ref(base_api),
                "M_PULL.GLUE",
            )?;
            let (_src_u, _tgt_u, _u_sig, locals_u) = match in_mor_nf {
                compat::MorNf::GlueAtom {
                    src_h,
                    tgt_h,
                    w_sig,
                    locals,
                } => (src_h, tgt_h, w_sig, locals),
                other => {
                    return Err(format!(
                        "M_PULL.GLUE requires inMorH to reference MorNF GlueAtom, got {other:?}"
                    ));
                }
            };
            let role_cover = crate::dsl::UniquePred {
                sort: Some(SORT_COVER),
                opcode: Some(C_PULLCOVER),
                meta_eq: BTreeMap::new(),
            };
            let (cover_dep, rem) = match_unique_role_ref(deps, &role_cover, "cover")?;
            let cover_meta = parse_cover_projection_meta_ref(&cover_dep, "M_PULL.GLUE")?;
            let expected_keys = expected_glue_keys_ref(&cover_meta, &locals_u, "M_PULL.GLUE")?;
            let pulled_locals = match_pull_glue_locals_ref(
                &rem,
                SORT_MOR,
                M_PULL,
                PullGlueMetaKindRef::Mor,
                &expected_keys,
                "M_PULL.GLUE",
            )?;
            let mut src_locals = Vec::with_capacity(pulled_locals.len());
            let mut tgt_locals = Vec::with_capacity(pulled_locals.len());
            for h in &pulled_locals {
                let parsed = parse_mor_nf_from_store_ref(
                    mor_store,
                    h,
                    env_sig,
                    uid,
                    base_api.is_some(),
                    base_api,
                    enforce_nf_canonicality_ref(base_api),
                    adopt_pull_atom_mor_ref(base_api),
                    "M_PULL.GLUE local dep",
                )?;
                let (s, t) = mor_endpoints_ref(&parsed);
                src_locals.push(s);
                tgt_locals.push(t);
            }
            let src_args = enc_list_b32_contract(&src_locals);
            let mut src_obj = Vec::with_capacity(1 + 32 + src_args.len());
            src_obj.push(0x06);
            src_obj.extend_from_slice(&cover_dep.out);
            src_obj.extend_from_slice(&src_args);
            let src_glue = digest_obj_with_backend_ref(base_api, env_sig, uid, &src_obj);

            let tgt_args = enc_list_b32_contract(&tgt_locals);
            let mut tgt_obj = Vec::with_capacity(1 + 32 + tgt_args.len());
            tgt_obj.push(0x06);
            tgt_obj.extend_from_slice(&cover_dep.out);
            tgt_obj.extend_from_slice(&tgt_args);
            let tgt_glue = digest_obj_with_backend_ref(base_api, env_sig, uid, &tgt_obj);

            let locals_args = enc_list_b32_contract(&pulled_locals);
            let mut mor_bytes = Vec::with_capacity(1 + 96 + locals_args.len());
            mor_bytes.push(0x19);
            mor_bytes.extend_from_slice(&src_glue);
            mor_bytes.extend_from_slice(&tgt_glue);
            mor_bytes.extend_from_slice(&cover_dep.out);
            mor_bytes.extend_from_slice(&locals_args);
            let exp_out = digest_mor_with_backend_ref(base_api, env_sig, uid, &mor_bytes);
            if out != exp_out {
                return Err(format!(
                    "M_PULL.GLUE out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(out)
                ));
            }
            Ok(MorOpcodeVerifyResultRef {
                meta: compat::mor_opcode_meta_to_dep_meta(&compat::MorOpcodeMeta::PullGlue {
                    p_id,
                    in_mor_h,
                    step_tag,
                    cover_out: cover_dep.out,
                    pulled_locals,
                }),
                overlay_mor_bytes: Some(mor_bytes),
            })
        }
        0x05 => {
            let role_fprime = crate::dsl::UniquePred {
                sort: Some(SORT_MAP),
                opcode: Some(M_BC_FPRIME),
                meta_eq: BTreeMap::new(),
            };
            let role_gprime = crate::dsl::UniquePred {
                sort: Some(SORT_MAP),
                opcode: Some(M_BC_GPRIME),
                meta_eq: BTreeMap::new(),
            };
            let role_inner_pull = crate::dsl::UniquePred {
                sort: Some(SORT_MOR),
                opcode: Some(M_PULL),
                meta_eq: BTreeMap::new(),
            };

            let (f_prime_dep, rem1) = match_unique_role_ref(deps, &role_fprime, "fPrime")?;
            let (g_prime_dep, rem2) = match_unique_role_ref(&rem1, &role_gprime, "gPrime")?;
            let (inner_pull_dep, rem3) = match_unique_role_ref(&rem2, &role_inner_pull, "innerPull")?;
            if !rem3.is_empty() {
                return Err(format!(
                    "M_PULL.BC_SWAP has unexpected extra deps after role match: {}",
                    rem3.len()
                ));
            }
            let inner_pull_meta = MorPullDepMetaRef::parse(&inner_pull_dep, "M_PULL.BC_SWAP innerPull")?;
            if mor_store.mor_nf_bytes(&in_mor_h).is_some() {
                let in_nf = parse_mor_nf_from_store_ref(
                    mor_store,
                    &in_mor_h,
                    env_sig,
                    uid,
                    base_api.is_some(),
                    base_api,
                    enforce_nf_canonicality_ref(base_api),
                    adopt_pull_atom_mor_ref(base_api),
                    "M_PULL.BC_SWAP",
                )?;
                let (f_id, inner_h) = match in_nf {
                    compat::MorNf::PushAtom { f_id, inner_h, .. } => (f_id, inner_h),
                    other => {
                        return Err(format!(
                            "M_PULL.BC_SWAP requires inMorH to reference MorNF PushAtom, got {other:?}"
                        ));
                    }
                };
                if let Some(inner_pull_in) = inner_pull_meta.in_mor_h {
                    if inner_pull_in != inner_h {
                        return Err(format!(
                            "M_PULL.BC_SWAP innerPull meta.inMorH mismatch: expected {}, got {}",
                            hex::encode(inner_h),
                            hex::encode(inner_pull_in)
                        ));
                    }
                }
                if let Some(api) = base_api {
                    if api.has_bc_policy() && !api.bc_allowed(&p_id, &f_id) {
                        return Err(format!(
                            "M_PULL.BC_SWAP requires BCAllowed for pull={} push={}",
                            hex::encode(p_id),
                            hex::encode(f_id)
                        ));
                    }
                    if let Some((f_prime, p_prime)) = api.bc_square(&f_id, &p_id) {
                        if f_prime_dep.out != f_prime {
                            return Err(format!(
                                "M_PULL.BC_SWAP fPrime out mismatch: expected {}, got {}",
                                hex::encode(f_prime),
                                hex::encode(f_prime_dep.out)
                            ));
                        }
                        if g_prime_dep.out != p_prime {
                            return Err(format!(
                                "M_PULL.BC_SWAP gPrime out mismatch: expected {}, got {}",
                                hex::encode(p_prime),
                                hex::encode(g_prime_dep.out)
                            ));
                        }
                        if let Some(inner_pull_pid) = inner_pull_meta.p_id {
                            if inner_pull_pid != p_prime {
                                return Err(format!(
                                    "M_PULL.BC_SWAP innerPull meta.pId mismatch: expected {}, got {}",
                                    hex::encode(p_prime),
                                    hex::encode(inner_pull_pid)
                                ));
                            }
                        }
                    }
                }
            }

            let parsed_inner = parse_mor_nf_from_store_ref(
                mor_store,
                &inner_pull_dep.out,
                env_sig,
                uid,
                base_api.is_some(),
                base_api,
                enforce_nf_canonicality_ref(base_api),
                adopt_pull_atom_mor_ref(base_api),
                "M_PULL.BC_SWAP",
            )?;
            let (src_h, tgt_h) = mor_endpoints_ref(&parsed_inner);

            let mut mor_bytes = Vec::with_capacity(129);
            mor_bytes.push(0x17);
            mor_bytes.extend_from_slice(&src_h);
            mor_bytes.extend_from_slice(&tgt_h);
            mor_bytes.extend_from_slice(&f_prime_dep.out);
            mor_bytes.extend_from_slice(&inner_pull_dep.out);
            let exp_out = digest_mor_with_backend_ref(base_api, env_sig, uid, &mor_bytes);
            if out != exp_out {
                return Err(format!(
                    "M_PULL.BC_SWAP out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(out)
                ));
            }
            Ok(MorOpcodeVerifyResultRef {
                meta: compat::mor_opcode_meta_to_dep_meta(&compat::MorOpcodeMeta::PullBcSwap {
                    p_id,
                    in_mor_h,
                    step_tag,
                    f_prime_out: f_prime_dep.out,
                    g_prime_out: g_prime_dep.out,
                    inner_pull_out: inner_pull_dep.out,
                }),
                overlay_mor_bytes: Some(mor_bytes),
            })
        }
        _ => Err(format!(
            "M_PULL stepTag 0x{step_tag:02x} is unsupported in this verifier slice (supported: 0x00 ID, 0x01 IDMOR, 0x02 COMP, 0x03 GLUE, 0x04 FUSE_PULLATOM (capability-gated), 0x05 BC_SWAP, 0x06 TENSOR, 0x07 WRAP (capability-gated))"
        )),
    }
}

fn verify_obj_opcode_contract_ref_pull(
    node: &DecodedNodeRefs,
    dep_records_ref: &[DepRecordRef],
    backend: &dyn KcirBackend,
    wire_codec: &dyn WireCodec,
    obj_lookup: &dyn compat::ObjNfStore,
) -> Result<ObjOpcodeVerifyResultRef, KcirV2Error> {
    if node.sort != SORT_OBJ || node.opcode != O_PULL {
        return Err(KcirV2Error::new(
            error_codes::CONTRACT_VIOLATION,
            format!(
                "OBJ pull verifier requires sort=0x03 opcode=0x10, got sort=0x{:02x} opcode=0x{:02x}",
                node.sort, node.opcode
            ),
        ));
    }
    let out = contract_key_for_ref(wire_codec, &node.out_ref, "O_PULL out")?;
    let dep_records = dep_records_key_from_ref(dep_records_ref, wire_codec)?;
    verify_obj_pull_opcode_contract_core_ref(
        &node.env_sig,
        &node.uid,
        out,
        &node.args,
        dep_records.len(),
        &dep_records,
        obj_lookup,
        Some(backend),
    )
    .map_err(|message| KcirV2Error::new(classify_legacy_core_error(&message), message))
}

fn verify_mor_opcode_contract_ref_pull(
    node: &DecodedNodeRefs,
    dep_records_ref: &[DepRecordRef],
    backend: &dyn KcirBackend,
    wire_codec: &dyn WireCodec,
    mor_lookup: &dyn compat::MorNfStore,
) -> Result<MorOpcodeVerifyResultRef, KcirV2Error> {
    if node.sort != SORT_MOR || node.opcode != M_PULL {
        return Err(KcirV2Error::new(
            error_codes::CONTRACT_VIOLATION,
            format!(
                "MOR pull verifier requires sort=0x04 opcode=0x10, got sort=0x{:02x} opcode=0x{:02x}",
                node.sort, node.opcode
            ),
        ));
    }
    let out = contract_key_for_ref(wire_codec, &node.out_ref, "M_PULL out")?;
    let dep_records = dep_records_key_from_ref(dep_records_ref, wire_codec)?;
    verify_mor_pull_opcode_contract_core_ref(
        &node.env_sig,
        &node.uid,
        out,
        &node.args,
        dep_records.len(),
        &dep_records,
        mor_lookup,
        Some(backend),
    )
    .map_err(|message| KcirV2Error::new(classify_legacy_core_error(&message), message))
}

struct RefObjStoreView<'a> {
    profile_scheme_id: &'a str,
    profile_params_hash: [u8; 32],
    wire_codec: &'a dyn WireCodec,
    ref_store: &'a dyn KcirRefStore,
    overlay: &'a BTreeMap<Ref, Vec<u8>>,
}

impl RefObjStoreView<'_> {
    fn make_ref(&self, domain: &str, digest: [u8; 32]) -> Option<Ref> {
        self.wire_codec
            .ref_from_contract_key(
                self.profile_scheme_id,
                self.profile_params_hash,
                domain,
                digest,
            )
            .ok()
    }
}

impl compat::ObjNfStore for RefObjStoreView<'_> {
    fn obj_nf_bytes(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        let reference = self.make_ref(DOMAIN_OBJ_NF, *key)?;
        if let Some(overlay) = self.overlay.get(&reference) {
            return Some(overlay.clone());
        }
        self.ref_store
            .get_obj_nf(&reference)
            .map(|(bytes, _)| bytes)
    }
}

struct RefMorStoreView<'a> {
    profile_scheme_id: &'a str,
    profile_params_hash: [u8; 32],
    wire_codec: &'a dyn WireCodec,
    ref_store: &'a dyn KcirRefStore,
    overlay: &'a BTreeMap<Ref, Vec<u8>>,
}

impl RefMorStoreView<'_> {
    fn make_ref(&self, domain: &str, digest: [u8; 32]) -> Option<Ref> {
        self.wire_codec
            .ref_from_contract_key(
                self.profile_scheme_id,
                self.profile_params_hash,
                domain,
                digest,
            )
            .ok()
    }
}

impl compat::MorNfStore for RefMorStoreView<'_> {
    fn mor_nf_bytes(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        let reference = self.make_ref(DOMAIN_MOR_NF, *key)?;
        if let Some(overlay) = self.overlay.get(&reference) {
            return Some(overlay.clone());
        }
        self.ref_store
            .get_mor_nf(&reference)
            .map(|(bytes, _)| bytes)
    }
}

fn payload_bytes_for_profile(
    profile: &dyn VerifierProfile,
    domain: &str,
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    raw_payload: &[u8],
) -> Vec<u8> {
    // Transitional adapter for hash-profile domain equations that bind env_sig/uid
    // into NF payloads. Other profiles consume raw payload bytes directly.
    if profile.scheme_id() == HASH_SCHEME_ID && (domain == DOMAIN_OBJ_NF || domain == DOMAIN_MOR_NF)
    {
        return hash_profile_nf_payload(env_sig, uid, raw_payload);
    }
    raw_payload.to_vec()
}

fn legacy_digest_for_profile(
    profile: &dyn VerifierProfile,
    domain: &str,
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    payload_bytes: &[u8],
) -> [u8; 32] {
    match profile.scheme_id() {
        HASH_SCHEME_ID => match domain {
            DOMAIN_NODE => cert_id(payload_bytes),
            DOMAIN_OBJ_NF => h_obj(env_sig, uid, payload_bytes),
            DOMAIN_MOR_NF => h_mor(env_sig, uid, payload_bytes),
            _ => cert_id(payload_bytes),
        },
        MERKLE_SCHEME_ID => {
            let merkle = MerkleProfile::new(profile.params_hash());
            merkle
                .leaf_hash(domain, payload_bytes)
                .expect("known KCIR domains must hash under Merkle profile")
        }
        _ => cert_id(payload_bytes),
    }
}

struct ProfileDigestBackend<'a> {
    hooks: &'a dyn KcirBackend,
    profile: &'a dyn VerifierProfile,
}

impl KcirBackend for ProfileDigestBackend<'_> {
    fn digest_node(&self, node_bytes: &[u8]) -> [u8; 32] {
        match self.profile.scheme_id() {
            HASH_SCHEME_ID | MERKLE_SCHEME_ID => legacy_digest_for_profile(
                self.profile,
                DOMAIN_NODE,
                &[0u8; 32],
                &[0u8; 32],
                node_bytes,
            ),
            _ => self.hooks.digest_node(node_bytes),
        }
    }

    fn digest_obj_nf(&self, env_sig: &[u8; 32], uid: &[u8; 32], obj_bytes: &[u8]) -> [u8; 32] {
        match self.profile.scheme_id() {
            HASH_SCHEME_ID | MERKLE_SCHEME_ID => {
                legacy_digest_for_profile(self.profile, DOMAIN_OBJ_NF, env_sig, uid, obj_bytes)
            }
            _ => self.hooks.digest_obj_nf(env_sig, uid, obj_bytes),
        }
    }

    fn digest_mor_nf(&self, env_sig: &[u8; 32], uid: &[u8; 32], mor_bytes: &[u8]) -> [u8; 32] {
        match self.profile.scheme_id() {
            HASH_SCHEME_ID | MERKLE_SCHEME_ID => {
                legacy_digest_for_profile(self.profile, DOMAIN_MOR_NF, env_sig, uid, mor_bytes)
            }
            _ => self.hooks.digest_mor_nf(env_sig, uid, mor_bytes),
        }
    }

    fn is_id_map(&self, map_id: &[u8; 32]) -> bool {
        self.hooks.is_id_map(map_id)
    }

    fn compose_maps(&self, outer: &[u8; 32], inner: &[u8; 32]) -> Option<[u8; 32]> {
        self.hooks.compose_maps(outer, inner)
    }

    fn bc_square(&self, push_id: &[u8; 32], pull_id: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
        self.hooks.bc_square(push_id, pull_id)
    }

    fn bc_allowed(&self, pull_id: &[u8; 32], push_id: &[u8; 32]) -> bool {
        self.hooks.bc_allowed(pull_id, push_id)
    }

    fn has_bc_policy(&self) -> bool {
        self.hooks.has_bc_policy()
    }

    fn validate_cover(&self, cover_sig: &[u8; 32]) -> Option<bool> {
        self.hooks.validate_cover(cover_sig)
    }

    fn cover_len(&self, cover_sig: &[u8; 32]) -> Option<u32> {
        self.hooks.cover_len(cover_sig)
    }

    fn pull_cover(&self, p_id: &[u8; 32], u_sig: &[u8; 32]) -> Option<PullCoverWitness> {
        self.hooks.pull_cover(p_id, u_sig)
    }

    fn adopt_pull_atom_mor(&self) -> bool {
        self.hooks.adopt_pull_atom_mor()
    }

    fn enforce_nf_canonicality(&self) -> bool {
        self.hooks.enforce_nf_canonicality()
    }
}

struct CoreVerifyCtxRef<'a> {
    store: &'a dyn KcirRefStore,
    backend: &'a dyn KcirBackend,
    profile: &'a dyn VerifierProfile,
    wire_codec: &'a dyn WireCodec,
    anchors: Option<&'a ProfileAnchors>,
    profile_scheme_id: &'a str,
    profile_params_hash: [u8; 32],
    root_env_sig: [u8; 32],
    root_uid: [u8; 32],
    memo: BTreeMap<Ref, CoreVerifiedNodeRef>,
    visiting: BTreeSet<Ref>,
    obj_overlay: BTreeMap<Ref, Vec<u8>>,
    mor_overlay: BTreeMap<Ref, Vec<u8>>,
}

impl CoreVerifyCtxRef<'_> {
    fn dep_record_ref(&self, dep: &CoreVerifiedNodeRef) -> DepRecordRef {
        DepRecordRef {
            sort: dep.sort,
            opcode: dep.opcode,
            out: dep.out.clone(),
            meta: dep.meta.clone(),
        }
    }

    fn verify_nf_out_ref(&self, out_ref: &Ref, sort: u8) -> Result<(), KcirV2Error> {
        match sort {
            SORT_OBJ => {
                let (obj_payload_source, obj_evidence) =
                    if let Some((bytes, evidence)) = self.store.get_obj_nf(out_ref) {
                        (bytes, evidence)
                    } else if let Some(overlay) = self.obj_overlay.get(out_ref) {
                        (overlay.clone(), None)
                    } else {
                        return Err(KcirV2Error::new(
                            error_codes::STORE_MISSING_OBJ_NF,
                            format!(
                                "missing ObjNF bytes for profile verification of out {}",
                                hex::encode(&out_ref.digest)
                            ),
                        ));
                    };
                let payload = payload_bytes_for_profile(
                    self.profile,
                    DOMAIN_OBJ_NF,
                    &self.root_env_sig,
                    &self.root_uid,
                    &obj_payload_source,
                );
                self.profile.verify_ref_with_anchors(
                    out_ref,
                    &payload,
                    obj_evidence.as_deref(),
                    self.anchors,
                    DOMAIN_OBJ_NF,
                )
            }
            SORT_MOR => {
                let (mor_payload_source, mor_evidence) =
                    if let Some((bytes, evidence)) = self.store.get_mor_nf(out_ref) {
                        (bytes, evidence)
                    } else if let Some(overlay) = self.mor_overlay.get(out_ref) {
                        (overlay.clone(), None)
                    } else {
                        return Err(KcirV2Error::new(
                            error_codes::STORE_MISSING_MOR_NF,
                            format!(
                                "missing MorNF bytes for profile verification of out {}",
                                hex::encode(&out_ref.digest)
                            ),
                        ));
                    };
                let payload = payload_bytes_for_profile(
                    self.profile,
                    DOMAIN_MOR_NF,
                    &self.root_env_sig,
                    &self.root_uid,
                    &mor_payload_source,
                );
                self.profile.verify_ref_with_anchors(
                    out_ref,
                    &payload,
                    mor_evidence.as_deref(),
                    self.anchors,
                    DOMAIN_MOR_NF,
                )
            }
            _ => Ok(()),
        }
    }

    fn verify_node(&mut self, cert_ref: Ref) -> Result<CoreVerifiedNodeRef, KcirV2Error> {
        if let Some(v) = self.memo.get(&cert_ref) {
            return Ok(v.clone());
        }
        if !self.visiting.insert(cert_ref.clone()) {
            return Err(KcirV2Error::new(
                error_codes::DEP_CYCLE,
                format!(
                    "KCIR dependency cycle detected at cert {}",
                    hex::encode(&cert_ref.digest)
                ),
            ));
        }

        let (node_bytes, node_evidence) = self.store.get_node(&cert_ref).ok_or_else(|| {
            KcirV2Error::new(
                error_codes::STORE_MISSING_NODE,
                format!(
                    "missing KCIR node bytes for cert ref {}",
                    hex::encode(&cert_ref.digest)
                ),
            )
        })?;
        self.profile.verify_ref_with_anchors(
            &cert_ref,
            &node_bytes,
            node_evidence.as_deref(),
            self.anchors,
            DOMAIN_NODE,
        )?;
        let node = self.wire_codec.decode_node_refs(
            &node_bytes,
            self.profile_scheme_id,
            self.profile_params_hash,
        )?;
        if node.env_sig != self.root_env_sig {
            return Err(KcirV2Error::new(
                error_codes::ENV_UID_MISMATCH,
                format!(
                    "envSig mismatch at node {}: expected {}, got {}",
                    hex::encode(&cert_ref.digest),
                    hex::encode(self.root_env_sig),
                    hex::encode(node.env_sig)
                ),
            ));
        }
        if node.uid != self.root_uid {
            return Err(KcirV2Error::new(
                error_codes::ENV_UID_MISMATCH,
                format!(
                    "Uid mismatch at node {}: expected {}, got {}",
                    hex::encode(&cert_ref.digest),
                    hex::encode(self.root_uid),
                    hex::encode(node.uid)
                ),
            ));
        }

        let mut dep_nodes = Vec::with_capacity(node.dep_refs.len());
        for dep_ref in &node.dep_refs {
            dep_nodes.push(self.verify_node(dep_ref.clone())?);
        }

        let out_ref = node.out_ref.clone();
        let map_cover_hooks = RefMapCoverBackend::new(
            self.backend,
            self.wire_codec,
            self.profile_scheme_id,
            self.profile_params_hash,
        );
        let meta = match node.sort {
            SORT_OBJ => {
                let dep_records_ref = dep_nodes
                    .iter()
                    .map(|dep| self.dep_record_ref(dep))
                    .collect::<Vec<_>>();
                let obj_lookup = RefObjStoreView {
                    profile_scheme_id: self.profile_scheme_id,
                    profile_params_hash: self.profile_params_hash,
                    wire_codec: self.wire_codec,
                    ref_store: self.store,
                    overlay: &self.obj_overlay,
                };
                let verified = if node.opcode == O_PULL {
                    verify_obj_opcode_contract_ref_pull(
                        &node,
                        &dep_records_ref,
                        self.backend,
                        self.wire_codec,
                        &obj_lookup,
                    )?
                } else {
                    verify_obj_opcode_contract_ref_non_pull(
                        &node,
                        &dep_nodes,
                        self.backend,
                        self.wire_codec,
                    )?
                };
                if let Some(obj_bytes) = verified.overlay_obj_bytes {
                    if let Some(prev) = self.obj_overlay.insert(out_ref.clone(), obj_bytes.clone())
                    {
                        if prev != obj_bytes {
                            return Err(KcirV2Error::new(
                                error_codes::CONTRACT_VIOLATION,
                                format!(
                                    "OBJ overlay collision for {} with non-identical bytes",
                                    hex::encode(&out_ref.digest)
                                ),
                            ));
                        }
                    }
                }
                self.verify_nf_out_ref(&out_ref, node.sort)?;
                verified.meta
            }
            SORT_MOR => {
                let dep_records_ref = dep_nodes
                    .iter()
                    .map(|dep| self.dep_record_ref(dep))
                    .collect::<Vec<_>>();
                let mor_lookup = RefMorStoreView {
                    profile_scheme_id: self.profile_scheme_id,
                    profile_params_hash: self.profile_params_hash,
                    wire_codec: self.wire_codec,
                    ref_store: self.store,
                    overlay: &self.mor_overlay,
                };
                let verified = if node.opcode == M_PULL {
                    verify_mor_opcode_contract_ref_pull(
                        &node,
                        &dep_records_ref,
                        self.backend,
                        self.wire_codec,
                        &mor_lookup,
                    )?
                } else {
                    verify_mor_opcode_contract_ref_non_pull(
                        &node,
                        &dep_nodes,
                        self.backend,
                        self.wire_codec,
                        &mor_lookup,
                    )?
                };
                if let Some(mor_bytes) = verified.overlay_mor_bytes {
                    if let Some(prev) = self.mor_overlay.insert(out_ref.clone(), mor_bytes.clone())
                    {
                        if prev != mor_bytes {
                            return Err(KcirV2Error::new(
                                error_codes::CONTRACT_VIOLATION,
                                format!(
                                    "MOR overlay collision for {} with non-identical bytes",
                                    hex::encode(&out_ref.digest)
                                ),
                            ));
                        }
                    }
                }
                self.verify_nf_out_ref(&out_ref, node.sort)?;
                verified.meta
            }
            SORT_MAP => verify_map_opcode_contract_ref(&node, &dep_nodes, &map_cover_hooks)?,
            SORT_COVER => verify_cover_opcode_contract_ref(&node, &dep_nodes, &map_cover_hooks)?,
            other => {
                return Err(KcirV2Error::new(
                    error_codes::UNSUPPORTED_SORT,
                    format!("unsupported KCIR sort in core verifier: 0x{other:02x}"),
                ));
            }
        };

        self.visiting.remove(&cert_ref);
        let verified = CoreVerifiedNodeRef {
            cert_ref: cert_ref.clone(),
            sort: node.sort,
            opcode: node.opcode,
            out: out_ref,
            meta,
        };
        self.memo.insert(cert_ref, verified.clone());
        Ok(verified)
    }
}

fn verify_core_dag_ref_recursive(
    root_cert_ref: &Ref,
    ref_store: &dyn KcirRefStore,
    profile_backend: &dyn KcirBackend,
    profile: &dyn VerifierProfile,
    wire_codec: &dyn WireCodec,
    anchors: Option<&ProfileAnchors>,
) -> Result<CoreVerifyResultRef, KcirV2Error> {
    let (root_bytes, root_evidence) = ref_store.get_node(root_cert_ref).ok_or_else(|| {
        KcirV2Error::new(
            error_codes::STORE_MISSING_NODE,
            format!(
                "missing KCIR root node bytes for cert ref {}",
                hex::encode(&root_cert_ref.digest)
            ),
        )
    })?;
    profile.verify_ref_with_anchors(
        root_cert_ref,
        &root_bytes,
        root_evidence.as_deref(),
        anchors,
        DOMAIN_NODE,
    )?;
    let root = wire_codec.decode_node_refs(
        &root_bytes,
        &root_cert_ref.scheme_id,
        root_cert_ref.params_hash,
    )?;

    let mut ctx = CoreVerifyCtxRef {
        store: ref_store,
        backend: profile_backend,
        profile,
        wire_codec,
        anchors,
        profile_scheme_id: &root_cert_ref.scheme_id,
        profile_params_hash: root_cert_ref.params_hash,
        root_env_sig: root.env_sig,
        root_uid: root.uid,
        memo: BTreeMap::new(),
        visiting: BTreeSet::new(),
        obj_overlay: BTreeMap::new(),
        mor_overlay: BTreeMap::new(),
    };

    let _ = ctx.verify_node(root_cert_ref.clone())?;
    let mut nodes = ctx.memo.values().cloned().collect::<Vec<_>>();
    nodes.sort_by(|a, b| a.cert_ref.cmp(&b.cert_ref));

    Ok(CoreVerifyResultRef {
        root_cert_ref: root_cert_ref.clone(),
        env_sig: root.env_sig,
        uid: root.uid,
        nodes,
        obj_overlay: ctx.obj_overlay,
        mor_overlay: ctx.mor_overlay,
    })
}

/// v2 entrypoint over a Ref-keyed store contract.
///
/// Transitional constraint: legacy pull-contract slices and backend hook adapters
/// still require 32-byte contract-key projection support in the selected wire codec.
pub fn verify_core_dag_with_profile_and_backend_and_store_and_anchors(
    root_cert_ref: &Ref,
    ref_store: &dyn KcirRefStore,
    backend: &dyn KcirBackend,
    profile: &dyn VerifierProfile,
    anchors: Option<&ProfileAnchors>,
) -> Result<CoreVerifyResultRef, KcirV2Error> {
    verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors(
        root_cert_ref,
        ref_store,
        backend,
        profile,
        &LEGACY_FIXED32_WIRE_CODEC,
        anchors,
    )
}

pub fn verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors(
    root_cert_ref: &Ref,
    ref_store: &dyn KcirRefStore,
    backend: &dyn KcirBackend,
    profile: &dyn VerifierProfile,
    wire_codec: &dyn WireCodec,
    anchors: Option<&ProfileAnchors>,
) -> Result<CoreVerifyResultRef, KcirV2Error> {
    if profile.scheme_id() != root_cert_ref.scheme_id {
        return Err(KcirV2Error::new(
            error_codes::PROFILE_MISMATCH,
            format!(
                "profile scheme mismatch: verifier {}, root ref {}",
                profile.scheme_id(),
                root_cert_ref.scheme_id
            ),
        ));
    }

    if root_cert_ref.domain != DOMAIN_NODE {
        return Err(KcirV2Error::new(
            error_codes::DOMAIN_MISMATCH,
            format!(
                "domain mismatch: expected {}, got {}",
                DOMAIN_NODE, root_cert_ref.domain
            ),
        ));
    }

    if root_cert_ref.params_hash != profile.params_hash() {
        return Err(KcirV2Error::new(
            error_codes::PARAMS_HASH_MISMATCH,
            format!(
                "profile params mismatch: verifier {}, root ref {}",
                hex::encode(profile.params_hash()),
                hex::encode(root_cert_ref.params_hash)
            ),
        ));
    }
    // Preserve deterministic legacy diagnostics for the default fixed32 adapter.
    if wire_codec.wire_format_id() == LEGACY_FIXED32_WIRE_CODEC.wire_format_id() {
        let _ = wire_codec.contract_key_from_ref(root_cert_ref, DOMAIN_NODE)?;
    }

    let profile_backend = ProfileDigestBackend {
        hooks: backend,
        profile,
    };
    verify_core_dag_ref_recursive(
        root_cert_ref,
        ref_store,
        &profile_backend,
        profile,
        wire_codec,
        anchors,
    )
}

pub fn verify_core_dag_with_profile_and_backend_and_store(
    root_cert_ref: &Ref,
    ref_store: &dyn KcirRefStore,
    backend: &dyn KcirBackend,
    profile: &dyn VerifierProfile,
) -> Result<CoreVerifyResultRef, KcirV2Error> {
    verify_core_dag_with_profile_and_backend_and_store_and_anchors(
        root_cert_ref,
        ref_store,
        backend,
        profile,
        None,
    )
}

pub fn verify_core_dag_with_profile_and_backend_and_anchors(
    root_cert_ref: &Ref,
    cert_store: &BTreeMap<[u8; 32], Vec<u8>>,
    obj_store: &BTreeMap<[u8; 32], Vec<u8>>,
    mor_store: &BTreeMap<[u8; 32], Vec<u8>>,
    backend: &dyn KcirBackend,
    profile: &dyn VerifierProfile,
    anchors: Option<&ProfileAnchors>,
) -> Result<CoreVerifyResultRef, KcirV2Error> {
    let ref_store = InMemoryDigestRefStore::new(
        root_cert_ref.scheme_id.clone(),
        root_cert_ref.params_hash,
        cert_store,
        obj_store,
        mor_store,
    );
    verify_core_dag_with_profile_and_backend_and_store_and_anchors(
        root_cert_ref,
        &ref_store,
        backend,
        profile,
        anchors,
    )
}

/// v2 entrypoint over current in-memory digest-keyed stores.
pub fn verify_core_dag_with_profile_and_backend(
    root_cert_ref: &Ref,
    cert_store: &BTreeMap<[u8; 32], Vec<u8>>,
    obj_store: &BTreeMap<[u8; 32], Vec<u8>>,
    mor_store: &BTreeMap<[u8; 32], Vec<u8>>,
    backend: &dyn KcirBackend,
    profile: &dyn VerifierProfile,
) -> Result<CoreVerifyResultRef, KcirV2Error> {
    verify_core_dag_with_profile_and_backend_and_anchors(
        root_cert_ref,
        cert_store,
        obj_store,
        mor_store,
        backend,
        profile,
        None,
    )
}

pub fn verify_core_dag_with_profile_and_anchors(
    root_cert_ref: &Ref,
    cert_store: &BTreeMap<[u8; 32], Vec<u8>>,
    obj_store: &BTreeMap<[u8; 32], Vec<u8>>,
    mor_store: &BTreeMap<[u8; 32], Vec<u8>>,
    profile: &dyn VerifierProfile,
    anchors: Option<&ProfileAnchors>,
) -> Result<CoreVerifyResultRef, KcirV2Error> {
    let backend = CoreBaseApi::default();
    verify_core_dag_with_profile_and_backend_and_anchors(
        root_cert_ref,
        cert_store,
        obj_store,
        mor_store,
        &backend,
        profile,
        anchors,
    )
}

pub fn verify_core_dag_with_profile(
    root_cert_ref: &Ref,
    cert_store: &BTreeMap<[u8; 32], Vec<u8>>,
    obj_store: &BTreeMap<[u8; 32], Vec<u8>>,
    mor_store: &BTreeMap<[u8; 32], Vec<u8>>,
    profile: &dyn VerifierProfile,
) -> Result<CoreVerifyResultRef, KcirV2Error> {
    verify_core_dag_with_profile_and_anchors(
        root_cert_ref,
        cert_store,
        obj_store,
        mor_store,
        profile,
        None,
    )
}

pub fn verify_core_dag_hash_profile_with_anchors(
    root_cert_ref: &Ref,
    cert_store: &BTreeMap<[u8; 32], Vec<u8>>,
    obj_store: &BTreeMap<[u8; 32], Vec<u8>>,
    mor_store: &BTreeMap<[u8; 32], Vec<u8>>,
    anchors: Option<&ProfileAnchors>,
) -> Result<CoreVerifyResultRef, KcirV2Error> {
    let profile = HashProfile::new(root_cert_ref.params_hash);
    verify_core_dag_with_profile_and_anchors(
        root_cert_ref,
        cert_store,
        obj_store,
        mor_store,
        &profile,
        anchors,
    )
}

pub fn verify_core_dag_hash_profile(
    root_cert_ref: &Ref,
    cert_store: &BTreeMap<[u8; 32], Vec<u8>>,
    obj_store: &BTreeMap<[u8; 32], Vec<u8>>,
    mor_store: &BTreeMap<[u8; 32], Vec<u8>>,
) -> Result<CoreVerifyResultRef, KcirV2Error> {
    verify_core_dag_hash_profile_with_anchors(root_cert_ref, cert_store, obj_store, mor_store, None)
}
