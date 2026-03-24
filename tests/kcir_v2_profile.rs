use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use paintgun::kcir_v2::{
    cert_id, h_obj, node_obj_mktensor, node_obj_prim, KcirBackend, KcirNode, SORT_MAP,
};
use paintgun::kcir_v2::{
    error_codes, hash_obj_ref, hash_ref_from_digest, verify_core_dag_hash_profile,
    verify_core_dag_hash_profile_with_anchors, verify_core_dag_with_profile_and_anchors,
    verify_core_dag_with_profile_and_backend_and_store,
    verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors, DecodedNodeRefs,
    HashProfile, InMemoryDigestRefStore, KcirRefStore, KcirV2Error, LenPrefixedRefWireCodec,
    MerkleDirection, MerkleEvidence, MerkleProfile, MerkleProofStep, ProfileAnchors, Ref,
    VerifierProfile, WireCodec, DOMAIN_MOR_NF, DOMAIN_NODE, DOMAIN_OBJ_NF, DOMAIN_OPAQUE,
    LEGACY_FIXED32_WIRE_CODEC,
};

struct CountingWireCodec {
    encode_calls: AtomicUsize,
    decode_calls: AtomicUsize,
}

impl CountingWireCodec {
    fn new() -> Self {
        Self {
            encode_calls: AtomicUsize::new(0),
            decode_calls: AtomicUsize::new(0),
        }
    }
}

struct CountingNodeDecodeCodec {
    encode_calls: AtomicUsize,
    decode_calls: AtomicUsize,
    node_decode_calls: AtomicUsize,
}

impl CountingNodeDecodeCodec {
    fn new() -> Self {
        Self {
            encode_calls: AtomicUsize::new(0),
            decode_calls: AtomicUsize::new(0),
            node_decode_calls: AtomicUsize::new(0),
        }
    }
}

struct NonLegacyOutNodeCodec;
struct ProjectedNonLegacyOutNodeCodec;
struct DepCertRefWideningCodec;

impl WireCodec for CountingWireCodec {
    fn wire_format_id(&self) -> &str {
        "test.counting-wire-codec.v1"
    }

    fn encode_ref_for_domain(&self, reference: &Ref, domain: &str) -> Result<Vec<u8>, KcirV2Error> {
        self.encode_calls.fetch_add(1, Ordering::Relaxed);
        LEGACY_FIXED32_WIRE_CODEC.encode_ref_for_domain(reference, domain)
    }

    fn decode_ref_for_domain(
        &self,
        encoded: &[u8],
        scheme_id: &str,
        params_hash: [u8; 32],
        domain: &str,
    ) -> Result<Ref, KcirV2Error> {
        self.decode_calls.fetch_add(1, Ordering::Relaxed);
        LEGACY_FIXED32_WIRE_CODEC.decode_ref_for_domain(encoded, scheme_id, params_hash, domain)
    }
}

impl WireCodec for DepCertRefWideningCodec {
    fn wire_format_id(&self) -> &str {
        "test.dep-cert-ref-widening-codec.v1"
    }

    fn encode_ref_for_domain(&self, reference: &Ref, domain: &str) -> Result<Vec<u8>, KcirV2Error> {
        LEGACY_FIXED32_WIRE_CODEC.encode_ref_for_domain(reference, domain)
    }

    fn decode_ref_for_domain(
        &self,
        encoded: &[u8],
        scheme_id: &str,
        params_hash: [u8; 32],
        domain: &str,
    ) -> Result<Ref, KcirV2Error> {
        LEGACY_FIXED32_WIRE_CODEC.decode_ref_for_domain(encoded, scheme_id, params_hash, domain)
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
        if domain == DOMAIN_NODE && reference.digest.len() != 32 {
            return Err(KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!(
                    "node contract key requires 32-byte digest, got {}",
                    reference.digest.len()
                ),
            ));
        }
        LEGACY_FIXED32_WIRE_CODEC.contract_key_from_ref(reference, domain)
    }

    fn decode_node_refs(
        &self,
        node_bytes: &[u8],
        scheme_id: &str,
        params_hash: [u8; 32],
    ) -> Result<DecodedNodeRefs, KcirV2Error> {
        let parsed = paintgun::kcir_v2::parse_node_bytes(node_bytes).map_err(|message| {
            KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!("failed to parse KCIR node bytes: {message}"),
            )
        })?;
        let out_ref = LEGACY_FIXED32_WIRE_CODEC.decode_ref_for_domain(
            &parsed.out,
            scheme_id,
            params_hash,
            DOMAIN_OPAQUE,
        )?;
        let dep_refs = parsed
            .deps
            .iter()
            .map(|dep| {
                let mut r = LEGACY_FIXED32_WIRE_CODEC.decode_ref_for_domain(
                    dep,
                    scheme_id,
                    params_hash,
                    DOMAIN_NODE,
                )?;
                r.digest.extend_from_slice(&[0xCD; 32]);
                Ok::<Ref, KcirV2Error>(r)
            })
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

impl WireCodec for NonLegacyOutNodeCodec {
    fn wire_format_id(&self) -> &str {
        "test.non-legacy-out-node-codec.v1"
    }

    fn encode_ref_for_domain(&self, reference: &Ref, domain: &str) -> Result<Vec<u8>, KcirV2Error> {
        LEGACY_FIXED32_WIRE_CODEC.encode_ref_for_domain(reference, domain)
    }

    fn decode_ref_for_domain(
        &self,
        encoded: &[u8],
        scheme_id: &str,
        params_hash: [u8; 32],
        domain: &str,
    ) -> Result<Ref, KcirV2Error> {
        LEGACY_FIXED32_WIRE_CODEC.decode_ref_for_domain(encoded, scheme_id, params_hash, domain)
    }

    fn decode_node_refs(
        &self,
        node_bytes: &[u8],
        scheme_id: &str,
        params_hash: [u8; 32],
    ) -> Result<DecodedNodeRefs, KcirV2Error> {
        let parsed = paintgun::kcir_v2::parse_node_bytes(node_bytes).map_err(|message| {
            KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!("failed to parse KCIR node bytes: {message}"),
            )
        })?;
        let mut out_ref = LEGACY_FIXED32_WIRE_CODEC.decode_ref_for_domain(
            &parsed.out,
            scheme_id,
            params_hash,
            DOMAIN_OPAQUE,
        )?;
        out_ref.digest = vec![0u8; 64];
        let dep_refs = parsed
            .deps
            .iter()
            .map(|dep| {
                LEGACY_FIXED32_WIRE_CODEC.decode_ref_for_domain(
                    dep,
                    scheme_id,
                    params_hash,
                    DOMAIN_NODE,
                )
            })
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

impl WireCodec for ProjectedNonLegacyOutNodeCodec {
    fn wire_format_id(&self) -> &str {
        "test.projected-non-legacy-out-node-codec.v1"
    }

    fn encode_ref_for_domain(&self, reference: &Ref, domain: &str) -> Result<Vec<u8>, KcirV2Error> {
        // Keep root-node refs legacy-compatible for profile/root checks.
        if domain == DOMAIN_NODE {
            return LEGACY_FIXED32_WIRE_CODEC.encode_ref_for_domain(reference, domain);
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
        if domain == DOMAIN_NODE {
            return LEGACY_FIXED32_WIRE_CODEC.decode_ref_for_domain(
                encoded,
                scheme_id,
                params_hash,
                domain,
            );
        }
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
                    "projected contract key requires at least 32 digest bytes, got {}",
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
        let parsed = paintgun::kcir_v2::parse_node_bytes(node_bytes).map_err(|message| {
            KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!("failed to parse KCIR node bytes: {message}"),
            )
        })?;
        let mut out_digest = Vec::from(parsed.out);
        out_digest.extend_from_slice(&[0xA5; 32]);
        let out_ref = Ref {
            scheme_id: scheme_id.to_string(),
            params_hash,
            domain: DOMAIN_OPAQUE.to_string(),
            digest: out_digest,
        };
        let dep_refs = parsed
            .deps
            .iter()
            .map(|dep| {
                LEGACY_FIXED32_WIRE_CODEC.decode_ref_for_domain(
                    dep,
                    scheme_id,
                    params_hash,
                    DOMAIN_NODE,
                )
            })
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

impl WireCodec for CountingNodeDecodeCodec {
    fn wire_format_id(&self) -> &str {
        "test.counting-node-decode-codec.v1"
    }

    fn encode_ref_for_domain(&self, reference: &Ref, domain: &str) -> Result<Vec<u8>, KcirV2Error> {
        self.encode_calls.fetch_add(1, Ordering::Relaxed);
        LEGACY_FIXED32_WIRE_CODEC.encode_ref_for_domain(reference, domain)
    }

    fn decode_ref_for_domain(
        &self,
        encoded: &[u8],
        scheme_id: &str,
        params_hash: [u8; 32],
        domain: &str,
    ) -> Result<Ref, KcirV2Error> {
        self.decode_calls.fetch_add(1, Ordering::Relaxed);
        LEGACY_FIXED32_WIRE_CODEC.decode_ref_for_domain(encoded, scheme_id, params_hash, domain)
    }

    fn decode_node_refs(
        &self,
        node_bytes: &[u8],
        scheme_id: &str,
        params_hash: [u8; 32],
    ) -> Result<DecodedNodeRefs, KcirV2Error> {
        self.node_decode_calls.fetch_add(1, Ordering::Relaxed);
        let parsed = paintgun::kcir_v2::parse_node_bytes(node_bytes).map_err(|message| {
            KcirV2Error::new(
                error_codes::PARSE_ERROR,
                format!("failed to parse KCIR node bytes: {message}"),
            )
        })?;
        let out_domain = match parsed.sort {
            paintgun::kcir_v2::SORT_OBJ => DOMAIN_OBJ_NF,
            paintgun::kcir_v2::SORT_MOR => paintgun::kcir_v2::DOMAIN_MOR_NF,
            _ => DOMAIN_OPAQUE,
        };
        let out_ref =
            self.decode_ref_for_domain(&parsed.out, scheme_id, params_hash, out_domain)?;
        let dep_refs = parsed
            .deps
            .iter()
            .map(|dep| self.decode_ref_for_domain(dep, scheme_id, params_hash, DOMAIN_NODE))
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

struct AnchorCheckingHashProfile {
    inner: HashProfile,
    required_root_commitment: Vec<u8>,
}

struct AcceptAllProfile {
    scheme_id: String,
    params_hash: [u8; 32],
}

#[derive(Default)]
struct EvidenceRefStore {
    node_entries: BTreeMap<Ref, (Vec<u8>, Option<Vec<u8>>)>,
    obj_entries: BTreeMap<Ref, (Vec<u8>, Option<Vec<u8>>)>,
    mor_entries: BTreeMap<Ref, (Vec<u8>, Option<Vec<u8>>)>,
}

impl KcirRefStore for EvidenceRefStore {
    fn get_node(&self, reference: &Ref) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        self.node_entries.get(reference).cloned()
    }

    fn get_obj_nf(&self, reference: &Ref) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        self.obj_entries.get(reference).cloned()
    }

    fn get_mor_nf(&self, reference: &Ref) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        self.mor_entries.get(reference).cloned()
    }
}

struct PanicDigestBackend;

impl KcirBackend for PanicDigestBackend {
    fn digest_node(&self, _node_bytes: &[u8]) -> [u8; 32] {
        panic!("unexpected digest_node call on hook backend")
    }

    fn digest_obj_nf(&self, _env_sig: &[u8; 32], _uid: &[u8; 32], _obj_bytes: &[u8]) -> [u8; 32] {
        panic!("unexpected digest_obj_nf call on hook backend")
    }

    fn digest_mor_nf(&self, _env_sig: &[u8; 32], _uid: &[u8; 32], _mor_bytes: &[u8]) -> [u8; 32] {
        panic!("unexpected digest_mor_nf call on hook backend")
    }
}

impl AnchorCheckingHashProfile {
    fn new(required_root_commitment: Vec<u8>, params_hash: [u8; 32]) -> Self {
        Self {
            inner: HashProfile::new(params_hash),
            required_root_commitment,
        }
    }
}

impl VerifierProfile for AnchorCheckingHashProfile {
    fn scheme_id(&self) -> &str {
        self.inner.scheme_id()
    }

    fn params_hash(&self) -> [u8; 32] {
        self.inner.params_hash()
    }

    fn verify_ref(
        &self,
        reference: &Ref,
        payload_bytes: &[u8],
        evidence: Option<&[u8]>,
        domain: &str,
    ) -> Result<(), KcirV2Error> {
        self.inner
            .verify_ref(reference, payload_bytes, evidence, domain)
    }

    fn verify_ref_with_anchors(
        &self,
        reference: &Ref,
        payload_bytes: &[u8],
        evidence: Option<&[u8]>,
        anchors: Option<&ProfileAnchors>,
        domain: &str,
    ) -> Result<(), KcirV2Error> {
        let root = anchors
            .and_then(|a| a.root_commitment.as_ref())
            .ok_or_else(|| {
                KcirV2Error::new(
                    error_codes::ANCHOR_MISSING,
                    "missing required root commitment anchor",
                )
            })?;
        if root != &self.required_root_commitment {
            return Err(KcirV2Error::new(
                error_codes::ANCHOR_MISMATCH,
                "unexpected root commitment anchor",
            ));
        }
        self.inner
            .verify_ref(reference, payload_bytes, evidence, domain)
    }
}

impl VerifierProfile for AcceptAllProfile {
    fn scheme_id(&self) -> &str {
        &self.scheme_id
    }

    fn params_hash(&self) -> [u8; 32] {
        self.params_hash
    }

    fn verify_ref(
        &self,
        _reference: &Ref,
        _payload_bytes: &[u8],
        _evidence: Option<&[u8]>,
        _domain: &str,
    ) -> Result<(), KcirV2Error> {
        Ok(())
    }
}

#[test]
fn hash_profile_adapter_verifies_legacy_core_store() {
    let env_sig = [0x11; 32];
    let uid = [0x22; 32];
    let prim_id = [0x33; 32];

    let node = node_obj_prim(env_sig, uid, prim_id);
    let node_bytes = node.encode();
    let root_cert_id = cert_id(&node_bytes);

    let mut cert_store = BTreeMap::new();
    cert_store.insert(root_cert_id, node_bytes);

    let profile = HashProfile::default();
    let root_ref = hash_ref_from_digest(DOMAIN_NODE, root_cert_id, profile.params_hash());
    let verified =
        verify_core_dag_hash_profile(&root_ref, &cert_store, &BTreeMap::new(), &BTreeMap::new())
            .expect("hash-profile adapter should verify legacy DAG");

    assert_eq!(verified.root_cert_ref, root_ref);
    assert_eq!(verified.nodes.len(), 1);
    assert_eq!(verified.nodes[0].cert_ref.domain, DOMAIN_NODE);
    assert_eq!(verified.nodes[0].out.domain, DOMAIN_OBJ_NF);
}

#[test]
fn hash_profile_store_entrypoint_verifies_ref_store_contract() {
    let env_sig = [0x21; 32];
    let uid = [0x22; 32];
    let prim_id = [0x23; 32];

    let node = node_obj_prim(env_sig, uid, prim_id);
    let node_bytes = node.encode();
    let root_cert_id = cert_id(&node_bytes);

    let mut cert_store = BTreeMap::new();
    cert_store.insert(root_cert_id, node_bytes);
    let obj_store = BTreeMap::new();
    let mor_store = BTreeMap::new();

    let profile = HashProfile::default();
    let root_ref = hash_ref_from_digest(DOMAIN_NODE, root_cert_id, profile.params_hash());
    let backend = paintgun::kcir_v2::CoreBaseApi::default();
    let ref_store = InMemoryDigestRefStore::new(
        root_ref.scheme_id.clone(),
        root_ref.params_hash,
        &cert_store,
        &obj_store,
        &mor_store,
    );
    let verified = verify_core_dag_with_profile_and_backend_and_store(
        &root_ref, &ref_store, &backend, &profile,
    )
    .expect("store entrypoint should verify hash-profile DAG");

    assert_eq!(verified.root_cert_ref, root_ref);
    assert_eq!(verified.nodes.len(), 1);
    assert_eq!(verified.nodes[0].out.domain, DOMAIN_OBJ_NF);
}

#[test]
fn codec_aware_store_entrypoint_uses_supplied_wire_codec() {
    let env_sig = [0x24; 32];
    let uid = [0x25; 32];
    let prim_id = [0x26; 32];

    let node = node_obj_prim(env_sig, uid, prim_id);
    let node_bytes = node.encode();
    let root_cert_id = cert_id(&node_bytes);

    let mut cert_store = BTreeMap::new();
    cert_store.insert(root_cert_id, node_bytes);
    let obj_store = BTreeMap::new();
    let mor_store = BTreeMap::new();

    let profile = HashProfile::default();
    let root_ref = hash_ref_from_digest(DOMAIN_NODE, root_cert_id, profile.params_hash());
    let backend = paintgun::kcir_v2::CoreBaseApi::default();
    let codec = CountingWireCodec::new();
    let ref_store = InMemoryDigestRefStore::new_with_codec(
        root_ref.scheme_id.clone(),
        root_ref.params_hash,
        &codec,
        &cert_store,
        &obj_store,
        &mor_store,
    );

    let verified = verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors(
        &root_ref, &ref_store, &backend, &profile, &codec, None,
    )
    .expect("codec-aware store entrypoint should verify hash-profile DAG");

    assert_eq!(verified.root_cert_ref, root_ref);
    assert_eq!(verified.nodes.len(), 1);
    assert!(
        codec.encode_calls.load(Ordering::Relaxed) > 0,
        "expected verifier path to call codec encode/decode adapters"
    );
    assert!(
        codec.decode_calls.load(Ordering::Relaxed) > 0,
        "expected verifier path to call codec decode adapters"
    );
}

#[test]
fn codec_aware_store_entrypoint_uses_wire_node_decoder() {
    let env_sig = [0x27; 32];
    let uid = [0x28; 32];
    let prim_id = [0x29; 32];

    let node = node_obj_prim(env_sig, uid, prim_id);
    let node_bytes = node.encode();
    let root_cert_id = cert_id(&node_bytes);

    let mut cert_store = BTreeMap::new();
    cert_store.insert(root_cert_id, node_bytes);
    let obj_store = BTreeMap::new();
    let mor_store = BTreeMap::new();

    let profile = HashProfile::default();
    let root_ref = hash_ref_from_digest(DOMAIN_NODE, root_cert_id, profile.params_hash());
    let backend = paintgun::kcir_v2::CoreBaseApi::default();
    let codec = CountingNodeDecodeCodec::new();
    let ref_store = InMemoryDigestRefStore::new_with_codec(
        root_ref.scheme_id.clone(),
        root_ref.params_hash,
        &codec,
        &cert_store,
        &obj_store,
        &mor_store,
    );

    let verified = verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors(
        &root_ref, &ref_store, &backend, &profile, &codec, None,
    )
    .expect("codec-aware store entrypoint should verify with custom node decode path");

    assert_eq!(verified.root_cert_ref, root_ref);
    assert_eq!(verified.nodes.len(), 1);
    assert!(
        codec.node_decode_calls.load(Ordering::Relaxed) > 0,
        "expected verifier path to call codec node decoder"
    );
}

#[test]
fn codec_bridge_reports_data_unavailable_for_non_legacy_node_refs() {
    let env_sig = [0x2A; 32];
    let uid = [0x2B; 32];
    let map_id = [0x2C; 32];
    let node = KcirNode {
        env_sig,
        uid,
        sort: SORT_MAP,
        opcode: 0x01, // M_LITERAL
        out: map_id,
        args: map_id.to_vec(),
        deps: Vec::new(),
    };
    let node_bytes = node.encode();
    let root_cert_id = cert_id(&node_bytes);

    let mut cert_store = BTreeMap::new();
    cert_store.insert(root_cert_id, node_bytes);
    let obj_store = BTreeMap::new();
    let mor_store = BTreeMap::new();

    let profile = HashProfile::default();
    let root_ref = hash_ref_from_digest(DOMAIN_NODE, root_cert_id, profile.params_hash());
    let backend = paintgun::kcir_v2::CoreBaseApi::default();
    let codec = NonLegacyOutNodeCodec;
    let ref_store = InMemoryDigestRefStore::new_with_codec(
        root_ref.scheme_id.clone(),
        root_ref.params_hash,
        &codec,
        &cert_store,
        &obj_store,
        &mor_store,
    );

    let err = verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors(
        &root_ref, &ref_store, &backend, &profile, &codec, None,
    )
    .expect_err("non-legacy node refs should fail bridge conversion for opcode contracts");

    assert_eq!(err.code, error_codes::DATA_UNAVAILABLE);
    assert!(
        err.message
            .contains("cannot project contract key for M_LITERAL out"),
        "unexpected error message: {err}"
    );
}

#[test]
fn codec_bridge_accepts_non_legacy_node_refs_with_projection() {
    let env_sig = [0x2D; 32];
    let uid = [0x2E; 32];
    let map_id = [0x2F; 32];
    let node = KcirNode {
        env_sig,
        uid,
        sort: SORT_MAP,
        opcode: 0x01, // M_LITERAL
        out: map_id,
        args: map_id.to_vec(),
        deps: Vec::new(),
    };
    let node_bytes = node.encode();
    let root_cert_id = cert_id(&node_bytes);

    let mut cert_store = BTreeMap::new();
    cert_store.insert(root_cert_id, node_bytes);
    let obj_store = BTreeMap::new();
    let mor_store = BTreeMap::new();

    let profile = HashProfile::default();
    let root_ref = hash_ref_from_digest(DOMAIN_NODE, root_cert_id, profile.params_hash());
    let backend = paintgun::kcir_v2::CoreBaseApi::default();
    let codec = ProjectedNonLegacyOutNodeCodec;
    let ref_store = InMemoryDigestRefStore::new_with_codec(
        root_ref.scheme_id.clone(),
        root_ref.params_hash,
        &codec,
        &cert_store,
        &obj_store,
        &mor_store,
    );

    let verified = verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors(
        &root_ref, &ref_store, &backend, &profile, &codec, None,
    )
    .expect("projected contract key codec should verify current MAP contracts");

    assert_eq!(verified.root_cert_ref, root_ref);
    assert_eq!(verified.nodes.len(), 1);
    assert_eq!(verified.nodes[0].sort, SORT_MAP);
    assert_eq!(verified.nodes[0].out.digest.len(), 64);
}

#[test]
fn len_prefixed_codec_roundtrips_variable_length_refs() {
    let profile = HashProfile::default();
    let codec = LenPrefixedRefWireCodec;
    let mut map_id = Vec::new();
    map_id.extend_from_slice(&[0xAB; 32]);
    map_id.extend_from_slice(&[0xCD; 12]);

    let node = DecodedNodeRefs {
        env_sig: [0x11; 32],
        uid: [0x22; 32],
        sort: SORT_MAP,
        opcode: 0x01,
        out_ref: Ref {
            scheme_id: profile.scheme_id().to_string(),
            params_hash: profile.params_hash(),
            domain: DOMAIN_OPAQUE.to_string(),
            digest: map_id.clone(),
        },
        args: vec![0xAB; 32],
        dep_refs: vec![Ref {
            scheme_id: profile.scheme_id().to_string(),
            params_hash: profile.params_hash(),
            domain: DOMAIN_NODE.to_string(),
            digest: vec![0x55; 40],
        }],
    };

    let node_bytes = codec
        .encode_node_refs(&node)
        .expect("encode len-prefixed node");
    let decoded = codec
        .decode_node_refs(&node_bytes, profile.scheme_id(), profile.params_hash())
        .expect("decode len-prefixed node");
    assert_eq!(decoded, node);
}

#[test]
fn len_prefixed_codec_rejects_trailing_bytes() {
    let profile = HashProfile::default();
    let codec = LenPrefixedRefWireCodec;

    let node = DecodedNodeRefs {
        env_sig: [0x31; 32],
        uid: [0x32; 32],
        sort: SORT_MAP,
        opcode: 0x01,
        out_ref: Ref {
            scheme_id: profile.scheme_id().to_string(),
            params_hash: profile.params_hash(),
            domain: DOMAIN_OPAQUE.to_string(),
            digest: vec![0x42; 32],
        },
        args: vec![0x42; 32],
        dep_refs: Vec::new(),
    };
    let mut node_bytes = codec
        .encode_node_refs(&node)
        .expect("encode len-prefixed node");
    node_bytes.push(0xFF);

    let err = codec
        .decode_node_refs(&node_bytes, profile.scheme_id(), profile.params_hash())
        .expect_err("trailing bytes should fail");
    assert_eq!(err.code, error_codes::PARSE_ERROR);
    assert!(
        err.message.contains("trailing bytes"),
        "unexpected parse error: {err}"
    );
}

#[test]
fn len_prefixed_codec_verifies_map_literal_with_projected_contract_key() {
    let env_sig = [0x41; 32];
    let uid = [0x42; 32];
    let map_id = [0x43; 32];

    let profile = HashProfile::default();
    let codec = LenPrefixedRefWireCodec;

    let mut out_digest = map_id.to_vec();
    out_digest.extend_from_slice(&[0xEE; 32]);
    let node = DecodedNodeRefs {
        env_sig,
        uid,
        sort: SORT_MAP,
        opcode: 0x01, // M_LITERAL
        out_ref: Ref {
            scheme_id: profile.scheme_id().to_string(),
            params_hash: profile.params_hash(),
            domain: DOMAIN_OPAQUE.to_string(),
            digest: out_digest,
        },
        args: map_id.to_vec(),
        dep_refs: Vec::new(),
    };
    let node_bytes = codec
        .encode_node_refs(&node)
        .expect("encode len-prefixed map literal node");
    let root_cert_id = cert_id(&node_bytes);

    let mut cert_store = BTreeMap::new();
    cert_store.insert(root_cert_id, node_bytes);
    let obj_store = BTreeMap::new();
    let mor_store = BTreeMap::new();

    let root_ref = hash_ref_from_digest(DOMAIN_NODE, root_cert_id, profile.params_hash());
    let backend = paintgun::kcir_v2::CoreBaseApi::default();
    let ref_store = InMemoryDigestRefStore::new_with_codec(
        root_ref.scheme_id.clone(),
        root_ref.params_hash,
        &codec,
        &cert_store,
        &obj_store,
        &mor_store,
    );

    let verified = verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors(
        &root_ref, &ref_store, &backend, &profile, &codec, None,
    )
    .expect("len-prefixed wire node should verify MAP literal contracts");

    assert_eq!(verified.nodes.len(), 1);
    assert_eq!(verified.nodes[0].sort, SORT_MAP);
    assert_eq!(verified.nodes[0].out.digest.len(), 64);
}

#[test]
fn obj_non_pull_verifier_uses_ref_native_projection_path() {
    let env_sig = [0x71; 32];
    let uid = [0x72; 32];
    let node = KcirNode {
        env_sig,
        uid,
        sort: paintgun::kcir_v2::SORT_OBJ,
        opcode: paintgun::kcir_v2::O_UNIT,
        out: h_obj(&env_sig, &uid, &[0x01]),
        args: Vec::new(),
        deps: Vec::new(),
    };
    let node_bytes = node.encode();
    let root_cert_id = cert_id(&node_bytes);

    let params_hash = HashProfile::default_params_hash();
    let profile = AcceptAllProfile {
        scheme_id: "hash".to_string(),
        params_hash,
    };
    let root_ref = hash_ref_from_digest(DOMAIN_NODE, root_cert_id, params_hash);
    let codec = ProjectedNonLegacyOutNodeCodec;

    let mut store = EvidenceRefStore::default();
    store
        .node_entries
        .insert(root_ref.clone(), (node_bytes, None));

    let backend = paintgun::kcir_v2::CoreBaseApi::default();
    let verified = verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors(
        &root_ref, &store, &backend, &profile, &codec, None,
    )
    .expect("OBJ non-pull should verify through ref-native projection path");

    assert_eq!(verified.root_cert_ref, root_ref);
    assert_eq!(verified.nodes.len(), 1);
    assert_eq!(verified.nodes[0].sort, paintgun::kcir_v2::SORT_OBJ);
    assert_eq!(verified.nodes[0].out.digest.len(), 64);
}

#[test]
fn map_bc_verifier_does_not_require_dep_cert_contract_projection() {
    let env_sig = [0x61; 32];
    let uid = [0x62; 32];
    let pull_map = [0x63; 32];
    let push_map = [0x64; 32];
    let f_prime = [0x65; 32];
    let p_prime = [0x66; 32];

    let dep_pull = KcirNode {
        env_sig,
        uid,
        sort: SORT_MAP,
        opcode: 0x01, // M_LITERAL
        out: pull_map,
        args: pull_map.to_vec(),
        deps: Vec::new(),
    };
    let dep_push = KcirNode {
        env_sig,
        uid,
        sort: SORT_MAP,
        opcode: 0x01, // M_LITERAL
        out: push_map,
        args: push_map.to_vec(),
        deps: Vec::new(),
    };
    let dep_pull_bytes = dep_pull.encode();
    let dep_push_bytes = dep_push.encode();
    let dep_pull_cert = cert_id(&dep_pull_bytes);
    let dep_push_cert = cert_id(&dep_push_bytes);

    let root = KcirNode {
        env_sig,
        uid,
        sort: SORT_MAP,
        opcode: paintgun::kcir_v2::M_BC_FPRIME,
        out: f_prime,
        args: Vec::new(),
        deps: vec![dep_pull_cert, dep_push_cert],
    };
    let root_bytes = root.encode();
    let root_cert = cert_id(&root_bytes);

    let params_hash = HashProfile::default_params_hash();
    let profile = AcceptAllProfile {
        scheme_id: "hash".to_string(),
        params_hash,
    };
    let root_ref = hash_ref_from_digest(DOMAIN_NODE, root_cert, params_hash);
    let codec = DepCertRefWideningCodec;

    let decoded_root = codec
        .decode_node_refs(&root_bytes, &root_ref.scheme_id, root_ref.params_hash)
        .expect("decode root refs");
    assert_eq!(decoded_root.dep_refs.len(), 2);
    assert_eq!(decoded_root.dep_refs[0].digest.len(), 64);
    assert_eq!(decoded_root.dep_refs[1].digest.len(), 64);

    let mut store = EvidenceRefStore::default();
    store
        .node_entries
        .insert(root_ref.clone(), (root_bytes, None));
    store
        .node_entries
        .insert(decoded_root.dep_refs[0].clone(), (dep_pull_bytes, None));
    store
        .node_entries
        .insert(decoded_root.dep_refs[1].clone(), (dep_push_bytes, None));

    let mut backend = paintgun::kcir_v2::CoreBaseApi::default();
    backend
        .bc_squares
        .insert((push_map, pull_map), (f_prime, p_prime));

    let verified = verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors(
        &root_ref, &store, &backend, &profile, &codec, None,
    )
    .expect("MAP BC verification should not require dep cert key projection");

    assert_eq!(verified.root_cert_ref, root_ref);
    assert_eq!(verified.nodes.len(), 3);
}

#[test]
fn obj_pull_verifier_does_not_require_dep_cert_contract_projection() {
    let env_sig = [0x91; 32];
    let uid = [0x92; 32];
    let p_id = [0x93; 32];

    let in_obj_bytes = vec![0x03, 0x00]; // ObjNF Tensor([])
    let in_obj_h = h_obj(&env_sig, &uid, &in_obj_bytes);
    let unit_obj_h = h_obj(&env_sig, &uid, &[0x01]);

    let mk_dep = KcirNode {
        env_sig,
        uid,
        sort: paintgun::kcir_v2::SORT_OBJ,
        opcode: paintgun::kcir_v2::O_MKTENSOR,
        out: unit_obj_h,
        args: vec![0x00], // enc_list_b32([])
        deps: Vec::new(),
    };
    let mk_dep_bytes = mk_dep.encode();
    let mk_dep_cert = cert_id(&mk_dep_bytes);

    let mut root_args = Vec::with_capacity(65);
    root_args.extend_from_slice(&p_id);
    root_args.extend_from_slice(&in_obj_h);
    root_args.push(0x02); // O_PULL.TENSOR
    let root = KcirNode {
        env_sig,
        uid,
        sort: paintgun::kcir_v2::SORT_OBJ,
        opcode: paintgun::kcir_v2::O_PULL,
        out: unit_obj_h,
        args: root_args,
        deps: vec![mk_dep_cert],
    };
    let root_bytes = root.encode();
    let root_cert = cert_id(&root_bytes);

    let params_hash = HashProfile::default_params_hash();
    let profile = AcceptAllProfile {
        scheme_id: "hash".to_string(),
        params_hash,
    };
    let root_ref = hash_ref_from_digest(DOMAIN_NODE, root_cert, params_hash);
    let codec = DepCertRefWideningCodec;

    let decoded_root = codec
        .decode_node_refs(&root_bytes, &root_ref.scheme_id, root_ref.params_hash)
        .expect("decode root refs");
    assert_eq!(decoded_root.dep_refs.len(), 1);
    assert_eq!(decoded_root.dep_refs[0].digest.len(), 64);

    let mut store = EvidenceRefStore::default();
    store
        .node_entries
        .insert(root_ref.clone(), (root_bytes, None));
    store
        .node_entries
        .insert(decoded_root.dep_refs[0].clone(), (mk_dep_bytes, None));
    store.obj_entries.insert(
        hash_ref_from_digest(DOMAIN_OBJ_NF, in_obj_h, params_hash),
        (in_obj_bytes, None),
    );

    let backend = paintgun::kcir_v2::CoreBaseApi::default();
    let verified = verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors(
        &root_ref, &store, &backend, &profile, &codec, None,
    )
    .expect("OBJ pull verification should not require dep cert key projection");

    assert_eq!(verified.root_cert_ref, root_ref);
    assert_eq!(verified.nodes.len(), 2);
    assert_eq!(verified.nodes[0].sort, paintgun::kcir_v2::SORT_OBJ);
}

#[test]
fn mor_pull_verifier_does_not_require_dep_cert_contract_projection() {
    let env_sig = [0x94; 32];
    let uid = [0x95; 32];
    let p_id = [0x96; 32];
    let src_h = h_obj(&env_sig, &uid, &[0x01]);

    let mut in_mor_bytes = Vec::with_capacity(66);
    in_mor_bytes.push(0x13); // MorNF Comp(src, tgt, parts[])
    in_mor_bytes.extend_from_slice(&src_h);
    in_mor_bytes.extend_from_slice(&src_h);
    in_mor_bytes.push(0x00); // enc_list_b32([])
    let in_mor_h = paintgun::kcir_v2::h_mor(&env_sig, &uid, &in_mor_bytes);

    let mut id_mor_bytes = Vec::with_capacity(33);
    id_mor_bytes.push(0x11);
    id_mor_bytes.extend_from_slice(&src_h);
    let id_mor_h = paintgun::kcir_v2::h_mor(&env_sig, &uid, &id_mor_bytes);

    let mut mk_args = Vec::with_capacity(65);
    mk_args.extend_from_slice(&src_h);
    mk_args.extend_from_slice(&src_h);
    mk_args.push(0x00); // enc_list_b32([])
    let mk_dep = KcirNode {
        env_sig,
        uid,
        sort: paintgun::kcir_v2::SORT_MOR,
        opcode: paintgun::kcir_v2::M_MKCOMP,
        out: id_mor_h,
        args: mk_args,
        deps: Vec::new(),
    };
    let mk_dep_bytes = mk_dep.encode();
    let mk_dep_cert = cert_id(&mk_dep_bytes);

    let mut root_args = Vec::with_capacity(65);
    root_args.extend_from_slice(&p_id);
    root_args.extend_from_slice(&in_mor_h);
    root_args.push(0x02); // M_PULL.COMP
    let root = KcirNode {
        env_sig,
        uid,
        sort: paintgun::kcir_v2::SORT_MOR,
        opcode: paintgun::kcir_v2::M_PULL,
        out: id_mor_h,
        args: root_args,
        deps: vec![mk_dep_cert],
    };
    let root_bytes = root.encode();
    let root_cert = cert_id(&root_bytes);

    let params_hash = HashProfile::default_params_hash();
    let profile = AcceptAllProfile {
        scheme_id: "hash".to_string(),
        params_hash,
    };
    let root_ref = hash_ref_from_digest(DOMAIN_NODE, root_cert, params_hash);
    let codec = DepCertRefWideningCodec;

    let decoded_root = codec
        .decode_node_refs(&root_bytes, &root_ref.scheme_id, root_ref.params_hash)
        .expect("decode root refs");
    assert_eq!(decoded_root.dep_refs.len(), 1);
    assert_eq!(decoded_root.dep_refs[0].digest.len(), 64);

    let mut store = EvidenceRefStore::default();
    store
        .node_entries
        .insert(root_ref.clone(), (root_bytes, None));
    store
        .node_entries
        .insert(decoded_root.dep_refs[0].clone(), (mk_dep_bytes, None));
    store.mor_entries.insert(
        hash_ref_from_digest(DOMAIN_MOR_NF, in_mor_h, params_hash),
        (in_mor_bytes, None),
    );

    let backend = paintgun::kcir_v2::CoreBaseApi::default();
    let verified = verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors(
        &root_ref, &store, &backend, &profile, &codec, None,
    )
    .expect("MOR pull verification should not require dep cert key projection");

    assert_eq!(verified.root_cert_ref, root_ref);
    assert_eq!(verified.nodes.len(), 2);
    assert_eq!(verified.nodes[0].sort, paintgun::kcir_v2::SORT_MOR);
}

#[test]
fn mor_id_verifier_uses_ref_native_projection_path() {
    let env_sig = [0x81; 32];
    let uid = [0x82; 32];
    let src_h = [0x83; 32];

    let mut mor_bytes = Vec::with_capacity(33);
    mor_bytes.push(0x11);
    mor_bytes.extend_from_slice(&src_h);
    let out = paintgun::kcir_v2::h_mor(&env_sig, &uid, &mor_bytes);
    let node = KcirNode {
        env_sig,
        uid,
        sort: paintgun::kcir_v2::SORT_MOR,
        opcode: paintgun::kcir_v2::M_ID,
        out,
        args: src_h.to_vec(),
        deps: Vec::new(),
    };
    let node_bytes = node.encode();
    let root_cert_id = cert_id(&node_bytes);

    let params_hash = HashProfile::default_params_hash();
    let profile = AcceptAllProfile {
        scheme_id: "hash".to_string(),
        params_hash,
    };
    let root_ref = hash_ref_from_digest(DOMAIN_NODE, root_cert_id, params_hash);
    let codec = ProjectedNonLegacyOutNodeCodec;

    let mut store = EvidenceRefStore::default();
    store
        .node_entries
        .insert(root_ref.clone(), (node_bytes, None));

    let backend = paintgun::kcir_v2::CoreBaseApi::default();
    let verified = verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors(
        &root_ref, &store, &backend, &profile, &codec, None,
    )
    .expect("M_ID should verify through ref-native projection path");

    assert_eq!(verified.root_cert_ref, root_ref);
    assert_eq!(verified.nodes.len(), 1);
    assert_eq!(verified.nodes[0].sort, paintgun::kcir_v2::SORT_MOR);
    assert_eq!(verified.nodes[0].out.digest.len(), 64);
}

#[test]
fn mor_mktensor_verifier_uses_ref_native_projection_path() {
    let env_sig = [0x84; 32];
    let uid = [0x85; 32];
    let unit_obj_h = h_obj(&env_sig, &uid, &[0x01]);

    let mut args = Vec::with_capacity(65);
    args.extend_from_slice(&unit_obj_h);
    args.extend_from_slice(&unit_obj_h);
    args.push(0x00); // enc_list_b32([]) varint length

    let mut mor_bytes = Vec::with_capacity(1 + args.len());
    mor_bytes.push(0x18);
    mor_bytes.extend_from_slice(&args);
    let out = paintgun::kcir_v2::h_mor(&env_sig, &uid, &mor_bytes);

    let node = KcirNode {
        env_sig,
        uid,
        sort: paintgun::kcir_v2::SORT_MOR,
        opcode: paintgun::kcir_v2::M_MKTENSOR,
        out,
        args,
        deps: Vec::new(),
    };
    let node_bytes = node.encode();
    let root_cert_id = cert_id(&node_bytes);

    let params_hash = HashProfile::default_params_hash();
    let profile = AcceptAllProfile {
        scheme_id: "hash".to_string(),
        params_hash,
    };
    let root_ref = hash_ref_from_digest(DOMAIN_NODE, root_cert_id, params_hash);
    let codec = ProjectedNonLegacyOutNodeCodec;

    let mut store = EvidenceRefStore::default();
    store
        .node_entries
        .insert(root_ref.clone(), (node_bytes, None));

    let backend = paintgun::kcir_v2::CoreBaseApi::default();
    let verified = verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors(
        &root_ref, &store, &backend, &profile, &codec, None,
    )
    .expect("M_MKTENSOR should verify through ref-native projection path");

    assert_eq!(verified.root_cert_ref, root_ref);
    assert_eq!(verified.nodes.len(), 1);
    assert_eq!(verified.nodes[0].sort, paintgun::kcir_v2::SORT_MOR);
    assert_eq!(verified.nodes[0].out.digest.len(), 64);
}

#[test]
fn mor_mkcomp_verifier_uses_ref_native_projection_path() {
    let env_sig = [0x86; 32];
    let uid = [0x87; 32];
    let src_h = [0x88; 32];

    let mut args = Vec::with_capacity(65);
    args.extend_from_slice(&src_h);
    args.extend_from_slice(&src_h);
    args.push(0x00); // enc_list_b32([]) varint length

    let mut id_mor_bytes = Vec::with_capacity(33);
    id_mor_bytes.push(0x11);
    id_mor_bytes.extend_from_slice(&src_h);
    let out = paintgun::kcir_v2::h_mor(&env_sig, &uid, &id_mor_bytes);

    let node = KcirNode {
        env_sig,
        uid,
        sort: paintgun::kcir_v2::SORT_MOR,
        opcode: paintgun::kcir_v2::M_MKCOMP,
        out,
        args,
        deps: Vec::new(),
    };
    let node_bytes = node.encode();
    let root_cert_id = cert_id(&node_bytes);

    let params_hash = HashProfile::default_params_hash();
    let profile = AcceptAllProfile {
        scheme_id: "hash".to_string(),
        params_hash,
    };
    let root_ref = hash_ref_from_digest(DOMAIN_NODE, root_cert_id, params_hash);
    let codec = ProjectedNonLegacyOutNodeCodec;

    let mut store = EvidenceRefStore::default();
    store
        .node_entries
        .insert(root_ref.clone(), (node_bytes, None));

    let backend = paintgun::kcir_v2::CoreBaseApi::default();
    let verified = verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors(
        &root_ref, &store, &backend, &profile, &codec, None,
    )
    .expect("M_MKCOMP should verify through ref-native projection path");

    assert_eq!(verified.root_cert_ref, root_ref);
    assert_eq!(verified.nodes.len(), 1);
    assert_eq!(verified.nodes[0].sort, paintgun::kcir_v2::SORT_MOR);
    assert_eq!(verified.nodes[0].out.digest.len(), 64);
}

#[test]
fn hash_profile_anchor_entrypoint_accepts_passthrough_anchors() {
    let env_sig = [0x31; 32];
    let uid = [0x32; 32];
    let prim_id = [0x33; 32];

    let node = node_obj_prim(env_sig, uid, prim_id);
    let node_bytes = node.encode();
    let root_cert_id = cert_id(&node_bytes);
    let mut cert_store = BTreeMap::new();
    cert_store.insert(root_cert_id, node_bytes);

    let profile = HashProfile::default();
    let root_ref = hash_ref_from_digest(DOMAIN_NODE, root_cert_id, profile.params_hash());
    let anchors = ProfileAnchors {
        root_commitment: Some(vec![0xAA; 32]),
        tree_epoch: Some(7),
        metadata: BTreeMap::new(),
    };
    let verified = verify_core_dag_hash_profile_with_anchors(
        &root_ref,
        &cert_store,
        &BTreeMap::new(),
        &BTreeMap::new(),
        Some(&anchors),
    )
    .expect("hash profile should ignore anchors and still verify");

    assert_eq!(verified.root_cert_ref, root_ref);
}

#[test]
fn anchor_aware_profile_requires_anchors_from_core_verifier() {
    let env_sig = [0x41; 32];
    let uid = [0x42; 32];
    let prim_id = [0x43; 32];

    let node = node_obj_prim(env_sig, uid, prim_id);
    let node_bytes = node.encode();
    let root_cert_id = cert_id(&node_bytes);
    let mut cert_store = BTreeMap::new();
    cert_store.insert(root_cert_id, node_bytes);
    let obj_store = BTreeMap::new();
    let mor_store = BTreeMap::new();

    let params_hash = HashProfile::default_params_hash();
    let root_ref = hash_ref_from_digest(DOMAIN_NODE, root_cert_id, params_hash);
    let profile = AnchorCheckingHashProfile::new(vec![0xEF; 32], params_hash);

    let err = verify_core_dag_with_profile_and_anchors(
        &root_ref,
        &cert_store,
        &obj_store,
        &mor_store,
        &profile,
        None,
    )
    .expect_err("missing anchors should fail in custom profile");
    assert_eq!(err.code, error_codes::ANCHOR_MISSING);
    assert!(
        err.message
            .contains("missing required root commitment anchor"),
        "unexpected error message: {err}"
    );

    let anchors = ProfileAnchors {
        root_commitment: Some(vec![0xEF; 32]),
        tree_epoch: Some(1),
        metadata: BTreeMap::new(),
    };
    let verified = verify_core_dag_with_profile_and_anchors(
        &root_ref,
        &cert_store,
        &obj_store,
        &mor_store,
        &profile,
        Some(&anchors),
    )
    .expect("anchors should be forwarded to profile checks");
    assert_eq!(verified.root_cert_ref, root_ref);
}

#[test]
fn hash_profile_adapter_rejects_root_domain_mismatch() {
    let env_sig = [0x41; 32];
    let uid = [0x42; 32];
    let prim_id = [0x43; 32];

    let node = node_obj_prim(env_sig, uid, prim_id);
    let node_bytes = node.encode();
    let root_cert_id = cert_id(&node_bytes);

    let mut cert_store = BTreeMap::new();
    cert_store.insert(root_cert_id, node_bytes);

    let params_hash = HashProfile::default_params_hash();
    let bad_root_ref = hash_ref_from_digest(DOMAIN_OBJ_NF, root_cert_id, params_hash);
    let err = verify_core_dag_hash_profile(
        &bad_root_ref,
        &cert_store,
        &BTreeMap::new(),
        &BTreeMap::new(),
    )
    .expect_err("domain mismatch should be rejected");

    assert_eq!(err.code, error_codes::DOMAIN_MISMATCH);
    assert!(
        err.message.contains("domain mismatch"),
        "unexpected error message: {err}"
    );
}

#[test]
fn hash_profile_adapter_rejects_scheme_mismatch() {
    let env_sig = [0x71; 32];
    let uid = [0x72; 32];
    let prim_id = [0x73; 32];

    let node = node_obj_prim(env_sig, uid, prim_id);
    let node_bytes = node.encode();
    let root_cert_id = cert_id(&node_bytes);

    let mut cert_store = BTreeMap::new();
    cert_store.insert(root_cert_id, node_bytes);

    let mut bad_root_ref = hash_ref_from_digest(
        DOMAIN_NODE,
        root_cert_id,
        HashProfile::default_params_hash(),
    );
    bad_root_ref.scheme_id = "merkle".to_string();
    bad_root_ref.digest = vec![0u8; 32];
    let err = verify_core_dag_hash_profile(
        &bad_root_ref,
        &cert_store,
        &BTreeMap::new(),
        &BTreeMap::new(),
    )
    .expect_err("scheme mismatch should be rejected");

    assert_eq!(err.code, error_codes::PROFILE_MISMATCH);
    assert!(
        err.message.contains("scheme mismatch"),
        "unexpected error message: {err}"
    );
}

#[test]
fn hash_profile_adapter_rejects_non_32_byte_digest_refs() {
    let params_hash = HashProfile::default_params_hash();
    let bad_root_ref = Ref {
        scheme_id: "hash".to_string(),
        params_hash,
        domain: DOMAIN_NODE.to_string(),
        digest: vec![0u8; 31],
    };

    let err = verify_core_dag_hash_profile(
        &bad_root_ref,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
    )
    .expect_err("non-32-byte digest should be rejected by current adapter");

    assert_eq!(err.code, error_codes::PARSE_ERROR);
    assert!(
        err.message.contains("32-byte digest"),
        "unexpected error message: {err}"
    );
}

#[test]
fn hash_profile_obj_ref_requires_env_uid_context_payload() {
    let env_sig = [0x01; 32];
    let uid = [0x02; 32];
    let obj_bytes = vec![0x01];
    let profile = HashProfile::default();
    let obj_ref = hash_obj_ref(&env_sig, &uid, &obj_bytes, profile.params_hash());

    let mut good_payload = Vec::new();
    good_payload.extend_from_slice(&env_sig);
    good_payload.extend_from_slice(&uid);
    good_payload.extend_from_slice(&obj_bytes);
    profile
        .verify_ref(&obj_ref, &good_payload, None, DOMAIN_OBJ_NF)
        .expect("ObjNF hash payload should include env_sig || uid prefix");

    let err = profile
        .verify_ref(&obj_ref, &obj_bytes, None, DOMAIN_OBJ_NF)
        .expect_err("missing env/uid prefix should fail hash verification");
    assert_eq!(err.code, error_codes::DIGEST_MISMATCH);
    assert!(
        err.message.contains("digest mismatch"),
        "unexpected error message: {err}"
    );
}

#[test]
fn hash_profile_adapter_rejects_obj_outputs_without_available_nf_bytes() {
    let env_sig = [0x51; 32];
    let uid = [0x52; 32];
    let factor = h_obj(&env_sig, &uid, &[0x01]);

    // For one-factor tensor canonicalization, out == factor and no overlay bytes are created.
    let root = node_obj_mktensor(env_sig, uid, vec![factor]);
    let root_bytes = root.encode();
    let root_cert_id = cert_id(&root_bytes);
    let mut cert_store = BTreeMap::new();
    cert_store.insert(root_cert_id, root_bytes);

    let params_hash = HashProfile::default_params_hash();
    let root_ref = hash_ref_from_digest(DOMAIN_NODE, root_cert_id, params_hash);
    let err =
        verify_core_dag_hash_profile(&root_ref, &cert_store, &BTreeMap::new(), &BTreeMap::new())
            .expect_err(
                "OBJ out refs should require available ObjNF bytes for profile verification",
            );

    assert_eq!(err.code, error_codes::STORE_MISSING_OBJ_NF);
    assert!(
        err.message.contains("missing ObjNF bytes"),
        "unexpected error message: {err}"
    );
}

#[test]
fn merkle_profile_verifies_valid_evidence_with_anchors() {
    let payload = b"node-payload-v1";
    let profile = MerkleProfile::default();
    let proof = vec![
        MerkleProofStep {
            direction: MerkleDirection::Right,
            sibling_hash: [0x11; 32],
        },
        MerkleProofStep {
            direction: MerkleDirection::Left,
            sibling_hash: [0x22; 32],
        },
    ];
    let evidence = profile
        .evidence_for_payload(DOMAIN_NODE, payload, proof)
        .expect("construct merkle evidence");
    let reference = profile
        .ref_for_payload(DOMAIN_NODE, payload)
        .expect("construct merkle ref");
    let anchors = ProfileAnchors {
        root_commitment: Some(evidence.root.to_vec()),
        tree_epoch: Some(7),
        metadata: BTreeMap::new(),
    };

    profile
        .verify_ref_with_anchors(
            &reference,
            payload,
            Some(&evidence.encode()),
            Some(&anchors),
            DOMAIN_NODE,
        )
        .expect("valid Merkle evidence + anchors should verify");
}

#[test]
fn merkle_profile_rejects_malformed_or_invalid_evidence() {
    let payload = b"node-payload-v1";
    let profile = MerkleProfile::default();
    let proof = vec![MerkleProofStep {
        direction: MerkleDirection::Right,
        sibling_hash: [0x33; 32],
    }];
    let evidence = profile
        .evidence_for_payload(DOMAIN_NODE, payload, proof)
        .expect("construct merkle evidence");
    let reference = profile
        .ref_for_payload(DOMAIN_NODE, payload)
        .expect("construct merkle ref");
    let anchors = ProfileAnchors {
        root_commitment: Some(evidence.root.to_vec()),
        tree_epoch: Some(9),
        metadata: BTreeMap::new(),
    };

    let malformed = vec![MerkleEvidence::FORMAT_VERSION];
    let malformed_err = profile
        .verify_ref_with_anchors(
            &reference,
            payload,
            Some(&malformed),
            Some(&anchors),
            DOMAIN_NODE,
        )
        .expect_err("malformed Merkle evidence should fail");
    assert_eq!(malformed_err.code, error_codes::EVIDENCE_MALFORMED);

    let mut invalid = evidence.encode();
    let last = invalid.len() - 1;
    invalid[last] ^= 0x01;
    let invalid_err = profile
        .verify_ref_with_anchors(
            &reference,
            payload,
            Some(&invalid),
            Some(&anchors),
            DOMAIN_NODE,
        )
        .expect_err("invalid Merkle proof root should fail");
    assert_eq!(invalid_err.code, error_codes::EVIDENCE_INVALID);
}

#[test]
fn merkle_profile_requires_matching_anchor_root_and_epoch() {
    let payload = b"node-payload-v1";
    let profile = MerkleProfile::default();
    let evidence = profile
        .evidence_for_payload(DOMAIN_NODE, payload, Vec::new())
        .expect("construct merkle evidence");
    let reference = profile
        .ref_for_payload(DOMAIN_NODE, payload)
        .expect("construct merkle ref");
    let evidence_bytes = evidence.encode();

    let missing_anchor_err = profile
        .verify_ref_with_anchors(
            &reference,
            payload,
            Some(&evidence_bytes),
            None,
            DOMAIN_NODE,
        )
        .expect_err("anchors are required for Merkle profile");
    assert_eq!(missing_anchor_err.code, error_codes::ANCHOR_MISSING);

    let missing_epoch = ProfileAnchors {
        root_commitment: Some(evidence.root.to_vec()),
        tree_epoch: None,
        metadata: BTreeMap::new(),
    };
    let missing_epoch_err = profile
        .verify_ref_with_anchors(
            &reference,
            payload,
            Some(&evidence_bytes),
            Some(&missing_epoch),
            DOMAIN_NODE,
        )
        .expect_err("tree_epoch anchor is required for Merkle profile");
    assert_eq!(missing_epoch_err.code, error_codes::ANCHOR_MISSING);

    let bad_anchor = ProfileAnchors {
        root_commitment: Some(vec![0xAA; 32]),
        tree_epoch: Some(3),
        metadata: BTreeMap::new(),
    };
    let mismatch_err = profile
        .verify_ref_with_anchors(
            &reference,
            payload,
            Some(&evidence_bytes),
            Some(&bad_anchor),
            DOMAIN_NODE,
        )
        .expect_err("anchor root mismatch should fail");
    assert_eq!(mismatch_err.code, error_codes::ANCHOR_MISMATCH);
}

#[test]
fn cross_profile_refs_are_rejected_by_scheme_id() {
    let payload = b"cross-profile-payload";
    let hash_profile = HashProfile::default();
    let merkle_profile = MerkleProfile::default();

    let merkle_ref = merkle_profile
        .ref_for_payload(DOMAIN_NODE, payload)
        .expect("merkle ref");
    let merkle_evidence = merkle_profile
        .evidence_for_payload(DOMAIN_NODE, payload, Vec::new())
        .expect("merkle evidence")
        .encode();
    let hash_err = hash_profile
        .verify_ref(&merkle_ref, payload, Some(&merkle_evidence), DOMAIN_NODE)
        .expect_err("hash profile must reject merkle refs");
    assert_eq!(hash_err.code, error_codes::PROFILE_MISMATCH);

    let hash_ref = hash_ref_from_digest(
        DOMAIN_NODE,
        paintgun::kcir_v2::cert_id(payload),
        hash_profile.params_hash(),
    );
    let anchors = ProfileAnchors {
        root_commitment: Some(vec![0x00; 32]),
        tree_epoch: Some(1),
        metadata: BTreeMap::new(),
    };
    let merkle_err = merkle_profile
        .verify_ref_with_anchors(&hash_ref, payload, None, Some(&anchors), DOMAIN_NODE)
        .expect_err("merkle profile must reject hash refs");
    assert_eq!(merkle_err.code, error_codes::PROFILE_MISMATCH);
}

#[test]
fn merkle_profile_core_adapter_uses_profile_digest_backend() {
    let env_sig = [0x91; 32];
    let uid = [0x92; 32];
    let map_id = [0x93; 32];
    let node = KcirNode {
        env_sig,
        uid,
        sort: SORT_MAP,
        opcode: 0x01, // M_LITERAL
        out: map_id,
        args: map_id.to_vec(),
        deps: Vec::new(),
    };
    let node_bytes = node.encode();

    let profile = MerkleProfile::default();
    let root_ref = profile
        .ref_for_payload(DOMAIN_NODE, &node_bytes)
        .expect("construct merkle root ref");
    let node_evidence = profile
        .evidence_for_payload(DOMAIN_NODE, &node_bytes, Vec::new())
        .expect("construct merkle evidence");
    let anchors = ProfileAnchors {
        root_commitment: Some(node_evidence.root.to_vec()),
        tree_epoch: Some(11),
        metadata: BTreeMap::new(),
    };

    let mut store = EvidenceRefStore::default();
    store
        .node_entries
        .insert(root_ref.clone(), (node_bytes, Some(node_evidence.encode())));

    let backend = PanicDigestBackend;
    let verified = verify_core_dag_with_profile_and_backend_and_store_with_codec_and_anchors(
        &root_ref,
        &store,
        &backend,
        &profile,
        &LEGACY_FIXED32_WIRE_CODEC,
        Some(&anchors),
    )
    .expect("merkle-profile core adapter should verify using profile digest backend");

    assert_eq!(verified.root_cert_ref, root_ref);
    assert_eq!(verified.nodes.len(), 1);
    assert_eq!(verified.nodes[0].sort, SORT_MAP);
}
