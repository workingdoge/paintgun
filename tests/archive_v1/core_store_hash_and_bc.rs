use std::collections::BTreeMap;

use tbp::kcir_v2::{
    cert_id, h_mor, h_obj, verify_core_dag, verify_core_dag_with_backend_and_store,
    verify_core_dag_with_base_api, verify_mor_opcode_contract_with_store,
    verify_obj_opcode_contract_with_store, CoreBaseApi, KcirCoreStore, KcirNode, MorNfStore,
    ObjNfStore, M_BC_FPRIME, M_BC_GPRIME, M_PULL, O_MKTENSOR, O_PRIM, O_PULL, SORT_MAP, SORT_MOR,
    SORT_OBJ,
};

const M_LITERAL: u8 = 0x01;

fn enc_list_b32(items: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + items.len() * 32);
    out.push(u8::try_from(items.len()).expect("small test list"));
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

fn push_node(node: KcirNode, cert_store: &mut BTreeMap<[u8; 32], Vec<u8>>) -> [u8; 32] {
    let bytes = node.encode();
    let id = cert_id(&bytes);
    cert_store.insert(id, bytes);
    id
}

#[test]
fn core_verify_rejects_hash_mismatched_obj_store_entry() {
    let env_sig = [0u8; 32];
    let uid = [1u8; 32];

    let p_id = [0xaa; 32];
    let in_obj_h = [0xbb; 32];
    let f1 = [0x11; 32];
    let f2 = [0x22; 32];

    let mut cert_store: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();

    let mut pull1_args = Vec::with_capacity(65);
    pull1_args.extend_from_slice(&p_id);
    pull1_args.extend_from_slice(&f1);
    pull1_args.push(0x00);
    let pull1_id = push_node(
        KcirNode {
            env_sig,
            uid,
            sort: SORT_OBJ,
            opcode: O_PULL,
            out: f1,
            args: pull1_args,
            deps: Vec::new(),
        },
        &mut cert_store,
    );

    let mut pull2_args = Vec::with_capacity(65);
    pull2_args.extend_from_slice(&p_id);
    pull2_args.extend_from_slice(&f2);
    pull2_args.push(0x00);
    let pull2_id = push_node(
        KcirNode {
            env_sig,
            uid,
            sort: SORT_OBJ,
            opcode: O_PULL,
            out: f2,
            args: pull2_args,
            deps: Vec::new(),
        },
        &mut cert_store,
    );

    let mk_args = enc_list_b32(&[f1, f2]);
    let mut mk_obj_bytes = Vec::with_capacity(1 + mk_args.len());
    mk_obj_bytes.push(0x03);
    mk_obj_bytes.extend_from_slice(&mk_args);
    let mk_out = h_obj(&env_sig, &uid, &mk_obj_bytes);
    let mk_id = push_node(
        KcirNode {
            env_sig,
            uid,
            sort: SORT_OBJ,
            opcode: O_MKTENSOR,
            out: mk_out,
            args: mk_args,
            deps: Vec::new(),
        },
        &mut cert_store,
    );

    let mut root_args = Vec::with_capacity(65);
    root_args.extend_from_slice(&p_id);
    root_args.extend_from_slice(&in_obj_h);
    root_args.push(0x02);
    let root = KcirNode {
        env_sig,
        uid,
        sort: SORT_OBJ,
        opcode: O_PULL,
        out: mk_out,
        args: root_args,
        deps: vec![mk_id, pull1_id, pull2_id],
    };
    let root_id = push_node(root, &mut cert_store);

    // ObjNF Tensor(f1,f2), deliberately keyed under the wrong hash.
    let mut tensor_obj_bytes = Vec::with_capacity(1 + 1 + 64);
    tensor_obj_bytes.push(0x03);
    tensor_obj_bytes.extend_from_slice(&enc_list_b32(&[f1, f2]));
    let mut obj_store: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    obj_store.insert(in_obj_h, tensor_obj_bytes);

    let err = verify_core_dag(root_id, &cert_store, &obj_store, &BTreeMap::new())
        .expect_err("core verifier should reject hash-mismatched ObjNF entry");
    assert!(
        err.contains("ObjNF hash mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
fn core_verify_rejects_bc_push_base_pull_pid_mismatch() {
    let env_sig = [0u8; 32];
    let uid = [1u8; 32];

    let p_id = [0xaa; 32];
    let f_id = [0x24; 32];
    let base_h = [0xc6; 32];
    let f_prime = [0xf4; 32];
    let p_prime = [0xe5; 32];

    let mut cert_store: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();

    let pull_lit_id = push_node(
        KcirNode {
            env_sig,
            uid,
            sort: SORT_MAP,
            opcode: M_LITERAL,
            out: p_id,
            args: p_id.to_vec(),
            deps: Vec::new(),
        },
        &mut cert_store,
    );
    let push_lit_id = push_node(
        KcirNode {
            env_sig,
            uid,
            sort: SORT_MAP,
            opcode: M_LITERAL,
            out: f_id,
            args: f_id.to_vec(),
            deps: Vec::new(),
        },
        &mut cert_store,
    );
    let map_f_id = push_node(
        KcirNode {
            env_sig,
            uid,
            sort: SORT_MAP,
            opcode: M_BC_FPRIME,
            out: f_prime,
            args: Vec::new(),
            deps: vec![pull_lit_id, push_lit_id],
        },
        &mut cert_store,
    );
    let map_g_id = push_node(
        KcirNode {
            env_sig,
            uid,
            sort: SORT_MAP,
            opcode: M_BC_GPRIME,
            out: p_prime,
            args: Vec::new(),
            deps: vec![pull_lit_id, push_lit_id],
        },
        &mut cert_store,
    );

    let mut base_pull_args = Vec::with_capacity(65);
    base_pull_args.extend_from_slice(&p_id);
    base_pull_args.extend_from_slice(&base_h);
    base_pull_args.push(0x00);
    let base_pull_id = push_node(
        KcirNode {
            env_sig,
            uid,
            sort: SORT_OBJ,
            opcode: O_PULL,
            out: base_h,
            args: base_pull_args,
            deps: Vec::new(),
        },
        &mut cert_store,
    );

    let mut in_obj_bytes = Vec::with_capacity(65);
    in_obj_bytes.push(0x05);
    in_obj_bytes.extend_from_slice(&f_id);
    in_obj_bytes.extend_from_slice(&base_h);
    let in_obj_h = h_obj(&env_sig, &uid, &in_obj_bytes);

    let mut root_args = Vec::with_capacity(65);
    root_args.extend_from_slice(&p_id);
    root_args.extend_from_slice(&in_obj_h);
    root_args.push(0x05);
    let mut root_obj_bytes = Vec::with_capacity(65);
    root_obj_bytes.push(0x05);
    root_obj_bytes.extend_from_slice(&f_prime);
    root_obj_bytes.extend_from_slice(&base_h);
    let root_out = h_obj(&env_sig, &uid, &root_obj_bytes);
    let root_id = push_node(
        KcirNode {
            env_sig,
            uid,
            sort: SORT_OBJ,
            opcode: O_PULL,
            out: root_out,
            args: root_args,
            deps: vec![map_f_id, map_g_id, base_pull_id],
        },
        &mut cert_store,
    );

    let mut obj_store: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    obj_store.insert(in_obj_h, in_obj_bytes);

    let mut base_api = CoreBaseApi::default();
    base_api.bc_squares.insert((f_id, p_id), (f_prime, p_prime));

    let err = verify_core_dag_with_base_api(
        root_id,
        &cert_store,
        &obj_store,
        &BTreeMap::new(),
        &base_api,
    )
    .expect_err("core verifier should reject BC basePull pId mismatch");
    assert!(
        err.contains("basePull meta.pId mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
fn core_verify_rejects_bc_swap_inner_pull_pid_mismatch() {
    let env_sig = [0u8; 32];
    let uid = [1u8; 32];

    let p_id = [0xaa; 32];
    let f_id = [0x24; 32];
    let f_prime = [0xf4; 32];
    let p_prime = [0xe5; 32];
    let src_h = [0x33; 32];
    let tgt_h = [0x33; 32];

    let mut cert_store: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();

    let pull_lit_id = push_node(
        KcirNode {
            env_sig,
            uid,
            sort: SORT_MAP,
            opcode: M_LITERAL,
            out: p_id,
            args: p_id.to_vec(),
            deps: Vec::new(),
        },
        &mut cert_store,
    );
    let push_lit_id = push_node(
        KcirNode {
            env_sig,
            uid,
            sort: SORT_MAP,
            opcode: M_LITERAL,
            out: f_id,
            args: f_id.to_vec(),
            deps: Vec::new(),
        },
        &mut cert_store,
    );
    let map_f_id = push_node(
        KcirNode {
            env_sig,
            uid,
            sort: SORT_MAP,
            opcode: M_BC_FPRIME,
            out: f_prime,
            args: Vec::new(),
            deps: vec![pull_lit_id, push_lit_id],
        },
        &mut cert_store,
    );
    let map_g_id = push_node(
        KcirNode {
            env_sig,
            uid,
            sort: SORT_MAP,
            opcode: M_BC_GPRIME,
            out: p_prime,
            args: Vec::new(),
            deps: vec![pull_lit_id, push_lit_id],
        },
        &mut cert_store,
    );

    let mut inner_bytes = Vec::with_capacity(33);
    inner_bytes.push(0x11);
    inner_bytes.extend_from_slice(&src_h);
    let inner_h = h_mor(&env_sig, &uid, &inner_bytes);

    let mut src_pull_args = Vec::with_capacity(65);
    src_pull_args.extend_from_slice(&p_id);
    src_pull_args.extend_from_slice(&src_h);
    src_pull_args.push(0x00);
    let src_pull_id = push_node(
        KcirNode {
            env_sig,
            uid,
            sort: SORT_OBJ,
            opcode: O_PULL,
            out: src_h,
            args: src_pull_args,
            deps: Vec::new(),
        },
        &mut cert_store,
    );

    let mut inner_pull_args = Vec::with_capacity(65);
    inner_pull_args.extend_from_slice(&p_id);
    inner_pull_args.extend_from_slice(&inner_h);
    inner_pull_args.push(0x01);
    let inner_pull_id = push_node(
        KcirNode {
            env_sig,
            uid,
            sort: SORT_MOR,
            opcode: M_PULL,
            out: inner_h,
            args: inner_pull_args,
            deps: vec![src_pull_id],
        },
        &mut cert_store,
    );

    let mut in_mor_bytes = Vec::with_capacity(129);
    in_mor_bytes.push(0x17);
    in_mor_bytes.extend_from_slice(&src_h);
    in_mor_bytes.extend_from_slice(&tgt_h);
    in_mor_bytes.extend_from_slice(&f_id);
    in_mor_bytes.extend_from_slice(&inner_h);
    let in_mor_h = h_mor(&env_sig, &uid, &in_mor_bytes);

    let mut root_args = Vec::with_capacity(65);
    root_args.extend_from_slice(&p_id);
    root_args.extend_from_slice(&in_mor_h);
    root_args.push(0x05);
    let mut root_mor_bytes = Vec::with_capacity(129);
    root_mor_bytes.push(0x17);
    root_mor_bytes.extend_from_slice(&src_h);
    root_mor_bytes.extend_from_slice(&tgt_h);
    root_mor_bytes.extend_from_slice(&f_prime);
    root_mor_bytes.extend_from_slice(&inner_h);
    let root_out = h_mor(&env_sig, &uid, &root_mor_bytes);
    let root_id = push_node(
        KcirNode {
            env_sig,
            uid,
            sort: SORT_MOR,
            opcode: M_PULL,
            out: root_out,
            args: root_args,
            deps: vec![map_f_id, map_g_id, inner_pull_id],
        },
        &mut cert_store,
    );

    let mut mor_store: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    mor_store.insert(in_mor_h, in_mor_bytes);
    mor_store.insert(inner_h, inner_bytes);

    let mut base_api = CoreBaseApi::default();
    base_api.bc_squares.insert((f_id, p_id), (f_prime, p_prime));

    let err = verify_core_dag_with_base_api(
        root_id,
        &cert_store,
        &BTreeMap::new(),
        &mor_store,
        &base_api,
    )
    .expect_err("core verifier should reject BC innerPull pId mismatch");
    assert!(
        err.contains("innerPull meta.pId mismatch"),
        "unexpected error: {err}"
    );
}

struct TestCoreStore {
    cert_store: BTreeMap<[u8; 32], Vec<u8>>,
    obj_store: BTreeMap<[u8; 32], Vec<u8>>,
    mor_store: BTreeMap<[u8; 32], Vec<u8>>,
}

impl KcirCoreStore for TestCoreStore {
    fn cert_node_bytes(&self, cert_id: &[u8; 32]) -> Option<Vec<u8>> {
        self.cert_store.get(cert_id).cloned()
    }
}

impl ObjNfStore for TestCoreStore {
    fn obj_nf_bytes(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.obj_store.get(key).cloned()
    }
}

impl MorNfStore for TestCoreStore {
    fn mor_nf_bytes(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.mor_store.get(key).cloned()
    }
}

#[test]
fn core_verify_accepts_custom_store_trait_impl() {
    let env_sig = [0u8; 32];
    let uid = [1u8; 32];
    let prim_id = [0x42; 32];

    let mut obj_bytes = Vec::with_capacity(33);
    obj_bytes.push(0x02);
    obj_bytes.extend_from_slice(&prim_id);
    let out = h_obj(&env_sig, &uid, &obj_bytes);
    let root = KcirNode {
        env_sig,
        uid,
        sort: SORT_OBJ,
        opcode: O_PRIM,
        out,
        args: prim_id.to_vec(),
        deps: Vec::new(),
    };
    let root_bytes = root.encode();
    let root_cert_id = cert_id(&root_bytes);

    let mut cert_store = BTreeMap::new();
    cert_store.insert(root_cert_id, root_bytes);
    let store = TestCoreStore {
        cert_store,
        obj_store: BTreeMap::new(),
        mor_store: BTreeMap::new(),
    };
    let backend = CoreBaseApi::default();
    let verified = verify_core_dag_with_backend_and_store(root_cert_id, &store, &backend)
        .expect("custom store-backed verification should succeed");
    assert_eq!(verified.root_cert_id, root_cert_id);
    assert_eq!(verified.nodes.len(), 1);
    assert_eq!(verified.nodes[0].sort, SORT_OBJ);
    assert_eq!(verified.nodes[0].opcode, O_PRIM);
    assert_eq!(verified.nodes[0].out, out);
}

struct TestObjStore {
    entries: BTreeMap<[u8; 32], Vec<u8>>,
}

impl ObjNfStore for TestObjStore {
    fn obj_nf_bytes(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.entries.get(key).cloned()
    }
}

struct TestMorStore {
    entries: BTreeMap<[u8; 32], Vec<u8>>,
}

impl MorNfStore for TestMorStore {
    fn mor_nf_bytes(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.entries.get(key).cloned()
    }
}

#[test]
fn opcode_verify_obj_accepts_custom_obj_store_trait_impl() {
    let env_sig = [0u8; 32];
    let uid = [1u8; 32];
    let p_id = [0xaa; 32];
    let in_obj_h = [0xbb; 32];

    let mut args = Vec::with_capacity(65);
    args.extend_from_slice(&p_id);
    args.extend_from_slice(&in_obj_h);
    args.push(0x01);

    let unit_bytes = vec![0x01];
    let out = h_obj(&env_sig, &uid, &unit_bytes);
    let node = KcirNode {
        env_sig,
        uid,
        sort: SORT_OBJ,
        opcode: O_PULL,
        out,
        args,
        deps: Vec::new(),
    };

    let mut entries = BTreeMap::new();
    entries.insert(in_obj_h, unit_bytes);
    let store = TestObjStore { entries };

    let verified = verify_obj_opcode_contract_with_store(&node, &[], &store, None)
        .expect("OBJ opcode verification with custom ObjNfStore should succeed");
    assert_eq!(verified.exp_out, out);
}

#[test]
fn opcode_verify_mor_accepts_custom_mor_store_trait_impl() {
    let env_sig = [0u8; 32];
    let uid = [1u8; 32];
    let p_id = [0xaa; 32];
    let src_h = [0x10; 32];
    let tgt_h = [0x20; 32];
    let f_id = [0x30; 32];
    let inner_h = [0x40; 32];

    let mut in_mor_bytes = Vec::with_capacity(129);
    in_mor_bytes.push(0x17);
    in_mor_bytes.extend_from_slice(&src_h);
    in_mor_bytes.extend_from_slice(&tgt_h);
    in_mor_bytes.extend_from_slice(&f_id);
    in_mor_bytes.extend_from_slice(&inner_h);
    let in_mor_h = h_mor(&env_sig, &uid, &in_mor_bytes);

    let mut args = Vec::with_capacity(65);
    args.extend_from_slice(&p_id);
    args.extend_from_slice(&in_mor_h);
    args.push(0x07);

    let mut out_bytes = Vec::with_capacity(129);
    out_bytes.push(0x16);
    out_bytes.extend_from_slice(&src_h);
    out_bytes.extend_from_slice(&tgt_h);
    out_bytes.extend_from_slice(&p_id);
    out_bytes.extend_from_slice(&in_mor_h);
    let out = h_mor(&env_sig, &uid, &out_bytes);

    let node = KcirNode {
        env_sig,
        uid,
        sort: SORT_MOR,
        opcode: M_PULL,
        out,
        args,
        deps: Vec::new(),
    };

    let mut entries = BTreeMap::new();
    entries.insert(in_mor_h, in_mor_bytes);
    let store = TestMorStore { entries };
    let base_api = CoreBaseApi {
        adopt_pull_atom_mor: true,
        ..CoreBaseApi::default()
    };

    let verified = verify_mor_opcode_contract_with_store(&node, &[], &store, Some(&base_api))
        .expect("MOR opcode verification with custom MorNfStore should succeed");
    assert_eq!(verified.exp_out, out);
}
