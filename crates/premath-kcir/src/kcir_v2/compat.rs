use premath_kcir_kernel as kernel;

pub(super) type KernelNode = kernel::KcirNode;
pub(super) type KernelPullCoverWitness = kernel::PullCoverWitness;

pub(super) const SORT_COVER: u8 = kernel::SORT_COVER;
pub(super) const SORT_MAP: u8 = kernel::SORT_MAP;
pub(super) const SORT_OBJ: u8 = kernel::SORT_OBJ;
pub(super) const SORT_MOR: u8 = kernel::SORT_MOR;

pub(super) const O_UNIT: u8 = kernel::O_UNIT;
pub(super) const O_PRIM: u8 = kernel::O_PRIM;
pub(super) const O_MKTENSOR: u8 = kernel::O_MKTENSOR;
pub(super) const O_PULL: u8 = kernel::O_PULL;

pub(super) const M_ID: u8 = kernel::M_ID;
pub(super) const M_MKTENSOR: u8 = kernel::M_MKTENSOR;
pub(super) const M_MKCOMP: u8 = kernel::M_MKCOMP;
pub(super) const M_PULL: u8 = kernel::M_PULL;

pub(super) const C_PULLCOVER: u8 = kernel::C_PULLCOVER;
pub(super) const M_BC_FPRIME: u8 = kernel::M_BC_FPRIME;
pub(super) const M_BC_GPRIME: u8 = kernel::M_BC_GPRIME;

pub(super) use kernel::{
    mor_opcode_meta_to_dep_meta, obj_opcode_meta_to_dep_meta, parse_mor_nf_bytes_with_options,
    parse_obj_nf_bytes, MorNf, MorNfStore, MorOpcodeMeta, ObjNf, ObjNfStore, ObjOpcodeMeta,
};

pub(super) fn h_obj(env_sig: &[u8; 32], uid: &[u8; 32], obj_bytes: &[u8]) -> [u8; 32] {
    kernel::h_obj(env_sig, uid, obj_bytes)
}

pub(super) fn h_mor(env_sig: &[u8; 32], uid: &[u8; 32], mor_bytes: &[u8]) -> [u8; 32] {
    kernel::h_mor(env_sig, uid, mor_bytes)
}

pub(super) fn cert_id(node_bytes: &[u8]) -> [u8; 32] {
    kernel::cert_id(node_bytes)
}

pub(super) fn parse_node_bytes(node_bytes: &[u8]) -> Result<KernelNode, String> {
    kernel::parse_node_bytes(node_bytes)
}

pub(super) fn node_obj_prim(env_sig: [u8; 32], uid: [u8; 32], prim_id: [u8; 32]) -> KernelNode {
    kernel::node_obj_prim(env_sig, uid, prim_id)
}

pub(super) fn node_obj_mktensor(
    env_sig: [u8; 32],
    uid: [u8; 32],
    factors: Vec<[u8; 32]>,
) -> KernelNode {
    kernel::node_obj_mktensor(env_sig, uid, factors)
}
