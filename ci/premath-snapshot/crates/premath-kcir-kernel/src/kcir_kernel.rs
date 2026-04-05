//! KCIR export (minimal)
//!
//! This module is intentionally small and self-contained:
//! - encodes KCIRNodeBytes
//! - computes certId = SHA256("KCIRNode" || nodeBytes)
//! - computes hObj = SHA256("ObjNF" || envSig || uid || objBytes)
//!
//! We only construct a few object opcodes that are useful as *glue*:
//! - OBJ/O_PRIM: wrap an external artifact digest as an ObjNF `Prim`
//! - OBJ/O_MKTENSOR: bundle multiple ObjNF hashes into an ObjNF `Tensor`
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::util::sha256_bytes;
use crate::{dsl, dsl::UniquePos};

pub const SORT_COVER: u8 = 0x01;
pub const SORT_MAP: u8 = 0x02;
pub const SORT_OBJ: u8 = 0x03;
pub const SORT_MOR: u8 = 0x04;

pub const O_PRIM: u8 = 0x02;
pub const O_MKTENSOR: u8 = 0x03;
pub const O_UNIT: u8 = 0x01;
pub const O_PULL: u8 = 0x10;

pub const M_ID: u8 = 0x01;
pub const M_MKTENSOR: u8 = 0x02;
pub const M_MKCOMP: u8 = 0x03;
pub const M_PULL: u8 = 0x10;

pub const C_PULLCOVER: u8 = 0x02;
pub const M_BC_FPRIME: u8 = 0x10;
pub const M_BC_GPRIME: u8 = 0x11;

/// Unsigned LEB128 varint.
fn enc_varint(mut n: u64, out: &mut Vec<u8>) {
    while n >= 0x80 {
        out.push(((n as u8) & 0x7F) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

/// Decode an unsigned LEB128 varint from `bytes` at `cursor`.
fn dec_varint(bytes: &[u8], cursor: &mut usize, field: &str) -> Result<u64, String> {
    let mut out: u64 = 0;
    let mut shift = 0u32;
    let mut steps = 0usize;
    loop {
        if *cursor >= bytes.len() {
            return Err(format!(
                "truncated varint for {field} at byte offset {}",
                cursor
            ));
        }
        let b = bytes[*cursor];
        *cursor += 1;
        steps += 1;
        if steps > 10 {
            return Err(format!("overlong varint for {field}"));
        }

        let chunk = (b & 0x7F) as u64;
        if shift >= 64 || (chunk.checked_shl(shift).is_none()) {
            return Err(format!("varint overflow for {field}"));
        }
        out |= chunk << shift;
        if (b & 0x80) == 0 {
            return Ok(out);
        }
        shift += 7;
    }
}

fn enc_list_b32(items: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + items.len() * 32);
    enc_varint(items.len() as u64, &mut out);
    for it in items {
        out.extend_from_slice(it);
    }
    out
}

fn dec_list_b32(bytes: &[u8], field: &str) -> Result<(Vec<[u8; 32]>, usize), String> {
    let mut cursor = 0usize;
    let len = dec_varint(bytes, &mut cursor, field)? as usize;
    let total_bytes = len
        .checked_mul(32)
        .ok_or_else(|| format!("{field} overflow"))?;
    if cursor + total_bytes > bytes.len() {
        return Err(format!(
            "{field} length {} runs past end of payload ({} bytes total)",
            len,
            bytes.len()
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

/// hObj(objBytes) = SHA256("ObjNF" || envSig || uid || objBytes)
pub fn h_obj(env_sig: &[u8; 32], uid: &[u8; 32], obj_bytes: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(5 + 32 + 32 + obj_bytes.len());
    buf.extend_from_slice(b"ObjNF");
    buf.extend_from_slice(env_sig);
    buf.extend_from_slice(uid);
    buf.extend_from_slice(obj_bytes);
    sha256_bytes(&buf)
}

/// hMor(morBytes) = SHA256("MorNF" || envSig || uid || morBytes)
pub fn h_mor(env_sig: &[u8; 32], uid: &[u8; 32], mor_bytes: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(5 + 32 + 32 + mor_bytes.len());
    buf.extend_from_slice(b"MorNF");
    buf.extend_from_slice(env_sig);
    buf.extend_from_slice(uid);
    buf.extend_from_slice(mor_bytes);
    sha256_bytes(&buf)
}

/// certId = SHA256("KCIRNode" || nodeBytes)
pub fn cert_id(node_bytes: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + node_bytes.len());
    buf.extend_from_slice(b"KCIRNode");
    buf.extend_from_slice(node_bytes);
    sha256_bytes(&buf)
}

#[derive(Clone, Debug)]
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
        let mut out = Vec::with_capacity(32 + 32 + 1 + 1 + 32 + 10 + self.args.len());
        out.extend_from_slice(&self.env_sig);
        out.extend_from_slice(&self.uid);
        out.push(self.sort);
        out.push(self.opcode);
        out.extend_from_slice(&self.out);

        enc_varint(self.args.len() as u64, &mut out);
        out.extend_from_slice(&self.args);

        enc_varint(self.deps.len() as u64, &mut out);
        for d in &self.deps {
            out.extend_from_slice(d);
        }
        out
    }

    pub fn cert_id(&self) -> [u8; 32] {
        cert_id(&self.encode())
    }
}

/// Parse and validate a KCIRNode byte payload.
///
/// This enforces raw wire-shape constraints used by conformance checks:
/// - fixed header lengths
/// - valid varints
/// - args/deps length bounds
/// - no trailing bytes
pub fn parse_node_bytes(node_bytes: &[u8]) -> Result<KcirNode, String> {
    // Fixed prefix: envSig(32) + uid(32) + sort(1) + opcode(1) + out(32)
    if node_bytes.len() < 98 {
        return Err(format!(
            "truncated KCIR node: expected at least 98 bytes, got {}",
            node_bytes.len()
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

    let mut out = [0u8; 32];
    out.copy_from_slice(&node_bytes[cursor..cursor + 32]);
    cursor += 32;

    let args_len = dec_varint(node_bytes, &mut cursor, "argsLen")? as usize;
    if cursor + args_len > node_bytes.len() {
        return Err(format!(
            "argsLen {} runs past end of KCIR node ({} bytes total)",
            args_len,
            node_bytes.len()
        ));
    }
    let args = node_bytes[cursor..cursor + args_len].to_vec();
    cursor += args_len;

    let deps_len = dec_varint(node_bytes, &mut cursor, "depsLen")? as usize;
    let deps_bytes = deps_len
        .checked_mul(32)
        .ok_or_else(|| "depsLen overflow".to_string())?;
    if cursor + deps_bytes > node_bytes.len() {
        return Err(format!(
            "depsLen {} runs past end of KCIR node ({} bytes total)",
            deps_len,
            node_bytes.len()
        ));
    }
    let mut deps = Vec::with_capacity(deps_len);
    for _ in 0..deps_len {
        let mut dep = [0u8; 32];
        dep.copy_from_slice(&node_bytes[cursor..cursor + 32]);
        cursor += 32;
        deps.push(dep);
    }

    if cursor != node_bytes.len() {
        return Err(format!(
            "KCIR node has trailing bytes: consumed {}, total {}",
            cursor,
            node_bytes.len()
        ));
    }

    Ok(KcirNode {
        env_sig,
        uid,
        sort,
        opcode,
        out,
        args,
        deps,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjNf {
    Unit,
    Prim([u8; 32]),
    Tensor(Vec<[u8; 32]>),
    PullSpine {
        p_id: [u8; 32],
        base_h: [u8; 32],
    },
    PushSpine {
        f_id: [u8; 32],
        base_h: [u8; 32],
    },
    Glue {
        w_sig: [u8; 32],
        locals: Vec<[u8; 32]>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MorNf {
    Id {
        src_h: [u8; 32],
    },
    Comp {
        src_h: [u8; 32],
        tgt_h: [u8; 32],
        parts: Vec<[u8; 32]>,
    },
    PullAtom {
        src_h: [u8; 32],
        tgt_h: [u8; 32],
        p_id: [u8; 32],
        inner_h: [u8; 32],
    },
    PushAtom {
        src_h: [u8; 32],
        tgt_h: [u8; 32],
        f_id: [u8; 32],
        inner_h: [u8; 32],
    },
    TensorAtom {
        src_h: [u8; 32],
        tgt_h: [u8; 32],
        parts: Vec<[u8; 32]>,
    },
    GlueAtom {
        src_h: [u8; 32],
        tgt_h: [u8; 32],
        w_sig: [u8; 32],
        locals: Vec<[u8; 32]>,
    },
}

/// Parse ObjNF bytes according to `raw/NF`.
pub fn parse_obj_nf_bytes(obj_bytes: &[u8]) -> Result<ObjNf, String> {
    if obj_bytes.is_empty() {
        return Err("ObjNF payload is empty".to_string());
    }
    let tag = obj_bytes[0];
    let rest = &obj_bytes[1..];
    match tag {
        0x01 => {
            if !rest.is_empty() {
                return Err("ObjNF Unit must not carry payload".to_string());
            }
            Ok(ObjNf::Unit)
        }
        0x02 => {
            if rest.len() != 32 {
                return Err(format!(
                    "ObjNF Prim expects 32-byte primId, got {} bytes",
                    rest.len()
                ));
            }
            let mut prim = [0u8; 32];
            prim.copy_from_slice(rest);
            Ok(ObjNf::Prim(prim))
        }
        0x03 => {
            let (factors, used) = dec_list_b32(rest, "ObjNF Tensor factors")?;
            if used != rest.len() {
                return Err("ObjNF Tensor has trailing bytes".to_string());
            }
            Ok(ObjNf::Tensor(factors))
        }
        0x04 => {
            if rest.len() != 64 {
                return Err(format!(
                    "ObjNF PullSpine expects 64-byte payload, got {} bytes",
                    rest.len()
                ));
            }
            let mut p_id = [0u8; 32];
            p_id.copy_from_slice(&rest[0..32]);
            let mut base_h = [0u8; 32];
            base_h.copy_from_slice(&rest[32..64]);
            Ok(ObjNf::PullSpine { p_id, base_h })
        }
        0x05 => {
            if rest.len() != 64 {
                return Err(format!(
                    "ObjNF PushSpine expects 64-byte payload, got {} bytes",
                    rest.len()
                ));
            }
            let mut f_id = [0u8; 32];
            f_id.copy_from_slice(&rest[0..32]);
            let mut base_h = [0u8; 32];
            base_h.copy_from_slice(&rest[32..64]);
            Ok(ObjNf::PushSpine { f_id, base_h })
        }
        0x06 => {
            if rest.len() < 32 {
                return Err(format!(
                    "ObjNF Glue expects at least 32-byte wSig, got {} bytes",
                    rest.len()
                ));
            }
            let mut w_sig = [0u8; 32];
            w_sig.copy_from_slice(&rest[0..32]);
            let (locals, used) = dec_list_b32(&rest[32..], "ObjNF Glue locals")?;
            if 32 + used != rest.len() {
                return Err("ObjNF Glue has trailing bytes".to_string());
            }
            Ok(ObjNf::Glue { w_sig, locals })
        }
        other => Err(format!("unknown ObjNF tag 0x{other:02x}")),
    }
}

/// Parse MorNF bytes according to `raw/NF`, optionally enabling PullAtom (`tag 0x16`).
pub fn parse_mor_nf_bytes_with_options(
    mor_bytes: &[u8],
    adopt_pull_atom_mor: bool,
) -> Result<MorNf, String> {
    if mor_bytes.is_empty() {
        return Err("MorNF payload is empty".to_string());
    }
    let tag = mor_bytes[0];
    let rest = &mor_bytes[1..];
    match tag {
        0x11 => {
            if rest.len() != 32 {
                return Err(format!(
                    "MorNF Id expects 32-byte srcH, got {} bytes",
                    rest.len()
                ));
            }
            let mut src_h = [0u8; 32];
            src_h.copy_from_slice(rest);
            Ok(MorNf::Id { src_h })
        }
        0x13 => {
            if rest.len() < 64 {
                return Err(format!(
                    "MorNF Comp expects at least 64-byte src/tgt payload, got {} bytes",
                    rest.len()
                ));
            }
            let mut src_h = [0u8; 32];
            src_h.copy_from_slice(&rest[0..32]);
            let mut tgt_h = [0u8; 32];
            tgt_h.copy_from_slice(&rest[32..64]);
            let (parts, used) = dec_list_b32(&rest[64..], "MorNF Comp parts")?;
            if 64 + used != rest.len() {
                return Err("MorNF Comp has trailing bytes".to_string());
            }
            Ok(MorNf::Comp {
                src_h,
                tgt_h,
                parts,
            })
        }
        0x16 => {
            if !adopt_pull_atom_mor {
                return Err("MorNF PullAtom (tag 0x16) is not adopted in this profile".to_string());
            }
            if rest.len() != 128 {
                return Err(format!(
                    "MorNF PullAtom expects 128-byte payload, got {} bytes",
                    rest.len()
                ));
            }
            let mut src_h = [0u8; 32];
            src_h.copy_from_slice(&rest[0..32]);
            let mut tgt_h = [0u8; 32];
            tgt_h.copy_from_slice(&rest[32..64]);
            let mut p_id = [0u8; 32];
            p_id.copy_from_slice(&rest[64..96]);
            let mut inner_h = [0u8; 32];
            inner_h.copy_from_slice(&rest[96..128]);
            Ok(MorNf::PullAtom {
                src_h,
                tgt_h,
                p_id,
                inner_h,
            })
        }
        0x17 => {
            if rest.len() != 128 {
                return Err(format!(
                    "MorNF PushAtom expects 128-byte payload, got {} bytes",
                    rest.len()
                ));
            }
            let mut src_h = [0u8; 32];
            src_h.copy_from_slice(&rest[0..32]);
            let mut tgt_h = [0u8; 32];
            tgt_h.copy_from_slice(&rest[32..64]);
            let mut f_id = [0u8; 32];
            f_id.copy_from_slice(&rest[64..96]);
            let mut inner_h = [0u8; 32];
            inner_h.copy_from_slice(&rest[96..128]);
            Ok(MorNf::PushAtom {
                src_h,
                tgt_h,
                f_id,
                inner_h,
            })
        }
        0x18 => {
            if rest.len() < 64 {
                return Err(format!(
                    "MorNF TensorAtom expects at least 64-byte src/tgt payload, got {} bytes",
                    rest.len()
                ));
            }
            let mut src_h = [0u8; 32];
            src_h.copy_from_slice(&rest[0..32]);
            let mut tgt_h = [0u8; 32];
            tgt_h.copy_from_slice(&rest[32..64]);
            let (parts, used) = dec_list_b32(&rest[64..], "MorNF TensorAtom parts")?;
            if 64 + used != rest.len() {
                return Err("MorNF TensorAtom has trailing bytes".to_string());
            }
            Ok(MorNf::TensorAtom {
                src_h,
                tgt_h,
                parts,
            })
        }
        0x19 => {
            if rest.len() < 96 {
                return Err(format!(
                    "MorNF GlueAtom expects at least 96-byte src/tgt/wSig payload, got {} bytes",
                    rest.len()
                ));
            }
            let mut src_h = [0u8; 32];
            src_h.copy_from_slice(&rest[0..32]);
            let mut tgt_h = [0u8; 32];
            tgt_h.copy_from_slice(&rest[32..64]);
            let mut w_sig = [0u8; 32];
            w_sig.copy_from_slice(&rest[64..96]);
            let (locals, used) = dec_list_b32(&rest[96..], "MorNF GlueAtom locals")?;
            if 96 + used != rest.len() {
                return Err("MorNF GlueAtom has trailing bytes".to_string());
            }
            Ok(MorNf::GlueAtom {
                src_h,
                tgt_h,
                w_sig,
                locals,
            })
        }
        other => Err(format!("unknown MorNF tag 0x{other:02x}")),
    }
}

/// Parse MorNF bytes according to `raw/NF` with default profile settings.
pub fn parse_mor_nf_bytes(mor_bytes: &[u8]) -> Result<MorNf, String> {
    parse_mor_nf_bytes_with_options(mor_bytes, false)
}

pub fn verify_obj_hash_entry_with_options(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    key: &[u8; 32],
    obj_bytes: &[u8],
    obj_store: &dyn ObjNfStore,
    enforce_canonical: bool,
) -> Result<ObjNf, String> {
    let parsed = parse_obj_nf_bytes(obj_bytes)?;
    let got = h_obj(env_sig, uid, obj_bytes);
    if &got != key {
        return Err(format!(
            "ObjNF hash mismatch: expected {}, got {}",
            hex::encode(key),
            hex::encode(got)
        ));
    }
    if enforce_canonical {
        validate_obj_nf_canonical(&parsed, obj_store, env_sig, uid, true, None)?;
    }
    Ok(parsed)
}

pub fn verify_mor_hash_entry(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    key: &[u8; 32],
    mor_bytes: &[u8],
) -> Result<MorNf, String> {
    let empty_store = BTreeMap::new();
    verify_mor_hash_entry_with_options(env_sig, uid, key, mor_bytes, &empty_store, false)
}

pub fn verify_obj_hash_entry(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    key: &[u8; 32],
    obj_bytes: &[u8],
) -> Result<ObjNf, String> {
    let empty_store = BTreeMap::new();
    verify_obj_hash_entry_with_options(env_sig, uid, key, obj_bytes, &empty_store, false)
}

pub fn verify_mor_hash_entry_with_options(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    key: &[u8; 32],
    mor_bytes: &[u8],
    mor_store: &dyn MorNfStore,
    enforce_canonical: bool,
) -> Result<MorNf, String> {
    verify_mor_hash_entry_with_options_and_profile(
        env_sig,
        uid,
        key,
        mor_bytes,
        mor_store,
        enforce_canonical,
        false,
    )
}

pub fn verify_mor_hash_entry_with_options_and_profile(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    key: &[u8; 32],
    mor_bytes: &[u8],
    mor_store: &dyn MorNfStore,
    enforce_canonical: bool,
    adopt_pull_atom_mor: bool,
) -> Result<MorNf, String> {
    let parsed = parse_mor_nf_bytes_with_options(mor_bytes, adopt_pull_atom_mor)?;
    let got = h_mor(env_sig, uid, mor_bytes);
    if &got != key {
        return Err(format!(
            "MorNF hash mismatch: expected {}, got {}",
            hex::encode(key),
            hex::encode(got)
        ));
    }
    if enforce_canonical {
        validate_mor_nf_canonical(
            &parsed,
            mor_store,
            env_sig,
            uid,
            true,
            None,
            adopt_pull_atom_mor,
        )?;
    }
    Ok(parsed)
}

fn validate_obj_nf_canonical(
    parsed: &ObjNf,
    obj_store: &dyn ObjNfStore,
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    enforce_hash: bool,
    hash_backend: Option<&dyn KcirBackend>,
) -> Result<(), String> {
    match parsed {
        ObjNf::Tensor(factors) if factors.len() <= 1 => Err(format!(
            "non-canonical ObjNF Tensor has {} factor(s); canonical form requires len >= 2",
            factors.len()
        )),
        ObjNf::PullSpine { base_h, .. } => {
            if let Some(base_bytes) = obj_store.obj_nf_bytes(base_h) {
                let base_nf = if enforce_hash {
                    let parsed = parse_obj_nf_bytes(&base_bytes)?;
                    let got = digest_obj_with_backend(hash_backend, env_sig, uid, &base_bytes);
                    if &got != base_h {
                        return Err(format!(
                            "ObjNF hash mismatch: expected {}, got {}",
                            hex::encode(base_h),
                            hex::encode(got)
                        ));
                    }
                    parsed
                } else {
                    parse_obj_nf_bytes(&base_bytes)?
                };
                if matches!(base_nf, ObjNf::PullSpine { .. }) {
                    return Err(format!(
                        "non-canonical ObjNF PullSpine nests PullSpine at baseH={}",
                        hex::encode(base_h)
                    ));
                }
            }
            Ok(())
        }
        ObjNf::PushSpine { base_h, .. } => {
            if let Some(base_bytes) = obj_store.obj_nf_bytes(base_h) {
                let base_nf = if enforce_hash {
                    let parsed = parse_obj_nf_bytes(&base_bytes)?;
                    let got = digest_obj_with_backend(hash_backend, env_sig, uid, &base_bytes);
                    if &got != base_h {
                        return Err(format!(
                            "ObjNF hash mismatch: expected {}, got {}",
                            hex::encode(base_h),
                            hex::encode(got)
                        ));
                    }
                    parsed
                } else {
                    parse_obj_nf_bytes(&base_bytes)?
                };
                if matches!(base_nf, ObjNf::PushSpine { .. }) {
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

fn validate_mor_nf_canonical(
    parsed: &MorNf,
    mor_store: &dyn MorNfStore,
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    enforce_hash: bool,
    hash_backend: Option<&dyn KcirBackend>,
    adopt_pull_atom_mor: bool,
) -> Result<(), String> {
    match parsed {
        MorNf::Comp {
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
                    let parsed = parse_mor_nf_bytes_with_options(&part_bytes, adopt_pull_atom_mor)?;
                    let got = digest_mor_with_backend(hash_backend, env_sig, uid, &part_bytes);
                    if &got != part_h {
                        return Err(format!(
                            "MorNF hash mismatch: expected {}, got {}",
                            hex::encode(part_h),
                            hex::encode(got)
                        ));
                    }
                    parsed
                } else {
                    parse_mor_nf_bytes_with_options(&part_bytes, adopt_pull_atom_mor)?
                };
                match part_nf {
                    MorNf::Id { .. } => {
                        return Err(format!(
                            "non-canonical MorNF Comp contains Id part at index {idx}"
                        ));
                    }
                    MorNf::Comp { .. } => {
                        return Err(format!(
                            "non-canonical MorNF Comp contains nested Comp part at index {idx}"
                        ));
                    }
                    other => {
                        part_endpoints.push(mor_endpoints(&other));
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
        MorNf::PullAtom { inner_h, .. } => {
            if let Some(inner_bytes) = mor_store.mor_nf_bytes(inner_h) {
                let inner_nf = if enforce_hash {
                    let parsed =
                        parse_mor_nf_bytes_with_options(&inner_bytes, adopt_pull_atom_mor)?;
                    let got = digest_mor_with_backend(hash_backend, env_sig, uid, &inner_bytes);
                    if &got != inner_h {
                        return Err(format!(
                            "MorNF hash mismatch: expected {}, got {}",
                            hex::encode(inner_h),
                            hex::encode(got)
                        ));
                    }
                    parsed
                } else {
                    parse_mor_nf_bytes_with_options(&inner_bytes, adopt_pull_atom_mor)?
                };
                if matches!(inner_nf, MorNf::PullAtom { .. }) {
                    return Err(format!(
                        "non-canonical MorNF PullAtom nests PullAtom at innerH={}",
                        hex::encode(inner_h)
                    ));
                }
            }
            Ok(())
        }
        MorNf::PushAtom { inner_h, .. } => {
            if let Some(inner_bytes) = mor_store.mor_nf_bytes(inner_h) {
                let inner_nf = if enforce_hash {
                    let parsed =
                        parse_mor_nf_bytes_with_options(&inner_bytes, adopt_pull_atom_mor)?;
                    let got = digest_mor_with_backend(hash_backend, env_sig, uid, &inner_bytes);
                    if &got != inner_h {
                        return Err(format!(
                            "MorNF hash mismatch: expected {}, got {}",
                            hex::encode(inner_h),
                            hex::encode(got)
                        ));
                    }
                    parsed
                } else {
                    parse_mor_nf_bytes_with_options(&inner_bytes, adopt_pull_atom_mor)?
                };
                if matches!(inner_nf, MorNf::PushAtom { .. }) {
                    return Err(format!(
                        "non-canonical MorNF PushAtom nests PushAtom at innerH={}",
                        hex::encode(inner_h)
                    ));
                }
            }
            Ok(())
        }
        MorNf::TensorAtom { parts, .. } if parts.len() <= 1 => Err(format!(
            "non-canonical MorNF TensorAtom has {} part(s); canonical form requires len >= 2",
            parts.len()
        )),
        _ => Ok(()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjOpcodeMeta {
    Unit,
    Prim {
        prim_id: [u8; 32],
    },
    MkTensor {
        factors: Vec<[u8; 32]>,
    },
    PullId {
        p_id: [u8; 32],
        in_obj_h: [u8; 32],
        step_tag: u8,
    },
    PullUnit {
        p_id: [u8; 32],
        in_obj_h: [u8; 32],
        step_tag: u8,
    },
    PullWrap {
        p_id: [u8; 32],
        in_obj_h: [u8; 32],
        step_tag: u8,
    },
    PullGlue {
        p_id: [u8; 32],
        in_obj_h: [u8; 32],
        step_tag: u8,
        cover_out: [u8; 32],
        pulled_locals: Vec<[u8; 32]>,
    },
    PullTensor {
        p_id: [u8; 32],
        in_obj_h: [u8; 32],
        step_tag: u8,
        mk_out: [u8; 32],
        pulled_factors: Vec<[u8; 32]>,
    },
    PullBcPush {
        p_id: [u8; 32],
        in_obj_h: [u8; 32],
        step_tag: u8,
        f_prime_out: [u8; 32],
        g_prime_out: [u8; 32],
        base_pull_out: [u8; 32],
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjOpcodeVerifyResult {
    pub meta: ObjOpcodeMeta,
    pub exp_out: [u8; 32],
    pub overlay_obj_bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepRecord {
    pub sort: u8,
    pub opcode: u8,
    pub out: [u8; 32],
    #[serde(default)]
    pub meta: BTreeMap<String, String>,
}

impl DepRecord {
    fn as_dep_shape(&self) -> dsl::DepShape {
        dsl::DepShape {
            sort: self.sort,
            opcode: self.opcode,
            meta: self.meta.clone(),
        }
    }
}

fn ensure_dep_alignment(node: &KcirNode, deps: &[DepRecord], label: &str) -> Result<(), String> {
    if node.deps.len() != deps.len() {
        return Err(format!(
            "{label} dependency metadata count mismatch: node has {} dep cert ids, verifier received {} dep records",
            node.deps.len(),
            deps.len()
        ));
    }
    Ok(())
}

fn ensure_dep_alignment_len(dep_len: usize, deps: &[DepRecord], label: &str) -> Result<(), String> {
    if dep_len != deps.len() {
        return Err(format!(
            "{label} dependency metadata count mismatch: node has {} dep cert ids, verifier received {} dep records",
            dep_len,
            deps.len()
        ));
    }
    Ok(())
}

fn match_unique_role(
    deps: &[DepRecord],
    pred: &dsl::UniquePred,
    role_name: &str,
) -> Result<(DepRecord, Vec<DepRecord>), String> {
    let shapes = deps.iter().map(DepRecord::as_dep_shape).collect::<Vec<_>>();
    let matched = dsl::match_unique_spec(&shapes, pred, UniquePos::Anywhere, false)
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

fn parse_pull_args(args: &[u8], label: &str) -> Result<([u8; 32], [u8; 32], u8), String> {
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

fn parse_obj_nf_from_store(
    obj_store: &dyn ObjNfStore,
    key: &[u8; 32],
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    enforce_hash: bool,
    hash_backend: Option<&dyn KcirBackend>,
    enforce_canonical: bool,
    label: &str,
) -> Result<ObjNf, String> {
    let obj_bytes = obj_store
        .obj_nf_bytes(key)
        .ok_or_else(|| format!("{label} requires objStore entry for {}", hex::encode(key)))?;
    let parsed = if enforce_hash {
        let parsed = parse_obj_nf_bytes(&obj_bytes).map_err(|e| {
            format!(
                "{label} objStore entry {} is not valid ObjNF: {e}",
                hex::encode(key)
            )
        })?;
        let got = digest_obj_with_backend(hash_backend, env_sig, uid, &obj_bytes);
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
        parse_obj_nf_bytes(&obj_bytes).map_err(|e| {
            format!(
                "{label} objStore entry {} is not valid ObjNF: {e}",
                hex::encode(key)
            )
        })?
    };
    if enforce_canonical {
        validate_obj_nf_canonical(&parsed, obj_store, env_sig, uid, enforce_hash, hash_backend)
            .map_err(|e| {
                format!(
                    "{label} objStore entry {} canonicality validation failed: {e}",
                    hex::encode(key)
                )
            })?;
    }
    Ok(parsed)
}

fn parse_mor_nf_from_store(
    mor_store: &dyn MorNfStore,
    key: &[u8; 32],
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    enforce_hash: bool,
    hash_backend: Option<&dyn KcirBackend>,
    enforce_canonical: bool,
    adopt_pull_atom_mor: bool,
    label: &str,
) -> Result<MorNf, String> {
    let mor_bytes = mor_store
        .mor_nf_bytes(key)
        .ok_or_else(|| format!("{label} requires morStore entry for {}", hex::encode(key)))?;
    let parsed = if enforce_hash {
        let parsed =
            parse_mor_nf_bytes_with_options(&mor_bytes, adopt_pull_atom_mor).map_err(|e| {
                format!(
                    "{label} morStore entry {} is not valid MorNF: {e}",
                    hex::encode(key)
                )
            })?;
        let got = digest_mor_with_backend(hash_backend, env_sig, uid, &mor_bytes);
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
        parse_mor_nf_bytes_with_options(&mor_bytes, adopt_pull_atom_mor).map_err(|e| {
            format!(
                "{label} morStore entry {} is not valid MorNF: {e}",
                hex::encode(key)
            )
        })?
    };
    if enforce_canonical {
        validate_mor_nf_canonical(
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

fn dec_list_u32(bytes: &[u8], field: &str) -> Result<(Vec<u32>, usize), String> {
    let mut cursor = 0usize;
    let len = dec_varint(bytes, &mut cursor, field)? as usize;
    let mut out = Vec::with_capacity(len);
    for idx in 0..len {
        let v = dec_varint(bytes, &mut cursor, &format!("{field}[{idx}]"))?;
        let vv = u32::try_from(v).map_err(|_| format!("{field}[{idx}] out of range: {v}"))?;
        out.push(vv);
    }
    Ok((out, cursor))
}

fn parse_csv_u32(raw: &str, field: &str) -> Result<Vec<u32>, String> {
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

fn parse_csv_hex32(raw: &str, field: &str) -> Result<Vec<[u8; 32]>, String> {
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

fn parse_optional_dep_meta_hex32(
    dep: &DepRecord,
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
struct ObjPullDepMeta {
    p_id: Option<[u8; 32]>,
    in_obj_h: Option<[u8; 32]>,
}

impl ObjPullDepMeta {
    fn parse(dep: &DepRecord, label: &str) -> Result<Self, String> {
        Ok(Self {
            p_id: parse_optional_dep_meta_hex32(dep, "pId", label)?,
            in_obj_h: parse_optional_dep_meta_hex32(dep, "inObjH", label)?,
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
struct MorPullDepMeta {
    p_id: Option<[u8; 32]>,
    in_mor_h: Option<[u8; 32]>,
}

impl MorPullDepMeta {
    fn parse(dep: &DepRecord, label: &str) -> Result<Self, String> {
        Ok(Self {
            p_id: parse_optional_dep_meta_hex32(dep, "pId", label)?,
            in_mor_h: parse_optional_dep_meta_hex32(dep, "inMorH", label)?,
        })
    }
}

#[derive(Clone, Debug)]
struct CoverProjectionMeta {
    map_w_to_u: Vec<u32>,
    proj_ids: Vec<[u8; 32]>,
}

fn parse_cover_projection_meta(
    cover_dep: &DepRecord,
    label: &str,
) -> Result<CoverProjectionMeta, String> {
    let map_w_to_u_raw = cover_dep
        .meta
        .get("mapWtoU")
        .ok_or_else(|| format!("{label} cover dep requires meta.mapWtoU"))?;
    let proj_ids_raw = cover_dep
        .meta
        .get("projIds")
        .ok_or_else(|| format!("{label} cover dep requires meta.projIds"))?;
    let map_w_to_u = parse_csv_u32(map_w_to_u_raw, &format!("{label} mapWtoU"))?;
    let proj_ids = parse_csv_hex32(proj_ids_raw, &format!("{label} projIds"))?;
    if proj_ids.len() != map_w_to_u.len() {
        return Err(format!(
            "{label} cover meta mismatch: projIds len {} != mapWtoU len {}",
            proj_ids.len(),
            map_w_to_u.len()
        ));
    }
    Ok(CoverProjectionMeta {
        map_w_to_u,
        proj_ids,
    })
}

fn expected_glue_keys(
    cover_meta: &CoverProjectionMeta,
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
enum PullGlueMetaKind {
    Obj,
    Mor,
}

fn pull_dep_glue_key(
    dep: &DepRecord,
    kind: PullGlueMetaKind,
    label: &str,
) -> Result<Option<String>, String> {
    match kind {
        PullGlueMetaKind::Obj => {
            let meta = ObjPullDepMeta::parse(dep, label)?;
            Ok(match (meta.p_id, meta.in_obj_h) {
                (Some(p), Some(i)) => Some(format!("{}:{}", hex::encode(p), hex::encode(i))),
                _ => None,
            })
        }
        PullGlueMetaKind::Mor => {
            let meta = MorPullDepMeta::parse(dep, label)?;
            Ok(match (meta.p_id, meta.in_mor_h) {
                (Some(p), Some(i)) => Some(format!("{}:{}", hex::encode(p), hex::encode(i))),
                _ => None,
            })
        }
    }
}

fn match_pull_glue_locals(
    rem: &[DepRecord],
    sort: u8,
    opcode: u8,
    meta_kind: PullGlueMetaKind,
    expected_keys: &[String],
    label: &str,
) -> Result<Vec<[u8; 32]>, String> {
    let mut rem_shapes = Vec::with_capacity(rem.len());
    for dep in rem {
        let mut shape = dep.as_dep_shape();
        if let Some(glue_key) = pull_dep_glue_key(dep, meta_kind, label)? {
            shape.meta.insert("glueKey".to_string(), glue_key);
        }
        rem_shapes.push(shape);
    }
    let role_locals = dsl::UniquePred {
        sort: Some(sort),
        opcode: Some(opcode),
        meta_eq: BTreeMap::new(),
    };
    let bag = dsl::match_bag_spec(
        &rem_shapes,
        &role_locals,
        &dsl::KeySelector::Meta("glueKey".to_string()),
        expected_keys,
        dsl::BagMode::Unordered,
        UniquePos::Anywhere,
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

fn hex_keys(keys: &[[u8; 32]]) -> Vec<String> {
    keys.iter().map(hex::encode).collect()
}

fn canonical_obj_tensor_out(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    factors: &[[u8; 32]],
    hash_backend: Option<&dyn KcirBackend>,
) -> ([u8; 32], Option<Vec<u8>>) {
    match factors.len() {
        0 => {
            let obj_bytes = vec![0x01];
            (
                digest_obj_with_backend(hash_backend, env_sig, uid, &obj_bytes),
                Some(obj_bytes),
            )
        }
        1 => (factors[0], None),
        _ => {
            let args = enc_list_b32(factors);
            let mut obj_bytes = Vec::with_capacity(1 + args.len());
            obj_bytes.push(0x03);
            obj_bytes.extend_from_slice(&args);
            (
                digest_obj_with_backend(hash_backend, env_sig, uid, &obj_bytes),
                Some(obj_bytes),
            )
        }
    }
}

fn canonicalize_comp_parts(
    parts: &[[u8; 32]],
    mor_store: &dyn MorNfStore,
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
            match parse_mor_nf_from_store(
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
                MorNf::Id { .. } => {}
                MorNf::Comp { parts: inner, .. } => out.extend(inner),
                _ => out.push(*part),
            }
        } else {
            out.push(*part);
        }
    }
    Ok(out)
}

fn mor_endpoints(m: &MorNf) -> ([u8; 32], [u8; 32]) {
    match m {
        MorNf::Id { src_h } => (*src_h, *src_h),
        MorNf::Comp { src_h, tgt_h, .. } => (*src_h, *tgt_h),
        MorNf::PullAtom { src_h, tgt_h, .. } => (*src_h, *tgt_h),
        MorNf::PushAtom { src_h, tgt_h, .. } => (*src_h, *tgt_h),
        MorNf::TensorAtom { src_h, tgt_h, .. } => (*src_h, *tgt_h),
        MorNf::GlueAtom { src_h, tgt_h, .. } => (*src_h, *tgt_h),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PullCoverWitness {
    pub w_sig: [u8; 32],
    pub map_w_to_u: Vec<u32>,
    pub proj_ids: Vec<[u8; 32]>,
}

/// Backend hooks used by KCIR opcode/core verification.
///
/// `CoreBaseApi` provides the default in-memory implementation used by
/// conformance fixtures and tests, but callers can provide custom backends by
/// implementing this trait.
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

fn enforce_nf_canonicality(backend: Option<&dyn KcirBackend>) -> bool {
    backend.is_some_and(KcirBackend::enforce_nf_canonicality)
}

fn adopt_pull_atom_mor(backend: Option<&dyn KcirBackend>) -> bool {
    backend.is_some_and(KcirBackend::adopt_pull_atom_mor)
}

fn digest_obj_with_backend(
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

fn digest_mor_with_backend(
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

fn classify_obj_pull_step(
    p_id: &[u8; 32],
    in_obj_h: &[u8; 32],
    obj_store: &dyn ObjNfStore,
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
    let nf = parse_obj_nf_from_store(
        obj_store,
        in_obj_h,
        env_sig,
        uid,
        base_api.is_some(),
        base_api,
        enforce_nf_canonicality(base_api),
        "O_PULL prelude",
    )?;
    let step = match nf {
        ObjNf::Unit => 0x01,
        ObjNf::Tensor(_) => 0x02,
        ObjNf::Glue { .. } => 0x03,
        ObjNf::PullSpine { .. } => 0x04,
        ObjNf::PushSpine { f_id, .. } => {
            if base_api.is_some_and(|api| api.bc_allowed(p_id, &f_id)) {
                0x05
            } else {
                0x06
            }
        }
        ObjNf::Prim(_) => 0x06,
    };
    Ok(Some(step))
}

fn classify_mor_pull_step(
    p_id: &[u8; 32],
    in_mor_h: &[u8; 32],
    mor_store: &dyn MorNfStore,
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
    let nf = parse_mor_nf_from_store(
        mor_store,
        in_mor_h,
        env_sig,
        uid,
        base_api.is_some(),
        base_api,
        enforce_nf_canonicality(base_api),
        adopt_pull_atom_mor(base_api),
        "M_PULL prelude",
    )?;
    let step = match nf {
        MorNf::Id { .. } => 0x01,
        MorNf::Comp { .. } => 0x02,
        MorNf::PullAtom { .. } => 0x04,
        MorNf::GlueAtom { .. } => 0x03,
        MorNf::PushAtom { f_id, .. } => {
            if base_api.is_some_and(|api| api.bc_allowed(p_id, &f_id)) {
                0x05
            } else {
                0x07
            }
        }
        MorNf::TensorAtom { .. } => 0x06,
    };
    Ok(Some(step))
}

fn mk_pull_spine_out(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    p_id: [u8; 32],
    in_obj_h: [u8; 32],
    obj_store: &dyn ObjNfStore,
    base_api: Option<&dyn KcirBackend>,
) -> Result<([u8; 32], Option<Vec<u8>>), String> {
    if base_api.is_some_and(|api| api.is_id_map(&p_id)) {
        return Ok((in_obj_h, None));
    }

    if obj_store.obj_nf_bytes(&in_obj_h).is_some() {
        let parsed = parse_obj_nf_from_store(
            obj_store,
            &in_obj_h,
            env_sig,
            uid,
            base_api.is_some(),
            base_api,
            enforce_nf_canonicality(base_api),
            "O_PULL.WRAP/FUSE",
        )?;
        if let ObjNf::PullSpine {
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
                digest_obj_with_backend(base_api, env_sig, uid, &obj_bytes),
                Some(obj_bytes),
            ));
        }
    }

    let mut obj_bytes = Vec::with_capacity(65);
    obj_bytes.push(0x04);
    obj_bytes.extend_from_slice(&p_id);
    obj_bytes.extend_from_slice(&in_obj_h);
    Ok((
        digest_obj_with_backend(base_api, env_sig, uid, &obj_bytes),
        Some(obj_bytes),
    ))
}

fn mk_pull_atom_out(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    p_id: [u8; 32],
    in_mor_h: [u8; 32],
    mor_store: &dyn MorNfStore,
    base_api: Option<&dyn KcirBackend>,
) -> Result<([u8; 32], Option<Vec<u8>>), String> {
    if base_api.is_some_and(|api| api.is_id_map(&p_id)) {
        return Ok((in_mor_h, None));
    }

    let parsed = parse_mor_nf_from_store(
        mor_store,
        &in_mor_h,
        env_sig,
        uid,
        base_api.is_some(),
        base_api,
        enforce_nf_canonicality(base_api),
        adopt_pull_atom_mor(base_api),
        "M_PULL.WRAP/FUSE",
    )?;

    if let MorNf::PullAtom {
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
            digest_mor_with_backend(base_api, env_sig, uid, &mor_bytes),
            Some(mor_bytes),
        ));
    }

    let (src_h, tgt_h) = mor_endpoints(&parsed);
    let mut mor_bytes = Vec::with_capacity(129);
    mor_bytes.push(0x16);
    mor_bytes.extend_from_slice(&src_h);
    mor_bytes.extend_from_slice(&tgt_h);
    mor_bytes.extend_from_slice(&p_id);
    mor_bytes.extend_from_slice(&in_mor_h);
    Ok((
        digest_mor_with_backend(base_api, env_sig, uid, &mor_bytes),
        Some(mor_bytes),
    ))
}

/// Storage interface for ObjNF lookups used by OBJ opcode verification.
pub trait ObjNfStore {
    fn obj_nf_bytes(&self, key: &[u8; 32]) -> Option<Vec<u8>>;
}

/// In-memory ObjNF store adapter for map-backed call sites.
pub struct InMemoryObjNfStore<'a> {
    pub obj_store: &'a BTreeMap<[u8; 32], Vec<u8>>,
}

impl ObjNfStore for InMemoryObjNfStore<'_> {
    fn obj_nf_bytes(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.obj_store.get(key).cloned()
    }
}

impl ObjNfStore for BTreeMap<[u8; 32], Vec<u8>> {
    fn obj_nf_bytes(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.get(key).cloned()
    }
}

/// Storage interface for MorNF lookups used by MOR opcode verification.
pub trait MorNfStore {
    fn mor_nf_bytes(&self, key: &[u8; 32]) -> Option<Vec<u8>>;
}

/// In-memory MorNF store adapter for map-backed call sites.
pub struct InMemoryMorNfStore<'a> {
    pub mor_store: &'a BTreeMap<[u8; 32], Vec<u8>>,
}

impl MorNfStore for InMemoryMorNfStore<'_> {
    fn mor_nf_bytes(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.mor_store.get(key).cloned()
    }
}

impl MorNfStore for BTreeMap<[u8; 32], Vec<u8>> {
    fn mor_nf_bytes(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.get(key).cloned()
    }
}

/// Verify OBJ opcode contracts against a pluggable ObjNF store backend.
pub fn verify_obj_opcode_contract_with_store(
    node: &KcirNode,
    deps: &[DepRecord],
    obj_store: &dyn ObjNfStore,
    base_api: Option<&dyn KcirBackend>,
) -> Result<ObjOpcodeVerifyResult, String> {
    verify_obj_opcode_contract_with_stores(node, deps, obj_store, base_api)
}

/// Verify an `O_PULL` OBJ opcode contract from decomposed node fields.
///
/// This adapter preserves existing pull-role semantics while avoiding a requirement
/// for real dep cert ids at the call site (only dep-record metadata alignment matters).
pub fn verify_obj_pull_opcode_contract_parts(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    out: [u8; 32],
    args: &[u8],
    deps: &[DepRecord],
    obj_store: &dyn ObjNfStore,
    base_api: Option<&dyn KcirBackend>,
) -> Result<ObjOpcodeVerifyResult, String> {
    verify_obj_pull_opcode_contract_core(
        env_sig,
        uid,
        out,
        args,
        deps.len(),
        deps,
        obj_store,
        base_api,
    )
}

fn verify_obj_pull_opcode_contract_core(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    out: [u8; 32],
    args: &[u8],
    dep_len: usize,
    deps: &[DepRecord],
    obj_store: &dyn ObjNfStore,
    base_api: Option<&dyn KcirBackend>,
) -> Result<ObjOpcodeVerifyResult, String> {
    ensure_dep_alignment_len(dep_len, deps, "OBJ opcode contract")?;

    let (p_id, in_obj_h, step_tag) = parse_pull_args(args, "O_PULL")?;
    if let Some(exp_step) =
        classify_obj_pull_step(&p_id, &in_obj_h, obj_store, env_sig, uid, base_api)?
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
            Ok(ObjOpcodeVerifyResult {
                meta: ObjOpcodeMeta::PullId {
                    p_id,
                    in_obj_h,
                    step_tag,
                },
                exp_out: in_obj_h,
                overlay_obj_bytes: None,
            })
        }
        0x01 => {
            if !deps.is_empty() {
                return Err("O_PULL.UNIT expects no deps".to_string());
            }
            let obj_bytes = vec![0x01];
            let exp_out = digest_obj_with_backend(base_api, env_sig, uid, &obj_bytes);
            if out != exp_out {
                return Err(format!(
                    "O_PULL.UNIT out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(out)
                ));
            }
            Ok(ObjOpcodeVerifyResult {
                meta: ObjOpcodeMeta::PullUnit {
                    p_id,
                    in_obj_h,
                    step_tag,
                },
                exp_out,
                overlay_obj_bytes: Some(obj_bytes),
            })
        }
        0x04 | 0x06 => {
            if !deps.is_empty() {
                return Err(format!("O_PULL stepTag=0x{step_tag:02x} expects no deps"));
            }
            let (exp_out, overlay_obj_bytes) =
                mk_pull_spine_out(env_sig, uid, p_id, in_obj_h, obj_store, base_api)?;
            if out != exp_out {
                return Err(format!(
                    "O_PULL stepTag=0x{step_tag:02x} out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(out)
                ));
            }
            Ok(ObjOpcodeVerifyResult {
                meta: ObjOpcodeMeta::PullWrap {
                    p_id,
                    in_obj_h,
                    step_tag,
                },
                exp_out,
                overlay_obj_bytes,
            })
        }
        0x02 => {
            let role_mk = dsl::UniquePred {
                sort: Some(SORT_OBJ),
                opcode: Some(O_MKTENSOR),
                meta_eq: BTreeMap::new(),
            };
            let (mk_dep, rem) = match_unique_role(deps, &role_mk, "mk")?;
            let in_obj_nf = parse_obj_nf_from_store(
                obj_store,
                &in_obj_h,
                env_sig,
                uid,
                base_api.is_some(),
                base_api,
                enforce_nf_canonicality(base_api),
                "O_PULL.TENSOR",
            )?;
            let expected_keys = match in_obj_nf {
                ObjNf::Unit => Vec::new(),
                ObjNf::Tensor(factors) => hex_keys(&factors),
                other => {
                    return Err(format!(
                        "O_PULL.TENSOR requires inObjH to reference ObjNF Unit/Tensor, got {other:?}"
                    ))
                }
            };
            let mut factor_meta = BTreeMap::new();
            factor_meta.insert("pId".to_string(), hex::encode(p_id));
            let role_factors = dsl::UniquePred {
                sort: Some(SORT_OBJ),
                opcode: Some(O_PULL),
                meta_eq: factor_meta,
            };
            let rem_shapes = rem.iter().map(DepRecord::as_dep_shape).collect::<Vec<_>>();
            let bag = dsl::match_bag_spec(
                &rem_shapes,
                &role_factors,
                &dsl::KeySelector::Meta("inObjH".to_string()),
                &expected_keys,
                dsl::BagMode::Unordered,
                UniquePos::Anywhere,
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
            let (mk_exp_out, _) = canonical_obj_tensor_out(env_sig, uid, &pulled_factors, base_api);
            if mk_dep.out != mk_exp_out {
                return Err(format!(
                    "O_PULL.TENSOR mk out mismatch: expected {}, got {}",
                    hex::encode(mk_exp_out),
                    hex::encode(mk_dep.out)
                ));
            }
            if let Some(raw) = mk_dep.meta.get("factors") {
                let mk_factors = parse_csv_hex32(raw, "O_PULL.TENSOR mk.meta.factors")?;
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
            Ok(ObjOpcodeVerifyResult {
                meta: ObjOpcodeMeta::PullTensor {
                    p_id,
                    in_obj_h,
                    step_tag,
                    mk_out: mk_dep.out,
                    pulled_factors,
                },
                exp_out: mk_dep.out,
                overlay_obj_bytes: None,
            })
        }
        0x03 => {
            let in_obj_nf = parse_obj_nf_from_store(
                obj_store,
                &in_obj_h,
                env_sig,
                uid,
                base_api.is_some(),
                base_api,
                enforce_nf_canonicality(base_api),
                "O_PULL.GLUE",
            )?;
            let (u_sig, locals_u) = match in_obj_nf {
                ObjNf::Glue { w_sig, locals } => (w_sig, locals),
                other => {
                    return Err(format!(
                        "O_PULL.GLUE requires inObjH to reference ObjNF Glue, got {other:?}"
                    ))
                }
            };
            let role_cover = dsl::UniquePred {
                sort: Some(SORT_COVER),
                opcode: Some(C_PULLCOVER),
                meta_eq: BTreeMap::new(),
            };
            let (cover_dep, rem) = match_unique_role(deps, &role_cover, "cover")?;
            let cover_meta = parse_cover_projection_meta(&cover_dep, "O_PULL.GLUE")?;
            let expected_keys = expected_glue_keys(&cover_meta, &locals_u, "O_PULL.GLUE")?;
            let pulled_locals = match_pull_glue_locals(
                &rem,
                SORT_OBJ,
                O_PULL,
                PullGlueMetaKind::Obj,
                &expected_keys,
                "O_PULL.GLUE",
            )?;
            let args = enc_list_b32(&pulled_locals);
            let mut obj_bytes = Vec::with_capacity(1 + 32 + args.len());
            obj_bytes.push(0x06);
            obj_bytes.extend_from_slice(&cover_dep.out);
            obj_bytes.extend_from_slice(&args);
            let exp_out = digest_obj_with_backend(base_api, env_sig, uid, &obj_bytes);
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
            Ok(ObjOpcodeVerifyResult {
                meta: ObjOpcodeMeta::PullGlue {
                    p_id,
                    in_obj_h,
                    step_tag,
                    cover_out: cover_dep.out,
                    pulled_locals,
                },
                exp_out,
                overlay_obj_bytes: Some(obj_bytes),
            })
        }
        0x05 => {
            let role_fprime = dsl::UniquePred {
                sort: Some(SORT_MAP),
                opcode: Some(M_BC_FPRIME),
                meta_eq: BTreeMap::new(),
            };
            let role_gprime = dsl::UniquePred {
                sort: Some(SORT_MAP),
                opcode: Some(M_BC_GPRIME),
                meta_eq: BTreeMap::new(),
            };
            let role_base_pull = dsl::UniquePred {
                sort: Some(SORT_OBJ),
                opcode: Some(O_PULL),
                meta_eq: BTreeMap::new(),
            };

            let (f_prime_dep, rem1) = match_unique_role(deps, &role_fprime, "fPrime")?;
            let (g_prime_dep, rem2) = match_unique_role(&rem1, &role_gprime, "gPrime")?;
            let (base_pull_dep, rem3) = match_unique_role(&rem2, &role_base_pull, "basePull")?;
            if !rem3.is_empty() {
                return Err(format!(
                    "O_PULL.BC_PUSH has unexpected extra deps after role match: {}",
                    rem3.len()
                ));
            }
            let base_pull_meta = ObjPullDepMeta::parse(&base_pull_dep, "O_PULL.BC_PUSH basePull")?;
            if obj_store.obj_nf_bytes(&in_obj_h).is_some() {
                let in_nf = parse_obj_nf_from_store(
                    obj_store,
                    &in_obj_h,
                    env_sig,
                    uid,
                    base_api.is_some(),
                    base_api,
                    enforce_nf_canonicality(base_api),
                    "O_PULL.BC_PUSH",
                )?;
                let (f_id, base_h) = match in_nf {
                    ObjNf::PushSpine { f_id, base_h } => (f_id, base_h),
                    other => {
                        return Err(format!(
                            "O_PULL.BC_PUSH requires inObjH to reference ObjNF PushSpine, got {other:?}"
                        ))
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
            let exp_out = digest_obj_with_backend(base_api, env_sig, uid, &obj_bytes);
            if out != exp_out {
                return Err(format!(
                    "O_PULL.BC_PUSH out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(out)
                ));
            }

            Ok(ObjOpcodeVerifyResult {
                meta: ObjOpcodeMeta::PullBcPush {
                    p_id,
                    in_obj_h,
                    step_tag,
                    f_prime_out: f_prime_dep.out,
                    g_prime_out: g_prime_dep.out,
                    base_pull_out: base_pull_dep.out,
                },
                exp_out,
                overlay_obj_bytes: Some(obj_bytes),
            })
        }
        _ => Err(format!(
            "O_PULL stepTag 0x{step_tag:02x} is unsupported in this verifier slice (supported: 0x00 ID, 0x01 UNIT, 0x02 TENSOR, 0x03 GLUE, 0x04 FUSE_PULLSPINE, 0x05 BC_PUSH, 0x06 WRAP)"
        )),
    }
}

/// Verify a minimal OBJ opcode contract slice plus BC push pull-role checks.
pub fn verify_obj_opcode_contract_with_stores(
    node: &KcirNode,
    deps: &[DepRecord],
    obj_store: &dyn ObjNfStore,
    base_api: Option<&dyn KcirBackend>,
) -> Result<ObjOpcodeVerifyResult, String> {
    if node.sort != SORT_OBJ {
        return Err(format!(
            "OBJ opcode contract requires sort=0x03, got 0x{:02x}",
            node.sort
        ));
    }
    ensure_dep_alignment(node, deps, "OBJ opcode contract")?;

    match node.opcode {
        O_UNIT => {
            if !deps.is_empty() {
                return Err("O_UNIT expects no deps".to_string());
            }
            if !node.args.is_empty() {
                return Err("O_UNIT expects empty args".to_string());
            }
            let obj_bytes = vec![0x01];
            let exp_out = digest_obj_with_backend(base_api, &node.env_sig, &node.uid, &obj_bytes);
            if node.out != exp_out {
                return Err(format!(
                    "O_UNIT out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(node.out)
                ));
            }
            Ok(ObjOpcodeVerifyResult {
                meta: ObjOpcodeMeta::Unit,
                exp_out,
                overlay_obj_bytes: Some(obj_bytes),
            })
        }
        O_PRIM => {
            if !deps.is_empty() {
                return Err("O_PRIM expects no deps".to_string());
            }
            if node.args.len() != 32 {
                return Err(format!(
                    "O_PRIM expects 32-byte primId args, got {} bytes",
                    node.args.len()
                ));
            }
            let mut prim_id = [0u8; 32];
            prim_id.copy_from_slice(&node.args);
            let mut obj_bytes = Vec::with_capacity(33);
            obj_bytes.push(0x02);
            obj_bytes.extend_from_slice(&prim_id);
            let exp_out = digest_obj_with_backend(base_api, &node.env_sig, &node.uid, &obj_bytes);
            if node.out != exp_out {
                return Err(format!(
                    "O_PRIM out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(node.out)
                ));
            }
            Ok(ObjOpcodeVerifyResult {
                meta: ObjOpcodeMeta::Prim { prim_id },
                exp_out,
                overlay_obj_bytes: Some(obj_bytes),
            })
        }
        O_MKTENSOR => {
            if !deps.is_empty() {
                return Err("O_MKTENSOR expects no deps".to_string());
            }
            let (factors, used) = dec_list_b32(&node.args, "O_MKTENSOR factors")?;
            if used != node.args.len() {
                return Err("O_MKTENSOR args contain trailing bytes".to_string());
            }
            let (exp_out, overlay_obj_bytes) = match factors.len() {
                0 => {
                    let obj_bytes = vec![0x01];
                    (
                        digest_obj_with_backend(base_api, &node.env_sig, &node.uid, &obj_bytes),
                        Some(obj_bytes),
                    )
                }
                1 => (factors[0], None),
                _ => {
                    let mut obj_bytes = Vec::with_capacity(1 + node.args.len());
                    obj_bytes.push(0x03);
                    obj_bytes.extend_from_slice(&node.args);
                    (
                        digest_obj_with_backend(base_api, &node.env_sig, &node.uid, &obj_bytes),
                        Some(obj_bytes),
                    )
                }
            };
            if node.out != exp_out {
                return Err(format!(
                    "O_MKTENSOR out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(node.out)
                ));
            }
            Ok(ObjOpcodeVerifyResult {
                meta: ObjOpcodeMeta::MkTensor { factors },
                exp_out,
                overlay_obj_bytes,
            })
        }
        O_PULL => verify_obj_pull_opcode_contract_core(
            &node.env_sig,
            &node.uid,
            node.out,
            &node.args,
            node.deps.len(),
            deps,
            obj_store,
            base_api,
        ),
        other => Err(format!(
            "unsupported OBJ opcode for this verifier slice: 0x{other:02x}"
        )),
    }
}

/// Verify a minimal OBJ opcode contract slice (`O_UNIT`, `O_PRIM`, `O_MKTENSOR`).
pub fn verify_obj_opcode_contract_with_deps(
    node: &KcirNode,
    deps: &[DepRecord],
) -> Result<ObjOpcodeVerifyResult, String> {
    let obj_store: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    verify_obj_opcode_contract_with_stores(node, deps, &obj_store, None)
}

/// Verify a minimal OBJ opcode contract slice (`O_UNIT`, `O_PRIM`, `O_MKTENSOR`).
pub fn verify_obj_opcode_contract(node: &KcirNode) -> Result<ObjOpcodeVerifyResult, String> {
    verify_obj_opcode_contract_with_deps(node, &[])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MorOpcodeMeta {
    Id {
        src_h: [u8; 32],
    },
    MkTensor {
        src_h: [u8; 32],
        tgt_h: [u8; 32],
        parts: Vec<[u8; 32]>,
    },
    MkComp {
        src_h: [u8; 32],
        tgt_h: [u8; 32],
        parts: Vec<[u8; 32]>,
    },
    PullId {
        p_id: [u8; 32],
        in_mor_h: [u8; 32],
        step_tag: u8,
    },
    PullIdMor {
        p_id: [u8; 32],
        in_mor_h: [u8; 32],
        step_tag: u8,
        pulled_src_out: [u8; 32],
    },
    PullWrap {
        p_id: [u8; 32],
        in_mor_h: [u8; 32],
        step_tag: u8,
    },
    PullGlue {
        p_id: [u8; 32],
        in_mor_h: [u8; 32],
        step_tag: u8,
        cover_out: [u8; 32],
        pulled_locals: Vec<[u8; 32]>,
    },
    PullTensor {
        p_id: [u8; 32],
        in_mor_h: [u8; 32],
        step_tag: u8,
        mk_out: [u8; 32],
        pulled_parts: Vec<[u8; 32]>,
    },
    PullComp {
        p_id: [u8; 32],
        in_mor_h: [u8; 32],
        step_tag: u8,
        mk_out: [u8; 32],
        pulled_parts: Vec<[u8; 32]>,
    },
    PullBcSwap {
        p_id: [u8; 32],
        in_mor_h: [u8; 32],
        step_tag: u8,
        f_prime_out: [u8; 32],
        g_prime_out: [u8; 32],
        inner_pull_out: [u8; 32],
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MorOpcodeVerifyResult {
    pub meta: MorOpcodeMeta,
    pub exp_out: [u8; 32],
    pub overlay_mor_bytes: Option<Vec<u8>>,
}

fn parse_mor_args_src_tgt_parts(
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
    let (parts, used) = dec_list_b32(&args[64..], &format!("{label} parts"))?;
    if 64 + used != args.len() {
        return Err(format!("{label} args contain trailing bytes"));
    }
    Ok((src_h, tgt_h, parts))
}

/// Verify MOR opcode contracts against a pluggable MorNF store backend.
pub fn verify_mor_opcode_contract_with_store(
    node: &KcirNode,
    deps: &[DepRecord],
    mor_store: &dyn MorNfStore,
    base_api: Option<&dyn KcirBackend>,
) -> Result<MorOpcodeVerifyResult, String> {
    verify_mor_opcode_contract_with_stores(node, deps, mor_store, base_api)
}

/// Verify an `M_PULL` MOR opcode contract from decomposed node fields.
///
/// This adapter preserves existing pull-role semantics while avoiding a requirement
/// for real dep cert ids at the call site (only dep-record metadata alignment matters).
pub fn verify_mor_pull_opcode_contract_parts(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    out: [u8; 32],
    args: &[u8],
    deps: &[DepRecord],
    mor_store: &dyn MorNfStore,
    base_api: Option<&dyn KcirBackend>,
) -> Result<MorOpcodeVerifyResult, String> {
    verify_mor_pull_opcode_contract_core(
        env_sig,
        uid,
        out,
        args,
        deps.len(),
        deps,
        mor_store,
        base_api,
    )
}

fn verify_mor_pull_opcode_contract_core(
    env_sig: &[u8; 32],
    uid: &[u8; 32],
    out: [u8; 32],
    args: &[u8],
    dep_len: usize,
    deps: &[DepRecord],
    mor_store: &dyn MorNfStore,
    base_api: Option<&dyn KcirBackend>,
) -> Result<MorOpcodeVerifyResult, String> {
    ensure_dep_alignment_len(dep_len, deps, "MOR opcode contract")?;

    let (p_id, in_mor_h, step_tag) = parse_pull_args(args, "M_PULL")?;
    let pull_atom_enabled = adopt_pull_atom_mor(base_api);
    if !pull_atom_enabled && (step_tag == 0x04 || step_tag == 0x07) {
        return Err(
            "M_PULL stepTag 0x04/0x07 (FUSE_PULLATOM/WRAP) requires MorNF PullAtom (tag 0x16), which is not adopted in this profile"
                .to_string(),
        );
    }
    let exp_step = classify_mor_pull_step(&p_id, &in_mor_h, mor_store, env_sig, uid, base_api)?;
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
            Ok(MorOpcodeVerifyResult {
                meta: MorOpcodeMeta::PullId {
                    p_id,
                    in_mor_h,
                    step_tag,
                },
                exp_out: in_mor_h,
                overlay_mor_bytes: None,
            })
        }
        0x01 => {
            let in_nf = parse_mor_nf_from_store(
                mor_store,
                &in_mor_h,
                env_sig,
                uid,
                base_api.is_some(),
                base_api,
                enforce_nf_canonicality(base_api),
                adopt_pull_atom_mor(base_api),
                "M_PULL.IDMOR",
            )?;
            let src_h = match in_nf {
                MorNf::Id { src_h } => src_h,
                other => {
                    return Err(format!(
                        "M_PULL.IDMOR requires inMorH to reference MorNF Id, got {other:?}"
                    ))
                }
            };
            let role_src_pull = dsl::UniquePred {
                sort: Some(SORT_OBJ),
                opcode: Some(O_PULL),
                meta_eq: BTreeMap::new(),
            };
            let (src_pull_dep, rem) = match_unique_role(deps, &role_src_pull, "srcPull")?;
            if !rem.is_empty() {
                return Err(format!(
                    "M_PULL.IDMOR has unexpected extra deps after role match: {}",
                    rem.len()
                ));
            }
            let src_pull_meta = ObjPullDepMeta::parse(&src_pull_dep, "M_PULL.IDMOR srcPull")?;
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
            let exp_out = digest_mor_with_backend(base_api, env_sig, uid, &mor_bytes);
            if out != exp_out {
                return Err(format!(
                    "M_PULL.IDMOR out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(out)
                ));
            }
            Ok(MorOpcodeVerifyResult {
                meta: MorOpcodeMeta::PullIdMor {
                    p_id,
                    in_mor_h,
                    step_tag,
                    pulled_src_out: src_pull_dep.out,
                },
                exp_out,
                overlay_mor_bytes: Some(mor_bytes),
            })
        }
        0x04 | 0x07 => {
            if !deps.is_empty() {
                return Err(format!("M_PULL stepTag=0x{step_tag:02x} expects no deps"));
            }
            let (exp_out, overlay_mor_bytes) =
                mk_pull_atom_out(env_sig, uid, p_id, in_mor_h, mor_store, base_api)?;
            if out != exp_out {
                return Err(format!(
                    "M_PULL stepTag=0x{step_tag:02x} out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(out)
                ));
            }
            Ok(MorOpcodeVerifyResult {
                meta: MorOpcodeMeta::PullWrap {
                    p_id,
                    in_mor_h,
                    step_tag,
                },
                exp_out,
                overlay_mor_bytes,
            })
        }
        0x02 | 0x06 => {
            let mk_opcode = if step_tag == 0x02 {
                M_MKCOMP
            } else {
                M_MKTENSOR
            };
            let role_mk = dsl::UniquePred {
                sort: Some(SORT_MOR),
                opcode: Some(mk_opcode),
                meta_eq: BTreeMap::new(),
            };
            let (mk_dep, rem) = match_unique_role(deps, &role_mk, "mk")?;
            let in_mor_nf = parse_mor_nf_from_store(
                mor_store,
                &in_mor_h,
                env_sig,
                uid,
                base_api.is_some(),
                base_api,
                enforce_nf_canonicality(base_api),
                adopt_pull_atom_mor(base_api),
                if step_tag == 0x02 {
                    "M_PULL.COMP"
                } else {
                    "M_PULL.TENSOR"
                },
            )?;
            let expected_keys = match (&in_mor_nf, step_tag) {
                (MorNf::Id { .. }, 0x02) => Vec::new(),
                (MorNf::Comp { parts, .. }, 0x02) => hex_keys(parts),
                (MorNf::TensorAtom { parts, .. }, 0x06) => hex_keys(parts),
                (other, 0x02) => {
                    return Err(format!(
                        "M_PULL.COMP requires inMorH to reference MorNF Id/Comp, got {other:?}"
                    ))
                }
                (other, 0x06) => {
                    return Err(format!(
                        "M_PULL.TENSOR requires inMorH to reference MorNF TensorAtom, got {other:?}"
                    ))
                }
                _ => unreachable!("step tag guarded above"),
            };
            let mut part_meta = BTreeMap::new();
            part_meta.insert("pId".to_string(), hex::encode(p_id));
            let role_parts = dsl::UniquePred {
                sort: Some(SORT_MOR),
                opcode: Some(M_PULL),
                meta_eq: part_meta,
            };
            let rem_shapes = rem.iter().map(DepRecord::as_dep_shape).collect::<Vec<_>>();
            let bag = dsl::match_bag_spec(
                &rem_shapes,
                &role_parts,
                &dsl::KeySelector::Meta("inMorH".to_string()),
                &expected_keys,
                dsl::BagMode::Unordered,
                UniquePos::Anywhere,
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
                let parsed = parse_mor_nf_from_store(
                    mor_store,
                    &dep.out,
                    env_sig,
                    uid,
                    base_api.is_some(),
                    base_api,
                    enforce_nf_canonicality(base_api),
                    adopt_pull_atom_mor(base_api),
                    "M_PULL part dep",
                )?;
                pulled_parts.push(dep.out);
                part_endpoints.push(mor_endpoints(&parsed));
            }
            if step_tag == 0x02 {
                let raw_pulled_parts = pulled_parts.clone();
                pulled_parts = canonicalize_comp_parts(
                    &pulled_parts,
                    mor_store,
                    env_sig,
                    uid,
                    base_api.is_some(),
                    base_api,
                    enforce_nf_canonicality(base_api),
                    adopt_pull_atom_mor(base_api),
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
                        // Keep non-canonical parts when dropping identities would
                        // erase a non-identity path in malformed or underspecified data.
                        pulled_parts = raw_pulled_parts;
                    }
                }
            }

            let (exp_out, overlay_mor_bytes, meta) = if step_tag == 0x02 {
                let (exp_out, overlay_mor_bytes) = if pulled_parts.is_empty() {
                    let (src_h, tgt_h) = if part_endpoints.is_empty() {
                        mor_endpoints(&in_mor_nf)
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
                    (digest_mor_with_backend(base_api, env_sig, uid, &mor_bytes), Some(mor_bytes))
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
                            let args = enc_list_b32(&pulled_parts);
                            let mut mor_bytes = Vec::with_capacity(1 + 64 + args.len());
                            mor_bytes.push(0x13);
                            mor_bytes.extend_from_slice(&src_h);
                            mor_bytes.extend_from_slice(&tgt_h);
                            mor_bytes.extend_from_slice(&args);
                            (digest_mor_with_backend(base_api, env_sig, uid, &mor_bytes), Some(mor_bytes))
                        }
                    }
                };
                (
                    exp_out,
                    overlay_mor_bytes,
                    MorOpcodeMeta::PullComp {
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
                let (src_ten, _) = canonical_obj_tensor_out(env_sig, uid, &src_factors, base_api);
                let (tgt_ten, _) = canonical_obj_tensor_out(env_sig, uid, &tgt_factors, base_api);
                let args = enc_list_b32(&pulled_parts);
                let mut mor_bytes = Vec::with_capacity(1 + 64 + args.len());
                mor_bytes.push(0x18);
                mor_bytes.extend_from_slice(&src_ten);
                mor_bytes.extend_from_slice(&tgt_ten);
                mor_bytes.extend_from_slice(&args);
                (
                    digest_mor_with_backend(base_api, env_sig, uid, &mor_bytes),
                    Some(mor_bytes),
                    MorOpcodeMeta::PullTensor {
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
                let mk_parts = parse_csv_hex32(raw, "M_PULL mk.meta.parts")?;
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
            Ok(MorOpcodeVerifyResult {
                meta,
                exp_out: mk_dep.out,
                overlay_mor_bytes,
            })
        }
        0x03 => {
            let in_mor_nf = parse_mor_nf_from_store(
                mor_store,
                &in_mor_h,
                env_sig,
                uid,
                base_api.is_some(),
                base_api,
                enforce_nf_canonicality(base_api),
                adopt_pull_atom_mor(base_api),
                "M_PULL.GLUE",
            )?;
            let (_src_u, _tgt_u, _u_sig, locals_u) = match in_mor_nf {
                MorNf::GlueAtom {
                    src_h,
                    tgt_h,
                    w_sig,
                    locals,
                } => (src_h, tgt_h, w_sig, locals),
                other => {
                    return Err(format!(
                        "M_PULL.GLUE requires inMorH to reference MorNF GlueAtom, got {other:?}"
                    ))
                }
            };
            let role_cover = dsl::UniquePred {
                sort: Some(SORT_COVER),
                opcode: Some(C_PULLCOVER),
                meta_eq: BTreeMap::new(),
            };
            let (cover_dep, rem) = match_unique_role(deps, &role_cover, "cover")?;
            let cover_meta = parse_cover_projection_meta(&cover_dep, "M_PULL.GLUE")?;
            let expected_keys = expected_glue_keys(&cover_meta, &locals_u, "M_PULL.GLUE")?;
            let pulled_locals = match_pull_glue_locals(
                &rem,
                SORT_MOR,
                M_PULL,
                PullGlueMetaKind::Mor,
                &expected_keys,
                "M_PULL.GLUE",
            )?;
            let mut src_locals = Vec::with_capacity(pulled_locals.len());
            let mut tgt_locals = Vec::with_capacity(pulled_locals.len());
            for h in &pulled_locals {
                let parsed = parse_mor_nf_from_store(
                    mor_store,
                    h,
                    env_sig,
                    uid,
                    base_api.is_some(),
                    base_api,
                    enforce_nf_canonicality(base_api),
                    adopt_pull_atom_mor(base_api),
                    "M_PULL.GLUE local dep",
                )?;
                let (s, t) = mor_endpoints(&parsed);
                src_locals.push(s);
                tgt_locals.push(t);
            }
            let src_args = enc_list_b32(&src_locals);
            let mut src_obj = Vec::with_capacity(1 + 32 + src_args.len());
            src_obj.push(0x06);
            src_obj.extend_from_slice(&cover_dep.out);
            src_obj.extend_from_slice(&src_args);
            let src_glue = digest_obj_with_backend(base_api, env_sig, uid, &src_obj);

            let tgt_args = enc_list_b32(&tgt_locals);
            let mut tgt_obj = Vec::with_capacity(1 + 32 + tgt_args.len());
            tgt_obj.push(0x06);
            tgt_obj.extend_from_slice(&cover_dep.out);
            tgt_obj.extend_from_slice(&tgt_args);
            let tgt_glue = digest_obj_with_backend(base_api, env_sig, uid, &tgt_obj);

            let locals_args = enc_list_b32(&pulled_locals);
            let mut mor_bytes = Vec::with_capacity(1 + 96 + locals_args.len());
            mor_bytes.push(0x19);
            mor_bytes.extend_from_slice(&src_glue);
            mor_bytes.extend_from_slice(&tgt_glue);
            mor_bytes.extend_from_slice(&cover_dep.out);
            mor_bytes.extend_from_slice(&locals_args);
            let exp_out = digest_mor_with_backend(base_api, env_sig, uid, &mor_bytes);
            if out != exp_out {
                return Err(format!(
                    "M_PULL.GLUE out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(out)
                ));
            }

            Ok(MorOpcodeVerifyResult {
                meta: MorOpcodeMeta::PullGlue {
                    p_id,
                    in_mor_h,
                    step_tag,
                    cover_out: cover_dep.out,
                    pulled_locals,
                },
                exp_out,
                overlay_mor_bytes: Some(mor_bytes),
            })
        }
        0x05 => {
            let role_fprime = dsl::UniquePred {
                sort: Some(SORT_MAP),
                opcode: Some(M_BC_FPRIME),
                meta_eq: BTreeMap::new(),
            };
            let role_gprime = dsl::UniquePred {
                sort: Some(SORT_MAP),
                opcode: Some(M_BC_GPRIME),
                meta_eq: BTreeMap::new(),
            };
            let role_inner_pull = dsl::UniquePred {
                sort: Some(SORT_MOR),
                opcode: Some(M_PULL),
                meta_eq: BTreeMap::new(),
            };

            let (f_prime_dep, rem1) = match_unique_role(deps, &role_fprime, "fPrime")?;
            let (g_prime_dep, rem2) = match_unique_role(&rem1, &role_gprime, "gPrime")?;
            let (inner_pull_dep, rem3) = match_unique_role(&rem2, &role_inner_pull, "innerPull")?;
            if !rem3.is_empty() {
                return Err(format!(
                    "M_PULL.BC_SWAP has unexpected extra deps after role match: {}",
                    rem3.len()
                ));
            }
            let inner_pull_meta = MorPullDepMeta::parse(&inner_pull_dep, "M_PULL.BC_SWAP innerPull")?;
            if mor_store.mor_nf_bytes(&in_mor_h).is_some() {
                let in_nf = parse_mor_nf_from_store(
                    mor_store,
                    &in_mor_h,
                    env_sig,
                    uid,
                    base_api.is_some(),
                    base_api,
                    enforce_nf_canonicality(base_api),
                    adopt_pull_atom_mor(base_api),
                    "M_PULL.BC_SWAP",
                )?;
                let (f_id, inner_h) = match in_nf {
                    MorNf::PushAtom { f_id, inner_h, .. } => (f_id, inner_h),
                    other => {
                        return Err(format!(
                            "M_PULL.BC_SWAP requires inMorH to reference MorNF PushAtom, got {other:?}"
                        ))
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

            let parsed_inner = parse_mor_nf_from_store(
                mor_store,
                &inner_pull_dep.out,
                env_sig,
                uid,
                base_api.is_some(),
                base_api,
                enforce_nf_canonicality(base_api),
                adopt_pull_atom_mor(base_api),
                "M_PULL.BC_SWAP",
            )?;
            let (src_h, tgt_h) = mor_endpoints(&parsed_inner);

            let mut mor_bytes = Vec::with_capacity(129);
            mor_bytes.push(0x17);
            mor_bytes.extend_from_slice(&src_h);
            mor_bytes.extend_from_slice(&tgt_h);
            mor_bytes.extend_from_slice(&f_prime_dep.out);
            mor_bytes.extend_from_slice(&inner_pull_dep.out);
            let exp_out = digest_mor_with_backend(base_api, env_sig, uid, &mor_bytes);
            if out != exp_out {
                return Err(format!(
                    "M_PULL.BC_SWAP out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(out)
                ));
            }

            Ok(MorOpcodeVerifyResult {
                meta: MorOpcodeMeta::PullBcSwap {
                    p_id,
                    in_mor_h,
                    step_tag,
                    f_prime_out: f_prime_dep.out,
                    g_prime_out: g_prime_dep.out,
                    inner_pull_out: inner_pull_dep.out,
                },
                exp_out,
                overlay_mor_bytes: Some(mor_bytes),
            })
        }
        _ => Err(format!(
            "M_PULL stepTag 0x{step_tag:02x} is unsupported in this verifier slice (supported: 0x00 ID, 0x01 IDMOR, 0x02 COMP, 0x03 GLUE, 0x04 FUSE_PULLATOM (capability-gated), 0x05 BC_SWAP, 0x06 TENSOR, 0x07 WRAP (capability-gated))"
        )),
    }
}

/// Verify a minimal MOR opcode contract slice (`M_ID`, `M_MKTENSOR`, `M_MKCOMP`).
pub fn verify_mor_opcode_contract_with_stores(
    node: &KcirNode,
    deps: &[DepRecord],
    mor_store: &dyn MorNfStore,
    base_api: Option<&dyn KcirBackend>,
) -> Result<MorOpcodeVerifyResult, String> {
    if node.sort != SORT_MOR {
        return Err(format!(
            "MOR opcode contract requires sort=0x04, got 0x{:02x}",
            node.sort
        ));
    }
    ensure_dep_alignment(node, deps, "MOR opcode contract")?;

    match node.opcode {
        M_ID => {
            if !deps.is_empty() {
                return Err("M_ID expects no deps".to_string());
            }
            if node.args.len() != 32 {
                return Err(format!(
                    "M_ID expects 32-byte srcH args, got {} bytes",
                    node.args.len()
                ));
            }
            let mut src_h = [0u8; 32];
            src_h.copy_from_slice(&node.args);
            let mut mor_bytes = Vec::with_capacity(33);
            mor_bytes.push(0x11);
            mor_bytes.extend_from_slice(&src_h);
            let exp_out = digest_mor_with_backend(base_api, &node.env_sig, &node.uid, &mor_bytes);
            if node.out != exp_out {
                return Err(format!(
                    "M_ID out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(node.out)
                ));
            }
            Ok(MorOpcodeVerifyResult {
                meta: MorOpcodeMeta::Id { src_h },
                exp_out,
                overlay_mor_bytes: Some(mor_bytes),
            })
        }
        M_MKTENSOR => {
            if !deps.is_empty() {
                return Err("M_MKTENSOR expects no deps".to_string());
            }
            let (src_h, tgt_h, parts) = parse_mor_args_src_tgt_parts(&node.args, "M_MKTENSOR")?;
            let can_check_endpoints = parts
                .iter()
                .all(|part| mor_store.mor_nf_bytes(part).is_some());
            if can_check_endpoints {
                let mut src_factors = Vec::with_capacity(parts.len());
                let mut tgt_factors = Vec::with_capacity(parts.len());
                for part in &parts {
                    let parsed = parse_mor_nf_from_store(
                        mor_store,
                        part,
                        &node.env_sig,
                        &node.uid,
                        base_api.is_some(),
                        base_api,
                        enforce_nf_canonicality(base_api),
                        adopt_pull_atom_mor(base_api),
                        "M_MKTENSOR endpoint check",
                    )?;
                    let (s, t) = mor_endpoints(&parsed);
                    src_factors.push(s);
                    tgt_factors.push(t);
                }
                let (exp_src_h, _) =
                    canonical_obj_tensor_out(&node.env_sig, &node.uid, &src_factors, base_api);
                let (exp_tgt_h, _) =
                    canonical_obj_tensor_out(&node.env_sig, &node.uid, &tgt_factors, base_api);
                if src_h != exp_src_h {
                    return Err(format!(
                        "M_MKTENSOR srcH mismatch with tensor(part.src): expected {}, got {}",
                        hex::encode(exp_src_h),
                        hex::encode(src_h)
                    ));
                }
                if tgt_h != exp_tgt_h {
                    return Err(format!(
                        "M_MKTENSOR tgtH mismatch with tensor(part.tgt): expected {}, got {}",
                        hex::encode(exp_tgt_h),
                        hex::encode(tgt_h)
                    ));
                }
            }
            let mut mor_bytes = Vec::with_capacity(1 + node.args.len());
            mor_bytes.push(0x18);
            mor_bytes.extend_from_slice(&node.args);
            let exp_out = digest_mor_with_backend(base_api, &node.env_sig, &node.uid, &mor_bytes);
            if node.out != exp_out {
                return Err(format!(
                    "M_MKTENSOR out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(node.out)
                ));
            }
            Ok(MorOpcodeVerifyResult {
                meta: MorOpcodeMeta::MkTensor {
                    src_h,
                    tgt_h,
                    parts,
                },
                exp_out,
                overlay_mor_bytes: Some(mor_bytes),
            })
        }
        M_MKCOMP => {
            if !deps.is_empty() {
                return Err("M_MKCOMP expects no deps".to_string());
            }
            let (src_h, tgt_h, parts) = parse_mor_args_src_tgt_parts(&node.args, "M_MKCOMP")?;
            let canonical_parts = canonicalize_comp_parts(
                &parts,
                mor_store,
                &node.env_sig,
                &node.uid,
                base_api.is_some(),
                base_api,
                enforce_nf_canonicality(base_api),
                adopt_pull_atom_mor(base_api),
                "M_MKCOMP canonicalization",
            )?;
            let can_check_endpoints = !canonical_parts.is_empty()
                && canonical_parts
                    .iter()
                    .all(|part| mor_store.mor_nf_bytes(part).is_some());
            if can_check_endpoints {
                let mut part_endpoints = Vec::with_capacity(canonical_parts.len());
                for part in &canonical_parts {
                    let parsed = parse_mor_nf_from_store(
                        mor_store,
                        part,
                        &node.env_sig,
                        &node.uid,
                        base_api.is_some(),
                        base_api,
                        enforce_nf_canonicality(base_api),
                        adopt_pull_atom_mor(base_api),
                        "M_MKCOMP endpoint check",
                    )?;
                    part_endpoints.push(mor_endpoints(&parsed));
                }
                for idx in 0..part_endpoints.len().saturating_sub(1) {
                    let left_tgt = part_endpoints[idx].1;
                    let right_src = part_endpoints[idx + 1].0;
                    if left_tgt != right_src {
                        return Err(format!(
                            "M_MKCOMP part chain mismatch at idx {} -> {}: left tgt={} right src={}",
                            idx,
                            idx + 1,
                            hex::encode(left_tgt),
                            hex::encode(right_src)
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
                    return Err(format!(
                        "M_MKCOMP srcH mismatch with comp(part.src): expected {}, got {}",
                        hex::encode(exp_src_h),
                        hex::encode(src_h)
                    ));
                }
                if tgt_h != exp_tgt_h {
                    return Err(format!(
                        "M_MKCOMP tgtH mismatch with comp(part.tgt): expected {}, got {}",
                        hex::encode(exp_tgt_h),
                        hex::encode(tgt_h)
                    ));
                }
            }
            let (canonical_parts, exp_out, overlay_mor_bytes) = match canonical_parts.len() {
                0 => {
                    if src_h != tgt_h {
                        return Err(format!(
                            "M_MKCOMP canonical 0-part case requires srcH == tgtH; got src={} tgt={}",
                            hex::encode(src_h),
                            hex::encode(tgt_h)
                        ));
                    }
                    let mut mor_bytes = Vec::with_capacity(33);
                    mor_bytes.push(0x11);
                    mor_bytes.extend_from_slice(&src_h);
                    (
                        Vec::new(),
                        digest_mor_with_backend(base_api, &node.env_sig, &node.uid, &mor_bytes),
                        Some(mor_bytes),
                    )
                }
                1 => (canonical_parts.clone(), canonical_parts[0], None),
                _ => {
                    let args = enc_list_b32(&canonical_parts);
                    let mut mor_bytes = Vec::with_capacity(1 + 64 + args.len());
                    mor_bytes.push(0x13);
                    mor_bytes.extend_from_slice(&src_h);
                    mor_bytes.extend_from_slice(&tgt_h);
                    mor_bytes.extend_from_slice(&args);
                    (
                        canonical_parts.clone(),
                        digest_mor_with_backend(base_api, &node.env_sig, &node.uid, &mor_bytes),
                        Some(mor_bytes),
                    )
                }
            };
            if node.out != exp_out {
                return Err(format!(
                    "M_MKCOMP out mismatch: expected {}, got {}",
                    hex::encode(exp_out),
                    hex::encode(node.out)
                ));
            }
            Ok(MorOpcodeVerifyResult {
                meta: MorOpcodeMeta::MkComp {
                    src_h,
                    tgt_h,
                    parts: canonical_parts,
                },
                exp_out,
                overlay_mor_bytes,
            })
        }
        M_PULL => verify_mor_pull_opcode_contract_core(
            &node.env_sig,
            &node.uid,
            node.out,
            &node.args,
            node.deps.len(),
            deps,
            mor_store,
            base_api,
        ),
        other => Err(format!(
            "unsupported MOR opcode for this verifier slice: 0x{other:02x}"
        )),
    }
}

/// Verify a minimal MOR opcode contract slice (`M_ID`, `M_MKTENSOR`, `M_MKCOMP`).
pub fn verify_mor_opcode_contract_with_deps(
    node: &KcirNode,
    deps: &[DepRecord],
) -> Result<MorOpcodeVerifyResult, String> {
    let mor_store: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    verify_mor_opcode_contract_with_stores(node, deps, &mor_store, None)
}

/// Verify a minimal MOR opcode contract slice (`M_ID`, `M_MKTENSOR`, `M_MKCOMP`).
pub fn verify_mor_opcode_contract(node: &KcirNode) -> Result<MorOpcodeVerifyResult, String> {
    verify_mor_opcode_contract_with_deps(node, &[])
}

pub fn obj_opcode_meta_to_dep_meta(meta: &ObjOpcodeMeta) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    match meta {
        ObjOpcodeMeta::Prim { prim_id } => {
            out.insert("primId".to_string(), hex::encode(prim_id));
        }
        ObjOpcodeMeta::MkTensor { factors } => {
            out.insert(
                "factors".to_string(),
                factors
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        ObjOpcodeMeta::PullId {
            p_id,
            in_obj_h,
            step_tag,
        }
        | ObjOpcodeMeta::PullUnit {
            p_id,
            in_obj_h,
            step_tag,
        }
        | ObjOpcodeMeta::PullWrap {
            p_id,
            in_obj_h,
            step_tag,
        }
        | ObjOpcodeMeta::PullGlue {
            p_id,
            in_obj_h,
            step_tag,
            ..
        }
        | ObjOpcodeMeta::PullTensor {
            p_id,
            in_obj_h,
            step_tag,
            ..
        }
        | ObjOpcodeMeta::PullBcPush {
            p_id,
            in_obj_h,
            step_tag,
            ..
        } => {
            out.insert("pId".to_string(), hex::encode(p_id));
            out.insert("inObjH".to_string(), hex::encode(in_obj_h));
            out.insert("stepTag".to_string(), step_tag.to_string());
        }
        ObjOpcodeMeta::Unit => {}
    }
    out
}

pub fn mor_opcode_meta_to_dep_meta(meta: &MorOpcodeMeta) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    match meta {
        MorOpcodeMeta::Id { src_h } => {
            out.insert("srcH".to_string(), hex::encode(src_h));
        }
        MorOpcodeMeta::MkTensor {
            src_h,
            tgt_h,
            parts,
        }
        | MorOpcodeMeta::MkComp {
            src_h,
            tgt_h,
            parts,
        } => {
            out.insert("srcH".to_string(), hex::encode(src_h));
            out.insert("tgtH".to_string(), hex::encode(tgt_h));
            out.insert(
                "parts".to_string(),
                parts.iter().map(hex::encode).collect::<Vec<_>>().join(","),
            );
        }
        MorOpcodeMeta::PullId {
            p_id,
            in_mor_h,
            step_tag,
        }
        | MorOpcodeMeta::PullIdMor {
            p_id,
            in_mor_h,
            step_tag,
            ..
        }
        | MorOpcodeMeta::PullWrap {
            p_id,
            in_mor_h,
            step_tag,
        }
        | MorOpcodeMeta::PullGlue {
            p_id,
            in_mor_h,
            step_tag,
            ..
        }
        | MorOpcodeMeta::PullTensor {
            p_id,
            in_mor_h,
            step_tag,
            ..
        }
        | MorOpcodeMeta::PullComp {
            p_id,
            in_mor_h,
            step_tag,
            ..
        }
        | MorOpcodeMeta::PullBcSwap {
            p_id,
            in_mor_h,
            step_tag,
            ..
        } => {
            out.insert("pId".to_string(), hex::encode(p_id));
            out.insert("inMorH".to_string(), hex::encode(in_mor_h));
            out.insert("stepTag".to_string(), step_tag.to_string());
        }
    }
    out
}

pub(crate) fn verify_map_opcode_contract(
    node: &KcirNode,
    deps: &[CoreVerifiedNode],
    base_api: Option<&dyn KcirBackend>,
) -> Result<BTreeMap<String, String>, String> {
    if node.sort != SORT_MAP {
        return Err(format!(
            "MAP opcode contract requires sort=0x02, got 0x{:02x}",
            node.sort
        ));
    }
    match node.opcode {
        0x01 => {
            if !deps.is_empty() {
                return Err("M_LITERAL expects no deps".to_string());
            }
            if node.args.len() != 32 {
                return Err(format!(
                    "M_LITERAL expects 32-byte mapId args, got {} bytes",
                    node.args.len()
                ));
            }
            let mut map_id = [0u8; 32];
            map_id.copy_from_slice(&node.args);
            if node.out != map_id {
                return Err(format!(
                    "M_LITERAL out mismatch: expected {}, got {}",
                    hex::encode(map_id),
                    hex::encode(node.out)
                ));
            }
            let mut meta = BTreeMap::new();
            meta.insert("mapId".to_string(), hex::encode(map_id));
            Ok(meta)
        }
        M_BC_FPRIME | M_BC_GPRIME => {
            if !node.args.is_empty() {
                return Err(format!(
                    "MAP BC opcode 0x{:02x} expects empty args",
                    node.opcode
                ));
            }
            if deps.len() != 2 {
                return Err(format!(
                    "MAP BC opcode 0x{:02x} expects exactly 2 MAP deps, got {}",
                    node.opcode,
                    deps.len()
                ));
            }
            if deps.iter().any(|d| d.sort != SORT_MAP) {
                return Err(format!(
                    "MAP BC opcode 0x{:02x} deps must all be MAP sort",
                    node.opcode
                ));
            }
            let pull_id = deps[0].out;
            let push_id = deps[1].out;
            let api = base_api.ok_or_else(|| {
                format!(
                    "MAP BC opcode 0x{:02x} requires BaseApi.bcSquare hook",
                    node.opcode
                )
            })?;
            let (f_prime, p_prime) = api.bc_square(&push_id, &pull_id).ok_or_else(|| {
                format!(
                    "MAP BC opcode 0x{:02x} missing BaseApi.bcSquare for push={} pull={}",
                    node.opcode,
                    hex::encode(push_id),
                    hex::encode(pull_id)
                )
            })?;
            let exp_out = if node.opcode == M_BC_FPRIME {
                f_prime
            } else {
                p_prime
            };
            if node.out != exp_out {
                return Err(format!(
                    "MAP BC opcode 0x{:02x} out mismatch: expected {}, got {}",
                    node.opcode,
                    hex::encode(exp_out),
                    hex::encode(node.out)
                ));
            }
            let mut meta = BTreeMap::new();
            meta.insert("pullId".to_string(), hex::encode(pull_id));
            meta.insert("pushId".to_string(), hex::encode(push_id));
            Ok(meta)
        }
        other => Err(format!(
            "unsupported MAP opcode for this verifier slice: 0x{other:02x}"
        )),
    }
}

pub(crate) fn verify_cover_opcode_contract(
    node: &KcirNode,
    deps: &[CoreVerifiedNode],
    base_api: Option<&dyn KcirBackend>,
) -> Result<BTreeMap<String, String>, String> {
    if node.sort != SORT_COVER {
        return Err(format!(
            "COVER opcode contract requires sort=0x01, got 0x{:02x}",
            node.sort
        ));
    }
    match node.opcode {
        0x01 => {
            if !deps.is_empty() {
                return Err("C_LITERAL expects no deps".to_string());
            }
            if node.args.len() != 32 {
                return Err(format!(
                    "C_LITERAL expects 32-byte coverSig args, got {} bytes",
                    node.args.len()
                ));
            }
            let mut cover_sig = [0u8; 32];
            cover_sig.copy_from_slice(&node.args);
            if node.out != cover_sig {
                return Err(format!(
                    "C_LITERAL out mismatch: expected {}, got {}",
                    hex::encode(cover_sig),
                    hex::encode(node.out)
                ));
            }
            let api = base_api.ok_or_else(|| {
                format!(
                    "C_LITERAL requires BaseApi.validateCover hook for {}",
                    hex::encode(cover_sig)
                )
            })?;
            let valid = api.validate_cover(&cover_sig).ok_or_else(|| {
                format!(
                    "C_LITERAL requires BaseApi.validateCover hook for {}",
                    hex::encode(cover_sig)
                )
            })?;
            if !valid {
                return Err(format!(
                    "C_LITERAL cover validation failed for {}",
                    hex::encode(cover_sig)
                ));
            }
            let mut meta = BTreeMap::new();
            meta.insert("coverSig".to_string(), hex::encode(cover_sig));
            Ok(meta)
        }
        0x02 => {
            if deps.len() != 2 {
                return Err(format!(
                    "C_PULLCOVER expects exactly 2 deps, got {}",
                    deps.len()
                ));
            }
            let has_map = deps.iter().any(|d| d.sort == SORT_MAP);
            let has_cover = deps.iter().any(|d| d.sort == SORT_COVER);
            if !(has_map && has_cover) {
                return Err(
                    "C_PULLCOVER deps must include one MAP dep and one COVER dep".to_string(),
                );
            }
            let (map_dep, cover_dep) = if deps[0].sort == SORT_MAP {
                (&deps[0], &deps[1])
            } else {
                (&deps[1], &deps[0])
            };
            let (map_w_to_u, used1) = dec_list_u32(&node.args, "C_PULLCOVER mapWtoU")?;
            let (proj_ids, used2) = dec_list_b32(&node.args[used1..], "C_PULLCOVER projIds")?;
            if used1 + used2 != node.args.len() {
                return Err("C_PULLCOVER args contain trailing bytes".to_string());
            }
            if map_w_to_u.len() != proj_ids.len() {
                return Err(format!(
                    "C_PULLCOVER args mismatch: mapWtoU len {} != projIds len {}",
                    map_w_to_u.len(),
                    proj_ids.len()
                ));
            }
            let api = base_api.ok_or_else(|| {
                "C_PULLCOVER requires BaseApi.pullCover and BaseApi.coverLen hooks".to_string()
            })?;
            let u_sig = cover_dep.out;
            let cover_len = api.cover_len(&u_sig).ok_or_else(|| {
                format!(
                    "C_PULLCOVER missing BaseApi.coverLen for uSig={}",
                    hex::encode(u_sig)
                )
            })?;
            for (idx, w_to_u) in map_w_to_u.iter().enumerate() {
                if *w_to_u >= cover_len {
                    return Err(format!(
                        "C_PULLCOVER mapWtoU[{idx}]={} out of range for coverLen(uSig)={}",
                        w_to_u, cover_len
                    ));
                }
            }
            let wit = api
                .pull_cover(&map_dep.out, &cover_dep.out)
                .ok_or_else(|| {
                    format!(
                        "C_PULLCOVER missing BaseApi.pullCover for pId={} uSig={}",
                        hex::encode(map_dep.out),
                        hex::encode(cover_dep.out)
                    )
                })?;
            if node.out != wit.w_sig {
                return Err(format!(
                    "C_PULLCOVER out mismatch: expected {}, got {}",
                    hex::encode(wit.w_sig),
                    hex::encode(node.out)
                ));
            }
            if map_w_to_u != wit.map_w_to_u {
                return Err(
                    "C_PULLCOVER mapWtoU args mismatch against BaseApi.pullCover".to_string(),
                );
            }
            if proj_ids != wit.proj_ids {
                return Err(
                    "C_PULLCOVER projIds args mismatch against BaseApi.pullCover".to_string(),
                );
            }
            let mut meta = BTreeMap::new();
            meta.insert("pId".to_string(), hex::encode(map_dep.out));
            meta.insert("uSig".to_string(), hex::encode(cover_dep.out));
            meta.insert("wSig".to_string(), hex::encode(node.out));
            // Keep legacy alias for compatibility with existing role selectors.
            meta.insert("coverSig".to_string(), hex::encode(node.out));
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
        other => Err(format!(
            "unsupported COVER opcode for this verifier slice: 0x{other:02x}"
        )),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreVerifiedNode {
    pub cert_id: [u8; 32],
    pub sort: u8,
    pub opcode: u8,
    pub out: [u8; 32],
    pub meta: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreVerifyResult {
    pub root_cert_id: [u8; 32],
    pub env_sig: [u8; 32],
    pub uid: [u8; 32],
    pub nodes: Vec<CoreVerifiedNode>,
    pub obj_overlay: BTreeMap<[u8; 32], Vec<u8>>,
    pub mor_overlay: BTreeMap<[u8; 32], Vec<u8>>,
}

/// Storage interface for core KCIR DAG verification.
pub trait KcirCoreStore: ObjNfStore + MorNfStore {
    fn cert_node_bytes(&self, cert_id: &[u8; 32]) -> Option<Vec<u8>>;
}

/// In-memory store adapter for existing map-backed call sites.
pub struct InMemoryKcirCoreStore<'a> {
    pub cert_store: &'a BTreeMap<[u8; 32], Vec<u8>>,
    pub obj_store: &'a BTreeMap<[u8; 32], Vec<u8>>,
    pub mor_store: &'a BTreeMap<[u8; 32], Vec<u8>>,
}

impl ObjNfStore for InMemoryKcirCoreStore<'_> {
    fn obj_nf_bytes(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.obj_store.get(key).cloned()
    }
}

impl MorNfStore for InMemoryKcirCoreStore<'_> {
    fn mor_nf_bytes(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.mor_store.get(key).cloned()
    }
}

impl KcirCoreStore for InMemoryKcirCoreStore<'_> {
    fn cert_node_bytes(&self, cert_id: &[u8; 32]) -> Option<Vec<u8>> {
        self.cert_store.get(cert_id).cloned()
    }
}

struct CoreObjStoreView<'a> {
    base: &'a dyn KcirCoreStore,
    overlay: &'a BTreeMap<[u8; 32], Vec<u8>>,
}

impl ObjNfStore for CoreObjStoreView<'_> {
    fn obj_nf_bytes(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        if let Some(v) = self.overlay.get(key) {
            return Some(v.clone());
        }
        self.base.obj_nf_bytes(key)
    }
}

struct CoreMorStoreView<'a> {
    base: &'a dyn KcirCoreStore,
    overlay: &'a BTreeMap<[u8; 32], Vec<u8>>,
}

impl MorNfStore for CoreMorStoreView<'_> {
    fn mor_nf_bytes(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        if let Some(v) = self.overlay.get(key) {
            return Some(v.clone());
        }
        self.base.mor_nf_bytes(key)
    }
}

struct CoreVerifyCtx<'a> {
    store: &'a dyn KcirCoreStore,
    backend: &'a dyn KcirBackend,
    root_env_sig: [u8; 32],
    root_uid: [u8; 32],
    memo: BTreeMap<[u8; 32], CoreVerifiedNode>,
    visiting: BTreeSet<[u8; 32]>,
    obj_overlay: BTreeMap<[u8; 32], Vec<u8>>,
    mor_overlay: BTreeMap<[u8; 32], Vec<u8>>,
}

impl<'a> CoreVerifyCtx<'a> {
    fn verify_node(&mut self, cert_id_key: [u8; 32]) -> Result<CoreVerifiedNode, String> {
        if let Some(v) = self.memo.get(&cert_id_key) {
            return Ok(v.clone());
        }
        if !self.visiting.insert(cert_id_key) {
            return Err(format!(
                "KCIR dependency cycle detected at cert {}",
                hex::encode(cert_id_key)
            ));
        }

        let node_bytes = self.store.cert_node_bytes(&cert_id_key).ok_or_else(|| {
            format!(
                "missing KCIR node bytes for dep cert {}",
                hex::encode(cert_id_key)
            )
        })?;
        let got_id = self.backend.digest_node(&node_bytes);
        if got_id != cert_id_key {
            return Err(format!(
                "KCIR certId mismatch: key {} does not match backend digest {}",
                hex::encode(cert_id_key),
                hex::encode(got_id)
            ));
        }

        let node = parse_node_bytes(&node_bytes).map_err(|e| {
            format!(
                "failed to parse KCIR node {}: {e}",
                hex::encode(cert_id_key)
            )
        })?;
        if node.env_sig != self.root_env_sig {
            return Err(format!(
                "envSig mismatch at node {}: expected {}, got {}",
                hex::encode(cert_id_key),
                hex::encode(self.root_env_sig),
                hex::encode(node.env_sig)
            ));
        }
        if node.uid != self.root_uid {
            return Err(format!(
                "Uid mismatch at node {}: expected {}, got {}",
                hex::encode(cert_id_key),
                hex::encode(self.root_uid),
                hex::encode(node.uid)
            ));
        }

        let mut dep_nodes = Vec::with_capacity(node.deps.len());
        for dep in &node.deps {
            dep_nodes.push(self.verify_node(*dep)?);
        }
        let dep_records = dep_nodes
            .iter()
            .map(|d| DepRecord {
                sort: d.sort,
                opcode: d.opcode,
                out: d.out,
                meta: d.meta.clone(),
            })
            .collect::<Vec<_>>();

        let meta = match node.sort {
            SORT_OBJ => {
                let obj_lookup = CoreObjStoreView {
                    base: self.store,
                    overlay: &self.obj_overlay,
                };
                let verified = verify_obj_opcode_contract_with_store(
                    &node,
                    &dep_records,
                    &obj_lookup,
                    Some(self.backend),
                )?;
                if let Some(obj_bytes) = verified.overlay_obj_bytes {
                    if let Some(prev) = self.obj_overlay.insert(node.out, obj_bytes.clone()) {
                        if prev != obj_bytes {
                            return Err(format!(
                                "OBJ overlay collision for {} with non-identical bytes",
                                hex::encode(node.out)
                            ));
                        }
                    }
                }
                obj_opcode_meta_to_dep_meta(&verified.meta)
            }
            SORT_MOR => {
                let mor_lookup = CoreMorStoreView {
                    base: self.store,
                    overlay: &self.mor_overlay,
                };
                let verified = verify_mor_opcode_contract_with_store(
                    &node,
                    &dep_records,
                    &mor_lookup,
                    Some(self.backend),
                )?;
                if let Some(mor_bytes) = verified.overlay_mor_bytes {
                    if let Some(prev) = self.mor_overlay.insert(node.out, mor_bytes.clone()) {
                        if prev != mor_bytes {
                            return Err(format!(
                                "MOR overlay collision for {} with non-identical bytes",
                                hex::encode(node.out)
                            ));
                        }
                    }
                }
                mor_opcode_meta_to_dep_meta(&verified.meta)
            }
            SORT_MAP => verify_map_opcode_contract(&node, &dep_nodes, Some(self.backend))?,
            SORT_COVER => verify_cover_opcode_contract(&node, &dep_nodes, Some(self.backend))?,
            other => {
                return Err(format!(
                    "unsupported KCIR sort in core verifier: 0x{other:02x}"
                ));
            }
        };

        self.visiting.remove(&cert_id_key);
        let verified = CoreVerifiedNode {
            cert_id: cert_id_key,
            sort: node.sort,
            opcode: node.opcode,
            out: node.out,
            meta,
        };
        self.memo.insert(cert_id_key, verified.clone());
        Ok(verified)
    }
}

/// Verify a KCIR DAG from a root cert id over cert/NF stores.
///
/// This verifier enforces:
/// - node id integrity (`certId = SHA256("KCIRNode"||nodeBytes)`)
/// - envSig/Uid global invariants
/// - dependency acyclicity
/// - opcode contracts for the currently supported COVER/MAP/OBJ/MOR slices
pub fn verify_core_dag_with_backend_and_store(
    root_cert_id: [u8; 32],
    store: &dyn KcirCoreStore,
    backend: &dyn KcirBackend,
) -> Result<CoreVerifyResult, String> {
    let root_bytes = store.cert_node_bytes(&root_cert_id).ok_or_else(|| {
        format!(
            "missing KCIR root node bytes for cert {}",
            hex::encode(root_cert_id)
        )
    })?;
    let got_root_id = backend.digest_node(&root_bytes);
    if got_root_id != root_cert_id {
        return Err(format!(
            "root certId mismatch: key {} does not match backend digest {}",
            hex::encode(root_cert_id),
            hex::encode(got_root_id)
        ));
    }
    let root = parse_node_bytes(&root_bytes).map_err(|e| {
        format!(
            "failed to parse root KCIR node {}: {e}",
            hex::encode(root_cert_id)
        )
    })?;

    let mut ctx = CoreVerifyCtx {
        store,
        backend,
        root_env_sig: root.env_sig,
        root_uid: root.uid,
        memo: BTreeMap::new(),
        visiting: BTreeSet::new(),
        obj_overlay: BTreeMap::new(),
        mor_overlay: BTreeMap::new(),
    };
    let _ = ctx.verify_node(root_cert_id)?;

    let mut nodes = ctx.memo.values().cloned().collect::<Vec<_>>();
    nodes.sort_by(|a, b| a.cert_id.cmp(&b.cert_id));
    Ok(CoreVerifyResult {
        root_cert_id,
        env_sig: root.env_sig,
        uid: root.uid,
        nodes,
        obj_overlay: ctx.obj_overlay,
        mor_overlay: ctx.mor_overlay,
    })
}

/// Verify a KCIR DAG from in-memory cert/NF stores with a pluggable backend.
pub fn verify_core_dag_with_backend(
    root_cert_id: [u8; 32],
    cert_store: &BTreeMap<[u8; 32], Vec<u8>>,
    obj_store: &BTreeMap<[u8; 32], Vec<u8>>,
    mor_store: &BTreeMap<[u8; 32], Vec<u8>>,
    backend: &dyn KcirBackend,
) -> Result<CoreVerifyResult, String> {
    let store = InMemoryKcirCoreStore {
        cert_store,
        obj_store,
        mor_store,
    };
    verify_core_dag_with_backend_and_store(root_cert_id, &store, backend)
}

/// Verify a KCIR DAG using the in-memory `CoreBaseApi` backend.
pub fn verify_core_dag_with_base_api(
    root_cert_id: [u8; 32],
    cert_store: &BTreeMap<[u8; 32], Vec<u8>>,
    obj_store: &BTreeMap<[u8; 32], Vec<u8>>,
    mor_store: &BTreeMap<[u8; 32], Vec<u8>>,
    base_api: &CoreBaseApi,
) -> Result<CoreVerifyResult, String> {
    verify_core_dag_with_backend(root_cert_id, cert_store, obj_store, mor_store, base_api)
}

/// Verify a KCIR DAG with a default empty Base API hook set.
pub fn verify_core_dag(
    root_cert_id: [u8; 32],
    cert_store: &BTreeMap<[u8; 32], Vec<u8>>,
    obj_store: &BTreeMap<[u8; 32], Vec<u8>>,
    mor_store: &BTreeMap<[u8; 32], Vec<u8>>,
) -> Result<CoreVerifyResult, String> {
    let backend = CoreBaseApi::default();
    verify_core_dag_with_backend(root_cert_id, cert_store, obj_store, mor_store, &backend)
}

/// OBJ/O_PRIM with ObjNF `Prim(primId)`.
///
/// - Args: primId:Bytes32
/// - Deps: none
pub fn node_obj_prim(env_sig: [u8; 32], uid: [u8; 32], prim_id: [u8; 32]) -> KcirNode {
    // ObjNF Prim: tag 0x02 || primId
    let mut obj_bytes = Vec::with_capacity(1 + 32);
    obj_bytes.push(0x02);
    obj_bytes.extend_from_slice(&prim_id);
    let out = h_obj(&env_sig, &uid, &obj_bytes);

    KcirNode {
        env_sig,
        uid,
        sort: SORT_OBJ,
        opcode: O_PRIM,
        out,
        args: prim_id.to_vec(),
        deps: Vec::new(),
    }
}

/// OBJ/O_MKTENSOR with minimal canonicalization (0/1 cases only).
///
/// - Args: encListB32(factors:[hObj])
/// - Deps: none
pub fn node_obj_mktensor(env_sig: [u8; 32], uid: [u8; 32], factors: Vec<[u8; 32]>) -> KcirNode {
    let args = enc_list_b32(&factors);

    let out = match factors.len() {
        0 => {
            // ObjNF Unit: tag 0x01
            h_obj(&env_sig, &uid, &[0x01])
        }
        1 => factors[0],
        _ => {
            // ObjNF Tensor: tag 0x03 || encListB32(factors)
            let mut obj_bytes = Vec::with_capacity(1 + args.len());
            obj_bytes.push(0x03);
            obj_bytes.extend_from_slice(&args);
            h_obj(&env_sig, &uid, &obj_bytes)
        }
    };

    KcirNode {
        env_sig,
        uid,
        sort: SORT_OBJ,
        opcode: O_MKTENSOR,
        out,
        args,
        deps: Vec::new(),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KcirNodeJson {
    pub cert_id: String,
    pub env_sig: String,
    pub uid: String,
    pub sort: u8,
    pub opcode: u8,
    pub out: String,
    pub args_hex: String,
    pub deps: Vec<String>,
}

impl From<&KcirNode> for KcirNodeJson {
    fn from(n: &KcirNode) -> Self {
        Self {
            cert_id: hex::encode(n.cert_id()),
            env_sig: hex::encode(n.env_sig),
            uid: hex::encode(n.uid),
            sort: n.sort,
            opcode: n.opcode,
            out: hex::encode(n.out),
            args_hex: hex::encode(&n.args),
            deps: n.deps.iter().map(|d| hex::encode(d)).collect(),
        }
    }
}
