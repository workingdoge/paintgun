#!/usr/bin/env python3
"""
Small helper for building KCIR/NF fixture payloads.

Examples:
  # Hash MorNF bytes
  ./scripts/kcir_fixture_builder.py hash-mor \
    --env-sig 00...00 --uid 11...11 --mor-bytes 1133...33

  # Encode a KCIR node and compute certId
  ./scripts/kcir_fixture_builder.py encode-node \
    --env-sig 00...00 --uid 11...11 --sort 4 --opcode 16 \
    --out 00...00 --args aaaa...03 --deps <cert1>,<cert2>
"""

from __future__ import annotations

import argparse
import hashlib
import json
from typing import Iterable, List


def parse_hex32(label: str, raw: str) -> bytes:
    try:
        b = bytes.fromhex(raw)
    except ValueError as exc:
        raise SystemExit(f"{label}: invalid hex: {exc}") from exc
    if len(b) != 32:
        raise SystemExit(f"{label}: expected 32 bytes, got {len(b)}")
    return b


def parse_hex_bytes(label: str, raw: str) -> bytes:
    try:
        return bytes.fromhex(raw)
    except ValueError as exc:
        raise SystemExit(f"{label}: invalid hex: {exc}") from exc


def enc_varint(n: int) -> bytes:
    if n < 0:
        raise SystemExit(f"varint cannot encode negative value: {n}")
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def enc_list_b32(items: Iterable[bytes]) -> bytes:
    items = list(items)
    for idx, item in enumerate(items):
        if len(item) != 32:
            raise SystemExit(f"list-b32 item[{idx}] expected 32 bytes, got {len(item)}")
    return enc_varint(len(items)) + b"".join(items)


def enc_list_u32(items: Iterable[int]) -> bytes:
    items = list(items)
    for idx, item in enumerate(items):
        if item < 0:
            raise SystemExit(f"list-u32 item[{idx}] cannot be negative: {item}")
    return enc_varint(len(items)) + b"".join(enc_varint(i) for i in items)


def h_obj(env_sig: bytes, uid: bytes, obj_bytes: bytes) -> bytes:
    return hashlib.sha256(b"ObjNF" + env_sig + uid + obj_bytes).digest()


def h_mor(env_sig: bytes, uid: bytes, mor_bytes: bytes) -> bytes:
    return hashlib.sha256(b"MorNF" + env_sig + uid + mor_bytes).digest()


def cert_id(node_bytes: bytes) -> bytes:
    return hashlib.sha256(b"KCIRNode" + node_bytes).digest()


def encode_node(
    env_sig: bytes,
    uid: bytes,
    sort: int,
    opcode: int,
    out: bytes,
    args: bytes,
    deps: List[bytes],
) -> bytes:
    if not (0 <= sort <= 0xFF):
        raise SystemExit(f"sort must fit in u8, got {sort}")
    if not (0 <= opcode <= 0xFF):
        raise SystemExit(f"opcode must fit in u8, got {opcode}")
    for idx, dep in enumerate(deps):
        if len(dep) != 32:
            raise SystemExit(f"dep[{idx}] expected 32 bytes, got {len(dep)}")
    return (
        env_sig
        + uid
        + bytes([sort, opcode])
        + out
        + enc_varint(len(args))
        + args
        + enc_varint(len(deps))
        + b"".join(deps)
    )


def cmd_hash_obj(args: argparse.Namespace) -> None:
    env_sig = parse_hex32("envSig", args.env_sig)
    uid = parse_hex32("uid", args.uid)
    obj_bytes = parse_hex_bytes("objBytes", args.obj_bytes)
    print(
        json.dumps(
            {
                "objBytesHex": obj_bytes.hex(),
                "hObj": h_obj(env_sig, uid, obj_bytes).hex(),
            },
            indent=2,
        )
    )


def cmd_hash_mor(args: argparse.Namespace) -> None:
    env_sig = parse_hex32("envSig", args.env_sig)
    uid = parse_hex32("uid", args.uid)
    mor_bytes = parse_hex_bytes("morBytes", args.mor_bytes)
    print(
        json.dumps(
            {
                "morBytesHex": mor_bytes.hex(),
                "hMor": h_mor(env_sig, uid, mor_bytes).hex(),
            },
            indent=2,
        )
    )


def cmd_cert_id(args: argparse.Namespace) -> None:
    node_bytes = parse_hex_bytes("nodeBytes", args.node_bytes)
    print(json.dumps({"nodeBytesHex": node_bytes.hex(), "certId": cert_id(node_bytes).hex()}, indent=2))


def cmd_encode_node(args: argparse.Namespace) -> None:
    env_sig = parse_hex32("envSig", args.env_sig)
    uid = parse_hex32("uid", args.uid)
    out = parse_hex32("out", args.out)
    node_args = parse_hex_bytes("args", args.args)
    deps = []
    if args.deps:
        for idx, dep_hex in enumerate(args.deps.split(",")):
            dep_hex = dep_hex.strip()
            if not dep_hex:
                continue
            deps.append(parse_hex32(f"deps[{idx}]", dep_hex))
    node_bytes = encode_node(env_sig, uid, args.sort, args.opcode, out, node_args, deps)
    print(
        json.dumps(
            {
                "nodeBytesHex": node_bytes.hex(),
                "certId": cert_id(node_bytes).hex(),
            },
            indent=2,
        )
    )


def cmd_list_b32(args: argparse.Namespace) -> None:
    items = []
    if args.items:
        for idx, raw in enumerate(args.items.split(",")):
            raw = raw.strip()
            if not raw:
                continue
            items.append(parse_hex32(f"items[{idx}]", raw))
    payload = enc_list_b32(items)
    print(json.dumps({"listB32Hex": payload.hex()}, indent=2))


def cmd_list_u32(args: argparse.Namespace) -> None:
    items = []
    if args.items:
        for idx, raw in enumerate(args.items.split(",")):
            raw = raw.strip()
            if not raw:
                continue
            try:
                value = int(raw, 10)
            except ValueError as exc:
                raise SystemExit(f"items[{idx}] invalid integer: {raw}") from exc
            if value < 0:
                raise SystemExit(f"items[{idx}] must be >= 0, got {value}")
            items.append(value)
    payload = enc_list_u32(items)
    print(json.dumps({"listU32Hex": payload.hex()}, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="KCIR/NF fixture helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_hash_obj = sub.add_parser("hash-obj", help="compute hObj for ObjNF bytes")
    p_hash_obj.add_argument("--env-sig", required=True, help="32-byte hex envSig")
    p_hash_obj.add_argument("--uid", required=True, help="32-byte hex uid")
    p_hash_obj.add_argument("--obj-bytes", required=True, help="ObjNF payload hex")
    p_hash_obj.set_defaults(func=cmd_hash_obj)

    p_hash_mor = sub.add_parser("hash-mor", help="compute hMor for MorNF bytes")
    p_hash_mor.add_argument("--env-sig", required=True, help="32-byte hex envSig")
    p_hash_mor.add_argument("--uid", required=True, help="32-byte hex uid")
    p_hash_mor.add_argument("--mor-bytes", required=True, help="MorNF payload hex")
    p_hash_mor.set_defaults(func=cmd_hash_mor)

    p_cert = sub.add_parser("cert-id", help="compute certId from KCIR node bytes")
    p_cert.add_argument("--node-bytes", required=True, help="KCIR node bytes hex")
    p_cert.set_defaults(func=cmd_cert_id)

    p_node = sub.add_parser("encode-node", help="encode KCIR node bytes + certId")
    p_node.add_argument("--env-sig", required=True, help="32-byte hex envSig")
    p_node.add_argument("--uid", required=True, help="32-byte hex uid")
    p_node.add_argument("--sort", required=True, type=int, help="sort u8")
    p_node.add_argument("--opcode", required=True, type=int, help="opcode u8")
    p_node.add_argument("--out", required=True, help="32-byte hex out")
    p_node.add_argument("--args", required=True, help="args bytes hex")
    p_node.add_argument(
        "--deps",
        default="",
        help="comma-separated 32-byte cert ids for deps",
    )
    p_node.set_defaults(func=cmd_encode_node)

    p_l32 = sub.add_parser("list-b32", help="encode encListB32 from comma-separated 32-byte hex items")
    p_l32.add_argument("--items", default="", help="comma-separated 32-byte hex items")
    p_l32.set_defaults(func=cmd_list_b32)

    p_u32 = sub.add_parser("list-u32", help="encode varint list of u32 values")
    p_u32.add_argument("--items", default="", help="comma-separated integer items")
    p_u32.set_defaults(func=cmd_list_u32)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
