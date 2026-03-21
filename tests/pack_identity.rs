use tbp::pack_identity::{
    canonicalize_pack_hash, parse_pack_identity_label, parse_vendor_pack_identity_from_file_path,
};

#[test]
fn canonicalize_sha256_hash_variants() {
    let hex = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";
    let expected = "sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    assert_eq!(
        canonicalize_pack_hash(&format!("sha256:{hex}")).as_deref(),
        Some(expected)
    );
    assert_eq!(
        canonicalize_pack_hash(&format!("sha256-{hex}")).as_deref(),
        Some(expected)
    );
    assert_eq!(
        canonicalize_pack_hash(&format!("sha256_{hex}")).as_deref(),
        Some(expected)
    );
    assert_eq!(canonicalize_pack_hash(hex).as_deref(), Some(expected));
}

#[test]
fn parse_pack_identity_from_label_variants() {
    let hex = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";

    let a = parse_pack_identity_label(&format!("brand@1.2.3+sha256_{hex}"));
    assert_eq!(a.pack_id.as_deref(), Some("brand"));
    assert_eq!(a.pack_version.as_deref(), Some("1.2.3"));
    assert_eq!(
        a.pack_hash.as_deref(),
        Some("sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
    );

    let b = parse_pack_identity_label(&format!("brand@2.0.0#{hex}"));
    assert_eq!(b.pack_id.as_deref(), Some("brand"));
    assert_eq!(b.pack_version.as_deref(), Some("2.0.0"));
    assert_eq!(
        b.pack_hash.as_deref(),
        Some("sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
    );

    let c = parse_pack_identity_label("brand__sha256_aabb");
    assert_eq!(c.pack_id.as_deref(), Some("brand"));
    assert_eq!(c.pack_version, None);
    assert_eq!(c.pack_hash.as_deref(), Some("sha256:aabb"));

    let d = parse_pack_identity_label("brand@1.0.0");
    assert_eq!(d.pack_id.as_deref(), Some("brand"));
    assert_eq!(d.pack_version.as_deref(), Some("1.0.0"));
    assert_eq!(d.pack_hash, None);
}

#[test]
fn parse_vendor_pack_identity_detects_vendor_segment_anywhere() {
    let p = parse_vendor_pack_identity_from_file_path(
        "tokens/vendor/brand@1.2.3+sha256_deadbeef/color/base.tokens.json",
    );
    assert_eq!(p.pack_id.as_deref(), Some("brand"));
    assert_eq!(p.pack_version.as_deref(), Some("1.2.3"));
    assert_eq!(p.pack_hash.as_deref(), Some("sha256:deadbeef"));

    let none = parse_vendor_pack_identity_from_file_path("tokens/base.tokens.json");
    assert_eq!(none.pack_id, None);
    assert_eq!(none.pack_version, None);
    assert_eq!(none.pack_hash, None);
}
