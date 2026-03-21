#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PackIdentity {
    pub pack_id: Option<String>,
    pub pack_version: Option<String>,
    pub pack_hash: Option<String>,
}

fn normalize_opt(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

pub fn canonicalize_pack_hash(raw: &str) -> Option<String> {
    let mut token = raw.trim();
    if token.is_empty() {
        return None;
    }
    for prefix in [
        "sha256:", "sha256-", "sha256_", "SHA256:", "SHA256-", "SHA256_",
    ] {
        if let Some(rest) = token.strip_prefix(prefix) {
            token = rest;
            break;
        }
    }
    if token.is_empty() {
        return None;
    }
    if token.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(format!("sha256:{}", token.to_ascii_lowercase()));
    }
    None
}

fn split_hash_suffix(label: &str) -> (String, Option<String>) {
    if let Some((id, h)) = label.rsplit_once("__sha256_") {
        return (
            id.to_string(),
            canonicalize_pack_hash(&format!("sha256:{h}")),
        );
    }

    for sep in ['+', '#'] {
        if let Some((left, right)) = label.rsplit_once(sep) {
            if let Some(h) = canonicalize_pack_hash(right) {
                return (left.to_string(), Some(h));
            }
        }
    }
    (label.to_string(), None)
}

pub fn parse_pack_identity_label(label: &str) -> PackIdentity {
    let raw = label.trim();
    if raw.is_empty() {
        return PackIdentity::default();
    }

    let (base, pack_hash) = split_hash_suffix(raw);
    let mut pack_id = base.clone();
    let mut pack_version: Option<String> = None;

    if let Some(idx) = base.rfind('@') {
        if idx > 0 && idx + 1 < base.len() {
            let id = &base[..idx];
            let version = &base[idx + 1..];
            if let Some(v) = normalize_opt(version) {
                pack_id = id.to_string();
                pack_version = Some(v);
            }
        }
    }

    PackIdentity {
        pack_id: normalize_opt(&pack_id),
        pack_version,
        pack_hash,
    }
}

pub fn parse_vendor_pack_identity_from_file_path(file_path: &str) -> PackIdentity {
    let norm = file_path.replace('\\', "/");
    let segs: Vec<&str> = norm.split('/').collect();
    for i in 0..segs.len() {
        if segs[i] == "vendor" {
            if let Some(label) = segs.get(i + 1) {
                if !label.is_empty() {
                    return parse_pack_identity_label(label);
                }
            }
            break;
        }
    }
    PackIdentity::default()
}
