use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    hex::encode(out)
}

/// SHA-256 digest as raw 32 bytes.
pub fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

pub fn sha256_hex_str(s: &str) -> String {
    sha256_hex(s.as_bytes())
}
