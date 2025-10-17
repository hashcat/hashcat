/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
use hashcat_sys::ThreadContext;
use sha2::{Digest, Sha256};

// Trailing zeroes are necessary.
#[unsafe(no_mangle)]
pub static ST_HASH: &[u8] =
    b"33522b0fd9812aa68586f66dba7c17a8ce64344137f9c7d8b11f32a6921c22de*9348746780603343\0";
#[unsafe(no_mangle)]
pub static ST_PASS: &[u8] = b"hashcat\0";

pub(crate) fn calc_hash(password: &[u8], salt: &[u8]) -> Vec<String> {
    let mut sha256 = Sha256::new();
    sha256.update(salt);
    sha256.update(password);
    let mut hash = sha256.finalize_reset();
    for _ in 0..10_000 {
        sha256.update(hash);
        hash = sha256.finalize_reset();
    }

    vec![hex::encode(hash)]
}

#[allow(unused_variables)]
pub(crate) fn thread_init(ctx: &mut ThreadContext) {}

#[allow(unused_variables)]
pub(crate) fn thread_term(ctx: &mut ThreadContext) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calc_hash() {
        let password = b"hashcat";
        let salt = b"9348746780603343";
        let hash = calc_hash(password, salt);
        assert_eq!(hash.len(), 1);
        assert_eq!(
            hash[0],
            "33522b0fd9812aa68586f66dba7c17a8ce64344137f9c7d8b11f32a6921c22de"
        );
    }
}
