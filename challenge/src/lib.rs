use itoa;
use sha2::{Digest, Sha256};

/// Computes SHA-256 of (random_data + nonce) and returns the raw 32-byte hash.
///
/// # Arguments
/// * `random_data` - The random hex string provided by the server (128 chars)
/// * `nonce` - The nonce to append (as decimal string)
///
/// # Returns
/// The raw 32-byte SHA-256 hash
pub fn compute_hash(random_data: &str, nonce: u64) -> [u8; 32] {
    let mut hasher = <Sha256 as Digest>::new();
    hasher.update(random_data.as_bytes());

    let mut buffer = itoa::Buffer::new();
    let nonce_str = buffer.format(nonce);
    hasher.update(nonce_str.as_bytes());

    hasher.finalize().into()
}

/// Checks if a hash has the required number of leading zero hex digits.
///
/// # Arguments
/// * `hash` - A hex string representing the SHA-256 hash (64 characters)
/// * `difficulty` - The number of leading '0' characters required
///
/// # Returns
/// `true` if the hash has at least `difficulty` leading zeros, `false` otherwise
pub fn check_difficulty(hash: &str, difficulty: u32) -> bool {
    hash.len() >= difficulty as usize
        && hash
            .as_bytes()
            .iter()
            .take(difficulty as usize)
            .all(|&b| b == b'0')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
