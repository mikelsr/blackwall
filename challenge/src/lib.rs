use itoa;
use sha2::{Digest, Sha256};

/// Computes SHA-256 of (random_data + nonce) and returns the raw 32-byte hash.
pub fn compute_hash(random_data: &str, nonce: u64) -> [u8; 32] {
    let mut hasher = <Sha256 as Digest>::new();
    hasher.update(random_data.as_bytes());

    let mut buffer = itoa::Buffer::new();
    let nonce_str = buffer.format(nonce);
    hasher.update(nonce_str.as_bytes());

    hasher.finalize().into()
}

/// Checks if a hash has the required number of leading zero hex digits (nibbles).
pub fn check_difficulty(hash: &[u8; 32], difficulty: u32) -> bool {
    let full_bytes = (difficulty / 2) as usize;
    let check_nibble = difficulty % 2 == 1;

    // Check full zero bytes.
    if !hash[..full_bytes].iter().all(|&b| b == 0) {
        return false;
    }

    // Check upper nibble of next byte if difficulty is odd.
    if check_nibble && hash[full_bytes] >> 4 != 0 {
        return false;
    }

    true
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
