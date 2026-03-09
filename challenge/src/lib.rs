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

/// Solve the hash: find a hash for the data that has $difficulty leading zeros.
pub fn solve(random_data: &str, difficulty: u32, start_nonce: u64, step: u64) -> (u64, [u8; 32]) {
    let mut nonce = start_nonce;
    let mut hash: [u8; 32] = compute_hash(random_data, nonce);
    while !check_difficulty(&hash, difficulty) {
        nonce += step;
        hash = compute_hash(random_data, nonce);
    }
    return (nonce, hash);
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
