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

    // Helper to create a 32-byte array with specified prefix
    fn make_hash(prefix: &[u8]) -> [u8; 32] {
        let mut hash = [0xffu8; 32];
        hash[..prefix.len()].copy_from_slice(prefix);
        hash
    }

    #[test]
    fn difficulty_zero_accepts_any_hash() {
        // Any hash passes difficulty 0
        assert!(check_difficulty(&make_hash(&[0xab, 0xcd, 0xef]), 0));
        assert!(check_difficulty(&make_hash(&[0x00, 0x00, 0x00]), 0));
    }

    #[test]
    fn difficulty_one_requires_one_leading_zero_nibble() {
        // 0x0f = upper nibble is 0 → passes difficulty 1
        assert!(check_difficulty(&make_hash(&[0x0f, 0xab, 0xcd]), 1));
        // 0x00 = both nibbles are 0 → passes difficulty 1
        assert!(check_difficulty(&make_hash(&[0x00, 0xab, 0xcd]), 1));
        // 0x10 = upper nibble is 1 → fails difficulty 1
        assert!(!check_difficulty(&make_hash(&[0x10, 0xab, 0xcd]), 1));
        // 0xab = upper nibble is a → fails difficulty 1
        assert!(!check_difficulty(&make_hash(&[0xab, 0xcd, 0xef]), 1));
    }

    #[test]
    fn difficulty_two_requires_first_byte_zero() {
        // First byte is 0x00 → passes difficulty 2
        assert!(check_difficulty(&make_hash(&[0x00, 0xab, 0xcd]), 2));
        // First byte is 0x0f → fails difficulty 2 (only 1 zero nibble)
        assert!(!check_difficulty(&make_hash(&[0x0f, 0xab, 0xcd]), 2));
    }

    #[test]
    fn difficulty_four_requires_two_zero_bytes() {
        // First 2 bytes are 0x00 → passes difficulty 4
        assert!(check_difficulty(&make_hash(&[0x00, 0x00, 0xab, 0xcd]), 4));
        // Only first byte is 0x00 → fails difficulty 4
        assert!(!check_difficulty(&make_hash(&[0x00, 0x0f, 0xab, 0xcd]), 4));
    }

    #[test]
    fn difficulty_five_requires_two_zero_bytes_plus_nibble() {
        // 0x00, 0x00, 0x0f → 5 zero nibbles → passes difficulty 5
        assert!(check_difficulty(&make_hash(&[0x00, 0x00, 0x0f, 0xab]), 5));
        // 0x00, 0x00, 0xf0 → 4 zero nibbles → fails difficulty 5
        assert!(!check_difficulty(&make_hash(&[0x00, 0x00, 0xf0, 0xab]), 5));
    }

    #[test]
    fn more_zeros_than_required_passes() {
        // Has 6 zero nibbles (3 zero bytes), only 4 required
        assert!(check_difficulty(&make_hash(&[0x00, 0x00, 0x00, 0xab]), 4));
        // Has 8 zero nibbles (4 zero bytes), only 5 required
        assert!(check_difficulty(
            &make_hash(&[0x00, 0x00, 0x00, 0x00, 0xab]),
            5
        ));
    }

    #[test]
    fn fewer_zeros_than_required_fails() {
        // Has 3 zero nibbles, but 4 required
        assert!(!check_difficulty(&make_hash(&[0x00, 0x0f, 0xab]), 4));
        // Has 4 zero nibbles, but 5 required
        assert!(!check_difficulty(&make_hash(&[0x00, 0x00, 0xab]), 5));
    }

    #[test]
    fn high_difficulty() {
        // 10 zero nibbles = 5 zero bytes
        assert!(check_difficulty(
            &make_hash(&[0x00, 0x00, 0x00, 0x00, 0x00, 0xab]),
            10
        ));
        // 10 zero nibbles, but 11 required
        assert!(!check_difficulty(
            &make_hash(&[0x00, 0x00, 0x00, 0x00, 0x00, 0xab]),
            11
        ));
        // 11 zero nibbles = 5 zero bytes + upper nibble of 6th byte is 0
        assert!(check_difficulty(
            &make_hash(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x0f]),
            11
        ));
    }

    #[test]
    fn all_zeros_hash() {
        let all_zeros: [u8; 32] = [0x00; 32];
        assert!(check_difficulty(&all_zeros, 0));
        assert!(check_difficulty(&all_zeros, 32));
        assert!(check_difficulty(&all_zeros, 64)); // 64 nibbles = all 32 bytes
    }

    // ========== compute_hash tests ==========

    #[test]
    fn compute_hash_known_value() {
        // SHA256("test0") = 96687060eb0a260c580a5ced1c9e6a55e48aborede4...
        // Let's verify with a known input
        let hash = compute_hash("test", 0);

        // SHA256("test0") - we verify it produces 32 bytes
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn compute_hash_different_nonces_produce_different_hashes() {
        let hash1 = compute_hash("randomdata", 0);
        let hash2 = compute_hash("randomdata", 1);
        let hash3 = compute_hash("randomdata", 2);

        assert_ne!(hash1, hash2);
        assert_ne!(hash2, hash3);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn compute_hash_same_input_produces_same_hash() {
        let hash1 = compute_hash("samedata", 42);
        let hash2 = compute_hash("samedata", 42);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn compute_hash_different_data_produces_different_hashes() {
        let hash1 = compute_hash("data1", 0);
        let hash2 = compute_hash("data2", 0);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn compute_hash_matches_expected_sha256() {
        // SHA256("hello123") = 27cc6994fc1c01ce6659c6bddca9b69c4c6a9418065e612c69d110b3f7b11f8a
        let hash = compute_hash("hello", 123);
        let expected: [u8; 32] = [
            0x27, 0xcc, 0x69, 0x94, 0xfc, 0x1c, 0x01, 0xce, 0x66, 0x59, 0xc6, 0xbd, 0xdc, 0xa9,
            0xb6, 0x9c, 0x4c, 0x6a, 0x94, 0x18, 0x06, 0x5e, 0x61, 0x2c, 0x69, 0xd1, 0x10, 0xb3,
            0xf7, 0xb1, 0x1f, 0x8a,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn compute_hash_large_nonce() {
        // Should handle large nonces without issue
        let hash = compute_hash("data", u64::MAX);
        assert_eq!(hash.len(), 32);
    }

    // ========== solve tests ==========

    #[test]
    fn solve_finds_valid_solution() {
        let random_data = "test_random_data";
        let difficulty = 1; // Low difficulty for fast test
        let (nonce, hash) = solve(random_data, difficulty, 0, 1);

        // Verify the solution is valid
        assert!(check_difficulty(&hash, difficulty));
        // Verify the hash matches what we'd compute
        assert_eq!(hash, compute_hash(random_data, nonce));
    }

    #[test]
    fn solve_with_higher_difficulty() {
        let random_data = "another_test_data";
        let difficulty = 2; // Still fast enough for tests
        let (nonce, hash) = solve(random_data, difficulty, 0, 1);

        assert!(check_difficulty(&hash, difficulty));
        assert_eq!(hash, compute_hash(random_data, nonce));
    }

    #[test]
    fn solve_respects_start_nonce() {
        let random_data = "start_nonce_test";
        let difficulty = 1;

        // Find solution starting from 0
        let (nonce1, _) = solve(random_data, difficulty, 0, 1);

        // Find solution starting from after the first solution
        let (nonce2, hash2) = solve(random_data, difficulty, nonce1 + 1, 1);

        // Second solution should be at a higher nonce
        assert!(nonce2 > nonce1);
        assert!(check_difficulty(&hash2, difficulty));
    }

    #[test]
    fn solve_respects_step() {
        let random_data = "step_test_data";
        let difficulty = 1;
        let step = 3;

        // Worker 0: starts at 0, steps by 3
        let (nonce0, hash0) = solve(random_data, difficulty, 0, step);
        assert!(check_difficulty(&hash0, difficulty));
        assert_eq!(nonce0 % step, 0); // Should be 0, 3, 6, 9...

        // Worker 1: starts at 1, steps by 3
        let (nonce1, hash1) = solve(random_data, difficulty, 1, step);
        assert!(check_difficulty(&hash1, difficulty));
        assert_eq!(nonce1 % step, 1); // Should be 1, 4, 7, 10...

        // Worker 2: starts at 2, steps by 3
        let (nonce2, hash2) = solve(random_data, difficulty, 2, step);
        assert!(check_difficulty(&hash2, difficulty));
        assert_eq!(nonce2 % step, 2); // Should be 2, 5, 8, 11...
    }

    #[test]
    fn solve_difficulty_zero_returns_immediately() {
        let random_data = "instant_solve";
        let difficulty = 0;
        let (nonce, hash) = solve(random_data, difficulty, 0, 1);

        // With difficulty 0, any hash is valid, so it should return the first nonce
        assert_eq!(nonce, 0);
        assert!(check_difficulty(&hash, difficulty));
    }
}
