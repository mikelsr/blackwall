/// This create is kept minimal to ensure WASM files remain as compact as possible.
/// The rest of the challenge code is at /shared/src/challenge.rs.
use sha2::{Digest, Sha256};

/// Computes SHA-256 of (random_data + nonce) and returns the raw 32-byte hash.
pub fn compute_hash(random_data: &[u8], nonce: u64) -> [u8; 32] {
    let mut hasher = <Sha256 as Digest>::new();
    hasher.update(random_data);

    let mut buffer = itoa::Buffer::new();
    let nonce_str = buffer.format(nonce);
    hasher.update(nonce_str.as_bytes());

    hasher.finalize().into()
}

/// Checks if a hash has the required number of leading zero hex digits (nibbles).
pub fn check_difficulty(hash: &[u8; 32], difficulty: u32) -> bool {
    if difficulty > 64 {
        return false;
    }

    let full_bytes = (difficulty / 2) as usize;
    let check_nibble = difficulty % 2 == 1;

    if !hash[..full_bytes].iter().all(|&b| b == 0) {
        return false;
    }

    // Check upper nibble of next byte if difficulty is odd.
    if check_nibble && hash[full_bytes] >> 4 != 0 {
        return false;
    }

    true
}

/// Solve the hash: find a hash for the data that has `difficulty` leading zeros.
pub fn solve(random_data: &[u8], difficulty: u32, start_nonce: u64, step: u64) -> (u64, [u8; 32]) {
    assert!(step > 0, "step must be > 0");

    let mut nonce = start_nonce;
    let mut hash = compute_hash(random_data, nonce);
    while !check_difficulty(&hash, difficulty) {
        nonce = nonce
            .checked_add(step)
            .expect("nonce overflow while searching for solution");
        hash = compute_hash(random_data, nonce);
    }
    (nonce, hash)
}

// I've added a bunch of tests, I must confess with the help of an LLM.
// We'll be serving the challenge solver to every client, we need to make
// sure it works.
#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(prefix: &[u8]) -> [u8; 32] {
        let mut hash = [0xffu8; 32];
        hash[..prefix.len()].copy_from_slice(prefix);
        hash
    }

    #[test]
    fn difficulty_zero_accepts_any_hash() {
        // Difficulty 0 should accept any hash prefix.
        assert!(check_difficulty(&make_hash(&[0xab, 0xcd, 0xef]), 0));
        assert!(check_difficulty(&make_hash(&[0x00, 0x00, 0x00]), 0));
    }

    #[test]
    fn difficulty_one_requires_one_leading_zero_nibble() {
        // Difficulty 1 checks only the top nibble of the first byte.
        assert!(check_difficulty(&make_hash(&[0x0f, 0xab, 0xcd]), 1));
        assert!(check_difficulty(&make_hash(&[0x00, 0xab, 0xcd]), 1));
        assert!(!check_difficulty(&make_hash(&[0x10, 0xab, 0xcd]), 1));
        assert!(!check_difficulty(&make_hash(&[0xab, 0xcd, 0xef]), 1));
    }

    #[test]
    fn difficulty_two_requires_first_byte_zero() {
        // Difficulty 2 requires the full first byte to be zero.
        assert!(check_difficulty(&make_hash(&[0x00, 0xab, 0xcd]), 2));
        assert!(!check_difficulty(&make_hash(&[0x0f, 0xab, 0xcd]), 2));
    }

    #[test]
    fn difficulty_four_requires_two_zero_bytes() {
        // Difficulty 4 requires two full leading zero bytes.
        assert!(check_difficulty(&make_hash(&[0x00, 0x00, 0xab, 0xcd]), 4));
        assert!(!check_difficulty(&make_hash(&[0x00, 0x0f, 0xab, 0xcd]), 4));
    }

    #[test]
    fn difficulty_five_requires_two_zero_bytes_plus_nibble() {
        // Difficulty 5 requires two zero bytes plus a zero high nibble.
        assert!(check_difficulty(&make_hash(&[0x00, 0x00, 0x0f, 0xab]), 5));
        assert!(!check_difficulty(&make_hash(&[0x00, 0x00, 0xf0, 0xab]), 5));
    }

    #[test]
    fn more_zeros_than_required_passes() {
        // Hashes with stricter prefixes than requested must still pass.
        assert!(check_difficulty(&make_hash(&[0x00, 0x00, 0x00, 0xab]), 4));
        assert!(check_difficulty(
            &make_hash(&[0x00, 0x00, 0x00, 0x00, 0xab]),
            5
        ));
    }

    #[test]
    fn fewer_zeros_than_required_fails() {
        // Hashes missing required leading zero nibbles must fail.
        assert!(!check_difficulty(&make_hash(&[0x00, 0x0f, 0xab]), 4));
        assert!(!check_difficulty(&make_hash(&[0x00, 0x00, 0xab]), 5));
    }

    #[test]
    fn high_difficulty() {
        // Higher difficulty should keep nibble/byte boundary behavior correct.
        assert!(check_difficulty(
            &make_hash(&[0x00, 0x00, 0x00, 0x00, 0x00, 0xab]),
            10
        ));
        assert!(!check_difficulty(
            &make_hash(&[0x00, 0x00, 0x00, 0x00, 0x00, 0xab]),
            11
        ));
        assert!(check_difficulty(
            &make_hash(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x0f]),
            11
        ));
    }

    #[test]
    fn all_zeros_hash() {
        // All-zero hash should pass up to 64 nibbles and fail above that.
        let all_zeros: [u8; 32] = [0x00; 32];
        assert!(check_difficulty(&all_zeros, 0));
        assert!(check_difficulty(&all_zeros, 32));
        assert!(check_difficulty(&all_zeros, 64));
        assert!(!check_difficulty(&all_zeros, 65));
    }

    #[test]
    fn compute_hash_known_value() {
        // Hash output must always be exactly 32 bytes.
        let hash = compute_hash(b"test", 0);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn compute_hash_different_nonces_produce_different_hashes() {
        // Different nonces for same data should produce different digests.
        let hash1 = compute_hash(b"randomdata", 0);
        let hash2 = compute_hash(b"randomdata", 1);
        let hash3 = compute_hash(b"randomdata", 2);

        assert_ne!(hash1, hash2);
        assert_ne!(hash2, hash3);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn compute_hash_same_input_produces_same_hash() {
        // Hashing is deterministic for identical input bytes and nonce.
        let hash1 = compute_hash(b"samedata", 42);
        let hash2 = compute_hash(b"samedata", 42);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn compute_hash_different_data_produces_different_hashes() {
        // Different input data with same nonce should change the digest.
        let hash1 = compute_hash(b"data1", 0);
        let hash2 = compute_hash(b"data2", 0);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn compute_hash_matches_expected_sha256() {
        // Verify a fixed test vector for exact SHA-256 correctness.
        let hash = compute_hash(b"hello", 123);
        let expected: [u8; 32] = [
            0x27, 0xcc, 0x69, 0x94, 0xfc, 0x1c, 0x01, 0xce, 0x66, 0x59, 0xc6, 0xbd, 0xdc, 0xa9,
            0xb6, 0x9c, 0x4c, 0x6a, 0x94, 0x18, 0x06, 0x5e, 0x61, 0x2c, 0x69, 0xd1, 0x10, 0xb3,
            0xf7, 0xb1, 0x1f, 0x8a,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn compute_hash_large_nonce() {
        // Largest u64 nonce must hash without panicking or truncation.
        let hash = compute_hash(b"data", u64::MAX);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn compute_hash_raw_bytes_differs_from_hex_text() {
        // Raw bytes and their hex text representation must hash differently.
        let hash_raw_bytes = compute_hash(&[0xde, 0xad, 0xbe, 0xef], 0);
        let hash_hex_text = compute_hash(b"deadbeef", 0);
        assert_ne!(hash_raw_bytes, hash_hex_text);
    }

    #[test]
    fn solve_finds_valid_solution() {
        // Solver should return a nonce whose digest satisfies the difficulty.
        let random_data = b"test_random_data";
        let difficulty = 1;
        let (nonce, hash) = solve(random_data, difficulty, 0, 1);

        assert!(check_difficulty(&hash, difficulty));
        assert_eq!(hash, compute_hash(random_data, nonce));
    }

    #[test]
    fn solve_with_higher_difficulty() {
        // Solver should still find valid output at a higher difficulty.
        let random_data = b"another_test_data";
        let difficulty = 2;
        let (nonce, hash) = solve(random_data, difficulty, 0, 1);

        assert!(check_difficulty(&hash, difficulty));
        assert_eq!(hash, compute_hash(random_data, nonce));
    }

    #[test]
    fn solve_respects_start_nonce() {
        // Search should begin at start_nonce and continue forward from there.
        let random_data = b"start_nonce_test";
        let difficulty = 1;

        let (nonce1, _) = solve(random_data, difficulty, 0, 1);
        let (nonce2, hash2) = solve(random_data, difficulty, nonce1 + 1, 1);

        assert!(nonce2 > nonce1);
        assert!(check_difficulty(&hash2, difficulty));
    }

    #[test]
    fn solve_respects_step() {
        // Stride should preserve each worker's nonce congruence class.
        let random_data = b"step_test_data";
        let difficulty = 1;
        let step = 3;

        let (nonce0, hash0) = solve(random_data, difficulty, 0, step);
        assert!(check_difficulty(&hash0, difficulty));
        assert_eq!(nonce0 % step, 0);

        let (nonce1, hash1) = solve(random_data, difficulty, 1, step);
        assert!(check_difficulty(&hash1, difficulty));
        assert_eq!(nonce1 % step, 1);

        let (nonce2, hash2) = solve(random_data, difficulty, 2, step);
        assert!(check_difficulty(&hash2, difficulty));
        assert_eq!(nonce2 % step, 2);
    }

    #[test]
    fn solve_difficulty_zero_returns_immediately() {
        // Difficulty 0 should return the initial nonce without iteration.
        let random_data = b"instant_solve";
        let difficulty = 0;
        let (nonce, hash) = solve(random_data, difficulty, 0, 1);

        assert_eq!(nonce, 0);
        assert!(check_difficulty(&hash, difficulty));
    }

    #[test]
    #[should_panic(expected = "step must be > 0")]
    fn solve_step_zero_panics() {
        // Step 0 is invalid and must fail fast to avoid infinite loops.
        let _ = solve(b"data", 1, 0, 0);
    }

    #[test]
    #[should_panic(expected = "nonce overflow while searching for solution")]
    fn solve_difficulty_above_max_overflows() {
        // Difficulty > 64 can never be satisfied, so search runs until nonce overflow.
        let _ = solve(b"data", 65, u64::MAX, 1);
    }
}
