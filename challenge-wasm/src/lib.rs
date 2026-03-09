use challenge::solve as challenge_solve;
use wasm_bindgen;
use wasm_bindgen::prelude::*;

const CAPACITY: usize = 40; // 8 for encoded u64, 32 for hash.

// wasm_bindgen converts the Vec<u8> to Uint8Array.
#[wasm_bindgen]
pub fn solve(random_data: &str, difficulty: u32, start_nonce: u64, step: u64) -> Vec<u8> {
    let (nonce, hash) = challenge_solve(random_data, difficulty, start_nonce, step);
    let mut result = Vec::with_capacity(CAPACITY);
    result.extend_from_slice(&nonce.to_be_bytes());
    result.extend_from_slice(&hash);
    result
}
