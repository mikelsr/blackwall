use challenge::solve as challenge_solve;
use wasm_bindgen;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn solve(random_data: &[u8], difficulty: u32, start_nonce: u64, step: u64) -> u64 {
    challenge_solve(random_data, difficulty, start_nonce, step).0
}
