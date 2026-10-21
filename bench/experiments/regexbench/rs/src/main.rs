//! Same as ../go/main.go with Rust's regex crate, once per rule, as Blackwall
//! matches. Usage: cargo run --release -- rules.json (from ../extract.py).
use std::{hint::black_box, time::Instant};

const UA: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0 b7l-bench/1.0";
const ITERATIONS: u32 = 20000;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: regexbench rules.json");
    let rules: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut total = 0f64;
    for r in rules.iter().filter(|r| r["kind"] == "ua") {
        let re = regex::Regex::new(r["pattern"].as_str().unwrap().trim()).unwrap();
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            black_box(re.is_match(black_box(UA)));
        }
        let us = start.elapsed().as_secs_f64() * 1e6 / ITERATIONS as f64;
        total += us;
        println!("{:<40} {:6.3} µs", r["rule"].as_str().unwrap(), us);
    }
    println!("all once: {total:.2} µs");
}
