//! Gzips each challenge page with flate2's default miniz_oxide backend at
//! Compression::fast(), two ways: a new encoder per page (as Blackwall does)
//! and one encoder reset per page (as Anubis's pool does). Prints the time
//! per page and per input byte. Usage: cargo run --release -- <page.html>...
//! (pages from ../pages.sh).
use flate2::{write::GzEncoder, Compression};
use std::{hint::black_box, io::Write, time::Instant};

const ITERATIONS: u32 = 20000;

fn report(how: &str, path: &str, len: usize, start: Instant) {
    let per = start.elapsed().as_nanos() as f64 / ITERATIONS as f64;
    println!(
        "rs {how} {path} {len} B: {:.1} µs per page, {:.2} ns per byte",
        per / 1000.0,
        per / len as f64
    );
}

fn main() {
    for path in std::env::args().skip(1) {
        let page = std::fs::read(&path).unwrap();

        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
            encoder.write_all(&page).unwrap();
            black_box(encoder.finish().unwrap());
        }
        report("new", &path, page.len(), start);

        // GzEncoder can't be reset; a raw deflate stream with a reset
        // compressor does the same compression work minus the gzip framing.
        let mut compress = flate2::Compress::new(Compression::fast(), false);
        let mut out = Vec::with_capacity(page.len() + 1024);
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            compress.reset();
            out.clear();
            compress
                .compress_vec(&page, &mut out, flate2::FlushCompress::Finish)
                .unwrap();
            black_box(&out);
        }
        report("reused", &path, page.len(), start);
    }
}
