#![allow(dead_code)]

/// This module embeds the HTML and WASM files at compile time.
use const_str::split;

pub(crate) const ASSET_CHALLENGE_HTML: &str = include_str!("../../www/index.html");
pub(crate) const ASSET_SOLVER_WASM: &[u8] =
    include_bytes!("../../challenge-wasm/pkg/challenge_wasm_bg.wasm");
pub(crate) const ASSET_SOLVER_WASM_GZIP: &[u8] =
    include_bytes!("../../challenge-wasm/pkg/challenge_wasm_bg.wasm.gz");
pub(crate) const ASSET_SOLVER_WASM_BROTLI: &[u8] =
    include_bytes!("../../challenge-wasm/pkg/challenge_wasm_bg.wasm.br");
pub(crate) const ASSET_SOLVER_WASM_ZSTD: &[u8] =
    include_bytes!("../../challenge-wasm/pkg/challenge_wasm_bg.wasm.zst");

pub(crate) const SEPARATOR: &str = "<!--B7L_INJECTION-->";
pub(crate) const CHALLENGE_DECLARATION: &str = "window.ANUBIS_CHALLENGE = ";

pub(crate) const WIGGLE_ROOM: usize = 32; // Extra capacity for semicolons, line breaks...

// I've had to add this branch to keep the rust-analyzer happy,
// I found no other way with my editor (Zed).
#[cfg(rust_analyzer)]
pub(crate) const PARTS: [&str; 2] = ["", ""];
#[cfg(not(rust_analyzer))]
pub(crate) const PARTS: [&str; 2] = split!(ASSET_CHALLENGE_HTML, SEPARATOR);

pub(crate) const HTML_PREFIX: &str = PARTS[0];
pub(crate) const HTML_SUFFIX: &str = PARTS[1];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_split() {
        assert!(ASSET_CHALLENGE_HTML.contains(SEPARATOR));
        let parts = split!(ASSET_CHALLENGE_HTML, SEPARATOR);
        assert_eq!(parts.len(), 2);
    }
}
