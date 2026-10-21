/// Strips the challenge page to keep the embedded version small.
use std::{env, fs, path::Path};

const PAGE: &str = "../www/index.html";
const MARKER: &str = "<!--B7L_INJECTION-->";

fn main() {
    println!("cargo:rerun-if-changed={PAGE}");
    let page = fs::read_to_string(PAGE).expect("read the challenge page");
    let out = Path::new(&env::var("OUT_DIR").expect("OUT_DIR is set by cargo")).join("index.html");
    fs::write(out, strip(&page)).expect("write the stripped challenge page");
}

fn strip(page: &str) -> String {
    let page = without(&without(page, "<!--", "-->"), "/*", "*/");
    page.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Removes every span from `start` to `end`, except the injection marker,
/// where the server inserts the challenge.
fn without(text: &str, start: &str, end: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(start) {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        if rest.starts_with(MARKER) {
            out.push_str(MARKER);
            rest = &rest[MARKER.len()..];
            continue;
        }
        let close = rest[start.len()..]
            .find(end)
            .expect("every comment in the page is closed");
        rest = &rest[start.len() + close + end.len()..];
    }
    out.push_str(rest);
    out
}
