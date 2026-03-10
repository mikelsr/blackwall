fn main() {
    println!("cargo:rerun-if-env-changed=B7L_VERSION");

    if let Ok(version) = std::env::var("B7L_VERSION") {
        let version = version.trim();
        if !version.is_empty() {
            println!("cargo:rustc-env=B7L_VERSION={version}");
        }
    }
}
