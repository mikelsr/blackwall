fn main() {
    println!("cargo:rerun-if-env-changed=B7L_VERSION");

    let version = std::env::var("B7L_VERSION")
        .ok()
        .map(|version| version.trim().to_owned())
        .filter(|version| !version.is_empty())
        .unwrap_or_else(|| "devel".to_owned());

    println!("cargo:rustc-env=B7L_VERSION={version}");
}
