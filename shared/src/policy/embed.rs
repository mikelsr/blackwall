use include_dir::{Dir, include_dir};

static DATA: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../data");

pub fn get(path: &str) -> Option<&'static str> {
    DATA.get_file(path)?.contents_utf8()
}

/// Every bundled YAML file as (path, contents).
#[cfg(test)]
pub(crate) fn yaml_files() -> Vec<(&'static str, &'static str)> {
    fn walk(dir: &'static Dir<'static>, out: &mut Vec<(&'static str, &'static str)>) {
        for file in dir.files() {
            if file.path().extension().is_some_and(|ext| ext == "yaml") {
                let path = file.path().to_str().expect("UTF-8 path");
                out.push((path, file.contents_utf8().expect("UTF-8 contents")));
            }
        }
        for sub in dir.dirs() {
            walk(sub, out);
        }
    }

    let mut out = Vec::new();
    walk(&DATA, &mut out);
    out
}
