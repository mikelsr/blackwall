use include_dir::{Dir, include_dir};

static DATA: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../data");

pub fn get(path: &str) -> Option<&'static str> {
    DATA.get_file(path)?.contents_utf8()
}
