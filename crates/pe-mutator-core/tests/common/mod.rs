use std::path::PathBuf;

pub fn sample_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("pes")
        .join(name)
}
