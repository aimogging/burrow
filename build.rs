use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=BURROW_EMBEDDED_CONFIG");

    if env::var_os("CARGO_FEATURE_EMBEDDED_CONFIG").is_none() {
        return;
    }

    let path = env::var("BURROW_EMBEDDED_CONFIG").expect(
        "feature `embedded-config` is enabled but BURROW_EMBEDDED_CONFIG is not set; \
         e.g. BURROW_EMBEDDED_CONFIG=./deploy.conf cargo build --features embedded-config",
    );
    println!("cargo:rerun-if-changed={path}");

    let contents = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read BURROW_EMBEDDED_CONFIG ({path}): {e}"));

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR set by cargo"));
    let dest = out_dir.join("embedded_config.rs");
    let body = format!("pub const EMBEDDED_CONFIG: &str = {contents:?};\n");
    fs::write(&dest, body).unwrap_or_else(|e| panic!("write {}: {e}", dest.display()));
}
