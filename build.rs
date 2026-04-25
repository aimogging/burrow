use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    embed_burrow_config();
    embed_relay_bundle();
}

fn embed_burrow_config() {
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

fn embed_relay_bundle() {
    let env_vars = [
        "BURROW_RELAY_EMBED_TOKEN",
        "BURROW_RELAY_EMBED_CERT_FILE",
        "BURROW_RELAY_EMBED_KEY_FILE",
        "BURROW_RELAY_EMBED_LISTEN",
        "BURROW_RELAY_EMBED_FORWARD",
    ];
    for v in env_vars {
        println!("cargo:rerun-if-env-changed={v}");
    }

    if env::var_os("CARGO_FEATURE_EMBEDDED_RELAY_BUNDLE").is_none() {
        return;
    }

    let token = env::var("BURROW_RELAY_EMBED_TOKEN").expect(
        "feature `embedded-relay-bundle` is enabled but BURROW_RELAY_EMBED_TOKEN is not set",
    );
    let cert_path = env::var("BURROW_RELAY_EMBED_CERT_FILE").expect(
        "feature `embedded-relay-bundle` is enabled but BURROW_RELAY_EMBED_CERT_FILE is not set",
    );
    let key_path = env::var("BURROW_RELAY_EMBED_KEY_FILE").expect(
        "feature `embedded-relay-bundle` is enabled but BURROW_RELAY_EMBED_KEY_FILE is not set",
    );
    println!("cargo:rerun-if-changed={cert_path}");
    println!("cargo:rerun-if-changed={key_path}");

    let listen = env::var("BURROW_RELAY_EMBED_LISTEN").unwrap_or_else(|_| "0.0.0.0:443".into());
    let forward = env::var("BURROW_RELAY_EMBED_FORWARD")
        .unwrap_or_else(|_| "127.0.0.1:51820".into());

    let cert_pem = fs::read_to_string(&cert_path)
        .unwrap_or_else(|e| panic!("failed to read BURROW_RELAY_EMBED_CERT_FILE ({cert_path}): {e}"));
    let key_pem = fs::read_to_string(&key_path)
        .unwrap_or_else(|e| panic!("failed to read BURROW_RELAY_EMBED_KEY_FILE ({key_path}): {e}"));

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR set by cargo"));
    let dest = out_dir.join("embedded_relay_bundle.rs");
    let body = format!(
        "pub const RELAY_TOKEN: &str = {token:?};\n\
         pub const RELAY_CERT_PEM: &str = {cert_pem:?};\n\
         pub const RELAY_KEY_PEM: &str = {key_pem:?};\n\
         pub const RELAY_LISTEN: &str = {listen:?};\n\
         pub const RELAY_FORWARD: &str = {forward:?};\n"
    );
    fs::write(&dest, body).unwrap_or_else(|e| panic!("write {}: {e}", dest.display()));
}
