# burrow build recipes. Run `just` with no args to list them.

set shell := ["bash", "-c"]

# List available recipes.
default:
    @just --list

# Debug build of both binaries.
build:
    cargo build

# Release build with tracing intact. Optionally bake a config into the binary.
#   just release                 -> target/release/burrow(.exe), reads --config at runtime
#   just release ./deploy.conf   -> self-contained, --config no longer required
release CONFIG="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "{{CONFIG}}" ]; then
        BURROW_EMBEDDED_CONFIG="{{CONFIG}}" cargo build --release --features embedded-config
    else
        cargo build --release
    fi

# Minimum-size deploy binary with tracing compiled out (the `silent` feature
# sets release_max_level_off) and the `min` profile (opt-level=z, LTO,
# stripped symbols, panic=abort).
#   just min                     -> target/min/burrow(.exe), silent, --config at runtime
#   just min ./deploy.conf       -> silent + self-contained
min CONFIG="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "{{CONFIG}}" ]; then
        BURROW_EMBEDDED_CONFIG="{{CONFIG}}" cargo build --profile min --features embedded-config,silent
    else
        cargo build --profile min --features silent
    fi

# Deploy convenience: min-sized + silent + config embedded. CONFIG is required.
# The PrivateKey ends up in the binary's read-only data segment; anyone with
# read access to the file can extract it via `strings`, so do not share the
# resulting binary with anyone you would not trust with the original .conf.
#   just embed ./deploy.conf     -> target/min/burrow(.exe), self-contained
embed CONFIG:
    @just min {{CONFIG}}

# Run the debug binary. Pass args through (e.g. `just run run --config ./burrow.conf`).
run *ARGS:
    cargo run -- {{ARGS}}

# Full test suite (lib + integration).
test:
    cargo test

# Lint, fail on any warning.
clippy:
    cargo clippy --all-targets -- -D warnings

check:
    cargo check --all-targets

fmt:
    cargo fmt

clean:
    cargo clean

# Show sizes of any burrow binaries that have been built.
size:
    #!/usr/bin/env bash
    for p in target/debug/burrow target/debug/burrow.exe \
             target/release/burrow target/release/burrow.exe \
             target/min/burrow target/min/burrow.exe; do
        [ -f "$p" ] && ls -la "$p"
    done
