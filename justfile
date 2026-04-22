# wgnat build recipes. Run `just` with no args to list them.

set shell := ["bash", "-c"]

# List available recipes.
default:
    @just --list

# Debug build.
build:
    cargo build

# Release build with tracing intact. Optionally bake a config into the binary.
#   just release                 -> target/release/wgnat(.exe), reads --config at runtime
#   just release ./deploy.conf   -> self-contained, --config no longer required
release CONFIG="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "{{CONFIG}}" ]; then
        WGNAT_EMBEDDED_CONFIG="{{CONFIG}}" cargo build --release --features embedded-config
    else
        cargo build --release
    fi

# Absolute minimum-size deploy binary: release_max_level_off compiles every
# tracing event out, `[profile.min]` size-optimizes + strips + aborts on panic.
#   just min                     -> target/min/wgnat(.exe), silent, --config at runtime
#   just min ./deploy.conf       -> silent + self-contained
min CONFIG="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "{{CONFIG}}" ]; then
        WGNAT_EMBEDDED_CONFIG="{{CONFIG}}" cargo build --profile min --features embedded-config,silent
    else
        cargo build --profile min --features silent
    fi

# Run the debug binary. Pass args through (e.g. `just run run --config ./wgnat.conf`).
run *ARGS:
    cargo run -- {{ARGS}}

test:
    cargo test

clippy:
    cargo clippy --all-targets -- -D warnings

check:
    cargo check --all-targets

fmt:
    cargo fmt

clean:
    cargo clean

# Show sizes of any wgnat binaries that have been built.
size:
    #!/usr/bin/env bash
    for p in target/debug/wgnat target/debug/wgnat.exe \
             target/release/wgnat target/release/wgnat.exe \
             target/min/wgnat target/min/wgnat.exe; do
        [ -f "$p" ] && ls -la "$p"
    done
