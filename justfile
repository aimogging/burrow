# burrow build recipes.
#
# Install just:
#   Windows:  winget install Casey.Just  (or: scoop install just)
#   Linux:    your package manager, or `cargo install just`
#   macOS:    brew install just
#
# `set windows-shell` makes recipes run via powershell.exe (5.1, ships
# with every Windows). Without it just defaults to `sh`, which most
# Windows installs do not have on PATH.
#
# Cross-compile by either passing TARGET as a positional argument
# (`just embed deploy.conf x86_64-unknown-linux-musl`) or by exporting
# `BURROW_TARGET` once for the session
# (`$env:BURROW_TARGET = "x86_64-unknown-linux-musl"`). Recipes default
# their TARGET parameter to that env var.
#
# Cross-compilation requires the toolchain (`rustup target add <triple>`)
# and a working linker. Common triples:
#   x86_64-unknown-linux-musl   static linux
#   x86_64-unknown-linux-gnu    dynamic linux
#   x86_64-pc-windows-msvc      windows (native on Windows hosts)
#   x86_64-pc-windows-gnu       windows (mingw-w64)
#   aarch64-apple-darwin        apple silicon macOS
# For non-native targets the smoothest path is `cargo install cross` and
# substituting `cross` for `cargo` in the recipes.
#
# `embed` caveat: the PrivateKey ends up in the gateway binary's
# read-only data segment; anyone with read access can extract it via
# `strings`, do not share the binary with anyone you would not trust
# with the original .conf.

set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

target := env_var_or_default("BURROW_TARGET", "")

# List recipes.
default:
    @just --list

# Debug build of both binaries. Optional TARGET triple for cross-compile.
build TARGET=target:
    cargo build {{ if TARGET == "" { "" } else { "--target " + TARGET } }}

# Release build of both binaries. Optional TARGET triple.
release TARGET=target:
    cargo build --release {{ if TARGET == "" { "" } else { "--target " + TARGET } }}

# Min-sized silent burrow with CONFIG embedded, plus matching burrow-client.
[unix]
embed CONFIG TARGET=target:
    #!/usr/bin/env bash
    set -eu
    target_flag=""
    if [ -n "{{TARGET}}" ]; then
        target_flag="--target {{TARGET}}"
    fi
    BURROW_EMBEDDED_CONFIG="$(realpath '{{CONFIG}}')" \
        cargo build --bin burrow --profile min \
        --features embedded-config,silent $target_flag
    cargo build --bin burrow-client --profile min --features silent $target_flag

# Min-sized silent burrow with CONFIG embedded, plus matching burrow-client.
[windows]
embed CONFIG TARGET=target:
    $env:BURROW_EMBEDDED_CONFIG = (Resolve-Path '{{CONFIG}}').Path; \
    $t = if ('{{TARGET}}' -eq '') { @() } else { @('--target','{{TARGET}}') }; \
    cargo build --bin burrow --profile min --features embedded-config,silent @t; \
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; \
    cargo build --bin burrow-client --profile min --features silent @t

# Generate the config trio AND build min-sized binaries in one step.
gen-embed *GEN_ARGS:
    cargo run --release --bin burrow-client -- gen {{GEN_ARGS}} --out ./burrow-configs
    @just embed ./burrow-configs/burrow.conf

# Passthrough to `burrow-client gen`. Same args as the binary's gen subcommand.
gen *ARGS:
    cargo run --release --bin burrow-client -- gen {{ARGS}}

# Run the debug burrow binary with args passed through.
run *ARGS:
    cargo run --bin burrow -- {{ARGS}}

# Run the debug burrow-client binary with args passed through.
run-client *ARGS:
    cargo run --bin burrow-client -- {{ARGS}}

# Full test suite (lib + integration).
test:
    cargo test

# Lint; fail on any warning.
clippy:
    cargo clippy --all-targets -- -D warnings

# Quick compile check of everything.
check:
    cargo check --all-targets

# Format the codebase.
fmt:
    cargo fmt

# Wipe build artifacts.
clean:
    cargo clean

# List sizes of built burrow / burrow-client binaries across profiles.
[unix]
size:
    #!/usr/bin/env bash
    find target -type f \
        \( -name burrow -o -name burrow.exe -o -name burrow-client -o -name burrow-client.exe \) \
        -not -path '*/deps/*' 2>/dev/null \
      | xargs -I {} sh -c 'printf "%10d  %s\n" "$(stat -c%s "{}" 2>/dev/null || stat -f%z "{}")" "{}"'

# List sizes of built burrow / burrow-client binaries across profiles.
[windows]
size:
    Get-ChildItem -Path target -Recurse -File -Include burrow.exe,burrow-client.exe \
    | Where-Object { $_.FullName -notmatch '[\\/]deps[\\/]' } \
    | ForEach-Object { '{0,12}  {1}' -f $_.Length, $_.FullName }
