# burrow build recipes.
#
# Install just: https://github.com/casey/just
#   - Windows:  winget install Casey.Just  (or scoop install just)
#   - Linux:    cargo install just  (or your package manager)
#   - macOS:    brew install just
#
# Cross-compilation requires the target toolchain to be installed:
#   rustup target add <triple>
# and a suitable linker. Common targets:
#   x86_64-unknown-linux-musl   static linux, no libc dep (needs `cross` or musl-gcc)
#   x86_64-unknown-linux-gnu    dynamic linux
#   x86_64-pc-windows-msvc      windows (native on Windows hosts)
#   x86_64-pc-windows-gnu       windows (mingw-w64)
#   aarch64-apple-darwin        apple silicon macOS
#
# For anything non-native, `cargo install cross` is the path of least
# resistance — it runs the build inside a prepared Docker image. Then
# swap `cargo` for `cross` in the commands below.

# List available recipes.
default:
    @just --list

# Debug build. Optional TARGET triple for cross-compile.
build TARGET="":
    cargo build {{ if TARGET == "" { "" } else { "--target " + TARGET } }}

# Release build with tracing intact. Optional TARGET triple.
release TARGET="":
    cargo build --release {{ if TARGET == "" { "" } else { "--target " + TARGET } }}

# Min-sized deploy binary: `silent` feature compiles out all tracing,
# the `min` profile does opt-level=z, LTO, strip, panic=abort. Both
# CONFIG (embed a .conf) and TARGET (cross-compile) are optional.
#   just min                                   host, no embed
#   just min ./deploy.conf                     host, config embedded
#   just min "" x86_64-unknown-linux-musl      cross, no embed
#   just min ./deploy.conf x86_64-pc-windows-msvc
#                                              cross, config embedded
[unix]
min CONFIG="" TARGET="":
    #!/usr/bin/env bash
    set -eu
    args=(build --profile min)
    features=silent
    if [ -n "{{CONFIG}}" ]; then
        export BURROW_EMBEDDED_CONFIG="$(realpath '{{CONFIG}}')"
        features="silent,embedded-config"
    fi
    args+=(--features "$features")
    if [ -n "{{TARGET}}" ]; then
        args+=(--target '{{TARGET}}')
    fi
    cargo "${args[@]}"

[windows]
min CONFIG="" TARGET="":
    #!pwsh
    $ErrorActionPreference = 'Stop'
    $features = 'silent'
    if ('{{CONFIG}}' -ne '') {
        $env:BURROW_EMBEDDED_CONFIG = (Resolve-Path '{{CONFIG}}').Path
        $features = 'silent,embedded-config'
    }
    $cargoArgs = @('build', '--profile', 'min', '--features', $features)
    if ('{{TARGET}}' -ne '') {
        $cargoArgs += @('--target', '{{TARGET}}')
    }
    & cargo @cargoArgs

# Shorthand: `just min CONFIG TARGET` with CONFIG required. Produces a
# self-contained min-sized silent binary. The PrivateKey ends up in the
# read-only data segment — anyone with read access can extract it via
# `strings`, so do not share the binary with anyone you would not trust
# with the original .conf.
embed CONFIG TARGET="":
    @just min {{CONFIG}} {{TARGET}}

# Generate the full config trio AND embed the resulting burrow.conf into
# a min-sized silent binary. Gen args pass through verbatim; --out is
# pinned to ./burrow-configs so `embed` knows where to find burrow.conf.
# Uses the host target — for cross-compile, split into `just gen ...`
# followed by `just embed ./burrow-configs/burrow.conf <TARGET>`.
#
#   just gen-embed --endpoint vpn.example:51820 --routes 192.168.1.0/24
#   just gen-embed --endpoint vpn.example:51820 \
#       --routes 10.50.0.0/24 --dns 10.0.0.2 --clients 3
gen-embed *GEN_ARGS:
    cargo run --release -- gen {{GEN_ARGS}} --out ./burrow-configs
    @just embed ./burrow-configs/burrow.conf

# Passthrough to `burrow gen`.
#   just gen --endpoint vpn.example:51820 --routes 192.168.1.0/24
gen *ARGS:
    cargo run --release -- gen {{ARGS}}

# Run the debug binary with args passed through.
run *ARGS:
    cargo run -- {{ARGS}}

# Full test suite (lib + integration).
test:
    cargo test

# Lint; fail on any warning.
clippy:
    cargo clippy --all-targets -- -D warnings

# Quick compile check of everything.
check:
    cargo check --all-targets

# Format.
fmt:
    cargo fmt

# Wipe build artifacts.
clean:
    cargo clean

# List sizes of built burrow binaries across all profiles and targets.
[unix]
size:
    #!/usr/bin/env bash
    find target -type f \( -name burrow -o -name burrow.exe \) -not -path '*/deps/*' 2>/dev/null \
      | xargs -I {} sh -c 'printf "%10d  %s\n" "$(stat -c%s "{}" 2>/dev/null || stat -f%z "{}")" "{}"'

[windows]
size:
    #!pwsh
    Get-ChildItem -Path target -Recurse -File -Include burrow, burrow.exe `
      | Where-Object { $_.FullName -notmatch '[\\/]deps[\\/]' } `
      | ForEach-Object { '{0,10}  {1}' -f $_.Length, $_.FullName }
