# burrow dev-loop recipes. Build/configure/deploy lives in `burrowctl`
# (driven by `deployments/<name>/spec.toml`); these recipes are just
# the thin everyday convenience layer.
#
# Install just:
#   Windows:  winget install Casey.Just  (or: scoop install just)
#   Linux:    your package manager, or `cargo install just`
#   macOS:    brew install just

set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

# List recipes.
default:
    @just --list

# Debug build of every binary.
build:
    cargo build

# Release build of every binary.
release:
    cargo build --release

# Run the debug burrow binary with args passed through.
run *ARGS:
    cargo run --bin burrow -- {{ARGS}}

# Run the debug burrow-client binary with args passed through.
run-client *ARGS:
    cargo run --bin burrow-client -- {{ARGS}}

# Run burrowctl with args passed through. e.g. `just ctl up dev`.
ctl *ARGS:
    cargo run --release --bin burrowctl -- {{ARGS}}

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

# List sizes of built burrow / burrow-client / burrow-relay binaries
# across profiles + per-target output dirs.
[unix]
size:
    #!/usr/bin/env bash
    find target -type f \
        \( -name burrow -o -name burrow.exe \
        -o -name burrow-client -o -name burrow-client.exe \
        -o -name burrow-relay -o -name burrow-relay.exe \) \
        -not -path '*/deps/*' 2>/dev/null \
      | xargs -I {} sh -c 'printf "%10d  %s\n" "$(stat -c%s "{}" 2>/dev/null || stat -f%z "{}")" "{}"'

[windows]
size:
    Get-ChildItem -Path target -Recurse -File -Include burrow.exe,burrow-client.exe,burrow-relay.exe \
    | Where-Object { $_.FullName -notmatch '[\\/]deps[\\/]' } \
    | ForEach-Object { '{0,12}  {1}' -f $_.Length, $_.FullName }
