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

# WSS pair builds three binaries for potentially three different OSes:
# burrow runs wherever the gateway lives (often Windows on a dev box),
# burrow-relay + burrow-client almost always Linux. The defaults
# reflect that — only BURROW_TARGET is mandatory; override the others
# only if your relay/client hosts aren't 64-bit Linux.
relay_target := env_var_or_default("BURROW_RELAY_TARGET", "x86_64-unknown-linux-gnu")
client_target := env_var_or_default("BURROW_CLIENT_TARGET", "x86_64-unknown-linux-gnu")

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
#
# Computes RUSTFLAGS with `--remap-path-prefix` entries so that source
# paths embedded in panic strings (from `unwrap`/`expect`/`assert!` in
# any crate) don't leak the build user's home dir, the cargo registry
# hash, or the working-directory layout. `cargo` and `deps` and `src`
# replace the real prefixes.
[unix]
embed CONFIG TARGET=target:
    #!/usr/bin/env bash
    set -eu
    cargo_home="${CARGO_HOME:-$HOME/.cargo}"
    rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
    repo="$(pwd)"
    registry_src="$(find "$cargo_home/registry/src" -maxdepth 1 -type d -name 'index.crates.io-*' 2>/dev/null | head -1)"
    remap="--remap-path-prefix=$repo=src --remap-path-prefix=$cargo_home=cargo --remap-path-prefix=$rustup_home=rustup"
    if [ -n "$registry_src" ]; then
        remap="$remap --remap-path-prefix=$registry_src=deps"
    fi
    target_flag=""
    if [ -n "{{TARGET}}" ]; then
        target_flag="--target {{TARGET}}"
    fi
    BURROW_EMBEDDED_CONFIG="$(realpath '{{CONFIG}}')" RUSTFLAGS="$remap" \
        cargo build --bin burrow --profile min \
        --features embedded-config,silent $target_flag
    RUSTFLAGS="$remap" \
        cargo build --bin burrow-client --profile min --features silent $target_flag

# Min-sized silent burrow with CONFIG embedded, plus matching burrow-client.
[windows]
embed CONFIG TARGET=target:
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { "$env:USERPROFILE\.cargo" }; \
    $rustupHome = if ($env:RUSTUP_HOME) { $env:RUSTUP_HOME } else { "$env:USERPROFILE\.rustup" }; \
    $repo = (Get-Location).Path; \
    $registrySrc = (Get-ChildItem "$cargoHome\registry\src" -Directory -Filter 'index.crates.io-*' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName; \
    $remap = "--remap-path-prefix=$repo=src --remap-path-prefix=$cargoHome=cargo --remap-path-prefix=$rustupHome=rustup"; \
    if ($registrySrc) { $remap = "$remap --remap-path-prefix=$registrySrc=deps" }; \
    $env:RUSTFLAGS = $remap; \
    $env:BURROW_EMBEDDED_CONFIG = (Resolve-Path '{{CONFIG}}').Path; \
    $t = if ('{{TARGET}}' -eq '') { @() } else { @('--target','{{TARGET}}') }; \
    cargo build --bin burrow --profile min --features embedded-config,silent @t; \
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; \
    cargo build --bin burrow-client --profile min --features silent @t

# Generate the config trio AND build min-sized binaries in one step.
gen-embed *GEN_ARGS:
    cargo run --release --bin burrow-client -- gen {{GEN_ARGS}} --out ./burrow-configs
    @just embed ./burrow-configs/burrow.conf {{target}}

# Min-sized silent burrow + burrow-relay + burrow-client trio with their
# respective configs/materials embedded. Each binary builds for its own
# target triple — typically the gateway runs on a different OS from the
# relay/client. Targets:
#   GW_TARGET      = $BURROW_TARGET                — REQUIRED, no default.
#   RELAY_TARGET   = $BURROW_RELAY_TARGET          — defaults to x86_64-unknown-linux-gnu.
#   CLIENT_TARGET  = $BURROW_CLIENT_TARGET         — defaults to x86_64-unknown-linux-gnu.
# Cross-compile toolchains must already be installed (rustup target add
# <triple>, plus a matching linker — `cross` works as a drop-in cargo if
# you don't want to set it up by hand).
[unix]
embed-wss-pair CONFIG BUNDLE_DIR GW_TARGET=target RELAY_TARGET=relay_target CLIENT_TARGET=client_target:
    #!/usr/bin/env bash
    set -eu
    if [ -z "{{GW_TARGET}}" ]; then
        echo "embed-wss-pair: BURROW_TARGET must be set (target triple for the burrow gateway)." >&2
        echo "  Common values:" >&2
        echo "    x86_64-pc-windows-msvc      Windows 10/11 (MSVC)" >&2
        echo "    x86_64-pc-windows-gnu       Windows 10/11 (mingw)" >&2
        echo "    x86_64-unknown-linux-gnu    Linux x86_64 glibc" >&2
        echo "    aarch64-apple-darwin        macOS Apple Silicon" >&2
        echo "  BURROW_RELAY_TARGET / BURROW_CLIENT_TARGET default to x86_64-unknown-linux-gnu." >&2
        exit 2
    fi
    if [ ! -f "{{BUNDLE_DIR}}/cert.pem" ] || [ ! -f "{{BUNDLE_DIR}}/key.pem" ] || [ ! -f "{{BUNDLE_DIR}}/token.txt" ]; then
        echo "embed-wss-pair: {{BUNDLE_DIR}} is missing cert.pem / key.pem / token.txt." >&2
        echo "  Run \`burrow-client gen --relay HOST[:PORT] ...\` first, or use" >&2
        echo "  \`just gen-embed-wss --relay HOST[:PORT] ...\` to do both in one shot." >&2
        exit 2
    fi
    cargo_home="${CARGO_HOME:-$HOME/.cargo}"
    rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
    repo="$(pwd)"
    registry_src="$(find "$cargo_home/registry/src" -maxdepth 1 -type d -name 'index.crates.io-*' 2>/dev/null | head -1)"
    remap="--remap-path-prefix=$repo=src --remap-path-prefix=$cargo_home=cargo --remap-path-prefix=$rustup_home=rustup"
    if [ -n "$registry_src" ]; then
        remap="$remap --remap-path-prefix=$registry_src=deps"
    fi
    bundle="$(realpath '{{BUNDLE_DIR}}')"
    BURROW_EMBEDDED_CONFIG="$(realpath '{{CONFIG}}')" RUSTFLAGS="$remap" \
        cargo build --bin burrow --profile min --features embedded-config,silent --target {{GW_TARGET}}
    BURROW_RELAY_EMBED_TOKEN="$(cat "$bundle/token.txt" | tr -d '\n')" \
    BURROW_RELAY_EMBED_CERT_FILE="$bundle/cert.pem" \
    BURROW_RELAY_EMBED_KEY_FILE="$bundle/key.pem" \
    BURROW_RELAY_EMBED_LISTEN="$(cat "$bundle/listen.txt" | tr -d '\n')" \
    BURROW_RELAY_EMBED_FORWARD="$(cat "$bundle/forward.txt" | tr -d '\n')" \
    RUSTFLAGS="$remap" \
        cargo build --bin burrow-relay --profile min --features embedded-relay-bundle,silent --target {{RELAY_TARGET}}
    RUSTFLAGS="$remap" \
        cargo build --bin burrow-client --profile min --features silent --target {{CLIENT_TARGET}}
    # Collect each binary from its own per-target output dir into the
    # bundle. Match unix and .exe forms so any combination of targets
    # ends up with the right artifacts.
    for spec in "burrow:{{GW_TARGET}}" "burrow-relay:{{RELAY_TARGET}}" "burrow-client:{{CLIENT_TARGET}}"; do
        bin="${spec%:*}"
        tgt="${spec#*:}"
        for variant in "$bin" "$bin.exe"; do
            if [ -f "target/$tgt/min/$variant" ]; then
                cp -f "target/$tgt/min/$variant" "$bundle/$variant"
            fi
        done
    done

[windows]
embed-wss-pair CONFIG BUNDLE_DIR GW_TARGET=target RELAY_TARGET=relay_target CLIENT_TARGET=client_target:
    if ('{{GW_TARGET}}' -eq '') { \
        Write-Error "embed-wss-pair: BURROW_TARGET must be set (e.g. x86_64-pc-windows-msvc, x86_64-unknown-linux-gnu). BURROW_RELAY_TARGET / BURROW_CLIENT_TARGET default to x86_64-unknown-linux-gnu."; \
        exit 2 \
    }; \
    if (-not ((Test-Path '{{BUNDLE_DIR}}\cert.pem') -and (Test-Path '{{BUNDLE_DIR}}\key.pem') -and (Test-Path '{{BUNDLE_DIR}}\token.txt'))) { \
        Write-Error "embed-wss-pair: {{BUNDLE_DIR}} is missing cert.pem / key.pem / token.txt. Run ``burrow-client gen --relay HOST[:PORT] ...`` first, or use ``just gen-embed-wss --relay HOST[:PORT] ...`` to do both in one shot."; \
        exit 2 \
    }; \
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { "$env:USERPROFILE\.cargo" }; \
    $rustupHome = if ($env:RUSTUP_HOME) { $env:RUSTUP_HOME } else { "$env:USERPROFILE\.rustup" }; \
    $repo = (Get-Location).Path; \
    $registrySrc = (Get-ChildItem "$cargoHome\registry\src" -Directory -Filter 'index.crates.io-*' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName; \
    $remap = "--remap-path-prefix=$repo=src --remap-path-prefix=$cargoHome=cargo --remap-path-prefix=$rustupHome=rustup"; \
    if ($registrySrc) { $remap = "$remap --remap-path-prefix=$registrySrc=deps" }; \
    $env:RUSTFLAGS = $remap; \
    $env:BURROW_EMBEDDED_CONFIG = (Resolve-Path '{{CONFIG}}').Path; \
    cargo build --bin burrow --profile min --features embedded-config,silent --target '{{GW_TARGET}}'; \
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; \
    $bundle = (Resolve-Path '{{BUNDLE_DIR}}').Path; \
    $env:BURROW_RELAY_EMBED_TOKEN = (Get-Content "$bundle\token.txt" -Raw).Trim(); \
    $env:BURROW_RELAY_EMBED_CERT_FILE = "$bundle\cert.pem"; \
    $env:BURROW_RELAY_EMBED_KEY_FILE = "$bundle\key.pem"; \
    $env:BURROW_RELAY_EMBED_LISTEN = (Get-Content "$bundle\listen.txt" -Raw).Trim(); \
    $env:BURROW_RELAY_EMBED_FORWARD = (Get-Content "$bundle\forward.txt" -Raw).Trim(); \
    cargo build --bin burrow-relay --profile min --features embedded-relay-bundle,silent --target '{{RELAY_TARGET}}'; \
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; \
    cargo build --bin burrow-client --profile min --features silent --target '{{CLIENT_TARGET}}'; \
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; \
    foreach ($spec in @{bin='burrow';tgt='{{GW_TARGET}}'}, @{bin='burrow-relay';tgt='{{RELAY_TARGET}}'}, @{bin='burrow-client';tgt='{{CLIENT_TARGET}}'}) { \
        foreach ($variant in $spec.bin, "$($spec.bin).exe") { \
            $src = "target\$($spec.tgt)\min\$variant"; \
            if (Test-Path $src) { Copy-Item -Force $src "$bundle\$variant" } \
        } \
    }

# Generate the WSS deployment package + build the paired binaries.
# Pass through the same gen args (--endpoint, --routes, --dns, ...) plus
# --relay HOST[:PORT]. End result: target/<triple>/min/{burrow,burrow-relay,
# burrow-client} (collected into burrow-configs/relay-bundle/) plus the
# wg server.conf + clientN.conf. --relay is required (use `just gen-embed`
# for the UDP-only path); failing fast saves a doomed cargo invocation.
#
# Targets read from BURROW_TARGET / BURROW_RELAY_TARGET / BURROW_CLIENT_TARGET.
# BURROW_TARGET is required. The other two default to x86_64-unknown-linux-gnu.
[unix]
gen-embed-wss *GEN_ARGS:
    #!/usr/bin/env bash
    set -eu
    if [ -z "{{target}}" ]; then
        echo "gen-embed-wss: BURROW_TARGET must be set (target triple for the burrow gateway)." >&2
        echo "  e.g.: BURROW_TARGET=x86_64-pc-windows-msvc just gen-embed-wss --endpoint ..." >&2
        echo "  BURROW_RELAY_TARGET / BURROW_CLIENT_TARGET default to x86_64-unknown-linux-gnu." >&2
        exit 2
    fi
    if ! printf ' %s ' {{GEN_ARGS}} | grep -q -- ' --relay '; then
        echo "gen-embed-wss requires --relay HOST[:PORT] in the gen args." >&2
        echo "  (Use 'just gen-embed' for the UDP-only path.)" >&2
        exit 2
    fi
    cargo run --release --bin burrow-client -- gen {{GEN_ARGS}} --out ./burrow-configs
    just embed-wss-pair ./burrow-configs/burrow.conf ./burrow-configs/relay-bundle

[windows]
gen-embed-wss *GEN_ARGS:
    if ('{{target}}' -eq '') { \
        Write-Error "gen-embed-wss: BURROW_TARGET must be set (e.g. x86_64-pc-windows-msvc, x86_64-unknown-linux-gnu). BURROW_RELAY_TARGET / BURROW_CLIENT_TARGET default to x86_64-unknown-linux-gnu."; \
        exit 2 \
    }; \
    if ('{{GEN_ARGS}}' -notmatch '(^|\s)--relay(\s|$)') { \
        Write-Error "gen-embed-wss requires --relay HOST[:PORT] in the gen args. (Use 'just gen-embed' for the UDP-only path.)"; \
        exit 2 \
    }; \
    cargo run --release --bin burrow-client -- gen {{GEN_ARGS}} --out ./burrow-configs; \
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; \
    just embed-wss-pair ./burrow-configs/burrow.conf ./burrow-configs/relay-bundle

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

# Bring a WG server up inside a netns. Local by default; --target for remote.
deploy-server *ARGS:
    bash scripts/deploy-server.sh {{ARGS}}

# Bring a WG client up inside a netns. Local by default; --target for remote.
deploy-client *ARGS:
    bash scripts/deploy-client.sh {{ARGS}}

# Drop into an interactive shell inside the burrow netns. Local by default.
netns-shell *ARGS:
    bash scripts/netns-shell.sh {{ARGS}}

# Ship a pre-built burrow-relay to the WG server box and (re)start it.
# Pass --target user@host. See `bash scripts/deploy-relay.sh --help`.
deploy-relay *ARGS:
    bash scripts/deploy-relay.sh {{ARGS}}

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
