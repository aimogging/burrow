#!/usr/bin/env bash
# Ship a pre-built burrow-relay to the WG server box, drop the systemd
# unit, restart. The script does not provision certs or the bearer
# token — those go into /etc/burrow-relay/ on the target ahead of time
# (see README).
#
# Usage:
#   just deploy-relay --target root@vpn.example.com [--key ~/.ssh/id_ed25519]
#                     [--binary target/release/burrow-relay]
#
# The remote box must already have systemd. Designed for the typical
# WG-server box: a small Linux VPS that's also running kernel wg0.

set -euo pipefail

DEFAULT_BINARY="target/release/burrow-relay"
DEFAULT_UNIT="scripts/burrow-relay.service"

TARGET=""
KEY=""
BINARY="$DEFAULT_BINARY"
UNIT="$DEFAULT_UNIT"
TEARDOWN=0

usage() {
    cat <<EOF
Usage: $(basename "$0") --target HOST [options]

Required:
  --target HOST          ssh-style host (user@host or just host)

Options:
  --key PATH             ssh identity file (defaults to ssh's own resolution)
  --binary PATH          local path to the burrow-relay binary
                         (default: $DEFAULT_BINARY — build with \`cargo build --release\`)
  --unit PATH            local path to the systemd unit template
                         (default: $DEFAULT_UNIT)
  --teardown             stop + disable the service, remove binary + unit
  -h, --help             this help

Before first run, populate the target with:
  /etc/burrow-relay/fullchain.pem    public cert chain (PEM)
  /etc/burrow-relay/privkey.pem      private key (PEM)
  /etc/burrow-relay/env              one line: BURROW_RELAY_TOKEN=<token>
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --target)    TARGET="$2"; shift 2;;
        --key)       KEY="$2"; shift 2;;
        --binary)    BINARY="$2"; shift 2;;
        --unit)      UNIT="$2"; shift 2;;
        --teardown)  TEARDOWN=1; shift;;
        -h|--help)   usage; exit 0;;
        *) echo "unknown arg: $1" >&2; usage >&2; exit 1;;
    esac
done

if [ -z "$TARGET" ]; then
    echo "--target is required" >&2
    usage >&2
    exit 1
fi

ssh_args=()
scp_args=()
if [ -n "$KEY" ]; then
    ssh_args+=(-i "$KEY")
    scp_args+=(-i "$KEY")
fi

ssh_run() {
    ssh "${ssh_args[@]}" "$TARGET" "$@"
}

if [ "$TEARDOWN" = 1 ]; then
    ssh_run 'sudo systemctl disable --now burrow-relay.service 2>/dev/null || true; \
             sudo rm -f /etc/systemd/system/burrow-relay.service /usr/local/bin/burrow-relay; \
             sudo systemctl daemon-reload'
    echo "burrow-relay torn down on $TARGET (cert/key/env files left in /etc/burrow-relay)"
    exit 0
fi

if [ ! -f "$BINARY" ]; then
    echo "binary not found at $BINARY — build it first:" >&2
    echo "  cargo build --release --bin burrow-relay" >&2
    echo "  # or for a Linux remote from a non-Linux host:" >&2
    echo "  cargo build --release --bin burrow-relay --target x86_64-unknown-linux-gnu" >&2
    exit 1
fi
if [ ! -f "$UNIT" ]; then
    echo "unit file not found at $UNIT" >&2
    exit 1
fi

echo "shipping $BINARY → $TARGET:/usr/local/bin/burrow-relay"
scp "${scp_args[@]}" "$BINARY" "$TARGET:/tmp/burrow-relay.new"
scp "${scp_args[@]}" "$UNIT" "$TARGET:/tmp/burrow-relay.service"

ssh_run 'set -e; \
    sudo install -m 0755 /tmp/burrow-relay.new /usr/local/bin/burrow-relay; \
    sudo install -m 0644 /tmp/burrow-relay.service /etc/systemd/system/burrow-relay.service; \
    rm -f /tmp/burrow-relay.new /tmp/burrow-relay.service; \
    sudo mkdir -p /etc/burrow-relay; \
    sudo systemctl daemon-reload; \
    if [ -f /etc/burrow-relay/fullchain.pem ] && \
       [ -f /etc/burrow-relay/privkey.pem ] && \
       [ -f /etc/burrow-relay/env ]; then \
        sudo systemctl enable --now burrow-relay.service; \
        sudo systemctl status burrow-relay.service --no-pager || true; \
    else \
        echo; \
        echo "burrow-relay installed but NOT started — populate /etc/burrow-relay/ first:"; \
        echo "  fullchain.pem, privkey.pem, env (BURROW_RELAY_TOKEN=...)"; \
        echo "then: sudo systemctl enable --now burrow-relay.service"; \
    fi'
