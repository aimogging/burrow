#!/usr/bin/env bash
# Bring up a WireGuard server on a Linux host inside a network
# namespace. Defaults to LOCAL execution (sudo on this box); pass
# --target HOST to drive a remote box over SSH instead. Ephemeral:
# no systemd unit, no /etc/wireguard, state dies with the namespace
# (or the next reboot).
#
# WG UDP socket lives in the host (default) netns so peers can reach
# it from the public internet; the wg interface lives in the target
# netns. Pattern: https://www.wireguard.com/netns/.
#
# Auto-relay: if `<config_dir>/relay-bundle/` exists alongside
# server.conf — meaning the configs came from `gen-embed-wss` —
# this script also ships `target/min/burrow-relay` to the remote and
# starts it. The relay sends to 127.0.0.1:51820, which lands on the
# WG UDP socket living in the host netns (where the relay also
# runs), so no extra plumbing is needed to reach kernel WG.

set -euo pipefail

DEFAULT_CONFIG="burrow-configs/server.conf"
DEFAULT_RELAY_BIN="burrow-configs/relay-bundle/burrow-relay"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_deploy_common.sh
source "$SCRIPT_DIR/_deploy_common.sh"

usage() {
    cat <<EOF
Usage: $(basename "$0") [--config PATH] [--target TARGET] [auth] [options]

Brings up a WireGuard server on a Linux host inside a network
namespace. Local by default — pass --target to deploy remotely.

Defaults:
  --config         $DEFAULT_CONFIG
  --namespace      burrow
  --relay-binary   $DEFAULT_RELAY_BIN  (only used when relay-bundle/ is present)

Required:
  (none — but if --config's default doesn't exist, the script bails)
EOF
    common_usage_footer
    cat <<EOF

  --relay-binary PATH   Path to the burrow-relay binary to ship
                        when relay-bundle/ is present. Must be a
                        Linux ELF (the remote runs Linux).

Notes:
  * Linux only (the host running these commands needs ip/iproute2,
    sysctl, sudo). Remote target must also be Linux.
  * Script auto-installs wireguard-tools via apt-get / yum if wg(8)
    is missing on the target.
  * IP forwarding is enabled inside the netns only (per-netns sysctl,
    host stays untouched).
  * Sudo is required (locally or via the SSH user). For remote, the
    SSH user must be root or have NOPASSWD sudo.
  * burrow-relay is only deployed when a relay-bundle/ directory
    sits alongside the config. That directory is produced by
    \`burrow-client gen --relay\` / \`just gen-embed-wss\`. The
    binary itself is loaded from --relay-binary (default
    $DEFAULT_RELAY_BIN — gen-embed-wss collects it there from the
    cargo output). The binary must be a Linux ELF.
EOF
}

RELAY_BIN="$DEFAULT_RELAY_BIN"

while [ $# -gt 0 ]; do
    if parse_common_arg "$@"; then
        shift "$(arg_width "$1")"
    else
        case "$1" in
            -h|--help)       usage; exit 0;;
            --relay-binary)  RELAY_BIN="$2"; shift 2;;
            *) echo "unknown arg: $1" >&2; usage >&2; exit 1;;
        esac
    fi
done

if ! is_local; then build_ssh_cmds; fi

# Helper: run a one-line command as root on whichever side. Used by
# the relay deploy/teardown blocks below.
exec_as_root_oneliner() {
    local cmd="$1"
    if is_local; then
        sudo bash -c "$cmd"
    else
        "${SSH[@]}" "$TARGET" "sudo bash -c $(printf %q "$cmd")"
    fi
}

if [ "$TEARDOWN" = 1 ]; then
    # Stop + remove the relay first (best-effort — won't fail if it's
    # not present). The kernel WG netns goes after.
    exec_as_root_oneliner '
        pkill -f /usr/local/bin/burrow-relay 2>/dev/null || true
        rm -f /usr/local/bin/burrow-relay /var/log/burrow-relay.log
    ' || true
    exec_teardown
    echo "torn down namespace ${NAMESPACE} on $(target_label)"
    exit 0
fi

require_config_or_default "$DEFAULT_CONFIG"
CONF_PATH="$(stage_config)"

# If the configs came from gen-embed-wss, a relay-bundle/ sits next
# to the server.conf. That signals "also deploy burrow-relay". The
# relay binary itself isn't in the bundle (the bundle is just the
# materials baked into the binary at build time) — we ship it
# separately from --relay-binary.
RELAY_BUNDLE_DIR="$(dirname "$CONFIG")/relay-bundle"
DEPLOY_RELAY=0
if [ -d "$RELAY_BUNDLE_DIR" ]; then
    DEPLOY_RELAY=1
    if [ ! -f "$RELAY_BIN" ]; then
        echo "deploy: relay-bundle exists at $RELAY_BUNDLE_DIR but no binary at $RELAY_BIN" >&2
        echo "        Cross-compile first, e.g.:" >&2
        echo "            cargo build --release --bin burrow-relay \\" >&2
        echo "                --features embedded-relay-bundle,silent \\" >&2
        echo "                --target x86_64-unknown-linux-gnu" >&2
        echo "        Then re-run with --relay-binary target/x86_64-unknown-linux-gnu/release/burrow-relay" >&2
        exit 1
    fi
fi

# If the relay needs to ship, scp the binary now so REMOTE_SCRIPT can
# install it from /tmp in the same ssh round-trip as the WG bring-up.
RELAY_REMOTE_SRC=""
if [ "$DEPLOY_RELAY" = 1 ]; then
    if is_local; then
        # In LOCAL mode, just point at the local file; REMOTE_SCRIPT
        # runs under sudo in this same shell so the path is fine.
        RELAY_REMOTE_SRC="$(realpath "$RELAY_BIN")"
    else
        "${SCP[@]}" "$RELAY_BIN" "${TARGET}:/tmp/burrow-relay-new" >/dev/null
        RELAY_REMOTE_SRC="/tmp/burrow-relay-new"
    fi
fi

# Build the relay sub-script conditionally and splice it into the
# main remote script. setsid -f guarantees ssh returns immediately;
# nohup + disown turned out to be fragile across the
# bash -c -> sudo -> ssh chain (sudo waits for inherited fds).
RELAY_SETUP=""
if [ "$DEPLOY_RELAY" = 1 ]; then
    RELAY_SETUP=$(cat <<RELAY_EOS
pkill -f /usr/local/bin/burrow-relay 2>/dev/null || true
sleep 0.3
install -m 0755 ${RELAY_REMOTE_SRC} /usr/local/bin/burrow-relay
rm -f /tmp/burrow-relay-new
setsid -f /usr/local/bin/burrow-relay >/var/log/burrow-relay.log 2>&1 </dev/null
echo "burrow-relay started (PID via pgrep: \$(pgrep -f /usr/local/bin/burrow-relay | tr '\n' ' '))"
RELAY_EOS
)
fi

REMOTE_SCRIPT=$(cat <<EOS
set -e

if ! command -v wg >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y wireguard-tools iproute2
    elif command -v yum >/dev/null 2>&1; then
        yum install -y wireguard-tools iproute
    else
        echo "no apt-get or yum found — install wireguard-tools manually" >&2
        exit 1
    fi
fi

ip link del ${NAMESPACE} 2>/dev/null || true
ip netns del ${NAMESPACE} 2>/dev/null || true

ip netns add ${NAMESPACE}
ip netns exec ${NAMESPACE} sysctl -wq net.ipv4.ip_forward=1
ip netns exec ${NAMESPACE} ip link set lo up

# Create the wg interface in the host netns (UDP socket lives here, so
# peers can reach it via the public IP), then move the interface into
# the target netns. Standard pattern from wireguard.com/netns.
ip link add ${NAMESPACE} type wireguard
ip link set ${NAMESPACE} netns ${NAMESPACE}
# wg setconf only knows the kernel-WG keys (PrivateKey, ListenPort,
# PublicKey, Endpoint, AllowedIPs, PresharedKey, PersistentKeepalive).
# Address / DNS / PreUp / PostUp etc. are wg-quick concepts — pipe
# through wg-quick strip so they don't blow up the parse.
ip netns exec ${NAMESPACE} wg setconf ${NAMESPACE} <(wg-quick strip ${CONF_PATH})

addrs=\$(awk -F'= *' '/^Address[[:space:]]*=/{gsub(/[, ]+/, " ", \$2); print \$2; exit}' ${CONF_PATH})
for a in \$addrs; do
    ip netns exec ${NAMESPACE} ip addr add "\$a" dev ${NAMESPACE}
done
ip netns exec ${NAMESPACE} ip link set ${NAMESPACE} up

echo
echo "WG server up in netns ${NAMESPACE}:"
ip netns exec ${NAMESPACE} wg show

${RELAY_SETUP}
EOS
)

exec_as_root_script <<< "$REMOTE_SCRIPT"

RELAY_LINE=""
if [ "$DEPLOY_RELAY" = 1 ]; then
    RELAY_LINE="
  burrow-relay running in background; logs:
  $(if is_local; then echo "tail -f /var/log/burrow-relay.log"; \
                  else echo "ssh ${TARGET} tail -f /var/log/burrow-relay.log"; fi)"
fi

cat <<EOF

---
deployed on $(target_label). operate inside the netns:
  $(if is_local; then echo "sudo ip netns exec ${NAMESPACE} wg show"; \
                  else echo "ssh ${TARGET} sudo ip netns exec ${NAMESPACE} wg show"; fi)
  just netns-shell${TARGET:+ --target ${TARGET}} --namespace ${NAMESPACE}${RELAY_LINE}

tear down:
  just deploy-server${TARGET:+ --target ${TARGET}} --namespace ${NAMESPACE} --teardown
EOF
