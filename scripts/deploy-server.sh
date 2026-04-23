#!/usr/bin/env bash
# Bring up a WireGuard server on a remote Linux host inside a network
# namespace. Ephemeral: no systemd unit, no /etc/wireguard file, state
# dies with the namespace (or with the next reboot).
#
# WG UDP socket lives in the HOST netns (so peers can reach it from the
# public internet); the wg interface lives in the target netns. Pattern
# from https://www.wireguard.com/netns/.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_deploy_common.sh
source "$SCRIPT_DIR/_deploy_common.sh"

usage() {
    cat <<EOF
Usage: $(basename "$0") --target TARGET --config PATH [auth] [options]

Brings up a WireGuard server on a remote Linux host inside a network
namespace. State is entirely in the namespace + a /tmp config file —
no systemd, no /etc/wireguard. Tear down or reboot wipes it.

Required:
  --target TARGET   Anything ssh accepts:
                      myserver           (SSH config alias)
                      root@1.2.3.4
                      1.2.3.4            (uses your default ssh user)
  --config PATH     Path to server.conf (e.g. ./burrow-configs/server.conf).
                    Not needed with --teardown.
EOF
    common_usage_footer
    cat <<EOF

Notes:
  * Remote host needs wireguard-tools + iproute2. The script runs
    apt-get / yum install if wg(8) is missing.
  * IP forwarding is enabled inside the netns only (per-netns sysctl,
    host stays untouched).
  * Sudo is used on the remote — the SSH user must be root or have
    NOPASSWD sudo for the relevant commands.
EOF
}

# Drain args
while [ $# -gt 0 ]; do
    if parse_common_arg "$@"; then
        shift "$(arg_width "$1")"
    else
        case "$1" in
            -h|--help) usage; exit 0;;
            *) echo "unknown arg: $1" >&2; usage >&2; exit 1;;
        esac
    fi
done

require_target
build_ssh_cmds

REMOTE_CONF="/tmp/burrow-${NAMESPACE}.conf"

if [ "$TEARDOWN" = 1 ]; then
    run_remote "sudo ip link del ${NAMESPACE} 2>/dev/null || true; \
                sudo ip netns del ${NAMESPACE} 2>/dev/null || true; \
                sudo rm -f ${REMOTE_CONF}"
    echo "torn down namespace ${NAMESPACE} on ${TARGET}"
    exit 0
fi

require_config

# The remote-side script. Uses ${NAMESPACE} and ${REMOTE_CONF} from
# the local environment via parameter expansion at HEREDOC creation
# time — note the unquoted EOS.
REMOTE_SCRIPT=$(cat <<EOS
set -e

if ! command -v wg >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq && sudo apt-get install -y wireguard-tools iproute2
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y wireguard-tools iproute
    else
        echo "no apt-get or yum found — install wireguard-tools manually" >&2
        exit 1
    fi
fi

# Tear down any prior incarnation (idempotent re-deploy).
sudo ip link del ${NAMESPACE} 2>/dev/null || true
sudo ip netns del ${NAMESPACE} 2>/dev/null || true

sudo ip netns add ${NAMESPACE}
sudo ip netns exec ${NAMESPACE} sysctl -wq net.ipv4.ip_forward=1
sudo ip netns exec ${NAMESPACE} ip link set lo up

# Create the wg interface in the HOST netns (so its UDP socket is
# created here, in the host's network stack with public reachability),
# then move the interface into the target netns. The socket stays put.
sudo ip link add ${NAMESPACE} type wireguard
sudo ip link set ${NAMESPACE} netns ${NAMESPACE}
sudo ip netns exec ${NAMESPACE} wg setconf ${NAMESPACE} ${REMOTE_CONF}

# Pull Address from [Interface] (could be comma-separated).
addrs=\$(awk -F'= *' '/^Address[[:space:]]*=/{gsub(/[, ]+/, " ", \$2); print \$2; exit}' ${REMOTE_CONF})
for a in \$addrs; do
    sudo ip netns exec ${NAMESPACE} ip addr add "\$a" dev ${NAMESPACE}
done
sudo ip netns exec ${NAMESPACE} ip link set ${NAMESPACE} up

echo
echo "WG server up in netns ${NAMESPACE}:"
sudo ip netns exec ${NAMESPACE} wg show
EOS
)

scp_to_remote "$CONFIG" "$REMOTE_CONF"
run_remote_script <<< "$REMOTE_SCRIPT"

cat <<EOF

---
deployed. operate on the remote with:
  ssh ${TARGET} sudo ip netns exec ${NAMESPACE} wg show
  ssh ${TARGET} sudo ip netns exec ${NAMESPACE} bash      # interactive shell in the netns

tear down:
  $0 --target ${TARGET}${SSH_KEY:+ --key ${SSH_KEY}}${SSH_PORT:+ --port ${SSH_PORT}} --namespace ${NAMESPACE} --teardown
EOF
