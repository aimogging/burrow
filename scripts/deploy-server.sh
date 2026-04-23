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

set -euo pipefail

DEFAULT_CONFIG="burrow-configs/server.conf"

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

Required:
  (none — but if --config's default doesn't exist, the script bails)
EOF
    common_usage_footer
    cat <<EOF

Notes:
  * Linux only (the host running these commands needs ip/iproute2,
    sysctl, sudo). Remote target must also be Linux.
  * Script auto-installs wireguard-tools via apt-get / yum if wg(8)
    is missing on the target.
  * IP forwarding is enabled inside the netns only (per-netns sysctl,
    host stays untouched).
  * Sudo is required (locally or via the SSH user). For remote, the
    SSH user must be root or have NOPASSWD sudo.
EOF
}

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

if ! is_local; then build_ssh_cmds; fi

if [ "$TEARDOWN" = 1 ]; then
    exec_teardown
    echo "torn down namespace ${NAMESPACE} on $(target_label)"
    exit 0
fi

require_config_or_default "$DEFAULT_CONFIG"
CONF_PATH="$(stage_config)"

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
ip netns exec ${NAMESPACE} wg setconf ${NAMESPACE} ${CONF_PATH}

addrs=\$(awk -F'= *' '/^Address[[:space:]]*=/{gsub(/[, ]+/, " ", \$2); print \$2; exit}' ${CONF_PATH})
for a in \$addrs; do
    ip netns exec ${NAMESPACE} ip addr add "\$a" dev ${NAMESPACE}
done
ip netns exec ${NAMESPACE} ip link set ${NAMESPACE} up

echo
echo "WG server up in netns ${NAMESPACE}:"
ip netns exec ${NAMESPACE} wg show
EOS
)

exec_as_root_script <<< "$REMOTE_SCRIPT"

cat <<EOF

---
deployed on $(target_label). operate inside the netns:
  $(if is_local; then echo "sudo ip netns exec ${NAMESPACE} wg show"; \
                  else echo "ssh ${TARGET} sudo ip netns exec ${NAMESPACE} wg show"; fi)
  just netns-shell${TARGET:+ --target ${TARGET}} --namespace ${NAMESPACE}

tear down:
  just deploy-server${TARGET:+ --target ${TARGET}} --namespace ${NAMESPACE} --teardown
EOF
