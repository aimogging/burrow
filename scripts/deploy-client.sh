#!/usr/bin/env bash
# Bring up a WireGuard client on a Linux host inside a network
# namespace. Defaults to LOCAL execution (sudo on this box) — the
# client is the device you're typing on, not somewhere remote, in 99%
# of cases. Pass --target HOST to drive a remote box over SSH.
#
# Routes for every [Peer] AllowedIPs CIDR get added inside the
# namespace; the host's main routing table stays untouched.

set -euo pipefail

DEFAULT_CONFIG="burrow-configs/client1.conf"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_deploy_common.sh
source "$SCRIPT_DIR/_deploy_common.sh"

usage() {
    cat <<EOF
Usage: $(basename "$0") [--config PATH] [--target TARGET] [auth] [options]

Brings up a WireGuard client on a Linux host inside a network
namespace. Local by default — the client is normally the device
you're typing on. Pass --target to deploy remotely.

Defaults:
  --config         $DEFAULT_CONFIG
  --namespace      burrow

Required:
  (none — but if --config's default doesn't exist, the script bails)
EOF
    common_usage_footer
    cat <<EOF

Notes:
  * Linux only.
  * Auto-installs wireguard-tools via apt-get / yum if missing.
  * Routes for every [Peer] AllowedIPs CIDR are added inside the
    namespace. 0.0.0.0/0 is skipped (it would steal the default
    route from the netns). IPv6 entries are skipped.
  * To work over the tunnel from inside the namespace:
      just netns-shell${TARGET:+ --target ...}
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
ip netns exec ${NAMESPACE} ip link set lo up

# wg interface created in host netns (UDP socket dials the server's
# public IP from there), then moved into the target netns.
ip link add ${NAMESPACE} type wireguard
ip link set ${NAMESPACE} netns ${NAMESPACE}
ip netns exec ${NAMESPACE} wg setconf ${NAMESPACE} ${CONF_PATH}

addrs=\$(awk -F'= *' '/^Address[[:space:]]*=/{gsub(/[, ]+/, " ", \$2); print \$2; exit}' ${CONF_PATH})
for a in \$addrs; do
    ip netns exec ${NAMESPACE} ip addr add "\$a" dev ${NAMESPACE}
done
ip netns exec ${NAMESPACE} ip link set ${NAMESPACE} up

# Routes for every AllowedIPs CIDR. The Address line already covers
# the WG subnet; routes here are for whatever burrow exposes on top.
allowed=\$(awk -F'= *' '/^AllowedIPs[[:space:]]*=/{gsub(/[, ]+/, " ", \$2); print \$2}' ${CONF_PATH})
for cidr in \$allowed; do
    case "\$cidr" in
        *:*) continue;;       # skip IPv6
        0.0.0.0/0) continue;; # skip default-route catch-all
    esac
    ip netns exec ${NAMESPACE} ip route replace "\$cidr" dev ${NAMESPACE}
done

echo
echo "WG client up in netns ${NAMESPACE}:"
ip netns exec ${NAMESPACE} wg show
echo
echo "routes in netns:"
ip netns exec ${NAMESPACE} ip route
EOS
)

exec_as_root_script <<< "$REMOTE_SCRIPT"

cat <<EOF

---
deployed on $(target_label). drop into the netns to use the tunnel:
  just netns-shell${TARGET:+ --target ${TARGET}} --namespace ${NAMESPACE}

tear down:
  just deploy-client${TARGET:+ --target ${TARGET}} --namespace ${NAMESPACE} --teardown
EOF
