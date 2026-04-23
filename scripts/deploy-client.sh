#!/usr/bin/env bash
# Bring up a WireGuard client on a remote Linux host inside a network
# namespace. Same shape as deploy-server.sh: ephemeral, no persistence,
# WG UDP socket in the host netns, wg interface in the target netns.
#
# Adds routes for each AllowedIPs entry in [Peer] so processes inside
# the netns can reach the WG network without further setup.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_deploy_common.sh
source "$SCRIPT_DIR/_deploy_common.sh"

usage() {
    cat <<EOF
Usage: $(basename "$0") --target TARGET --config PATH [auth] [options]

Brings up a WireGuard client on a remote Linux host inside a network
namespace. State lives in the namespace + a /tmp config file. Tear
down or reboot wipes it.

Required:
  --target TARGET   Anything ssh accepts:
                      myclient           (SSH config alias)
                      root@1.2.3.4
                      1.2.3.4            (uses your default ssh user)
  --config PATH     Path to client.conf (e.g. ./burrow-configs/client1.conf).
                    Not needed with --teardown.
EOF
    common_usage_footer
    cat <<EOF

Notes:
  * Remote host needs wireguard-tools + iproute2. Script installs via
    apt-get / yum if wg(8) is missing.
  * Routes for every AllowedIPs CIDR in [Peer] go in the namespace's
    routing table; the host's main routing table stays untouched.
  * Sudo is used on the remote — the SSH user must be root or have
    NOPASSWD sudo for the relevant commands.
  * To run something inside the namespace afterwards (e.g. burrow-client):
      ssh TARGET sudo ip netns exec NAMESPACE bash
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

sudo ip link del ${NAMESPACE} 2>/dev/null || true
sudo ip netns del ${NAMESPACE} 2>/dev/null || true

sudo ip netns add ${NAMESPACE}
sudo ip netns exec ${NAMESPACE} ip link set lo up

# wg interface created in HOST netns (UDP socket lives there, can dial
# the server's public IP), then moved into the target netns.
sudo ip link add ${NAMESPACE} type wireguard
sudo ip link set ${NAMESPACE} netns ${NAMESPACE}
sudo ip netns exec ${NAMESPACE} wg setconf ${NAMESPACE} ${REMOTE_CONF}

addrs=\$(awk -F'= *' '/^Address[[:space:]]*=/{gsub(/[, ]+/, " ", \$2); print \$2; exit}' ${REMOTE_CONF})
for a in \$addrs; do
    sudo ip netns exec ${NAMESPACE} ip addr add "\$a" dev ${NAMESPACE}
done
sudo ip netns exec ${NAMESPACE} ip link set ${NAMESPACE} up

# Add routes for every AllowedIPs CIDR in [Peer]. The Address line
# already provides the on-link route for the WG subnet; any extra
# routes (the routes burrow exposes) come from here.
allowed=\$(awk -F'= *' '/^AllowedIPs[[:space:]]*=/{gsub(/[, ]+/, " ", \$2); print \$2}' ${REMOTE_CONF})
for cidr in \$allowed; do
    # Skip IPv6 (no support) and 0.0.0.0/0 catch-alls (would steal the
    # default route — unwanted on a non-VPN client).
    case "\$cidr" in
        *:*) continue;;
        0.0.0.0/0) continue;;
    esac
    sudo ip netns exec ${NAMESPACE} ip route replace "\$cidr" dev ${NAMESPACE}
done

echo
echo "WG client up in netns ${NAMESPACE}:"
sudo ip netns exec ${NAMESPACE} wg show
echo
echo "routes in netns:"
sudo ip netns exec ${NAMESPACE} ip route
EOS
)

scp_to_remote "$CONFIG" "$REMOTE_CONF"
run_remote_script <<< "$REMOTE_SCRIPT"

cat <<EOF

---
deployed. enter the netns to run things over the tunnel:
  ssh ${TARGET} sudo ip netns exec ${NAMESPACE} bash
  # then inside: curl http://10.0.0.2 / dig @10.0.0.2 ... / burrow-client ...

tear down:
  $0 --target ${TARGET}${SSH_KEY:+ --key ${SSH_KEY}}${SSH_PORT:+ --port ${SSH_PORT}} --namespace ${NAMESPACE} --teardown
EOF
