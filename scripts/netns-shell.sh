#!/usr/bin/env bash
# Drop into an interactive shell inside the burrow netns. Local by
# default (sudo on this box); pass --target to enter the netns on a
# remote host over SSH.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_deploy_common.sh
source "$SCRIPT_DIR/_deploy_common.sh"

usage() {
    cat <<EOF
Usage: $(basename "$0") [--target TARGET] [--namespace NAME] [auth]

Drop into an interactive bash inside the burrow netns. Local by
default — pass --target to enter the namespace on a remote host.

Defaults:
  --namespace      burrow

Target / auth options match deploy-server / deploy-client; see
\`deploy-server.sh --help\` for the full list.
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

if is_local; then
    sudo ip netns exec "$NAMESPACE" bash
else
    build_ssh_cmds
    # -t allocates a TTY so bash inside the netns is interactive.
    "${SSH[@]}" -t "$TARGET" "sudo ip netns exec $NAMESPACE bash"
fi
