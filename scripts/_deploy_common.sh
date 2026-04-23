#!/usr/bin/env bash
# Shared helpers for scripts/deploy-{server,client}.sh and netns-shell.sh.
#
# `_target` is whatever ssh accepts: an SSH-config alias, `user@host`,
# or a bare hostname / IP. Auth is whichever of agent / password / key
# the caller picked. Empty $TARGET means LOCAL mode — operations run
# directly with sudo, no ssh / no scp.

# Globals the caller fills in via parse_common_arg:
TARGET=""
SSH_PASSWORD=""
SSH_KEY=""
SSH_PORT=""
NAMESPACE="burrow"
CONFIG=""
TEARDOWN=0

common_usage_footer() {
    cat <<'EOF'

Target (omit for LOCAL mode — runs commands here with sudo):
  --target TARGET   Anything ssh accepts:
                      myhost              (SSH config alias)
                      root@1.2.3.4
                      1.2.3.4

Auth (only meaningful with --target; ssh's normal resolution is used
otherwise — agent, default key, ~/.ssh/config):
  --password PASS   SSH password (requires sshpass on this machine).
  --key PATH        SSH private key (-i).

Optional:
  --port PORT       SSH port (default: 22 / whatever SSH config says).
  --namespace NAME  netns name (default: burrow). Also the wg interface
                    name inside the namespace.
  --teardown        Remove the namespace + interface + on-disk config
                    and exit.
EOF
}

# Eat one common arg. Returns 0 if consumed (caller shifts by
# arg_width), 1 otherwise.
parse_common_arg() {
    case "$1" in
        --target)    TARGET="$2"; return 0;;
        --password)  SSH_PASSWORD="$2"; return 0;;
        --key)       SSH_KEY="$2"; return 0;;
        --port)      SSH_PORT="$2"; return 0;;
        --namespace) NAMESPACE="$2"; return 0;;
        --config)    CONFIG="$2"; return 0;;
        --teardown)  TEARDOWN=1; return 0;;
        *) return 1;;
    esac
}

arg_width() {
    case "$1" in
        --teardown) echo 1;;
        *) echo 2;;
    esac
}

# True iff we're in LOCAL mode (no --target).
is_local() { [ -z "$TARGET" ]; }

# Build $SSH and $SCP command arrays. Only needed in remote mode.
build_ssh_cmds() {
    local opts=(-o "StrictHostKeyChecking=accept-new" -o "UserKnownHostsFile=/dev/null")
    [ -n "$SSH_PORT" ] && opts+=(-p "$SSH_PORT")
    [ -n "$SSH_KEY" ] && opts+=(-i "$SSH_KEY")

    local prefix=()
    if [ -n "$SSH_PASSWORD" ]; then
        if ! command -v sshpass >/dev/null 2>&1; then
            echo "deploy: sshpass not on PATH — install it (apt: sshpass," >&2
            echo "        brew: hudochenkov/sshpass/sshpass) or use --key." >&2
            exit 2
        fi
        prefix=(sshpass -p "$SSH_PASSWORD")
    fi

    SSH=("${prefix[@]}" ssh "${opts[@]}")
    local scp_opts=(-o "StrictHostKeyChecking=accept-new" -o "UserKnownHostsFile=/dev/null")
    [ -n "$SSH_PORT" ] && scp_opts+=(-P "$SSH_PORT")
    [ -n "$SSH_KEY" ] && scp_opts+=(-i "$SSH_KEY")
    SCP=("${prefix[@]}" scp "${scp_opts[@]}")
}

# Pipe stdin into a root shell on the target (local: sudo bash; remote:
# ssh ... bash -s). Used to run a heredoc-built script.
exec_as_root_script() {
    if is_local; then
        sudo bash -s
    else
        "${SSH[@]}" "$TARGET" "bash -s"
    fi
}

# Stage the config so the remote script can find it. Local: emit the
# absolute path of $CONFIG. Remote: scp to /tmp/burrow-<ns>.conf and
# emit that. Either way, stdout is the path the remote script should
# read from.
stage_config() {
    if is_local; then
        # realpath isn't on every host (BSD); fall back to readlink -f.
        if command -v realpath >/dev/null 2>&1; then
            realpath "$CONFIG"
        else
            readlink -f "$CONFIG"
        fi
    else
        local remote="/tmp/burrow-${NAMESPACE}.conf"
        "${SCP[@]}" "$CONFIG" "${TARGET}:${remote}" >/dev/null
        echo "$remote"
    fi
}

# Run a one-line teardown command (drop link, drop netns, rm config) in
# whichever mode we're in.
exec_teardown() {
    local conf_path
    if is_local; then
        conf_path="/tmp/burrow-${NAMESPACE}.conf"
    else
        conf_path="/tmp/burrow-${NAMESPACE}.conf"
    fi
    local cmd="ip link del ${NAMESPACE} 2>/dev/null || true; \
               ip netns del ${NAMESPACE} 2>/dev/null || true; \
               rm -f ${conf_path}"
    if is_local; then
        sudo bash -c "$cmd"
    else
        "${SSH[@]}" "$TARGET" "sudo bash -c '$cmd'"
    fi
}

require_config_or_default() {
    if [ "$TEARDOWN" = 1 ]; then return; fi
    if [ -z "$CONFIG" ]; then CONFIG="$1"; fi
    if [ ! -f "$CONFIG" ]; then
        echo "deploy: config file not found: $CONFIG" >&2
        echo "        (omit --config to use the default at burrow-configs/)" >&2
        exit 1
    fi
}

# Pretty-print where we ran (local vs <target>). For status banner.
target_label() {
    if is_local; then echo "local"; else echo "$TARGET"; fi
}
