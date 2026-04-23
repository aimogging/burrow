#!/usr/bin/env bash
# Shared helpers for scripts/deploy-{server,client}.sh.
#
# `_target` is whatever ssh accepts: an SSH-config alias, `user@host`,
# or a bare hostname / IP. Auth is whichever of agent / password / key
# the caller picked. We never parse `_target` ourselves — ssh does.

# Globals the caller fills in via parse_common_args:
TARGET=""
SSH_PASSWORD=""
SSH_KEY=""
SSH_PORT=""
NAMESPACE="burrow"
CONFIG=""
TEARDOWN=0

# Print usage and exit. Called by trap or explicit error path.
common_usage_footer() {
    cat <<'EOF'

Auth (omit to defer to ssh's normal resolution: SSH config alias,
agent, default key):
  --password PASS   SSH password (requires sshpass on this machine).
  --key PATH        SSH private key (-i).

Optional:
  --port PORT       SSH port (default: 22 / whatever SSH config says).
  --namespace NAME  netns name on the remote (default: burrow). Also
                    used as the wg interface name inside the netns.
  --teardown        Remove the namespace + interface + on-disk config
                    on the target and exit.
EOF
}

# Eat one common arg (--target/--password/--key/--port/--namespace/
# --config/--teardown). Returns 0 if consumed, 1 otherwise. Pass the
# rest of "$@" so we can shift inside.
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

# How many args parse_common_arg consumed (1 for --teardown, 2 for the
# rest). Matches one of the arg names in $1.
arg_width() {
    case "$1" in
        --teardown) echo 1;;
        *) echo 2;;
    esac
}

# Build $SSH and $SCP arrays after args are parsed. Both arrays are
# safe to expand with `"${SSH[@]}" target ...` — no eval, no quoting
# nightmare for paths-with-spaces.
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
    # scp uses -P (uppercase) for port; rebuild without -p.
    local scp_opts=(-o "StrictHostKeyChecking=accept-new" -o "UserKnownHostsFile=/dev/null")
    [ -n "$SSH_PORT" ] && scp_opts+=(-P "$SSH_PORT")
    [ -n "$SSH_KEY" ] && scp_opts+=(-i "$SSH_KEY")
    SCP=("${prefix[@]}" scp "${scp_opts[@]}")
}

# Run a command on the remote (any number of args).
run_remote() {
    "${SSH[@]}" "$TARGET" "$@"
}

# Pipe stdin into `bash -s` on the remote — used to run a local
# heredoc-built script.
run_remote_script() {
    "${SSH[@]}" "$TARGET" "bash -s"
}

# scp a local file to a remote path.
scp_to_remote() {
    "${SCP[@]}" "$1" "${TARGET}:$2"
}

# Validate that --target was given.
require_target() {
    if [ -z "$TARGET" ]; then
        echo "deploy: --target required (ssh alias, user@host, or hostname)" >&2
        exit 1
    fi
}

# Validate config path exists, unless we're tearing down.
require_config() {
    if [ "$TEARDOWN" = 1 ]; then return; fi
    if [ -z "$CONFIG" ]; then
        echo "deploy: --config required (path to a .conf file)" >&2
        exit 1
    fi
    if [ ! -f "$CONFIG" ]; then
        echo "deploy: config file not found: $CONFIG" >&2
        exit 1
    fi
}
