#!/usr/bin/env bash
# Redeploy burrow.exe to a Windows host through an existing SOCKS5
# tunnel: SMB-upload the new binary, then kill+restart it via WMI.
#
# Defaults are wired to the dev setup (10.2.10.11 via the burrow tunnel
# at 127.0.0.1:9050). Override with flags or env vars.
#
# Usage: scripts/redeploy-win.sh [-t target] [-c creds] [-b binary] [-r remote] [-p proxy]
# Env:   TARGET, CREDS, BINARY, REMOTE, PROXY
#
# CREDS shape: 'DOMAIN/user:pass' (gopacket / impacket connection-string form).

set -euo pipefail

TARGET="${TARGET:-10.2.10.11}"
CREDS="${CREDS:-NORTH/robb.stark:sexywolfy}"
BINARY="${BINARY:-deployments/dev/relay-bundle/burrow.exe}"
REMOTE="${REMOTE:-\\Windows\\Temp\\burrow.exe}"
PROXY="${PROXY:-socks5h://127.0.0.1:9050}"

while getopts "t:c:b:r:p:h" opt; do
    case "$opt" in
        t) TARGET="$OPTARG" ;;
        c) CREDS="$OPTARG" ;;
        b) BINARY="$OPTARG" ;;
        r) REMOTE="$OPTARG" ;;
        p) PROXY="$OPTARG" ;;
        h) sed -n '2,/^$/p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "see -h for usage" >&2; exit 2 ;;
    esac
done

USER_PART="${CREDS%:*}"      # DOMAIN/user
PASS_PART="${CREDS##*:}"     # pass

[[ -f "$BINARY" ]] || { echo "no such file: $BINARY" >&2; exit 1; }

cmds="$(mktemp)"
trap 'rm -f "$cmds"' EXIT
printf '%s\n%s\n' \
    'use C$' \
    "put $BINARY $REMOTE" \
    > "$cmds"

echo ">>> SMB-uploading $BINARY -> $TARGET:C\$$REMOTE"
gopacket-smbclient \
    -proxy "$PROXY" \
    -inputfile "$cmds" \
    "${CREDS}@${TARGET}"

echo ">>> killing burrow.exe + relaunching $REMOTE on $TARGET"
goexec wmi proc "$TARGET" \
    -u "$USER_PART" \
    -p "$PASS_PART" \
    -x "$PROXY" \
    -c "cmd /c taskkill /IM burrow.exe /F & start \"\" /B C:$REMOTE"

echo ">>> done"
