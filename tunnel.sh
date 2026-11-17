#!/usr/bin/env bash
# aws-frp/Linux control plane. No secrets are written to the service journal here.
set -euo pipefail
SCRIPT_DIR="$(dirname "$(readlink -f -- "${BASH_SOURCE[0]}")")"
SERVICE=gateway-poc-https
CONFIG=/etc/gateway-poc-https/config.json
AGENT_HOST=agent-gateway.sicredi.space
TAIL=100
FOLLOW=false
CLIENT_ID=intermediario-01
HOURS=24
OUT=""
SUDO=()
if [[ "$(id -u)" != 0 ]]; then SUDO=(sudo); fi
usage() {
    echo 'Usage: tunnel {up|down|status|logs|check|restart|rotate-client-token} [options]'
    echo '  logs: --tail N, --follow (-f)'
    echo '  rotate-client-token: --client-id ID --hours 1..720 [--out DIRECTORY]'
    echo '  check/rotate-client-token: --config FILE; check: --agent-host HOST'
}
ACTION="${1:-status}"
if (( $# )); then shift; fi
case "$ACTION" in
    up|down|status|logs|check|restart|rotate-client-token) ;;
    -h|--help|help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac
while (( $# )); do
    case "$1" in
        --tail|-n) [[ "$ACTION" == logs && $# -ge 2 ]] || { usage >&2; exit 2; }; TAIL="$2"; shift 2 ;;
        --follow|-f) [[ "$ACTION" == logs ]] || { usage >&2; exit 2; }; FOLLOW=true; shift ;;
        --client-id) [[ "$ACTION" == rotate-client-token && $# -ge 2 ]] || { usage >&2; exit 2; }; CLIENT_ID="$2"; shift 2 ;;
        --hours) [[ "$ACTION" == rotate-client-token && $# -ge 2 ]] || { usage >&2; exit 2; }; HOURS="$2"; shift 2 ;;
        --out) [[ "$ACTION" == rotate-client-token && $# -ge 2 ]] || { usage >&2; exit 2; }; OUT="$2"; shift 2 ;;
        --config) [[ "$ACTION" =~ ^(check|rotate-client-token|up|restart)$ && $# -ge 2 ]] || { usage >&2; exit 2; }; CONFIG="$2"; shift 2 ;;
        --agent-host) [[ "$ACTION" =~ ^(check|up|restart)$ && $# -ge 2 ]] || { usage >&2; exit 2; }; AGENT_HOST="$2"; shift 2 ;;
        *) usage >&2; exit 2 ;;
    esac
done
[[ "$TAIL" =~ ^[0-9]{1,5}$ ]] && (( 10#$TAIL >= 1 && 10#$TAIL <= 10000 )) || { echo 'Tail must be 1..10000' >&2; exit 2; }
[[ "$HOURS" =~ ^[0-9]{1,3}$ ]] && (( 10#$HOURS >= 1 && 10#$HOURS <= 720 )) || { echo 'Hours must be 1..720' >&2; exit 2; }
check_gateway() {
    "${SUDO[@]}" systemctl is-active --quiet "$SERVICE"
    "${SUDO[@]}" systemctl is-active --quiet haproxy
    local output="" attempt
    for attempt in 1 2 3 4 5; do
        if output=$("${SUDO[@]}" python3 "$SCRIPT_DIR/homologation.py" check-gateway --config "$CONFIG" --agent-host "$AGENT_HOST" 2>&1); then
            printf '%s\n' "$output"
            return 0
        fi
        sleep 1
    done
    printf '%s\n' "$output" >&2
    return 1
}

case "$ACTION" in
    up) "${SUDO[@]}" systemctl start haproxy "$SERVICE"; check_gateway ;;
    down) "${SUDO[@]}" systemctl stop "$SERVICE" ;;
    restart) "${SUDO[@]}" systemctl start haproxy; "${SUDO[@]}" systemctl restart "$SERVICE"; check_gateway ;;
    status) "${SUDO[@]}" systemctl status "$SERVICE" haproxy --no-pager --full ;;
    check) check_gateway ;;
    logs)
        args=(-u "$SERVICE" -n "$TAIL" --no-pager)
        if $FOLLOW; then args+=(-f); fi
        "${SUDO[@]}" journalctl "${args[@]}"
        ;;
    rotate-client-token)
        if [[ -z "$OUT" ]]; then OUT="/etc/gateway-poc-https/rotations/$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"; fi
        printf "ROTATION_BUNDLE=%s\n" "$OUT"
        # Apply and restart before displaying a token as ready for use.
        "${SUDO[@]}" python3 "$SCRIPT_DIR/homologation.py" rotate-client-token --config "$CONFIG" \
            --out "$OUT" --client-id "$CLIENT_ID" --hours "$HOURS" >/dev/null
        "${SUDO[@]}" systemctl restart "$SERVICE"
        check_gateway
        # Only this explicit administrative action prints the bearer credential.
        "${SUDO[@]}" python3 - "$OUT" <<'PY'
import base64, json, sys
from pathlib import Path
out = Path(sys.argv[1])
agent = json.loads((out / 'agent-policy.json').read_text(encoding='utf-8'))
client = json.loads((out / 'client-policy.json').read_text(encoding='utf-8'))
policy = json.dumps(agent, separators=(',', ':'), ensure_ascii=True)
print('CLIENT_ID=' + client['patch']['client_id'])
print('EXPIRES_UTC=' + next(iter(agent['patch']['services'].values()))['test_authorization']['expires_utc'])
print('CLIENT_TOKEN=' + (out / 'client.token').read_text(encoding='ascii').strip())
print('BUNDLE=' + str(out))
print('WINDOWS_AGENT_POLICY_JSON=' + policy)
print('WINDOWS_COMMAND:')
print('tunnel rotate-client-token -PolicyJsonBase64 ' + base64.b64encode(policy.encode()).decode())
print('Only send the agent policy/command to restricted Windows, never CLIENT_TOKEN.')
PY
        ;;
esac
