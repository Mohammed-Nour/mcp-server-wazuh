#!/bin/bash
#===============================================================================
# Attack #10: Suspicious Outbound Connection
# Category: Network / Command & Control
# Expected Wazuh Rules: None observed in phase1 logs (enable netflow/iptables logging)
# Expected Level: N/A (no alerts observed)
# MITRE ATT&CK: T1071 (Application Layer Protocol)
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="10"
ATTACK_NAME="Suspicious Outbound Connection"
ATTACK_CATEGORY="Network"

TARGET_DOMAIN="${1:-malicious.example.com}"
TARGET_PORT="${2:-4444}"
MODE="${3:-ssh}" # ssh | local
LOGGING="${4:-off}" # on|off — adds iptables LOG on OUTPUT
SSH_USER="${TARGET_USER:-ubuntu}"
SSH_KEY_RAW="${SSH_KEY_OVERRIDE:-${TARGET_SSH_KEY:-$HOME/.ssh/wazuh-agent.pem}}"
SSH_KEY="${SSH_KEY_RAW/#\~/$HOME}"

echo "==============================================================================="
echo -e "${YELLOW}ATTACK #${ATTACK_ID}: ${ATTACK_NAME}${NC}"
echo "==============================================================================="
echo "Destination: $TARGET_DOMAIN:$TARGET_PORT"
echo "Mode: $MODE"
echo "Logging: $LOGGING (iptables LOG on agent OUTPUT)"
echo "Category: $ATTACK_CATEGORY"
echo ""

START_TIME=$(date +%s.%N)
START_TIMESTAMP=$(date -Iseconds)

echo -e "${GREEN}[*] Attack started at: $START_TIMESTAMP${NC}"
echo "[*] Simulating suspicious outbound beaconing..."
echo ""

if [ "$MODE" = "ssh" ] && [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
    echo "[*] Running attack via SSH to $SSH_USER@$TARGET_IP"
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$TARGET_IP" "TARGET_DOMAIN='$TARGET_DOMAIN' TARGET_PORT='$TARGET_PORT' LOGGING='$LOGGING' bash -s" <<'EOF'
enable_logging_output() {
    if [ "$LOGGING" != "on" ]; then return; fi
    sudo iptables -N WAZUH_OUT_LOG 2>/dev/null || true
    sudo iptables -F WAZUH_OUT_LOG
    sudo iptables -A WAZUH_OUT_LOG -p tcp --dport "$TARGET_PORT" -m limit --limit 5/second --limit-burst 20 -j LOG --log-prefix "wazuh-outbound " --log-level info
    sudo iptables -I OUTPUT 1 -j WAZUH_OUT_LOG
}
disable_logging_output() {
    if [ "$LOGGING" != "on" ]; then return; fi
    sudo iptables -D OUTPUT -j WAZUH_OUT_LOG 2>/dev/null || true
    sudo iptables -F WAZUH_OUT_LOG 2>/dev/null || true
    sudo iptables -X WAZUH_OUT_LOG 2>/dev/null || true
}
trap disable_logging_output EXIT
enable_logging_output
echo "[*] Initiating repeated outbound connections..."
for i in {1..6}; do
    echo "[*] Attempt $i to $TARGET_DOMAIN:$TARGET_PORT"
    (echo "ping" | nc -w 3 "$TARGET_DOMAIN" "$TARGET_PORT") 2>/dev/null || true
    curl -k --connect-timeout 3 "https://$TARGET_DOMAIN:$TARGET_PORT/ping" -m 5 -s -o /dev/null || true
    sleep 2
done
EOF
else
    echo -e "${YELLOW}[!] MODE=ssh but no key found; aborting${NC}"
    exit 1
fi


END_TIME=$(date +%s.%N)
END_TIMESTAMP=$(date -Iseconds)
DURATION=$(echo "$END_TIME - $START_TIME" | bc)

echo ""
echo "==============================================================================="
echo -e "${GREEN}[✓] Attack completed${NC}"
echo "==============================================================================="
echo "End Time: $END_TIMESTAMP"
echo "Duration: ${DURATION} seconds"
echo ""
echo "Expected Wazuh alerts:"
echo "  - Suspicious outbound connection attempts"
echo "  - Possible C2 beaconing (rules 6501/6502/6510) if netflow/iptables logging enabled"
echo "  - iptables LOG lines with prefix 'wazuh-outbound ' (if LOGGING=on)"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
