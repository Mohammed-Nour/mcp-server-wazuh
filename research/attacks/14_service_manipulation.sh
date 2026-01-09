#!/bin/bash
#===============================================================================
# Attack #14: Service Manipulation (Stop/Disable)
# Category: System / Availability
# Expected Wazuh Rules: 5501 (lvl3), 5502 (lvl3), 5503 (lvl5)
# Expected Level: 3-5 (observed)
# MITRE ATT&CK: T1489 (Service Stop)
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="14"
ATTACK_NAME="Service Manipulation"
ATTACK_CATEGORY="System"

TARGET="${1:-$TARGET_IP}"
SERVICE_NAME="${2:-rsyslog}"

echo "==============================================================================="
echo -e "${YELLOW}ATTACK #${ATTACK_ID}: ${ATTACK_NAME}${NC}"
echo "==============================================================================="
echo "Target: $TARGET"
echo "Service: $SERVICE_NAME"
echo "Category: $ATTACK_CATEGORY"
echo ""

START_TIME=$(date +%s.%N)
START_TIMESTAMP=$(date -Iseconds)

echo -e "${GREEN}[*] Attack started at: $START_TIMESTAMP${NC}"
echo "[*] Attempting to stop and disable a service..."
echo ""

ATTACK_COMMANDS='
#!/bin/bash
echo "[*] Checking service $SERVICE_NAME status"
sudo systemctl status $SERVICE_NAME >/dev/null 2>&1 || echo "[!] Service $SERVICE_NAME may not exist"

echo "[*] Stopping $SERVICE_NAME"
sudo systemctl stop $SERVICE_NAME 2>/dev/null || true

echo "[*] Disabling $SERVICE_NAME"
sudo systemctl disable $SERVICE_NAME 2>/dev/null || true

echo "[*] Restarting $SERVICE_NAME to restore state"
sudo systemctl enable $SERVICE_NAME 2>/dev/null || true
sudo systemctl start $SERVICE_NAME 2>/dev/null || true

echo "[*] Final status:"
sudo systemctl status $SERVICE_NAME 2>/dev/null || true
'

TARGET="${1:-$TARGET_IP}"
SSH_KEY_RAW="${SSH_KEY_OVERRIDE:-${TARGET_SSH_KEY:-$HOME/.ssh/wazuh-agent.pem}}"
SSH_USER="${3:-${TARGET_USER:-ubuntu}}"
SSH_KEY="${SSH_KEY_RAW/#\~/$HOME}"


if [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
    echo "[*] Running attack via SSH..."
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$TARGET" "$ATTACK_COMMANDS"
else
    echo -e "${YELLOW}[!] Cannot connect to target. Printing commands to run manually:${NC}"
    echo ""
    echo "--- Run these commands on the target agent ---"
    echo "$ATTACK_COMMANDS"
    echo "--- End of commands ---"
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
echo "  - Service stop/disable events"
echo "  - Potential availability impact (rules 5502/5503/5504)"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
