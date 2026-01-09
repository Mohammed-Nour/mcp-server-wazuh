#!/bin/bash
#===============================================================================
# Attack #15: Cron Job Modification
# Category: Persistence
# Expected Wazuh Rules: 550 (lvl7), 553 (lvl7), 554 (lvl5)
# Expected Level: 5-7 (observed)
# MITRE ATT&CK: T1053.003 (Cron)
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="15"
ATTACK_NAME="Cron Job Modification"
ATTACK_CATEGORY="Persistence"

TARGET="${1:-$TARGET_IP}"

echo "==============================================================================="
echo -e "${YELLOW}ATTACK #${ATTACK_ID}: ${ATTACK_NAME}${NC}"
echo "==============================================================================="
echo "Target: $TARGET"
echo "Category: $ATTACK_CATEGORY"
echo ""

START_TIME=$(date +%s.%N)
START_TIMESTAMP=$(date -Iseconds)

echo -e "${GREEN}[*] Attack started at: $START_TIMESTAMP${NC}"
echo "[*] Creating a malicious cron job..."
echo ""

ATTACK_COMMANDS='
#!/bin/bash
CRON_FILE="/etc/cron.d/system_update"
echo "[*] Writing malicious cron entry to $CRON_FILE"
echo "*/2 * * * * root /bin/bash -c \"echo cron-backdoor >> /tmp/cron_backdoor.log\"" | sudo tee "$CRON_FILE" >/dev/null
sudo chmod 644 "$CRON_FILE"
sudo cat "$CRON_FILE"

echo "[*] Cleaning up cron entry after creation"
sleep 5
sudo rm -f "$CRON_FILE"
'

TARGET="${1:-$TARGET_IP}"
SSH_KEY_RAW="${SSH_KEY_OVERRIDE:-${TARGET_SSH_KEY:-$HOME/.ssh/wazuh-agent.pem}}"
SSH_USER="${3:-${TARGET_USER:-ubuntu}}"
SSH_KEY="${SSH_KEY_RAW/#\~/$HOME}"


if [ "$TARGET" = "localhost" ] || [ "$TARGET" = "127.0.0.1" ]; then
    echo "[*] Running attack locally..."
    eval "$ATTACK_COMMANDS"
elif [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
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
echo "  - Cron modification detection"
echo "  - FIM alerts on /etc/cron.d"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
