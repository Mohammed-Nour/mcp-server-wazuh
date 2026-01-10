#!/bin/bash
#===============================================================================
# Attack #22 (FP-3): Legitimate Cron Job Execution (logrotate)
# Category: False Positive / Maintenance
# Scenario: System logrotate runs at midnight; triggers process/FIM alerts
# Expected Wazuh Rules: Process exec, FIM on /etc/logrotate.conf, level ~6
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="FP-3"
ATTACK_NAME="Legitimate Cron Job (logrotate)"
ATTACK_CATEGORY="FalsePositive"

TARGET="${1:-$TARGET_IP}"
SSH_USER="${TARGET_USER:-ubuntu}"
SSH_KEY_RAW="${SSH_KEY_OVERRIDE:-${TARGET_SSH_KEY:-$HOME/.ssh/wazuh-agent.pem}}"
SSH_KEY="${SSH_KEY_RAW/#\~/$HOME}"

echo "==============================================================================="
echo -e "${YELLOW}ATTACK ${ATTACK_ID}: ${ATTACK_NAME}${NC}"
echo "==============================================================================="
echo "Target: $TARGET"
echo "Category: $ATTACK_CATEGORY"
echo "Note: benign scheduled maintenance activity"
echo ""

START_TIME=$(date +%s.%N)
START_TIMESTAMP=$(date -Iseconds)

echo -e "${GREEN}[*] Cron simulation started at: $START_TIMESTAMP${NC}"

COMMANDS=$(cat <<'EOF'
echo "[*] Running logrotate manually to mimic scheduled cron..."
sudo /usr/sbin/logrotate /etc/logrotate.conf
EOF
)


echo "[*] Executing on admin host via SSH -> target"
ssh -i "$SSH_KEY" "$SSH_USER@$TARGET" "$COMMANDS"


END_TIME=$(date +%s.%N)
END_TIMESTAMP=$(date -Iseconds)
DURATION=$(echo "$END_TIME - $START_TIME" | bc)

echo ""
echo "==============================================================================="
echo -e "${GREEN}[✓] Cron simulation completed${NC}"
echo "==============================================================================="
echo "End Time: $END_TIMESTAMP"
echo "Duration: ${DURATION} seconds"
echo ""
echo "Expected Wazuh alerts: logrotate execution; potential FIM touches on rotated logs"
echo "Mitigation guidance: whitelist scheduled logrotate cron"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
