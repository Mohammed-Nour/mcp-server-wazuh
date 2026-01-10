#!/bin/bash
#===============================================================================
# Attack #23 (FP-4): Legitimate System Update (apt upgrade)
# Category: False Positive / Maintenance
# Scenario: Admin runs apt update && apt upgrade; triggers FIM/process alerts
# Expected Wazuh Rules: FIM changes on /usr/bin,/usr/lib; package manager events; level ~7
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="FP-4"
ATTACK_NAME="Legitimate System Update"
ATTACK_CATEGORY="FalsePositive"

TARGET="${1:-$TARGET_IP}"
SSH_USER="${TARGET_USER:-ubuntu}"
SSH_KEY_RAW="${SSH_KEY_OVERRIDE:-${TARGET_SSH_KEY:-$HOME/.ssh/wazuh-agent.pem}}"
SSH_KEY="${SSH_KEY_RAW/#\~/$HOME}"


PACKAGE_CMD="${PACKAGE_CMD_OVERRIDE:-"sudo apt update && sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y"}"

if [ -z "$TARGET" ]; then
    echo -e "${RED}Error: No target specified${NC}"
    exit 1
fi

echo "==============================================================================="
echo -e "${YELLOW}ATTACK ${ATTACK_ID}: ${ATTACK_NAME}${NC}"
echo "==============================================================================="
echo "Target: $TARGET"
echo "Category: $ATTACK_CATEGORY"
echo "Executor: ${ADMIN_HOST:-local (this machine)}"
echo "Command: $PACKAGE_CMD"
echo "Note: This is expected maintenance, not malicious"
echo ""

START_TIME=$(date +%s.%N)
START_TIMESTAMP=$(date -Iseconds)

echo -e "${GREEN}[*] System update started at: $START_TIMESTAMP${NC}"

COMMANDS=$(cat <<EOF
echo "[*] Running package update/upgrade..."
$PACKAGE_CMD
EOF
)

echo "[*] Executing on admin host via SSH"
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$TARGET" "$COMMANDS"


END_TIME=$(date +%s.%N)
END_TIMESTAMP=$(date -Iseconds)
DURATION=$(echo "$END_TIME - $START_TIME" | bc)

echo ""
echo "==============================================================================="
echo -e "${GREEN}[✓] System update completed${NC}"
echo "==============================================================================="
echo "End Time: $END_TIMESTAMP"
echo "Duration: ${DURATION} seconds"
echo ""
echo "Expected Wazuh alerts: FIM changes, package manager activity (benign)"
echo "Mitigation guidance: correlate with maintenance window/release notes"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
