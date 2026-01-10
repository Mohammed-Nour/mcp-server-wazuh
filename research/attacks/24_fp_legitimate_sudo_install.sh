#!/bin/bash
#===============================================================================
# Attack #25 (FP-6): Legitimate Sudo Usage by Developer
# Category: False Positive / Maintenance
# Scenario: Developer installs a package with sudo apt install
# Expected Wazuh Rules: sudo usage, package install events; level ~5
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="FP-6"
ATTACK_NAME="Legitimate Sudo Package Install"
ATTACK_CATEGORY="FalsePositive"

TARGET="${1:-$TARGET_IP}"
SSH_USER="${TARGET_USER:-ubuntu}"
SSH_KEY_RAW="${SSH_KEY_OVERRIDE:-${TARGET_SSH_KEY:-$HOME/.ssh/wazuh-agent.pem}}"
SSH_KEY="${SSH_KEY_RAW/#\~/$HOME}"

PACKAGE_NAME="${PACKAGE_NAME:-nginx}"

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
echo "Package: $PACKAGE_NAME"
echo ""

START_TIME=$(date +%s.%N)
START_TIMESTAMP=$(date -Iseconds)

echo -e "${GREEN}[*] Sudo install started at: $START_TIMESTAMP${NC}"

COMMANDS=$(cat <<EOF
echo "[*] Installing package with sudo (benign developer action)..."
sudo apt update >/dev/null 2>&1 || true
sudo DEBIAN_FRONTEND=noninteractive apt install -y ${PACKAGE_NAME}
EOF
)

echo "[*] Executing on target host via SSH"
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$TARGET" "$COMMANDS"


END_TIME=$(date +%s.%N)
END_TIMESTAMP=$(date -Iseconds)
DURATION=$(echo "$END_TIME - $START_TIME" | bc)

echo ""
echo "==============================================================================="
echo -e "${GREEN}[✓] Sudo install completed${NC}"
echo "==============================================================================="
echo "End Time: $END_TIMESTAMP"
echo "Duration: ${DURATION} seconds"
echo ""
echo "Expected Wazuh alerts: sudo usage + package install (benign)"
echo "Mitigation guidance: correlate with developer change/approval logs"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
