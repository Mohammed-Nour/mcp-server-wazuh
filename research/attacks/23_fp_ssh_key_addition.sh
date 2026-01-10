#!/bin/bash
#===============================================================================
# Attack #24 (FP-5): Legitimate SSH Key Addition by User
# Category: False Positive / Access Management
# Scenario: User adds their own SSH key to authorized_keys
# Expected Wazuh Rules: FIM on ~/.ssh/authorized_keys; level ~8
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="FP-5"
ATTACK_NAME="Legitimate SSH Key Addition"
ATTACK_CATEGORY="FalsePositive"

TARGET="${1:-$TARGET_IP}"
SSH_USER="${TARGET_USER:-ubuntu}"
SSH_KEY_RAW="${SSH_KEY_OVERRIDE:-${TARGET_SSH_KEY:-$HOME/.ssh/wazuh-agent.pem}}"
SSH_KEY="${SSH_KEY_RAW/#\~/$HOME}"


NEW_KEY_CONTENT="${NEW_KEY_CONTENT:-ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdemo_fake_fp_key_for_testing_only user@test}"
AUTH_FILE="${AUTH_FILE:-/home/${SSH_USER}/.ssh/authorized_keys}"
CLEANUP_AFTER="${CLEANUP_AFTER:-true}"

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
echo "Authorized keys file: $AUTH_FILE"
echo "Cleanup after? $CLEANUP_AFTER"
echo ""

START_TIME=$(date +%s.%N)
START_TIMESTAMP=$(date -Iseconds)

echo -e "${GREEN}[*] SSH key addition started at: $START_TIMESTAMP${NC}"

COMMANDS=$(cat <<EOF
echo "[*] Adding SSH key to $AUTH_FILE"
sudo mkdir -p "$(dirname "$AUTH_FILE")"
sudo sh -c "echo '$NEW_KEY_CONTENT' >> '$AUTH_FILE'"
sudo chown ${SSH_USER}:${SSH_USER} "$AUTH_FILE"
sudo chmod 600 "$AUTH_FILE"
if [ "$CLEANUP_AFTER" = "true" ]; then
  echo "[*] Cleanup enabled; removing key after 5 seconds"
  sleep 5
  sudo sed -i "\|$NEW_KEY_CONTENT|d" "$AUTH_FILE"
fi
EOF
)

echo "[*] Executing on target host via SSH"
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$TARGET" "$COMMANDS"


END_TIME=$(date +%s.%N)
END_TIMESTAMP=$(date -Iseconds)
DURATION=$(echo "$END_TIME - $START_TIME" | bc)

echo ""
echo "==============================================================================="
echo -e "${GREEN}[✓] SSH key addition simulation completed${NC}"
echo "==============================================================================="
echo "End Time: $END_TIMESTAMP"
echo "Duration: ${DURATION} seconds"
echo ""
echo "Expected Wazuh alerts: authorized_keys modified (benign user action)"
echo "Mitigation guidance: confirm user request/approval; allow if expected"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
