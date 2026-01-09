#!/bin/bash
#===============================================================================
# Attack #16: Multiple Failed Authentication Attempts
# Category: Authentication
# Expected Wazuh Rules: 5710 (lvl5), 5712 (lvl10), 5715 (lvl3), 40112 (lvl12)
# Expected Level: 3-12 (observed)
# MITRE ATT&CK: T1110 (Brute Force)
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="16"
ATTACK_NAME="Failed Authentication Attempts"
ATTACK_CATEGORY="Authentication"

TARGET="${1:-$TARGET_IP}"
ATTEMPTS="${2:-6}"

if [ -z "$TARGET" ]; then
    echo -e "${RED}Error: No target IP specified${NC}"
    echo "Usage: $0 <target_ip> [attempts]"
    exit 1
fi

echo "==============================================================================="
echo -e "${YELLOW}ATTACK #${ATTACK_ID}: ${ATTACK_NAME}${NC}"
echo "==============================================================================="
echo "Target: $TARGET"
echo "Attempts: $ATTEMPTS"
echo "Category: $ATTACK_CATEGORY"
echo ""

START_TIME=$(date +%s.%N)
START_TIMESTAMP=$(date -Iseconds)

echo -e "${GREEN}[*] Attack started at: $START_TIMESTAMP${NC}"
echo "[*] Generating multiple failed logins..."
echo ""

ATTACK_COMMANDS='
#!/bin/bash
INVALID_USER="fakeuser"
for i in $(seq 1 $ATTEMPTS); do
    echo "[*] Attempt $i with invalid credentials"
    sshpass -p "wrongpassword" ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=no "$INVALID_USER@$TARGET" "exit" 2>/dev/null || true
    sudo -k
    echo "wrongpassword" | sudo -S id >/dev/null 2>&1 || true
    sleep 1
done
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
echo "  - Multiple failed login attempts (SSH, sudo)"
echo "  - Brute-force authentication patterns"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
