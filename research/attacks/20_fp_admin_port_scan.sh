#!/bin/bash
#===============================================================================
# Attack #21 (FP-2): Legitimate Port Scan by Network Admin
# Category: False Positive / Recon (authorized)
# Scenario: Admin performs internal discovery with nmap during business hours
# Expected Wazuh Rules: Port scan detections (level ~7) but should be classified benign
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="FP-2"
ATTACK_NAME="Admin Legitimate Port Scan"
ATTACK_CATEGORY="FalsePositive"

TARGET_SUBNET="${1:-${TARGET_IP:-""}}"
SCAN_TYPE="${2:--sV --reason}"
ADMIN_HOST="${ADMIN_HOST_OVERRIDE:-${ADMIN_HOST:-""}}"   # where the scan originates (admin workstation)
ADMIN_USER="${ADMIN_USER_OVERRIDE:-${ADMIN_USER:-${TARGET_USER:-ubuntu}}}"
ADMIN_KEY_RAW="${ADMIN_SSH_KEY_OVERRIDE:-${ADMIN_SSH_KEY:-${TARGET_SSH_KEY:-$HOME/.ssh/wazuh-agent.pem}}}"
ADMIN_KEY="${ADMIN_KEY_RAW/#\~/$HOME}"

if [ -z "$TARGET_SUBNET" ]; then
    echo -e "${RED}Error: No target subnet specified${NC}"
    echo "Usage: $0 <subnet> [scan_type]"
    exit 1
fi

echo "==============================================================================="
echo -e "${YELLOW}ATTACK ${ATTACK_ID}: ${ATTACK_NAME}${NC}"
echo "==============================================================================="
echo "Target Subnet: $TARGET_SUBNET"
echo "Scan Type: $SCAN_TYPE"
echo "Origin: ${ADMIN_HOST:-local (this machine)}"
echo "Category: $ATTACK_CATEGORY"
echo "Note: This simulates authorized admin scanning"
echo ""

START_TIME=$(date +%s.%N)
START_TIMESTAMP=$(date -Iseconds)

echo -e "${GREEN}[*] Benign admin scan started at: $START_TIMESTAMP${NC}"

default_cmd="if command -v nmap >/dev/null 2>&1; then sudo nmap ${SCAN_TYPE} ${TARGET_SUBNET}; else echo '[!] nmap not installed on executor'; fi"

if [ -n "$ADMIN_HOST" ]; then
    echo "[*] Running from admin host via SSH: $ADMIN_HOST"
    ssh -i "$ADMIN_KEY" -o StrictHostKeyChecking=no "$ADMIN_USER@$ADMIN_HOST" "$default_cmd"
else
    eval "$default_cmd"
fi

END_TIME=$(date +%s.%N)
END_TIMESTAMP=$(date -Iseconds)
DURATION=$(echo "$END_TIME - $START_TIME" | bc)

echo ""
echo "==============================================================================="
echo -e "${GREEN}[✓] Admin scan completed${NC}"
echo "==============================================================================="
echo "End Time: $END_TIMESTAMP"
echo "Duration: ${DURATION} seconds"
echo ""
echo "Expected Wazuh alerts: Port scan detections (benign admin activity)"
echo "Mitigation guidance: check source IP is whitelisted admin host and business hours"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
