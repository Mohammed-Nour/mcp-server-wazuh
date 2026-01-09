#!/bin/bash
#===============================================================================
# Attack #13: Rootkit Indicator Simulation
# Category: Rootkit / Persistence
# Expected Wazuh Rules: 550 (lvl7), 554 (lvl5)
# Expected Level: 5-7 (observed)
# MITRE ATT&CK: T1014 (Rootkit)
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="13"
ATTACK_NAME="Rootkit Indicator"
ATTACK_CATEGORY="Rootkit"

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
echo "[*] Dropping files and entries that mimic rootkit artifacts..."
echo ""

ATTACK_COMMANDS='
#!/bin/bash
echo "[*] Creating suspicious hidden files and modules..."
sudo mkdir -p /tmp/.rkdir
echo "rootkit payload" | sudo tee /tmp/.rkdir/.rkpayload >/dev/null
sudo touch /etc/ld.so.preload
echo "# malicious preload" | sudo tee -a /etc/ld.so.preload >/dev/null
echo "[+] Fake rootkit artifacts created"

echo "[*] Creating suspicious kernel module entry (fake)"
echo "malicious 999 0 - Live 0xffffffffc0000000" | sudo tee -a /proc/modules >/dev/null || true

echo "[*] Creating persistence via rc.local" 
echo "# rc.local backdoor" | sudo tee -a /etc/rc.local >/dev/null
echo "exit 0" | sudo tee -a /etc/rc.local >/dev/null

echo "[*] Listing artifacts for verification" 
sudo ls -la /tmp/.rkdir
sudo head -n 5 /etc/ld.so.preload 2>/dev/null || true
sudo tail -n 5 /proc/modules 2>/dev/null || true
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
echo "  - Rootkit detection triggers"
echo "  - FIM alerts on /etc/ld.so.preload and rc.local"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
