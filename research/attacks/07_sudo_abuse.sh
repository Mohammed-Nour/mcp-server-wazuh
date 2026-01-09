#!/bin/bash
#===============================================================================
# Attack #07: Sudo Abuse / Privilege Escalation
# Category: Privilege Escalation
# Expected Wazuh Rules: 5402 (lvl3)
# Expected Level: 3 (observed)
# MITRE ATT&CK: T1548.003 (Abuse Elevation Control Mechanism: Sudo)
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="07"
ATTACK_NAME="Sudo Abuse"
ATTACK_CATEGORY="Privilege Escalation"

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
echo ""

ATTACK_COMMANDS='
#!/bin/bash
echo "[*] Sudo abuse / privilege escalation attack..."

# 1. Multiple failed sudo attempts (wrong password)
echo "[*] Simulating failed sudo attempts..."
for i in {1..10}; do
    echo "wrongpassword" | sudo -S ls /root 2>/dev/null
    sleep 0.5
done

# 2. Sudo to root shell
echo ""
echo "[*] Attempting sudo to root..."
sudo whoami
sudo id

# 3. Sudo with suspicious commands
echo ""
echo "[*] Running suspicious commands with sudo..."
sudo cat /etc/shadow | head -3
sudo cat /etc/sudoers | head -5
sudo ls -la /root/

# 4. Sudo -i (interactive root shell simulation)
echo ""
echo "[*] Simulating sudo -i..."
sudo -i bash -c "echo Running as root: $(whoami)"

# 5. Check sudo privileges (reconnaissance)
echo ""
echo "[*] Sudo reconnaissance..."
sudo -l 2>/dev/null

# 6. Sudo with NOPASSWD abuse simulation
echo ""
echo "[*] Checking for NOPASSWD entries..."
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null

# 7. Attempt to modify sudoers (will likely fail without root)
echo ""
echo "[*] Attempting sudoers modification..."
echo "testuser ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/backdoor_test 2>/dev/null
sudo rm /etc/sudoers.d/backdoor_test 2>/dev/null

# 8. Sudo with environment variables (potential bypass)
echo ""
echo "[*] Testing sudo with environment preservation..."
sudo -E env | grep -i path | head -3

# 9. Su attempts
echo ""
echo "[*] Simulating su attempts..."
for i in {1..5}; do
    echo "wrongpass" | su - root 2>/dev/null
    sleep 0.5
done

# 10. SUID binary abuse check
echo ""
echo "[*] Searching for SUID binaries..."
find /usr/bin -perm -4000 2>/dev/null | head -10

echo ""
echo "[*] Privilege escalation simulation complete"
'

echo "[*] Commands to run on target agent:"
echo ""
echo "$ATTACK_COMMANDS"



TARGET="${1:-$TARGET_IP}"
SSH_KEY_RAW="${SSH_KEY_OVERRIDE:-${TARGET_SSH_KEY:-$HOME/.ssh/wazuh-agent.pem}}"
SSH_USER="${3:-${TARGET_USER:-ubuntu}}"
SSH_KEY="${SSH_KEY_RAW/#\~/$HOME}"



if [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
    echo "[*] Running attack via SSH using key $SSH_KEY ..."
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
echo -e "${GREEN}[✓] Attack script generated${NC}"
echo "==============================================================================="
echo "Start Time: $START_TIMESTAMP"
echo "End Time: $END_TIMESTAMP"
echo ""
echo "Expected Wazuh alerts:"
echo "  - Rule 5401: First time user executed sudo"
echo "  - Rule 5402: Failed attempt to run sudo"
echo "  - Rule 5403: Successful sudo to root"
echo "  - Rule 5404: User NOT in sudoers file"
echo "  - Rule 5405: sudo authentication failure"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
