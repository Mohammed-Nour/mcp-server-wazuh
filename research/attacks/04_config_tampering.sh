#!/bin/bash
#===============================================================================
# Attack #04: Configuration File Tampering
# Category: File Integrity
# Expected Wazuh Rules: 550 (lvl7), 553 (lvl7), 554 (lvl5), 592 (lvl8)
# Expected Level: 5-8
# MITRE ATT&CK: T1543 (Create or Modify System Process)
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="04"
ATTACK_NAME="Configuration File Tampering"
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
echo -e "${RED}NOTE: This attack must be executed ON the target agent${NC}"
echo ""

START_TIME=$(date +%s.%N)
START_TIMESTAMP=$(date -Iseconds)

echo -e "${GREEN}[*] Attack started at: $START_TIMESTAMP${NC}"
echo ""

if [ "$MODE" = "ssh" ] && [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
    echo "[*] Running attack via SSH to $SSH_USER@$TARGET"
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$TARGET" "bash -s" <<'EOF'
BACKUP_DIR="/tmp/config_backup_$(date +%s)"
mkdir -p "$BACKUP_DIR"
echo "[*] Tampering with SSH configuration..."; sudo cp /etc/ssh/sshd_config "$BACKUP_DIR/" 2>/dev/null; echo "# Malicious SSH config changes" | sudo tee -a /etc/ssh/sshd_config >/dev/null; echo "PermitRootLogin yes" | sudo tee -a /etc/ssh/sshd_config >/dev/null; echo "PasswordAuthentication yes" | sudo tee -a /etc/ssh/sshd_config >/dev/null
echo "[*] Tampering with PAM configuration..."; sudo cp /etc/pam.d/common-auth "$BACKUP_DIR/" 2>/dev/null; echo "# Backdoor PAM module" | sudo tee -a /etc/pam.d/common-auth >/dev/null 2>&1
echo "[*] Tampering with sudoers..."; sudo cp /etc/sudoers "$BACKUP_DIR/" 2>/dev/null; echo "# Malicious sudoers entry" | sudo tee -a /etc/sudoers.d/backdoor >/dev/null 2>&1
echo "[*] Tampering with sysctl configuration..."; sudo cp /etc/sysctl.conf "$BACKUP_DIR/" 2>/dev/null; echo "# Disable security features" | sudo tee -a /etc/sysctl.conf >/dev/null; echo "kernel.randomize_va_space=0" | sudo tee -a /etc/sysctl.conf >/dev/null
if [ -f /etc/apache2/apache2.conf ]; then echo "[*] Tampering with Apache configuration..."; sudo cp /etc/apache2/apache2.conf "$BACKUP_DIR/"; echo "# Malicious Apache config" | sudo tee -a /etc/apache2/apache2.conf >/dev/null; fi
if [ -f /etc/nginx/nginx.conf ]; then echo "[*] Tampering with Nginx configuration..."; sudo cp /etc/nginx/nginx.conf "$BACKUP_DIR/"; echo "# Malicious Nginx config" | sudo tee -a /etc/nginx/nginx.conf >/dev/null; fi
echo "[*] Creating malicious systemd service..."; sudo tee /etc/systemd/system/backdoor.service >/dev/null 2>&1 <<EOFSVC
[Unit]
Description=Backdoor Service

[Service]
ExecStart=/bin/bash -c "while true; do sleep 3600; done"
Restart=always

[Install]
WantedBy=multi-user.target
EOFSVC
echo "[*] Sleeping for detection"; sleep 8
sudo cp "$BACKUP_DIR/sshd_config" /etc/ssh/sshd_config 2>/dev/null; sudo cp "$BACKUP_DIR/common-auth" /etc/pam.d/common-auth 2>/dev/null; sudo cp "$BACKUP_DIR/sysctl.conf" /etc/sysctl.conf 2>/dev/null; sudo rm -f /etc/sudoers.d/backdoor 2>/dev/null; sudo rm -f /etc/systemd/system/backdoor.service 2>/dev/null
if [ -f "$BACKUP_DIR/apache2.conf" ]; then sudo cp "$BACKUP_DIR/apache2.conf" /etc/apache2/apache2.conf 2>/dev/null; fi
if [ -f "$BACKUP_DIR/nginx.conf" ]; then sudo cp "$BACKUP_DIR/nginx.conf" /etc/nginx/nginx.conf 2>/dev/null; fi
echo "[*] Cleanup complete"
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
echo "Start Time: $START_TIMESTAMP"
echo "End Time: $END_TIMESTAMP"
echo "Duration: ${DURATION} seconds"
echo ""
echo "Expected Wazuh alerts:"
echo "  - Rule 550 (lvl7): File modification in /etc"
echo "  - Rule 553 (lvl7): File deletion (backup/restores)"
echo "  - Rule 554 (lvl5): File added (syscheck)"
echo "  - Rule 592 (lvl8): System file modification"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
