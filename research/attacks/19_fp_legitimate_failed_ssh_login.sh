#!/bin/bash
#===============================================================================
# Attack #19 (FP-1): Legitimate Failed SSH Login Attempts
# Category: False Positive / Authentication Noise
# Scenario: User types wrong password a few times (no malicious intent)
# Expected Wazuh Rules: 5501/5502/5503 (failed SSH auth), level ~5
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="FP-1"
ATTACK_NAME="Legitimate Failed SSH Login"
ATTACK_CATEGORY="FalsePositive"

TARGET="${1:-$TARGET_IP}"
SSH_USER="${TARGET_USER:-ubuntu}"
SSH_KEY_RAW="${SSH_KEY_OVERRIDE:-${TARGET_SSH_KEY:-$HOME/.ssh/wazuh-agent.pem}}"
SSH_KEY="${SSH_KEY_RAW/#\~/$HOME}"
ATTEMPTS="${ATTEMPTS:-6}"
DELAY="${DELAY:-1}"

ADMIN_HOST="${ADMIN_HOST_OVERRIDE:-${ADMIN_HOST:-""}}"
ADMIN_USER="${ADMIN_USER_OVERRIDE:-${ADMIN_USER:-${TARGET_USER:-ubuntu}}}"
ADMIN_KEY_RAW="${ADMIN_SSH_KEY_OVERRIDE:-${ADMIN_SSH_KEY:-$SSH_KEY_RAW}}"
ADMIN_KEY="${ADMIN_KEY_RAW/#\~/$HOME}"

if [ -z "$TARGET" ]; then
    echo -e "${RED}Error: No target IP/host specified${NC}"
    echo "Usage: $0 <target_host> [ATTEMPTS=4] [DELAY=1]"
    exit 1
fi

echo "==============================================================================="
echo -e "${YELLOW}ATTACK ${ATTACK_ID}: ${ATTACK_NAME}${NC}"
echo "==============================================================================="
echo "Target: $TARGET"
echo "Category: $ATTACK_CATEGORY"
echo "Attempts: $ATTEMPTS"
echo "Delay: ${DELAY}s"
echo "Executor: ${ADMIN_HOST:+admin over SSH → $ADMIN_HOST}"${ADMIN_HOST:++""}
[ -z "$ADMIN_HOST" ] && echo "Executor: local (this machine)"
echo ""

START_TIME=$(date +%s.%N)
START_TIMESTAMP=$(date -Iseconds)

echo -e "${GREEN}[*] Benign login noise started at: $START_TIMESTAMP${NC}"

COMMANDS=$(cat <<'EOF'
  if ! command -v sshpass >/dev/null 2>&1; then
    echo "sshpass not installed on executor" >&2
    exit 1
  fi

  for i in $(seq 1 ${ATTEMPTS}); do
    sshpass -p "wrongpassword" ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no "${SSH_USER}@${TARGET}" 'exit' 2>/dev/null || true
    sleep "${DELAY}"
  done
EOF
)

if [ -z "$ADMIN_HOST" ]; then
  echo "[*] Running locally"
  TARGET="$TARGET" SSH_USER="$SSH_USER" ATTEMPTS="$ATTEMPTS" DELAY="$DELAY" bash -lc "$COMMANDS"
else
  echo "[*] Running from admin host via SSH: $ADMIN_HOST"
  ssh -i "$ADMIN_KEY" -o StrictHostKeyChecking=no "$ADMIN_USER@$ADMIN_HOST" \
    "TARGET='$TARGET' SSH_USER='$SSH_USER' ATTEMPTS='$ATTEMPTS' DELAY='$DELAY' bash -lc '$COMMANDS'"
fi


END_TIME=$(date +%s.%N)
END_TIMESTAMP=$(date -Iseconds)
DURATION=$(echo "$END_TIME - $START_TIME" | bc)

echo ""
echo "==============================================================================="
echo -e "${GREEN}[✓] Benign failed logins completed${NC}"
echo "==============================================================================="
echo "End Time: $END_TIMESTAMP"
echo "Duration: ${DURATION} seconds"
echo ""
echo "Expected Wazuh alerts: failed SSH authentication (benign user errors)"
echo "Mitigation guidance: verify recent successful login and user context; avoid lockout"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
