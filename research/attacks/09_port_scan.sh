#!/bin/bash
#===============================================================================
# Attack #09: Network Port Scan (nmap)
# Category: Network Reconnaissance
# Expected Wazuh Rules: None observed in phase1 logs (enable firewall/IDS logging)
# Expected Level: N/A (no alerts observed)
# MITRE ATT&CK: T1046 (Network Service Discovery)
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="09"
ATTACK_NAME="Network Port Scan"
ATTACK_CATEGORY="Network"

TARGET="${1:-$TARGET_IP}"
PORT_RANGE="${2:-1-1000}"
SCAN_TYPE="${3:--sS}" # default SYN scan
MODE="${4:-basic}" # basic | aggressive
LOGGING="${5:-off}" # on|off — add iptables LOG on agent for detection
SSH_USER="${TARGET_USER:-ubuntu}"
SSH_KEY_RAW="${SSH_KEY_OVERRIDE:-${TARGET_SSH_KEY:-$HOME/.ssh/wazuh-agent.pem}}"
SSH_KEY="${SSH_KEY_RAW/#\~/$HOME}"

if [ -z "$TARGET" ]; then
    echo -e "${RED}Error: No target IP specified${NC}"
    echo "Usage: $0 <target_ip> [port_range] [scan_type]"
    exit 1
fi

echo "==============================================================================="
echo -e "${YELLOW}ATTACK #${ATTACK_ID}: ${ATTACK_NAME}${NC}"
echo "==============================================================================="
echo "Target: $TARGET"
echo "Port Range: $PORT_RANGE"
echo "Scan Type: $SCAN_TYPE"
echo "Mode: $MODE"
echo "Logging: $LOGGING (iptables LOG on agent INPUT)"
echo "Category: $ATTACK_CATEGORY"
echo "Note: run this from the attacker machine, targeting the Wazuh agent's IP"
echo ""

START_TIME=$(date +%s.%N)
START_TIMESTAMP=$(date -Iseconds)

echo -e "${GREEN}[*] Attack started at: $START_TIMESTAMP${NC}"
echo "[*] Running nmap port scan..."
echo ""

echo "[*] Performing port scan from $(hostname)..."
if command -v nmap >/dev/null 2>&1; then
    if [ "$MODE" = "aggressive" ]; then
        echo "[*] Aggressive mode: SYN, TCP connect, UDP top, and service/version probes"
        sudo nmap -T4 -sS -Pn -p "$PORT_RANGE" "$TARGET"
        sudo nmap -T4 -sT -Pn -p "$PORT_RANGE" "$TARGET"
        sudo nmap -T4 -sU --top-ports 200 "$TARGET"
        sudo nmap -T4 -sV -Pn --version-intensity 9 -p "$PORT_RANGE" "$TARGET"
    else
        sudo nmap $SCAN_TYPE -Pn -p "$PORT_RANGE" "$TARGET"
    fi
else
    echo "[!] nmap not installed; falling back to bash /dev/tcp scan"
    IFS='-' read -r START END <<< "$PORT_RANGE"
    START=${START:-1}
    END=${END:-$START}
    for port in $(seq "$START" "$END"); do
        timeout 1 bash -c ": </dev/tcp/$TARGET/$port" 2>/dev/null && echo "Port $port open" || true
    done | head -n 200
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
echo "  - Port scan detection (rules 40008/40012/40013) if firewall/IDS logging enabled"
echo "  - iptables LOG lines with prefix 'wazuh-portscan ' on agent (if LOGGING=on)"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
