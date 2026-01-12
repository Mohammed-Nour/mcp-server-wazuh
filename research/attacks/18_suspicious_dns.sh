#!/bin/bash
#===============================================================================
# Attack #18: Suspicious DNS Queries
# Category: Command & Control
# Expected Wazuh Rules: None observed in phase1 logs (enable DNS query logging)
# Expected Level: N/A (no alerts observed)
# MITRE ATT&CK: T1071.004 (DNS)
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/config.env" 2>/dev/null || true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ATTACK_ID="18"
ATTACK_NAME="Suspicious DNS Queries"
ATTACK_CATEGORY="Command & Control"

MODE="${1:-ssh}" # ssh | local
LOGGING="${2:-off}" # on|off — adds iptables LOG on OUTPUT udp/53
SSH_USER="${TARGET_USER:-ubuntu}"
SSH_KEY_RAW="${SSH_KEY_OVERRIDE:-${TARGET_SSH_KEY:-$HOME/.ssh/wazuh-agent.pem}}"
SSH_KEY="${SSH_KEY_RAW/#\~/$HOME}"

DOMAIN_LIST=(
    "malicious-domain.example"
    "c2.example.net"
    "dropzone.attacker.com"
    "exfil.badactor.io"
)

echo "==============================================================================="
echo -e "${YELLOW}ATTACK #${ATTACK_ID}: ${ATTACK_NAME}${NC}"
echo "==============================================================================="
echo "Mode: $MODE"
echo "Logging: $LOGGING (iptables LOG on agent OUTPUT udp/53)"
echo "Category: $ATTACK_CATEGORY"
echo ""

START_TIME=$(date +%s.%N)
START_TIMESTAMP=$(date -Iseconds)

echo -e "${GREEN}[*] Attack started at: $START_TIMESTAMP${NC}"
echo "[*] Issuing suspicious DNS lookups..."
echo ""

enable_dns_logging() {
    if [ "$LOGGING" != "on" ]; then
        return
    fi
    sudo iptables -N WAZUH_DNS_LOG 2>/dev/null || true
    sudo iptables -F WAZUH_DNS_LOG
    sudo iptables -A WAZUH_DNS_LOG -p udp --dport 53 -m limit --limit 10/second --limit-burst 40 -j LOG --log-prefix "wazuh-dns " --log-level info
    sudo iptables -I OUTPUT 1 -j WAZUH_DNS_LOG
}

disable_dns_logging() {
    if [ "$LOGGING" != "on" ]; then
        return
    fi
    sudo iptables -D OUTPUT -j WAZUH_DNS_LOG 2>/dev/null || true
    sudo iptables -F WAZUH_DNS_LOG 2>/dev/null || true
    sudo iptables -X WAZUH_DNS_LOG 2>/dev/null || true
}

run_payload() {
    enable_dns_logging
    for d in "${DOMAIN_LIST[@]}"; do
        sub=$(head -c 4 /dev/urandom | base64 | tr '/+' 'ab')
        fqdn="$sub.$d"
        echo "[*] Resolving $fqdn"
        dig +short "$fqdn" || true
        nslookup "$fqdn" 2>/dev/null || true
        host "$fqdn" 2>/dev/null || true
        sleep 1
    done
    disable_dns_logging
}

TARGET="${TARGET_IP:-localhost}"

if [ "$MODE" = "ssh" ] && [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
    echo "[*] Running attack via SSH to $SSH_USER@$TARGET_IP"
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$TARGET_IP" "LOGGING='$LOGGING'" "bash -s" <<'EOF'
DOMAIN_LIST=(
    "malicious-domain.example"
    "c2.example.net"
    "dropzone.attacker.com"
    "exfil.badactor.io"
)
enable_dns_logging() {
    if [ "$LOGGING" != "on" ]; then return; fi
    sudo iptables -N WAZUH_DNS_LOG 2>/dev/null || true
    sudo iptables -F WAZUH_DNS_LOG
    sudo iptables -A WAZUH_DNS_LOG -p udp --dport 53 -m limit --limit 10/second --limit-burst 40 -j LOG --log-prefix "wazuh-dns " --log-level info
    sudo iptables -I OUTPUT 1 -j WAZUH_DNS_LOG
}
disable_dns_logging() {
    if [ "$LOGGING" != "on" ]; then return; fi
    sudo iptables -D OUTPUT -j WAZUH_DNS_LOG 2>/dev/null || true
    sudo iptables -F WAZUH_DNS_LOG 2>/dev/null || true
    sudo iptables -X WAZUH_DNS_LOG 2>/dev/null || true
}
trap disable_dns_logging EXIT
enable_dns_logging
for d in "${DOMAIN_LIST[@]}"; do
    sub=$(head -c 4 /dev/urandom | base64 | tr '/+' 'ab')
    fqdn="$sub.$d"
    echo "[*] Resolving $fqdn"
    dig +short "$fqdn" || true
    nslookup "$fqdn" 2>/dev/null || true
    host "$fqdn" 2>/dev/null || true
    sleep 1
done
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
echo "Expected Wazuh alerts:"
echo "  - Suspicious DNS queries / potential C2 traffic (enable DNS/iptables logging)"
echo "  - iptables LOG lines with prefix 'wazuh-dns ' (if LOGGING=on)"
echo ""
echo "Data for CSV:"
echo "  attack_id: $ATTACK_ID"
echo "  attack_name: $ATTACK_NAME"
echo "  category: $ATTACK_CATEGORY"
echo "  attack_start_time: $START_TIMESTAMP"
echo "  attack_end_time: $END_TIMESTAMP"
