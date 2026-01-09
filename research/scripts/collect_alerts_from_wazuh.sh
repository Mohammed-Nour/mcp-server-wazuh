#!/bin/bash
# Collect alerts for a given attack window (JSON only)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/config.env" 2>/dev/null || true

ATTACK_ID="${1:-}"
ATTACK_START="${2:-}"
ATTACK_END="${3:-$(date -Iseconds)}"
SOURCE_JSON="${4:-}"
PHASE="${CURRENT_PHASE:-1}"

if [ "${RESULTS_DIR:-}" = "../results" ]; then
  RESULTS_DIR="$PROJECT_ROOT/results"
else
  RESULTS_DIR="${RESULTS_DIR:-$PROJECT_ROOT/results}"
fi

# Normalize to absolute and create phase alerts folder
RESULTS_DIR="$(cd "$PROJECT_ROOT" && mkdir -p "$RESULTS_DIR" && cd "$RESULTS_DIR" && pwd)"
ALERTS_DIR="$RESULTS_DIR/phase${PHASE}/alerts-from-wazuh"
ALERT_FILE="$ALERTS_DIR/attack_${ATTACK_ID}_alerts.json"

if [ -z "$ATTACK_ID" ] || [ -z "$ATTACK_START" ]; then
  echo "Usage: $0 <attack_id> <attack_start_timestamp> [attack_end_timestamp] [alerts_json]"
  exit 1
fi

mkdir -p "$ALERTS_DIR"
cd "$ALERTS_DIR" || exit 1

if [ -n "$SOURCE_JSON" ] && [ -f "$SOURCE_JSON" ]; then
  cp "$SOURCE_JSON" "$ALERT_FILE"
  echo "[*] Copied provided alerts JSON to $ALERT_FILE"
elif [ -n "${WAZUH_INDEXER:-}" ] && [ -n "${WAZUH_INDEXER_USER:-}" ] && [ -n "${WAZUH_INDEXER_PASS:-}" ]; then
  echo "[*] Querying indexer ${WAZUH_INDEXER} for alerts between $ATTACK_START and $ATTACK_END"
  curl -s -k -u "$WAZUH_INDEXER_USER:$WAZUH_INDEXER_PASS" \
    -H 'Content-Type: application/json' \
    -X POST "${WAZUH_INDEXER%/}/wazuh-alerts-*/_search" \
    -d "{\"size\":5000,\"query\":{\"range\":{\"timestamp\":{\"gte\":\"$ATTACK_START\",\"lte\":\"$ATTACK_END\"}}}}" \
    -o "$ALERT_FILE"
else
  echo "[!] WAZUH_INDEXER credentials not set and no source JSON provided"
  exit 1
fi

echo "[*] Alerts saved to $ALERT_FILE"
