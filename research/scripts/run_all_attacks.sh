#!/bin/bash
# Run all attack scripts sequentially, log output, and collect Wazuh alerts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/config.env" 2>/dev/null || true

TARGET="${1:-$TARGET_IP}"
PHASE="${CURRENT_PHASE:-1}"
RESULTS_DIR="${RESULTS_DIR:-$PROJECT_ROOT/results}"

# Normalize RESULTS_DIR to an absolute path before changing directories
PHASE_DIR="$RESULTS_DIR/phase${PHASE}"

LOG_DIR="$PHASE_DIR/logs-attacks"
mkdir -p "$LOG_DIR"

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target_ip> [delay_seconds]"
  exit 1
fi

cd "$PROJECT_ROOT/attacks" || exit 1

mapfile -t ATTACK_SCRIPTS < <(ls -1 [0-9][0-9]_*.sh 2>/dev/null | sort)

if [ ${#ATTACK_SCRIPTS[@]} -eq 0 ]; then
  echo "No attack scripts found."
  exit 1
fi

echo "Running ${#ATTACK_SCRIPTS[@]} attacks against $TARGET logs -> $LOG_DIR"
for script in "${ATTACK_SCRIPTS[@]}"; do
  ATTACK_ID="${script:0:2}"
  START_TS=$(date -Iseconds)
  LOG_FILE="$LOG_DIR/${script%.sh}.log"

  echo "------------------------------------------------------------"
  echo "Starting $script (log: $LOG_FILE)"

  # Run and tee output
  if ! bash "$script" "$TARGET" 2>&1 | tee "$LOG_FILE"; then
    echo "[!] $script failed; continuing"
  fi

  END_TS=$(date -Iseconds)

  if [ -x "$SCRIPT_DIR/collect_alerts_from_wazuh.sh" ] && [ "${COLLECT_IMMEDIATE:-1}" = "1" ]; then
    echo "[*] COLLECT_IMMEDIATE=1 -> collecting alerts for attack $ATTACK_ID ($START_TS -> $END_TS)"
    "$SCRIPT_DIR/collect_alerts_from_wazuh.sh" "$ATTACK_ID" "$START_TS" "$END_TS" || echo "[!] collect_alerts_from_wazuh failed"
  else
    echo "[*] Skipping immediate collection for $ATTACK_ID (set COLLECT_IMMEDIATE=1 to enable)"
  fi
done

echo "All attacks completed. Logs at $LOG_DIR"
