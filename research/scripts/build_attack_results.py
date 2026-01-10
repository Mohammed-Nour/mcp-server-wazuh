#!/usr/bin/env python3
"""
Build a fresh attack_results CSV by parsing logs and alert JSON files.

Inputs (defaults match current repo layout):
    - Logs:    ../results/phase<N>/logs-attacks/<id>_*.log
    - Alerts:  ../results/phase<N>/alerts-from-wazuh/attack_<id>_alerts.json

Outputs:
    - ../results/phase<N>/attack_results_generated.csv

Fields mirror templates/attack_results.csv:
attack_id,attack_name,category,attack_start_time,attack_end_time,alert_generated,
alert_time,detection_time_seconds,rule_id,rule_level,rule_description,
analysis_start_time,analysis_end_time,analysis_time_minutes,remediation_start_time,
remediation_end_time,remediation_time_minutes,total_response_time_minutes,classification,phase,notes

Notes:
- Detection time is (first alert ts - attack_start), if both present.
- alert_time/rule_* are taken from the earliest alert in the JSON.
- classification/phase/notes left blank for manual filling; phase defaults to CURRENT_PHASE env or 1.
"""

import csv
import json
import os
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Tuple


ROOT = Path(__file__).resolve().parents[1]  # scripts/

def read_phase() -> int:
    env_phase = os.environ.get("CURRENT_PHASE")
    if env_phase and env_phase.isdigit():
        return int(env_phase)
    cfg = Path(__file__).parent / "config.env"
    if cfg.exists():
        m = re.search(r"CURRENT_PHASE=\"?(\d+)\"?", cfg.read_text())
        if m:
            return int(m.group(1))
    return 1


PHASE = read_phase()
RESULTS_ROOT = (ROOT / "results").resolve()  # run from research/scripts
PHASE_DIR = RESULTS_ROOT / f"phase{PHASE}"
ALERT_DIR = PHASE_DIR / "alerts-from-wazuh"
LOG_DIR = PHASE_DIR / "logs-attacks"
RESULTS_DIR = PHASE_DIR / "metrics"
OUTPUT_CSV = RESULTS_DIR / "attack_results_generated.csv"
ALERTS_FLAT_CSV = RESULTS_DIR / "attack_alerts_flat.csv"
RESPONSE_TIMES_FILE = RESULTS_DIR / "response_times.json"

# Ensure output directories exist (alerts/logs may already be created by other scripts)
for path in [PHASE_DIR, OUTPUT_CSV.parent, ALERTS_FLAT_CSV.parent]:
    path.mkdir(parents=True, exist_ok=True)


def normalize_ts(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    ts = ts.strip()
    # Common Wazuh formats: 2026-01-04T22:48:30.224+0000 or ...Z
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    if re.search(r"[+-]\d{4}$", ts):
        ts = ts[:-5] + ts[-5:-2] + ":" + ts[-2:]
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def parse_log(log_path: Path) -> Tuple[Optional[str], Optional[str], Optional[datetime], Optional[datetime]]:
    name = None
    category = None
    start = None
    end = None
    if not log_path or not log_path.exists():
        return name, category, start, end

    ansi_re = re.compile(r"\x1b\[[0-9;]*m")
    with log_path.open() as f:
        for line in f:
            line_clean = ansi_re.sub("", line.strip("\n"))
            m_name = re.search(r"ATTACK #\d+:\s*(.+)$", line_clean)
            if m_name:
                name = m_name.group(1).strip()
            m_cat = re.search(r"^Category:\s*(.+)$", line_clean)
            if m_cat:
                category = m_cat.group(1).strip()

            # Accept any "... started at:" phrasing (attack, benign, cron, system update, etc.)
            m_start = re.search(r"started at:\s*(.+)$", line_clean, re.IGNORECASE)
            if m_start:
                start = normalize_ts(m_start.group(1).strip())

            m_end = re.search(r"^End Time:\s*(.+)$", line_clean)
            if m_end:
                end = normalize_ts(m_end.group(1).strip())
    return name, category, start, end


def parse_alerts(alert_path: Path):
    if not alert_path.exists():
        return None, None, None, None
    try:
        data = json.loads(alert_path.read_text())
    except Exception:
        return None, None, None, None
    hits = data.get("hits", {}).get("hits", []) or []
    earliest = None
    rule_id = rule_level = rule_desc = None
    for h in hits:
        src = h.get("_source") or h.get("data") or {}
        ts = src.get("timestamp") or src.get("@timestamp") or src.get("event", {}).get("timestamp") or src.get("EventTime")
        dt = normalize_ts(ts) if ts else None
        if dt is None:
            continue
        if earliest is None or dt < earliest:
            earliest = dt
            rule = src.get("rule", {}) if isinstance(src.get("rule"), dict) else {}
            rule_id = rule.get("id")
            rule_level = rule.get("level")
            rule_desc = rule.get("description")
    return earliest, rule_id, rule_level, rule_desc


def flatten_alerts(alert_path: Path, attack_id: str, attack_name: str):
    rows = []
    if not alert_path.exists():
        return rows
    try:
        data = json.loads(alert_path.read_text())
    except Exception:
        return rows
    hits = data.get("hits", {}).get("hits", []) or []
    seen = set()  # dedupe per attack_name
    for h in hits:
        src = h.get("_source") or h.get("data") or {}
        ts = src.get("timestamp") or src.get("@timestamp") or src.get("event", {}).get("timestamp") or src.get("EventTime")
        dt = normalize_ts(ts) if ts else None
        rule = src.get("rule", {}) if isinstance(src.get("rule"), dict) else {}
        row = {
            "attack_id": attack_id,
            "attack_name": attack_name,
            "alert_time": dt.isoformat() if dt else "",
            "rule_id": rule.get("id", ""),
            "rule_level": rule.get("level", ""),
            "rule_description": rule.get("description", ""),
            "location": src.get("location", ""),
            "agent_id": (src.get("agent") or {}).get("id", ""),
        }
        key = (attack_name, row["alert_time"], row["rule_id"], row["rule_level"], row["rule_description"], row["location"], row["agent_id"])
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)
    return rows


def load_response_times(path: Path):
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {}
    if isinstance(data, dict):
        records = list(data.values())
    elif isinstance(data, list):
        records = data
    else:
        return {}
    by_attack = {}
    for rec in records:
        aid = str(rec.get("attack_id", "")).zfill(2)
        by_attack[aid] = rec
    return by_attack


def main():
    rows = []
    flat_rows = []
    response_times = load_response_times(RESPONSE_TIMES_FILE)
    alert_files = sorted(ALERT_DIR.glob("attack_*_alerts.json")) if ALERT_DIR.exists() else []
    for alert_file in alert_files:
        attack_id = alert_file.stem.split("_")[1]
        log_candidates = list(LOG_DIR.glob(f"{attack_id}_*.log")) if LOG_DIR.exists() else []
        log_path = log_candidates[0] if log_candidates else None
        name, category, start, end = parse_log(log_path) if log_path else (None, None, None, None)
        alert_time, rule_id, rule_level, rule_desc = parse_alerts(alert_file)
        flat_rows.extend(flatten_alerts(alert_file, attack_id, name or f"Attack_{attack_id}"))

        detection = None
        if alert_time and start:
            detection = (alert_time - start).total_seconds()

        rt = response_times.get(attack_id, {})
        a_start = normalize_ts(rt.get("analysis_start_time", "")) if rt else None
        a_end = normalize_ts(rt.get("analysis_end_time", "")) if rt else None
        r_start = normalize_ts(rt.get("remediation_start_time", "")) if rt else None
        r_end = normalize_ts(rt.get("remediation_end_time", "")) if rt else None

        analysis_minutes = None
        if a_start and a_end:
            analysis_minutes = (a_end - a_start).total_seconds() / 60.0
        remediation_minutes = None
        if r_start and r_end:
            remediation_minutes = (r_end - r_start).total_seconds() / 60.0
        total_response_minutes = None
        if alert_time and r_end:
            total_response_minutes = (r_end - alert_time).total_seconds() / 60.0

        rows.append({
            "attack_id": attack_id,
            "attack_name": name or f"Attack_{attack_id}",
            "category": category or "Unknown",
            "attack_start_time": start.isoformat() if start else "",
            "attack_end_time": end.isoformat() if end else "",
            "alert_generated": "Yes" if alert_time else "No",
            "alert_time": alert_time.isoformat() if alert_time else "",
            "detection_time_seconds": detection if detection is not None else "",
            "rule_id": rule_id or "",
            "rule_level": rule_level or "",
            "rule_description": rule_desc or "",
            "analysis_start_time": a_start.isoformat() if a_start else rt.get("analysis_start_time", "") if rt else "",
            "analysis_end_time": a_end.isoformat() if a_end else rt.get("analysis_end_time", "") if rt else "",
            "analysis_time_minutes": analysis_minutes if analysis_minutes is not None else "",
            "remediation_start_time": r_start.isoformat() if r_start else rt.get("remediation_start_time", "") if rt else "",
            "remediation_end_time": r_end.isoformat() if r_end else rt.get("remediation_end_time", "") if rt else "",
            "remediation_time_minutes": remediation_minutes if remediation_minutes is not None else "",
            "total_response_time_minutes": total_response_minutes if total_response_minutes is not None else "",
            "classification": rt.get("classification", "") if rt else "",
            "phase": PHASE,
            "notes": rt.get("notes", "") if rt else "",
        })

    header = [
        "attack_id","attack_name","category","attack_start_time","attack_end_time",
        "alert_generated","alert_time","detection_time_seconds","rule_id","rule_level",
        "rule_description","analysis_start_time","analysis_end_time","analysis_time_minutes",
        "remediation_start_time","remediation_end_time","remediation_time_minutes",
        "total_response_time_minutes","classification","phase","notes"
    ]

    with OUTPUT_CSV.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for row in rows:
            writer.writerow([row.get(h, "") for h in header])

    flat_header = ["attack_id","attack_name","alert_time","rule_id","rule_level","rule_description","location","agent_id"]
    with ALERTS_FLAT_CSV.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(flat_header)
        for row in flat_rows:
            writer.writerow([row.get(h, "") for h in flat_header])

    print(f"Wrote {len(rows)} rows to {OUTPUT_CSV}")
    print(f"Wrote {len(flat_rows)} alert rows to {ALERTS_FLAT_CSV}")


if __name__ == "__main__":
    main()
