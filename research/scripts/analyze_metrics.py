#!/usr/bin/env python3
"""Analyze attack_results.csv for extended SIEM metrics."""
import argparse
import csv
import datetime as dt
import json
import os
from collections import defaultdict
from pathlib import Path


def parse_args():
    env_phase = os.environ.get("CURRENT_PHASE")
    default_phase = int(env_phase) if env_phase and env_phase.isdigit() else 1
    default_results = f"../results/phase{default_phase}/metrics/attack_results_generated.csv"
    p = argparse.ArgumentParser(description="Analyze Wazuh research metrics")
    p.add_argument("--results", default=default_results,
                   help=f"Path to attack_results.csv (default: {default_results})")
    p.add_argument("--phase", type=int, choices=[1, 2], default=None,
                   help="Filter by phase (1 or 2)")
    p.add_argument("--out", default=None,
                   help="Optional path to write summary JSON (default: metrics_summary.json next to results)")
    return p.parse_args()


def load_rows(path: Path):
    with path.open() as f:
        reader = csv.DictReader(f)
        rows = [r for r in reader if any(r.values())]
    return rows


def to_float(val):
    try:
        return float(val)
    except Exception:
        return None


def parse_time(val):
    try:
        return dt.datetime.fromisoformat(val.replace('Z', '+00:00'))
    except Exception:
        return None


def summarize(rows):
    detection_times = []
    analysis_times = []
    remediation_times = []
    classifications = defaultdict(int)
    mtta_times = []
    mttc_times = []
    total_response_times = []
    dwell_times = []
    alerts = 0
    no_alerts = 0
    tp = fp = fn_labeled = 0

    for r in rows:
        if r.get("alert_generated", "").lower().startswith("y"):
            alerts += 1
        else:
            no_alerts += 1

        dt_secs = to_float(r.get("detection_time_seconds", ""))
        if dt_secs is not None:
            detection_times.append(dt_secs)
        an_min = to_float(r.get("analysis_time_minutes", ""))
        if an_min is not None:
            analysis_times.append(an_min)
        rm_min = to_float(r.get("remediation_time_minutes", ""))
        if rm_min is not None:
            remediation_times.append(rm_min)
        cls_raw = r.get("classification", "").strip().lower() or "unknown"
        classifications[cls_raw] += 1
        if "false positive" in cls_raw:
            fp += 1
        elif "true" in cls_raw:
            tp += 1
        elif "false negative" in cls_raw:
            fn_labeled += 1

        atk_start = parse_time(r.get("attack_start_time", ""))
        alert_time = parse_time(r.get("alert_time", ""))
        a_start = parse_time(r.get("analysis_start_time", ""))
        r_start = parse_time(r.get("remediation_start_time", ""))
        r_end = parse_time(r.get("remediation_end_time", ""))

        if alert_time and a_start:
            mtta_times.append((a_start - alert_time).total_seconds())
        if alert_time and r_start:
            mttc_times.append((r_start - alert_time).total_seconds())
        if alert_time and r_end:
            total_response_times.append((r_end - alert_time).total_seconds())
        if atk_start and r_end:
            dwell_times.append((r_end - atk_start).total_seconds())

    total = len(rows) if rows else 1
    detection_rate = alerts / total * 100
    fn_rate = (no_alerts + fn_labeled) / total * 100
    fp_rate = (fp / total) * 100 if total else 0
    precision = tp / (tp + fp) * 100 if (tp + fp) else 0

    def avg(values):
        return sum(values) / len(values) if values else 0

    total_response_avg = avg(total_response_times)
    dwell_avg = avg(dwell_times)

    return {
        "sample_size": len(rows),
        "detection_rate_pct": detection_rate,
        "false_negative_rate_pct": fn_rate,
        "false_positive_rate_pct": fp_rate,
        "precision_pct": precision,
        "mttd_sec": avg(detection_times),
        "analysis_time_min": avg(analysis_times),
        "remediation_time_min": avg(remediation_times),
        "mtta_sec": avg(mtta_times),
        "mttc_sec": avg(mttc_times),
        "mttr_sec": total_response_avg,
        "total_response_sec": total_response_avg,  # kept for backward compatibility
        "dwell_time_sec": dwell_avg,
        "classifications": dict(classifications),
        "alerts": alerts,
        "no_alerts": no_alerts,
    }


def main():
    args = parse_args()
    path = Path(args.results).resolve()
    if not path.exists():
        raise SystemExit(f"Results file not found: {path}")

    rows = load_rows(path)
    if args.phase is not None:
        rows = [r for r in rows if r.get("phase") == str(args.phase)]

    summary = summarize(rows)
    out_path = Path(args.out).resolve() if args.out else path.parent / "metrics_summary.json"
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("=== Metrics Summary ===")
    print(f"Samples: {summary['sample_size']}")
    print(f"Detection rate: {summary['detection_rate_pct']:.2f}%")
    print(f"False negative rate: {summary['false_negative_rate_pct']:.2f}%")
    print(f"False positive rate: {summary['false_positive_rate_pct']:.2f}%")
    print(f"Precision: {summary['precision_pct']:.2f}%")
    print(f"MTTD: {summary['mttd_sec']:.2f} sec")
    print(f"MTTA: {summary['mtta_sec']:.2f} sec")
    print(f"MTTC: {summary['mttc_sec']:.2f} sec")
    print(f"MTTR: {summary['mttr_sec']:.2f} sec (alert → remediation_end)")
    print(f"Dwell time: {summary['dwell_time_sec']:.2f} sec (attack_start → remediation_end)")
    print(f"Analysis time (avg): {summary['analysis_time_min']:.2f} min")
    print(f"Remediation time (avg): {summary['remediation_time_min']:.2f} min")
    print("Classifications:")
    for cls, count in summary['classifications'].items():
        print(f"  - {cls}: {count}")
    print(f"Summary written to: {out_path}")


if __name__ == "__main__":
    main()
