#!/usr/bin/env python3
"""Analyze attack_results.csv for extended SIEM metrics."""
import argparse
import csv
import datetime as dt
import json
import math
import os
import re
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
        value = float(val)
        return value if math.isfinite(value) and value >= 0 else None
    except Exception:
        return None


def parse_time(val):
    try:
        return dt.datetime.fromisoformat(val.replace('Z', '+00:00'))
    except Exception:
        return None


def normalize_classification(value):
    label = re.sub(r"[\s_-]+", "-", (value or "").strip().lower())
    return {"tp": "true-positive", "tn": "true-negative",
            "fp": "false-positive", "fn": "false-negative"}.get(label, label or "unknown")


def elapsed_seconds(start, end):
    if start is None or end is None:
        return None
    try:
        return to_float((end - start).total_seconds())
    except TypeError:
        return None  # Mixed timezone-aware and naive timestamps cannot be compared.


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
        classification = normalize_classification(r.get("classification"))
        classifications[classification] += 1

        atk_start = parse_time(r.get("attack_start_time", ""))
        alert_time = parse_time(r.get("alert_time", ""))
        a_start = parse_time(r.get("analysis_start_time", ""))
        r_start = parse_time(r.get("remediation_start_time", ""))
        r_end = parse_time(r.get("remediation_end_time", ""))

        for values, start, end in (
            (mtta_times, alert_time, a_start),
            (mttc_times, alert_time, r_start),
            (total_response_times, alert_time, r_end),
            (dwell_times, atk_start, r_end),
        ):
            elapsed = elapsed_seconds(start, end)
            if elapsed is not None:
                values.append(elapsed)

    tp = classifications.get("true-positive", 0)
    tn = classifications.get("true-negative", 0)
    fp = classifications.get("false-positive", 0)
    fn = classifications.get("false-negative", 0)
    classified = tp + tn + fp + fn

    def rate(numerator, denominator):
        return numerator / denominator * 100 if denominator else None

    def avg(values):
        return sum(values) / len(values) if values else None

    total_response_avg = avg(total_response_times)
    dwell_avg = avg(dwell_times)

    return {
        "sample_size": len(rows),
        "classified_sample_size": classified,
        "unclassified_samples": len(rows) - classified,
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "detection_rate_pct": rate(tp, tp + fn),
        "false_negative_rate_pct": rate(fn, tp + fn),
        "false_positive_rate_pct": rate(fp, fp + tn),
        "precision_pct": rate(tp, tp + fp),
        "alert_row_rate_pct": rate(alerts, len(rows)),
        "mttd_sec": avg(detection_times),
        "analysis_time_min": avg(analysis_times),
        "remediation_time_min": avg(remediation_times),
        "mtta_sec": avg(mtta_times),
        "mttc_sec": avg(mttc_times),
        "mttr_sec": total_response_avg,
        "total_response_sec": total_response_avg,  # kept for backward compatibility
        "dwell_time_sec": dwell_avg,
        "timing_sample_counts": {
            "mttd": len(detection_times), "analysis": len(analysis_times),
            "remediation": len(remediation_times), "mtta": len(mtta_times),
            "mttc": len(mttc_times), "mttr": len(total_response_times),
            "dwell": len(dwell_times),
        },
        "classifications": dict(classifications),
        "alerts": alerts,
        "no_alerts": no_alerts,
    }


def display(value):
    return f"{value:.2f}" if value is not None else "n/a"


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
    print(f"Classified samples: {summary['classified_sample_size']}")
    print(f"Unclassified samples excluded from classification rates: {summary['unclassified_samples']}")
    print(f"Detection rate: {display(summary['detection_rate_pct'])}%")
    print(f"False negative rate: {display(summary['false_negative_rate_pct'])}%")
    print(f"False positive rate: {display(summary['false_positive_rate_pct'])}%")
    print(f"Precision: {display(summary['precision_pct'])}%")
    print(f"MTTD: {display(summary['mttd_sec'])} sec")
    print(f"MTTA: {display(summary['mtta_sec'])} sec")
    print(f"MTTC: {display(summary['mttc_sec'])} sec")
    print(f"MTTR: {display(summary['mttr_sec'])} sec (alert → remediation_end)")
    print(f"Dwell time: {display(summary['dwell_time_sec'])} sec (attack_start → remediation_end)")
    print(f"Analysis time (avg): {display(summary['analysis_time_min'])} min")
    print(f"Remediation time (avg): {display(summary['remediation_time_min'])} min")
    print("Classifications:")
    for cls, count in summary['classifications'].items():
        print(f"  - {cls}: {count}")
    print(f"Summary written to: {out_path}")


if __name__ == "__main__":
    main()
