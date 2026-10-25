import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).parents[1] / "scripts" / "analyze_metrics.py"
spec = importlib.util.spec_from_file_location("analyze_metrics", SCRIPT)
metrics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metrics)


class MetricsTests(unittest.TestCase):
    def test_confusion_matrix_uses_classified_denominators(self):
        rows = [
            {"classification": "true-positive", "alert_generated": "Yes"},
            {"classification": "TRUE_POSITIVE", "alert_generated": "Yes"},
            {"classification": "false negative", "alert_generated": "No"},
            {"classification": "false-positive", "alert_generated": "Yes"},
            {"classification": "true-negative", "alert_generated": "No"},
            {"classification": "TN", "alert_generated": "No"},
            {"classification": "unknown", "alert_generated": "No"},
        ]
        summary = metrics.summarize(rows)
        self.assertEqual(summary["confusion_matrix"], {"tp": 2, "tn": 2, "fp": 1, "fn": 1})
        self.assertAlmostEqual(summary["detection_rate_pct"], 200 / 3)
        self.assertAlmostEqual(summary["false_negative_rate_pct"], 100 / 3)
        self.assertAlmostEqual(summary["false_positive_rate_pct"], 100 / 3)
        self.assertAlmostEqual(summary["precision_pct"], 200 / 3)
        self.assertAlmostEqual(summary["alert_row_rate_pct"], 300 / 7)
        self.assertEqual(summary["unclassified_samples"], 1)

    def test_no_alert_false_negative_is_counted_once(self):
        summary = metrics.summarize([{"classification": "false-negative", "alert_generated": "No"}])
        self.assertEqual(summary["false_negative_rate_pct"], 100)
        self.assertEqual(summary["detection_rate_pct"], 0)

    def test_true_negatives_are_not_true_positives(self):
        summary = metrics.summarize([{"classification": "true negative"}])
        self.assertIsNone(summary["precision_pct"])
        self.assertIsNone(summary["detection_rate_pct"])
        self.assertEqual(summary["false_positive_rate_pct"], 0)

    def test_labels_are_exact_and_short_forms_are_accepted(self):
        labels = [" TP ", "tn", "false_positive", "FALSE-NEGATIVE", "untrue", "true-positive (maybe)", None]
        summary = metrics.summarize([{"classification": value} for value in labels])
        self.assertEqual(summary["confusion_matrix"], {"tp": 1, "tn": 1, "fp": 1, "fn": 1})
        self.assertEqual(summary["classified_sample_size"], 4)
        self.assertEqual(summary["unclassified_samples"], 3)

    def test_no_alert_is_not_automatically_a_false_negative(self):
        summary = metrics.summarize([{"alert_generated": "No"}])
        self.assertIsNone(summary["false_negative_rate_pct"])
        self.assertEqual(summary["confusion_matrix"]["fn"], 0)

    def test_empty_data_has_no_measurements(self):
        summary = metrics.summarize([])
        for field in ("detection_rate_pct", "false_negative_rate_pct", "false_positive_rate_pct", "precision_pct", "alert_row_rate_pct", "mttd_sec", "mttr_sec"):
            with self.subTest(field=field):
                self.assertIsNone(summary[field])
        self.assertEqual(summary["sample_size"], 0)
        json.dumps(summary, allow_nan=False)

    def test_valid_zero_and_positive_timing_samples(self):
        summary = metrics.summarize([
            {"detection_time_seconds": "0", "analysis_time_minutes": "2"},
            {"detection_time_seconds": "10", "analysis_time_minutes": "4"},
        ])
        self.assertEqual(summary["mttd_sec"], 5)
        self.assertEqual(summary["analysis_time_min"], 3)
        self.assertEqual(summary["timing_sample_counts"]["mttd"], 2)

    def test_invalid_timing_samples_do_not_become_zero_or_nan(self):
        rows = [{"detection_time_seconds": value} for value in ("", "bad", "nan", "inf", "-1")]
        summary = metrics.summarize(rows)
        self.assertIsNone(summary["mttd_sec"])
        self.assertEqual(summary["timing_sample_counts"]["mttd"], 0)
        json.dumps(summary, allow_nan=False)

    def test_elapsed_timings_skip_negative_and_incompatible_pairs(self):
        summary = metrics.summarize([
            {"alert_time": "2026-01-01T00:00:00Z", "remediation_end_time": "2026-01-01T00:00:10Z"},
            {"alert_time": "2026-01-01T00:00:10Z", "remediation_end_time": "2026-01-01T00:00:00Z"},
            {"alert_time": "2026-01-01T00:00:00Z", "remediation_end_time": "2026-01-01T00:00:20"},
        ])
        self.assertEqual(summary["mttr_sec"], 10)
        self.assertEqual(summary["timing_sample_counts"]["mttr"], 1)

    def test_cli_handles_unavailable_metrics_and_phase_filter(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "results.csv"
            output = Path(temp) / "summary.json"
            path.write_text("phase,classification,alert_generated\n1,,No\n2,true-positive,Yes\n")
            result = subprocess.run([sys.executable, str(SCRIPT), "--phase", "1", "--results", str(path), "--out", str(output)], capture_output=True, text=True, check=True)
            self.assertIn("n/a", result.stdout)
            summary = json.loads(output.read_text())
            self.assertEqual(summary["sample_size"], 1)
            self.assertIsNone(summary["precision_pct"])


if __name__ == "__main__":
    unittest.main()
