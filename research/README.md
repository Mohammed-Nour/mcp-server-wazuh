# Wazuh incident-response experiments

I use these scripts to study incident response with the Wazuh MCP Server. The folder contains 24 scenarios: 18 attack simulations and six scenarios for legitimate activity, along with scripts to collect alerts and analyze the results.

## Folder structure

```text
research/
├── attacks/                    # 24 scripts: 18 attack + 6 intended benign
│   ├── 01_ssh_brute_force.sh
│   ├── 02_web_brute_force.sh
│   ├── ...
│   ├── 18_suspicious_dns.sh
│   ├── 19_fp_legitimate_failed_ssh_login.sh
│   ├── ...
│   └── 24_fp_legitimate_sudo_install.sh
├── scripts/                    # Helper and analysis scripts
│   ├── config.env              # Create locally; not supplied in the repository
│   ├── collect_alerts_from_wazuh.sh # Pull alerts for a given attack window into phase folders
│   ├── analyze_metrics.py      # Calculate MTTD/MTTR/FP rate from CSV
│   ├── run_all_attacks.sh      # Run scenarios sequentially, optionally collecting alerts
│   └── build_attack_results.py # Build CSVs from collected logs and alerts
├── results/
│   ├── phase0/                 # Example completed phase (do not modify)
│   │   ├── alerts-from-wazuh/  # attack_<id>_alerts.json per attack
│   │   ├── logs-attacks/       # <id>_*.log from each attack
│   │   ├── metrics/            # Generated CSVs and optional response timing data
│   │   └── mitigations-evidence/ # manual evidence storage
│   ├── phase1/                 # Baseline run outputs live here
│   └── phase2/                 # Enhanced run outputs live here
└── README.md                   # This file
```

## Prerequisites

### On the attack machine
```bash
sudo apt update
sudo apt install -y hydra nmap nikto netcat curl wget sshpass jq bc
```

### On the target agent instance
```bash
# Install vulnerable services for testing
sudo apt install -y openssh-server apache2 vsftpd
```

## Usage

### 1. Configure the environment
From the `research/` directory, create `scripts/config.env` locally with your isolated lab settings. Do not commit credentials:
```bash
TARGET_IP="your-agent-instance-ip"
TARGET_USER="your-user"
TARGET_SSH_KEY="your-ssh-key"

WAZUH_INDEXER="https://your-wazuh-indexer-host:9200"
WAZUH_INDEXER_USER="wazuh"
WAZUH_INDEXER_PASS="your-password"

RESULTS_DIR="/absolute/path/to/mcp-server-wazuh/research/results"

CURRENT_PHASE="1"
```

The runner and collector resolve relative `RESULTS_DIR` paths against `research/`. The legacy value `../results` also resolves to `research/results`. Use this directory when you plan to run the CSV builder, which reads it directly. An absolute path works too.

### 2. Run an individual scenario

Run these commands from the repository root:

```bash
cd research/attacks
./01_ssh_brute_force.sh <target_ip>
```

### 3. Run all scenarios

In a shell at the repository root:

```bash
cd research/scripts
./run_all_attacks.sh
```

This runs all 24 scripts, including the six intended benign scenarios. It also attempts to collect alerts after each script unless `COLLECT_IMMEDIATE=0` is set.

### 4. Collect alerts separately

In a shell at the repository root:

```bash
cd research/scripts
./collect_alerts_from_wazuh.sh <attack_id> <attack_start_timestamp> [attack_end_timestamp]
```

The collector saves JSON to `results/phase<N>/alerts-from-wazuh/attack_<id>_alerts.json`. It queries alerts by time window, so review the results for unrelated activity. It does not create a metrics CSV.

### 5. Build and analyze the results

In a shell at the repository root:

```bash
cd research/scripts
CURRENT_PHASE=1 python3 build_attack_results.py
```

The builder writes `attack_results_generated.csv` and `attack_alerts_flat.csv` to `research/results/phase1/metrics/`. It rebuilds these files, so keep a copy of any manual edits first. Response timings and classifications can be supplied in that phase's `metrics/response_times.json`.

Review the generated CSV, fill in any missing classifications or timing data from the experiment records, then run:

```bash
python3 analyze_metrics.py --phase 1 --results ../results/phase1/metrics/attack_results_generated.csv
```

Use phase `2` in both commands when analyzing phase 2.

## Attack scenarios

The table lists the expected rules and levels used in the experiment. Check the collected alerts for the actual values, since they depend on the Wazuh configuration.

| # | Attack | Category | Expected Rule | Level |
|---|--------|----------|---------------|-------|
| 01 | SSH Brute Force | Brute Force | 5710, 5712 | 10 |
| 02 | Web Login Brute Force | Brute Force | 31151 | 10 |
| 03 | File Modification | File Integrity | 550, 554 | 7-10 |
| 04 | Config Tampering | File Integrity | 550 | 12 |
| 05 | EICAR Test File | Malware | 510 | 8 |
| 06 | Suspicious Script | Malware | 5902 | 7 |
| 07 | Sudo Abuse | Privilege Escalation | 5401, 5402 | 10-12 |
| 08 | User to Sudoers | Privilege Escalation | 5904 | 8 |
| 09 | Port Scan | Network | 5706 | 6-8 |
| 10 | Suspicious Outbound / Reverse Shell | Network | 5902 | 7 |
| 11 | SQL Injection | Web Attack | 31103 | 10-12 |
| 12 | XSS Attempt | Web Attack | 31105 | 8 |
| 13 | Rootkit Simulation | Rootkit | 510 | 12-15 |
| 14 | Service Manipulation | System | 5902 | 8-10 |
| 15 | Cron Job Modification | System | 550 | 7-9 |
| 16 | Multiple Failed Auth | Authentication | 5301 | 5-10 |
| 17 | Log Tampering / Deletion | Log Tampering | 554, 60611 | 12 |
| 18 | Suspicious DNS | Command & Control | 5302 | 8 |

## Intended benign scenarios

| # | Scenario | Script |
|---|----------|--------|
| 19 | Legitimate failed SSH login | [19_fp_legitimate_failed_ssh_login.sh](attacks/19_fp_legitimate_failed_ssh_login.sh) |
| 20 | Authorized administrator port scan | [20_fp_admin_port_scan.sh](attacks/20_fp_admin_port_scan.sh) |
| 21 | Legitimate cron job | [21_fp_legitimate_cron_job.sh](attacks/21_fp_legitimate_cron_job.sh) |
| 22 | System update | [22_fp_system_update.sh](attacks/22_fp_system_update.sh) |
| 23 | Authorized SSH key addition | [23_fp_ssh_key_addition.sh](attacks/23_fp_ssh_key_addition.sh) |
| 24 | Legitimate package installation with sudo | [24_fp_legitimate_sudo_install.sh](attacks/24_fp_legitimate_sudo_install.sh) |

I included these scenarios to test how the system handles legitimate activity. The `fp` prefix identifies the scenario; it does not mean every resulting alert is a false positive. Check the activity, its authorization, and the system decision before assigning a classification.

Check which scenarios have saved records in each phase before comparing the results.

## Reading the metrics

The analysis script reports detection and response timings, along with classification counts and rates:

- MTTD: average time from scenario start to the first recorded alert.
- MTTR: average time from an alert to the recorded end of remediation.
- Analysis time: average duration between the recorded analysis start and end.
- `detection_rate_pct`: TP / (TP + FN), using classified attack scenarios.
- `false_negative_rate_pct`: FN / (TP + FN).
- `false_positive_rate_pct`: FP / (FP + TN), using classified benign scenarios.
- `precision_pct`: TP / (TP + FP).
- `alert_row_rate_pct`: percentage of all CSV rows with an alert, regardless of classification.

Classifications must be `true-positive`, `true-negative`, `false-positive`, or `false-negative`. Spaces, underscores, case differences, and the short forms TP/TN/FP/FN are accepted. Other labels count as unclassified and are excluded from classification-based rates; the summary reports their number separately. A missing alert does not establish a false negative without a classification from the experiment records.

Missing timing or classification fields do not establish a successful response. A rate with no denominator or a timing average with no valid samples is `null` in JSON and `n/a` in the console. Negative and non-finite timing values are excluded; `timing_sample_counts` shows how many samples contributed to each average. Timestamp pairs with incompatible timezone information are also excluded.

These rate definitions differ from older saved summaries. Regenerate summaries from reviewed classifications before comparing runs; existing experiment outputs are kept unchanged.

Run the regression tests from the repository root:

```bash
python3 -m unittest discover -s research/tests -v
```

The runner tests use harmless stub scenarios and a fake alert collector transport. They do not run the attack scripts or contact Wazuh.

## Safety Notes

⚠️ **WARNING**: These scripts are for RESEARCH PURPOSES ONLY in controlled environments.

- Only run on systems you own or have permission to test
- Use isolated test environments
- Never run on production systems
- Document all activities for compliance

## License

Research use only. Part of university research on AI-assisted incident response.
