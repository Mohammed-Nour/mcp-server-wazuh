# Research Attack Simulation Scripts

This folder contains all scripts needed for the research methodology to measure incident response metrics with the Wazuh MCP Server.

## Folder Structure

```logs
research/
├── attacks/                    # Attack simulation scripts (20 scenarios)
│   ├── 01_ssh_brute_force.sh
│   ├── 02_web_brute_force.sh
│   ├── ...
│   └── 18_suspicious_dns.sh
├── scripts/                    # Helper and analysis scripts
│   ├── config.env              # Environment and credential variables
│   ├── collect_alerts_from_wazuh.sh # Pull alerts for a given attack window into phase folders
│   ├── analyze_metrics.py      # Calculate MTTD/MTTR/FP rate from CSV
│   └── run_all_attacks.sh      # Run all attacks sequentially with optional immediate alert collection
    └── build_attack_results.py 
├── results/
│   ├── phase0/                 # Example completed phase (do not modify)
│   │   ├── alerts-from-wazuh/  # attack_<id>_alerts.json per attack
│   │   ├── logs-attacks/       # <id>_*.log from each attack
│   │   ├── metrics/            # response_times.json (optional)
│   │   └── mitigations-evidence/ # manual evidence storage
│   ├── phase1/                 # Baseline run outputs live here
│   └── phase2/                 # Enhanced run outputs live here
└── README.md                   # This file
```

## Prerequisites

### On Attack Machine (your local or separate instance)
```bash
sudo apt update
sudo apt install -y hydra nmap nikto netcat curl wget sshpass jq bc
```

### On Target Agent Instance
```bash
# Install vulnerable services for testing
sudo apt install -y openssh-server apache2 vsftpd
```

## Usage

### 1. Configure Environment
Edit `scripts/config.env` with your settings:
```bash
TARGET_IP="your-agent-instance-ip"
TARGET_USER="your-user"
TARGET_SSH_KEY="your-ssh-key"

WAZUH_INDEXER="your-wazuh-indexer-ip"
WAZUH_INDEXER_USER="wazuh"
WAZUH_INDEXER_PASS="your-password"

RESULTS_DIR="../results"

CURRENT_PHASE="0"
```

### 2. Run Individual Attack
```bash
cd attacks
./01_ssh_brute_force.sh <target_ip>
```

### 3. Run All Attacks
```bash
cd scripts
./run_all_attacks.sh
```

### 4. Collect Results
```bash
cd scripts
./collect_alerts_from_wazuh.sh <attack_id> <attack_start_timestamp> [attack_end_timestamp]
```

This saves alerts to `results/phase<N>/alerts-from-wazuh/attack_<id>_alerts.json` and appends the per-phase `attack_results.csv` (created from `templates/attack_results.csv` if missing).

### 5. Analyze Results
```bash
cd scripts
python3 analyze_metrics.py --phase 1 --results ../results/phase1/attack_results_generated.csv
```

## Attack Scenarios

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

## Metrics Measured

- **MTTD (Mean Time to Detect)**: Time from attack start to alert generation
- **MTTR (Mean Time to Respond)**: Time from alert to remediation complete
- **False Positive Rate**: Percentage of alerts that are false positives
- **Detection Rate**: Percentage of attacks that generated alerts
- **Analysis Time**: Human time spent analyzing alerts

## Safety Notes

⚠️ **WARNING**: These scripts are for RESEARCH PURPOSES ONLY in controlled environments.

- Only run on systems you own or have permission to test
- Use isolated test environments
- Never run on production systems
- Document all activities for compliance

## License

Research use only. Part of university research on AI-assisted incident response.
