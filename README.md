# Detection-as-Code SOC Pipeline

A production-style detection engineering pipeline built on the MITRE ATT&CK framework. Simulates real adversary techniques, captures host telemetry, validates Sigma detection rules with automated tests, and deploys via a CI/CD pipeline — all from code.

---

## Pipeline Overview

```
Atomic Red Team  →  Sysmon + Winlogbeat  →  Elasticsearch/Kibana  →  Sigma Rules  →  GitHub Actions CI/CD
  (attack sim)        (telemetry)                 (SIEM)              (detections)       (validate + deploy)
```

---

## Techniques Covered

| Technique | Name | Severity | TPR | FPR |
|-----------|------|----------|-----|-----|
| T1059.001 | PowerShell Encoded Command Execution | HIGH | 100% | 0% |
| T1003.001 | LSASS Memory Dump via comsvcs.dll | CRITICAL | 100% | 0% |
| T1053.005 | Suspicious Scheduled Task Creation | HIGH | 100% | 0% |
| T1055 | Process Injection via CreateRemoteThread | HIGH | 100% | 0% |
| T1136.001 | Local User Account Creation | MEDIUM | 100% | 0% |

All 5 rules passed validation across 22 test cases (positive + negative).

---

## Repository Structure

```
detection-as-code/
├── .github/
│   └── workflows/
│       └── validate-detections.yml   # 5-job CI/CD pipeline
├── rules/
│   └── sigma/
│       ├── T1059.001_powershell_encoded_command.yml
│       ├── T1003.001_lsass_memory_dump.yml
│       ├── T1053.005_scheduled_task_creation.yml
│       ├── T1055_process_injection.yml
│       └── T1136.001_local_account_creation.yml
├── tests/
│   └── logs/
│       ├── positive/                 # Known-bad events (must trigger alert)
│       └── negative/                 # Benign events (must NOT trigger alert)
├── scripts/
│   └── validate_rules.py            # TPR/FPR validation engine
├── report/
│   └── Detection_as_a_code_lab_report.pdf
├── requirements.txt
└── README.md
```

---

## CI/CD Pipeline

The GitHub Actions workflow runs automatically on every push or pull request:

```
Lint Sigma Rules → Test Detection Logic → Convert to SIEM Queries → Publish Metrics → Deploy to SIEM
     (9s)                (10s)                   (12s)                  (7s)              (8s)
```

**Job 1 — Lint Sigma Rules**
Validates YAML syntax, required fields, ATT&CK tags, and duplicate rule IDs.

**Job 2 — Test Detection Logic**
Runs `validate_rules.py` and enforces TPR ≥ 95% and FPR = 0% per rule before anything proceeds.

**Job 3 — Convert to SIEM Queries**
Converts Sigma rules to Elastic EQL and Splunk SPL using sigma-cli.

**Job 4 — Publish Detection Metrics**
Generates a coverage report and posts a pass/fail summary as a PR comment.

**Job 5 — Deploy Rules to SIEM**
Pushes converted rules to Kibana via the Detection Rules API. Runs on `main` only, with a manual approval gate.

---

## Running Locally

### Prerequisites

- Python 3.10+
- sigma-cli

```bash
pip install -r requirements.txt
sigma plugin install eql
sigma plugin install ecs-windows
```

### Validate Rules

```bash
python3 scripts/validate_rules.py \
  --rules rules/sigma \
  --logs tests/logs \
  --output test_report.json
```

Expected output:
```
[INFO] Found 5 rule(s) to validate
[INFO] TPR=100.0% | FPR=0.0% | Tests=22 | Passed=22 | Failed=0
ALL RULES PASSED — Safe to deploy
```

### Convert a Rule to Elastic EQL

```bash
sigma convert \
  --target eql \
  --pipeline ecs-windows \
  rules/sigma/T1059.001_powershell_encoded_command.yml
```

### Convert a Rule to Splunk SPL

```bash
sigma convert \
  --target splunk \
  --pipeline splunk_windows \
  rules/sigma/T1059.001_powershell_encoded_command.yml
```

---

## Stack

| Component | Version |
|-----------|---------|
| Elasticsearch | 8.12.0 |
| Kibana | 8.12.0 |
| Winlogbeat | 8.12.0 |
| Sysmon | 64-bit (SwiftOnSecurity config) |
| Atomic Red Team | Invoke-AtomicRedTeam v2.3.0 |
| sigma-cli | 0.9.x |
| Python | 3.11 |


---

## Author

**Nouha Mkhinini** — Detection Engineering Lab, March 2026
Built as a hands-on project covering the full detection lifecycle: adversary simulation → telemetry → detection logic → automated validation → CI/CD deployment.
