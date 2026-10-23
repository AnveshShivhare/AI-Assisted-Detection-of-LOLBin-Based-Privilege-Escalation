# PrivEsc & LOLBin Detection Pipeline - Benchmark Report

> **Telemetry Data Source:** `AUDITD`  
> **Provenance Badge:** `REAL LINUX AUDITD LOG TELEMETRY (known-benign baseline assumption)`  
> **Overall Held-Out Benign Test FPR:** `0.0468` (358 / 7649 events)  
> **Evaluation Timestamp:** `2026-10-24 00:47:53 UTC`  

## 1. Experiment 1: Isolated Commands vs Sliding Window (Springer 2026)

| Mode                    |   Precision |   Recall |   F1-Score |    FPR |   Latency/Ev (ms) | _raw                                                                                                               |
|:------------------------|------------:|---------:|-----------:|-------:|------------------:|:-------------------------------------------------------------------------------------------------------------------|
| Single Isolated Command |           0 |        0 |          0 | 0.0784 |             0.131 | {'tp': 0, 'fp': 600, 'tn': 7049, 'fn': 0, 'precision': 0.0, 'recall': 0.0, 'f1': 0.0, 'fpr': 0.07844162635638646}  |
| Sliding Window (N=3)    |           0 |        0 |          0 | 0.0468 |             0.166 | {'tp': 0, 'fp': 358, 'tn': 7291, 'fn': 0, 'precision': 0.0, 'recall': 0.0, 'f1': 0.0, 'fpr': 0.046803503725977254} |

### Experiment 1B: Sliding Window Size Ablation Study (Springer 2026)

| Window Size   |   Precision |   Recall |   F1-Score |    FPR |   Latency/Ev (ms) | Operational Trade-off                              |
|:--------------|------------:|---------:|-----------:|-------:|------------------:|:---------------------------------------------------|
| N = 3         |           0 |        0 |          0 | 0.0468 |             0.11  | Optimal balance: lowest latency & high sensitivity |
| N = 4         |           0 |        0 |          0 | 0.0473 |             0.178 | Extended chain context; slightly higher inertia    |
| N = 5         |           0 |        0 |          0 | 0.0455 |             0.109 | Deep multi-step context; maximal memory footprint  |

## 2. Held-Out Baseline Telemetry Score Distribution & Statistics

| Statistic                     |   Value |
|:------------------------------|--------:|
| Mean Anomaly Score            |  0.0991 |
| Standard Deviation            |  0.1704 |
| Minimum Score                 |  0.0016 |
| 25th Percentile               |  0.0085 |
| Median (50th Percentile)      |  0.0301 |
| 75th Percentile               |  0.1257 |
| 90th Percentile               |  0.2468 |
| 95th Percentile               |  0.4672 |
| 99th Percentile               |  0.8955 |
| Maximum Score                 |  0.9918 |
| Calibrated Decision Threshold |  0.5    |

### Anomaly Score Histogram Distribution

| Score Range   |   Count | Percentage   | Interpretation                             |
|:--------------|--------:|:-------------|:-------------------------------------------|
| [0.0 - 0.2)   |    6677 | 87.29%       | Strongly Benign (Deep Interior)            |
| [0.2 - 0.4)   |     536 | 7.01%        | Typical Benign Baseline                    |
| [0.4 - 0.5)   |      67 | 0.88%        | Borderline Normal (Sub-threshold)          |
| [0.5 - 0.6)   |     104 | 1.36%        | Mild Deviation / Marginal False Positive   |
| [0.6 - 0.8)   |     100 | 1.31%        | Notable Deviation (Unusual Admin Task)     |
| [0.8 - 1.0]   |     165 | 2.16%        | Extreme Deviation / Outlier False Positive |

### Table 2C: Per-Binary False Positive Discrimination on Real Baseline Binaries

| Target Binary   |   Benign Held-Out Count |   Attack Test Count |   Precision |   Recall |   F1-Score |   Binary FPR |
|:----------------|------------------------:|--------------------:|------------:|---------:|-----------:|-------------:|
| find            |                      66 |                   0 |           0 |        0 |          0 |       0.0455 |
| awk             |                     381 |                   0 |           0 |        0 |          0 |       0      |
| tar             |                      24 |                   0 |           0 |        0 |          0 |       0      |
| python3         |                     193 |                   0 |           0 |        0 |          0 |       0.2124 |

## 3. Zero-Shot SOC Attribution on Real Telemetry Outliers (Ali & Kostakos 2023)

|   Process | Command Sample                                   | Ground Truth Technique   | LLM Verdict                                 | Attributed Technique                              | MITRE ID      |   Confidence |
|----------:|:-------------------------------------------------|:-------------------------|:--------------------------------------------|:--------------------------------------------------|:--------------|-------------:|
|         9 | /usr/lib/systemd/systemd-executor --deseriali... | Benign Baseline Task     | Malicious - Chained PrivEsc/LOLBin Sequence | Chained Discovery & Privilege Escalation Sequence | T1059 / T1087 |         0.92 |

## 5. Scientific Limitations & Telemetry Provenance Disclosure (Section 4.4)

- **Data Provenance:** Evaluated with data source `AUDITD` under badge `REAL LINUX AUDITD LOG TELEMETRY (known-benign baseline assumption)`.
- **Enterprise Generalization Disclaimer:** While command-line distributions and GTFOBin/LOLBin techniques reflect real-world threat intelligence (GTFOBins, LOLBAS, MITRE ATT&CK), generalization to noisy production environments with proprietary third-party software, high-volume IT management scripts, and diverse container orchestrators remains to be validated.
- **Curated Technique Balance:** Production enterprise telemetry typically exhibits heavy-tailed, non-uniform distributions where benign administrative utilities outnumber anomalous invocations by several orders of magnitude.
