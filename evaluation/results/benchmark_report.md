# PrivEsc & LOLBin Detection Pipeline - Benchmark Report

> **Telemetry Data Source:** `SYNTHETIC`  
> **Provenance Badge:** `SYNTHETIC LAB SIMULATION (Sysmon + Auditd)`  
> **Overall Held-Out Benign Test FPR:** `0.0331` (17 / 514 events)  
> **Evaluation Timestamp:** `2026-10-23 21:55:37 UTC`  

## 1. Experiment 1: Isolated Commands vs Sliding Window (Springer 2026)

| Mode                    |   Precision |   Recall |   F1-Score |    FPR |   Latency/Ev (ms) | _raw                                                                                                                                                           |
|:------------------------|------------:|---------:|-----------:|-------:|------------------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Single Isolated Command |      1      |   0.5102 |     0.6757 | 0      |             0.08  | {'tp': 375, 'fp': 0, 'tn': 514, 'fn': 360, 'precision': 1.0, 'recall': 0.5102040816326531, 'f1': 0.6756756756756758, 'fpr': 0.0}                               |
| Sliding Window (N=3)    |      0.9761 |   0.9456 |     0.9606 | 0.0331 |             0.111 | {'tp': 695, 'fp': 17, 'tn': 497, 'fn': 40, 'precision': 0.976123595505618, 'recall': 0.9455782312925171, 'f1': 0.960608154803041, 'fpr': 0.033073929961089495} |

### Experiment 1B: Sliding Window Size Ablation Study (Springer 2026)

| Window Size   |   Precision |   Recall |   F1-Score |    FPR |   Latency/Ev (ms) | Operational Trade-off                              |
|:--------------|------------:|---------:|-----------:|-------:|------------------:|:---------------------------------------------------|
| N = 3         |      0.9761 |   0.9456 |     0.9606 | 0.0331 |             0.093 | Optimal balance: lowest latency & high sensitivity |
| N = 4         |      0.9772 |   0.9347 |     0.9555 | 0.0311 |             0.11  | Extended chain context; slightly higher inertia    |
| N = 5         |      0.9758 |   0.9333 |     0.9541 | 0.0331 |             0.115 | Deep multi-step context; maximal memory footprint  |

## 2. Experiment 2: Performance Across Attack Complexity Tiers (SLR 2026)

| Attack Evaluation Tier                                    |   Attack Events |   Benign Test (Fold) |   Precision |   Recall |   F1-Score |   Tier FPR | _raw                                                                                                                                                           |
|:----------------------------------------------------------|----------------:|---------------------:|------------:|---------:|-----------:|-----------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Tier 1: Overt / Isolated GTFOBins & LOLBins               |             300 |                  171 |      0.9901 |   1      |     0.995  |     0.0175 | {'tp': 300, 'fp': 3, 'tn': 168, 'fn': 0, 'precision': 0.9900990099009901, 'recall': 1.0, 'f1': 0.9950248756218906, 'fpr': 0.017543859649122806}                |
| Tier 2: Multi-step Chained Sequences                      |             285 |                  171 |      0.9738 |   0.9123 |     0.942  |     0.0409 | {'tp': 260, 'fp': 7, 'tn': 164, 'fn': 25, 'precision': 0.9737827715355806, 'recall': 0.9122807017543859, 'f1': 0.9420289855072465, 'fpr': 0.04093567251461988} |
| Tier 3: Obfuscated / Stealthy (Base64/Ticks/IFS/Aliasing) |             150 |                  172 |      0.9507 |   0.9    |     0.9247 |     0.0407 | {'tp': 135, 'fp': 7, 'tn': 165, 'fn': 15, 'precision': 0.9507042253521126, 'recall': 0.9, 'f1': 0.9246575342465754, 'fpr': 0.040697674418604654}               |

### Table 2B: Chained Sequence Detection & Time-to-Detect Highlight (Springer 2026)

| Evaluation Dimension                  | Observed Metric       | Detection Value        | Operational Significance                                                             |
|:--------------------------------------|:----------------------|:-----------------------|:-------------------------------------------------------------------------------------|
| Event-Level Recall                    | 260 / 285 Events      | 0.9123                 | Individual command anomaly detection across multi-step execution                     |
| Chain-Level Detection Rate            | 60 / 60 Attack Chains | 1.0000                 | Chains interrupted (>=1 step flagged in window) halting adversary progression        |
| Time-to-Detect: Mean Event Delay      | 0.25 commands elapsed | 0.25 steps (Median: 0) | Average command progression before detection engine triggers critical alert          |
| Earliest Stage Interception           | 45 / 60 Chains        | 75.0% on Step 0        | Attack chains halted at initial reconnaissance/discovery before privilege escalation |
| Time-to-Detect: Mean Wall-Clock Delay | 0.80 seconds          | 0.80 sec               | Mean elapsed time from first adversary command to alert generation                   |

### Table 2C: Per-Binary Benign vs. Malicious Discrimination (Held-Out Benign Negatives)

| Target Binary   |   Benign Held-Out Count |   Attack Test Count |   Precision |   Recall |   F1-Score |   Binary FPR |
|:----------------|------------------------:|--------------------:|------------:|---------:|-----------:|-------------:|
| find            |                      24 |                  30 |      1      |        1 |      1     |        0     |
| vim             |                      27 |                  15 |      1      |        1 |      1     |        0     |
| awk             |                      28 |                  30 |      1      |        1 |      1     |        0     |
| tar             |                      28 |                  30 |      1      |        1 |      1     |        0     |
| python3         |                      26 |                  15 |      1      |        1 |      1     |        0     |
| certutil.exe    |                      40 |                  45 |      0.9783 |        1 |      0.989 |        0.025 |
| powershell.exe  |                      30 |                  60 |      1      |        1 |      1     |        0     |
| rundll32.exe    |                      25 |                  30 |      1      |        1 |      1     |        0     |
| regsvr32.exe    |                      38 |                  30 |      1      |        1 |      1     |        0     |
| mshta.exe       |                      34 |                  15 |      1      |        1 |      1     |        0     |

## 3. Experiment 3: Supervised Generalization Failure (Stamp 2022) with SMOTE vs Unsupervised Anomaly Detection

| Model Architecture                               |   Precision |   Recall |   F1-Score |    FPR | Evaluation Scope                                             |
|:-------------------------------------------------|------------:|---------:|-----------:|-------:|:-------------------------------------------------------------|
| Isolation Forest (Unsupervised)                  |      0.9587 |   0.908  |     0.9327 | 0.0331 | Unseen Attack Tiers (Tiers 2 & 3) [0 attack labels in train] |
| RandomForest (SMOTE + Balanced Supervised)       |      1      |   0.4828 |     0.6512 | 0      | Unseen Attack Tiers (Tiers 2 & 3) [Trained on Tier 1 Overt]  |
| DecisionTree (SMOTE + Balanced Supervised)       |      1      |   0.5172 |     0.6818 | 0      | Unseen Attack Tiers (Tiers 2 & 3) [Trained on Tier 1 Overt]  |
| RandomForest (Supervised - Seen Tier 1 Baseline) |      1      |   1      |     1      | 0      | Seen Attack Partition (Tier 1 Overt Test)                    |

## 4. Experiment 4: Zero-Shot LLM Attribution Evaluation (Ali & Kostakos 2023)

| Process        | Command Sample                                   | Ground Truth Technique                | LLM Verdict                                 | Attributed Technique                                            | MITRE ID          |   Confidence |
|:---------------|:-------------------------------------------------|:--------------------------------------|:--------------------------------------------|:----------------------------------------------------------------|:------------------|-------------:|
| find           | sudo find . -exec /bin/sh -p \; -quit            | Sudo GTFOBins (find) Abuse            | Malicious - PrivEsc/LOLBin                  | GTFOBins Sudo Abuse (find -exec)                                | T1548.003         |         0.95 |
| certutil.exe   | certutil.exe -urlcache -split -f http://10.0.... | Certutil Ingress Tool Transfer        | Malicious - PrivEsc/LOLBin                  | Certutil Ingress Tool Transfer                                  | T1105             |         0.97 |
| whoami         | whoami && id                                     | Chained Sequence: Discovery           | Malicious - Chained PrivEsc/LOLBin Sequence | Chained Discovery & Privilege Escalation Sequence               | T1059 / T1087     |         0.92 |
| powershell.exe | powershell.exe -e JABjACAAPQAgAE4AZQB3AC0ATwB... | Obfuscated Base64 PowerShell Download | Malicious - PrivEsc/LOLBin                  | Obfuscated / Base64 Encoded Command Execution                   | T1059.001 / T1027 |         0.96 |
| cmd.exe        | cmd.exe /c "set p=certutil&& call %p% -dump c... | Subtle Env-Var LOLBin Aliasing        | Malicious - Obfuscated LOLBin Aliasing      | Obfuscated LOLBin Aliasing via Environment Variables (certutil) | T1027.010         |         0.94 |

## 5. Scientific Limitations & Telemetry Provenance Disclosure (Section 4.4)

- **Synthetic Telemetry Lab Boundary:** The empirical results reported above are generated using synthetic lab telemetry simulating Linux auditd (`SYSCALL`, `EXECVE`, `PATH`, `CWD`) and Windows Sysmon (`EventID 1`, `EventID 11`) event structures.
- **Enterprise Generalization Disclaimer:** While command-line distributions and GTFOBin/LOLBin techniques reflect real-world threat intelligence (GTFOBins, LOLBAS, MITRE ATT&CK), generalization to noisy production environments with proprietary third-party software, high-volume IT management scripts, and diverse container orchestrators remains to be validated.
- **Curated Technique Balance:** The benchmark incorporates a balanced representation of 10 target LOLBins/GTFOBins across 3 complexity tiers. Production enterprise telemetry typically exhibits heavy-tailed, non-uniform distributions where benign administrative utilities outnumber anomalous invocations by several orders of magnitude.
