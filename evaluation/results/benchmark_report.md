# PrivEsc & LOLBin Detection Pipeline - Benchmark Report

## 1. Experiment 1: Isolated Commands vs Sliding Window (Springer 2026)

| Mode                    |   Precision |   Recall |   F1-Score |   FPR |   Latency/Ev (ms) | _raw                                                                                                                                                            |
|:------------------------|------------:|---------:|-----------:|------:|------------------:|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Single Isolated Command |      1      |   0.4694 |     0.6389 | 0     |             0.087 | {'tp': 345, 'fp': 0, 'tn': 514, 'fn': 390, 'precision': 1.0, 'recall': 0.46938775510204084, 'f1': 0.6388888888888888, 'fpr': 0.0}                               |
| Sliding Window (N=3)    |      0.9735 |   0.898  |     0.9342 | 0.035 |             0.098 | {'tp': 660, 'fp': 18, 'tn': 496, 'fn': 75, 'precision': 0.9734513274336283, 'recall': 0.8979591836734694, 'f1': 0.9341825902335457, 'fpr': 0.03501945525291829} |

## 2. Experiment 2: Performance Across Attack Complexity Tiers (SLR 2026)

| Attack Evaluation Tier                                    |   Attack Events |   Benign Test |   Precision |   Recall |   F1-Score |   FPR | _raw                                                                                                                                                            |
|:----------------------------------------------------------|----------------:|--------------:|------------:|---------:|-----------:|------:|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Tier 1: Overt / Isolated GTFOBins & LOLBins               |             300 |           514 |      0.9434 |   1      |     0.9709 | 0.035 | {'tp': 300, 'fp': 18, 'tn': 496, 'fn': 0, 'precision': 0.9433962264150944, 'recall': 1.0, 'f1': 0.970873786407767, 'fpr': 0.03501945525291829}                  |
| Tier 2: Multi-step Chained Sequences                      |             285 |           514 |      0.9302 |   0.8421 |     0.884  | 0.035 | {'tp': 240, 'fp': 18, 'tn': 496, 'fn': 45, 'precision': 0.9302325581395349, 'recall': 0.8421052631578947, 'f1': 0.8839779005524862, 'fpr': 0.03501945525291829} |
| Tier 3: Obfuscated / Stealthy (Base64/Ticks/IFS/Aliasing) |             150 |           514 |      0.8696 |   0.8    |     0.8333 | 0.035 | {'tp': 120, 'fp': 18, 'tn': 496, 'fn': 30, 'precision': 0.8695652173913043, 'recall': 0.8, 'f1': 0.8333333333333333, 'fpr': 0.03501945525291829}                |

### Table 2B: Chained Sequence Detection Highlight (Tier 2 Multi-Step Attack Chains)

| Evaluation Dimension       | Observed Count        |   Detection Rate | Operational Significance                                                      |
|:---------------------------|:----------------------|-----------------:|:------------------------------------------------------------------------------|
| Event-Level Recall         | 240 / 285 Events      |           0.8421 | Individual command anomaly detection across multi-step execution              |
| Chain-Level Detection Rate | 60 / 60 Attack Chains |           1      | Chains interrupted (>=1 step flagged in window) halting adversary progression |

### Table 2C: Per-Binary Benign vs. Malicious Discrimination

| Target Binary   |   Benign Test Count |   Attack Test Count |   Precision |   Recall |   F1-Score |   FPR |
|:----------------|--------------------:|--------------------:|------------:|---------:|-----------:|------:|
| find            |                  24 |                  30 |      1      |        1 |      1     | 0     |
| vim             |                  27 |                  15 |      1      |        1 |      1     | 0     |
| awk             |                  28 |                  30 |      1      |        1 |      1     | 0     |
| tar             |                  28 |                  30 |      1      |        1 |      1     | 0     |
| python3         |                  26 |                  15 |      1      |        1 |      1     | 0     |
| certutil.exe    |                  40 |                  45 |      0.9783 |        1 |      0.989 | 0.025 |
| powershell.exe  |                  30 |                  60 |      1      |        1 |      1     | 0     |
| rundll32.exe    |                  25 |                  30 |      1      |        1 |      1     | 0     |
| regsvr32.exe    |                  38 |                  30 |      1      |        1 |      1     | 0     |
| mshta.exe       |                  34 |                  15 |      1      |        1 |      1     | 0     |

## 3. Experiment 3: Supervised Generalization Failure (Stamp 2022) vs Unsupervised Anomaly Detection

| Model Architecture                               |   Precision |   Recall |   F1-Score |   FPR | Evaluation Scope                                             |
|:-------------------------------------------------|------------:|---------:|-----------:|------:|:-------------------------------------------------------------|
| Isolation Forest (Unsupervised)                  |      0.9524 |   0.8276 |     0.8856 | 0.035 | Unseen Attack Tiers (Tiers 2 & 3) [0 attack labels in train] |
| RandomForest (Supervised Benchmark)              |      1      |   0.5172 |     0.6818 | 0     | Unseen Attack Tiers (Tiers 2 & 3) [Trained on Tier 1 Overt]  |
| DecisionTree (Supervised Benchmark)              |      1      |   0.5172 |     0.6818 | 0     | Unseen Attack Tiers (Tiers 2 & 3) [Trained on Tier 1 Overt]  |
| RandomForest (Supervised - Seen Tier 1 Baseline) |      1      |   1      |     1      | 0     | Seen Attack Partition (Tier 1 Overt Test)                    |

## 4. Experiment 4: Zero-Shot LLM Attribution Evaluation

| Process        | Command Sample                                   | Ground Truth Technique                | LLM Verdict                                 | Attributed Technique                                            | MITRE ID          |   Confidence |
|:---------------|:-------------------------------------------------|:--------------------------------------|:--------------------------------------------|:----------------------------------------------------------------|:------------------|-------------:|
| find           | sudo find . -exec /bin/sh -p \; -quit            | Sudo GTFOBins (find) Abuse            | Malicious - PrivEsc/LOLBin                  | GTFOBins Sudo Abuse (find -exec)                                | T1548.003         |         0.95 |
| certutil.exe   | certutil.exe -urlcache -split -f http://10.0.... | Certutil Ingress Tool Transfer        | Malicious - PrivEsc/LOLBin                  | Certutil Ingress Tool Transfer                                  | T1105             |         0.97 |
| whoami         | whoami && id                                     | Chained Sequence: Discovery           | Malicious - Chained PrivEsc/LOLBin Sequence | Chained Discovery & Privilege Escalation Sequence               | T1059 / T1087     |         0.92 |
| powershell.exe | powershell.exe -e JABjACAAPQAgAE4AZQB3AC0ATwB... | Obfuscated Base64 PowerShell Download | Malicious - PrivEsc/LOLBin                  | Obfuscated / Base64 Encoded Command Execution                   | T1059.001 / T1027 |         0.96 |
| cmd.exe        | cmd.exe /c "set p=certutil&& call %p% -dump c... | Subtle Env-Var LOLBin Aliasing        | Malicious - Obfuscated LOLBin Aliasing      | Obfuscated LOLBin Aliasing via Environment Variables (certutil) | T1027.010         |         0.94 |

