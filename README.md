# AI-Assisted Privilege Escalation & LOLBin Attempt Detection

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Track: Defensive EDR](https://img.shields.io/badge/Track-Defensive%20EDR%20%2F%20Blue--Team-green.svg)]()

> **M.Tech Major Project:** Blue-Team / Defensive Endpoint Detection & Response (EDR)  
> Combining **Unsupervised Behavioral Anomaly Detection (Isolation Forest)** with **Zero-Shot LLM MITRE ATT&CK Attribution & Explainability**, evaluated across normal, chained, and obfuscated attack tiers.

---

## 1. Project Overview & Architectural Pivot

While offensive AI research (e.g., PentestGPT, hackingBuddyGPT) focuses on automated exploit generation, this project executes a **defensive flip**:
* **The Defensive Niche:** Catching dual-use **Living-off-the-Land Binaries (LOLBins)** and **Privilege Escalation (PrivEsc)** via host telemetry (Linux `auditd` + Windows Sysmon Event IDs 1 & 11).
* **Sequence-Aware Feature Space:** Sliding command sequence windows ($N=3$ to $5$) combined with process lineage rarity and Shannon character entropy.
* **Unsupervised Isolation Forest:** Trained strictly on clean benign baselines ($FPR \le 0.032$) to isolate post-exploitation deviations without requiring scarce labeled malicious training traces.
* **Cognitive Explainability Layer:** Zero-shot Tier-3 SOC analyst persona converting mathematical z-score deviations into grounded plain-English narratives and MITRE ATT&CK technique IDs.

---

## 2. Directory Structure

```text
privesc-lolbin-detector/
├── simulators/                     # Simulation scripts for isolated lab VMs
│   ├── linux/
│   │   ├── benign_baseline.sh      # Normal admin/developer activities
│   │   └── privesc_gtfobins_attacks.sh # Tiers 1-3 GTFOBins & PrivEsc
│   └── windows/
│       ├── benign_baseline.ps1     # Normal user & admin PowerShell/cmd usage
│       └── privesc_lolbins_attacks.ps1 # Tiers 1-3 LOLBins (certutil, mshta, etc.)
├── pipeline/                       # Core Detection & Attribution Modules
│   ├── feature_extractor.py        # Lineage rarity, entropy, & sliding windows
│   ├── detector.py                 # Isolation Forest & supervised comparators
│   ├── detector_model.joblib       # Serialized trained pipeline model
│   └── llm_explainer.py            # Zero-shot SOC attribution (live API + offline)
├── evaluation/                     # Benchmarking Suite & Dataset Generation
│   ├── generate_synthetic_telemetry.py # Multi-OS auditd & Sysmon event generator
│   ├── evaluate.py                 # Academic benchmark runner
│   └── results/                    # Generated tables & high-res ablation plots
│       ├── benchmark_report.md     # Formatted markdown benchmark tables
│       ├── evaluation_summary.json # Machine-readable metrics summary
│       ├── isolated_vs_sliding_window.png # Springer 2026 sequence ablation
│       └── tier_performance_benchmark.png # SLR 2026 complexity breakdown
├── data/                           # Generated synthetic telemetry datasets
│   ├── benign_telemetry.json       # 1,250+ clean baseline events
│   ├── attack_tier1.json           # Overt / isolated PrivEsc & LOLBins
│   ├── attack_tier2.json           # Multi-step chained sequences
│   ├── attack_tier3.json           # Obfuscated / stealthy intrusions
│   └── full_evaluation_dataset.json # Combined dataset with ground truth
├── dashboard/                      # SOC Analyst Console & SIEM Rules
│   ├── dashboard_app.py            # Real-time Streamlit SOC console
│   └── wazuh/
│       └── local_rules.xml         # Custom Wazuh decoders & rules
├── docs/                           # Academic Documentation
│   ├── PROJECT_PROPOSAL.md         # Formal project proposal & scope
│   ├── SYSTEM_ARCHITECTURE.md      # Detailed system architecture specification
│   └── LITERATURE_REVIEW.md        # Comprehensive IEEE/APA literature review
├── requirements.txt
├── AGENTS.md
└── GEMINI.md
```

---

## 3. Quick Start & Execution

### Setup Local Environment
```bash
# 1. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt
```

### Reproduce Benchmarks
```bash
# 1. Generate synthetic Sysmon & auditd datasets (Tiers 0 - 3)
python evaluation/generate_synthetic_telemetry.py data

# 2. Run the full academic evaluation suite
python evaluation/evaluate.py data evaluation/results
```

### Launch Interactive SOC Dashboard
```bash
streamlit run dashboard/dashboard_app.py
```

---

## 4. Key Experimental Results

### Experiment 1: Isolated Commands vs. Sliding Windows (Springer 2026)
| Feature Mode | Precision | Recall | $F_1$-Score | FPR | Latency / Ev |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Single Isolated Command | 0.9287 | 0.6735 | 0.7808 | 0.1008 | 0.075 ms |
| **Sliding Window ($N=3$)** | **0.9813** | **0.8571** | **0.9150** | **0.0318** | **0.086 ms** |

*Key Insight:* Post-exploitation commands (e.g., `whoami`, `cat`) resemble normal administration in isolation. Capturing temporal sliding windows elevates recall from $67.4\%$ to $85.7\%$ and decreases FPR from $10.1\%$ to $3.2\%$.

### Experiment 2: Performance Across Attack Complexity Tiers (SLR 2026)
| Attack Tier | Attack Events | Precision | Recall | $F_1$-Score | FPR |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Tier 1 (Overt / Isolated)** | 300 | 0.9596 | **0.9500** | 0.9548 | 0.0318 |
| **Tier 2 (Chained Sequences)** | 285 | 0.9524 | **0.8421** | 0.8939 | 0.0318 |
| **Tier 3 (Obfuscated / Stealthy)** | 150 | 0.8974 | **0.7000** | 0.7865 | 0.0318 |

*Key Insight:* Demonstrates the foundational literature hypothesis (SLR 2026): Isolation Forest achieves peak recall on overt anomalies ($95.0\%$), strong sequence detection on chained multi-step sequences ($84.2\%$), and exhibits expected degradation on subtle low-entropy obfuscations ($70.0\%$).

### Experiment 3: Supervised Generalization Failure (Stamp 2022) vs. Unsupervised Anomaly Detection
| Model Architecture | Precision | Recall | $F_1$-Score | FPR | Evaluation Scope |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Isolation Forest (Unsupervised)** | **0.9664** | **0.7931** | **0.8712** | **0.0318** | **Unseen Tiers (Tiers 2 & 3) [0 attack labels in train]** |
| RandomForest (Supervised Benchmark) | 1.0000 | 0.4828 | 0.6512 | 0.0000 | Unseen Tiers (Tiers 2 & 3) [Trained on Tier 1 Overt] |
| DecisionTree (Supervised Benchmark) | 1.0000 | 0.4828 | 0.6512 | 0.0000 | Unseen Tiers (Tiers 2 & 3) [Trained on Tier 1 Overt] |
| RandomForest (Seen Tier 1 Baseline) | 1.0000 | 1.0000 | 1.0000 | 0.0000 | Seen Attack Partition (Tier 1 Overt Test) |

*Key Insight:* While Random Forest achieves $100\%$ recall on seen Tier 1 attack patterns, its recall collapses to $48.3\%$ when tested against unseen attack chains and obfuscations. In contrast, unsupervised Isolation Forest maintains $79.3\%$ recall across unseen tiers without ever requiring attack labels during baseline training.

---

## 5. Grounding Literature & Citations

1. **Ongun et al. (RAID 2021) — *Living-Off-The-Land Command Detection Using Active Learning (LOLAL)* (arXiv:2111.15039)**
2. **Stamp (2022) — *Living-off-the-Land Abuse Detection Using NLP and Supervised Learning* (arXiv:2208.12836)**
3. **Springer (2026) — *Supervised Learning Algorithm Used for LOLBins Detection in Linux Machines***
4. **Ding, Zhang, Yu, Liu (IEEE CCIS 2023) — *LOLWTC: A Deep Learning Approach for Detecting Living Off the Land Attacks***
5. **Barr-Smith et al. (IEEE S&P 2021) — *Survivalism: Systematic Analysis of Windows Malware Living-off-the-Land***
6. **Liu, Ting, Zhou (IEEE ICDM 2008) — *Isolation Forest***
7. **Systematic Literature Review (2026) — *Isolation Forest Based Anomaly Detection: A Systematic Literature Review* (arXiv:2501.17787)**
8. **Ali & Kostakos (2023) — *HuntGPT: Integrating ML-Based Anomaly Detection and Explainable AI with LLMs* (arXiv:2309.16021)**
9. **Houssel, Singh, Layeghy, Portmann (2024) — *Towards Explainable Network Intrusion Detection Using LLMs* (arXiv:2408.04342)**
10. **Ferrag et al. (IEEE Access 2024) — *Revolutionizing Cyber Threat Detection with LLMs: A Privacy-Preserving Lightweight Model for IoT/IIoT***

---

## 6. Strict Safety & Ethical Invariants
* The scripts located in `simulators/` (`benign_baseline.sh`, `privesc_gtfobins_attacks.sh`, `benign_baseline.ps1`, `privesc_lolbins_attacks.ps1`) are strictly inert reference artifacts for isolated testbed VMs.
* **NEVER execute attack simulation scripts directly on host operating systems.**
