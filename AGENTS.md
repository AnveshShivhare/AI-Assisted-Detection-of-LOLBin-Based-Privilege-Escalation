# PROJECT SPECIFICATION & AUTOMATION BLUEPRINT

**Role:** Act as an Autonomous Senior Security Engineer & ML Systems Architect.
**Objective:** Automate the implementation, codebase generation, data pipeline, evaluation framework, and documentation for the M.Tech Major Project detailed below.

---

## 1. PROJECT OVERVIEW & STRATEGIC PIVOT

* **Project Title:** AI-Assisted Privilege Escalation & Living-off-the-Land (LOLBin) Attempt Detection via Endpoint Telemetry and LLM Explainability
* **Research Track:** Blue-Team / Defensive Endpoint Detection & Response (EDR)
* **Strategic Context (Why this scope was chosen):**
  * **What We Avoided:** Offensive AI-for-PrivEsc (auto-exploitation, BloodHound/PEASS LLM wrappers, payload mutation/AV evasion). Offensive automation is already heavily saturated in research (e.g., Happe et al., PentestGPT, hackingBuddyGPT) and triggers severe ethics/IRB pushback regarding automated exploit generation.
  * **The Defensive Flip (Our Niche):** While offensive LLM privesc is crowded, the **Blue-Team detection side**—specifically catching privilege escalation and Living-off-the-Land (LOLBin) abuse using unsupervised anomaly detection paired with zero-shot LLM technique attribution—is an open, defensible gap.
  * **Core Academic Contribution:** Combining **unsupervised sequence/behavioral anomaly detection (Isolation Forest)** on raw endpoint telemetry with **zero-shot LLM-generated technique attribution & plain-English explainability**, evaluated rigorously against normal vs. chained vs. obfuscated attack tiers.
  * **Ethical & Lab Boundary:** All attack simulation and telemetry generation are strictly executed within **isolated, non-networked local VMs** (Linux & Windows) under full researcher control. No adversarial ML evasion attacks are in scope.

---

## 2. SYSTEM ARCHITECTURE & DATA PIPELINE

```text
[Isolated Lab VMs: Linux + Windows] 
   ├── Benign Activity (Admin/User Baseline)
   └── Controlled Attack Execution (PrivEsc + 8–10 Target LOLBins)
          │
          ▼
[Telemetry Collection Layer]
   ├── Windows: Sysmon + Wazuh Agent
   └── Linux: auditd + Wazuh Agent
          │
          ▼
[Feature Extraction & Preprocessing Engine (Python)]
   ├── Process lineage & parent-child anomalies
   ├── Command-line NLP / token representations & sliding command windows
   ├── Privilege token changes, unusual sudo/service calls, file ACL touches
   └── Syscall / audit event timing & sequence chaining
          │
          ▼
[Unsupervised Anomaly Detection Layer]
   └── Isolation Forest (Trained on Benign Baseline -> Flags Deviations)
          │
          ▼
[AI Explainability & Attribution Layer (Zero-Shot LLM API)]
   ├── Input: JSON summary of flagged anomaly features + command window
   └── Output: Plain-English SOC verdict, MITRE ATT&CK / technique guess, confidence score
          │
          ▼
[Wazuh / SOC Visualization Dashboard]
   └── Displays Alert, Technique Attribution, Confidence, and Analyst Explanation
```

---

## 3. IMPLEMENTATION MODULES (WHAT TO BUILD & AUTOMATE)

### Module 1: Lab Telemetry Generation Scripts
Create safe, reproducible simulation scripts (Bash for Linux, PowerShell/Batch for Windows) to run inside isolated VMs:
1. **Benign Baseline Generator:** Automates routine user/admin tasks (package updates, cron jobs, standard file operations, regular developer workflows, normal PowerShell/Bash usage) to build clean training logs.
2. **PrivEsc & LOLBin Attack Simulator:** Automates 4–5 well-known PrivEsc techniques and 8–10 prevalent LOLBins across three complexity tiers:
   * **Linux Targets:** `sudo` misconfigurations, SUID binary abuse, GTFOBins abuse (`find`, `vim`, `awk`, `curl`, `tar`, `python`), cron/service hijacks.
   * **Windows Targets:** Token impersonation, unquoted service paths / service ACL misconfigurations, LOLBins (`powershell.exe`, `certutil.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `wmic.exe`, `bitsadmin.exe`).
   * **Three Evaluation Tiers to Simulate:**
     1. **Tier 1 (Overt / Isolated):** Single-command standard PrivEsc/LOLBin execution.
     2. **Tier 2 (Chained Sequences):** Multi-step command sequences (evaluating sliding windows of commands rather than isolated commands).
     3. **Tier 3 (Obfuscated / Stealthy):** Base64 encoding, string concatenation, environment variable substitution, or flag reordering to test where Isolation Forest struggles.

### Module 2: Telemetry Parser & Feature Extractor (`feature_extractor.py`)
Write a modular Python pipeline that ingests Sysmon XML/JSON, Linux `auditd` logs, and Wazuh alert JSONs, extracting:
* **Process Lineage Features:** Parent process name, child process name, parent-child rarity score, process tree depth.
* **Privilege & Access Features:** UID/GID/Integrity-level changes, `sudo` invocation anomalies, sensitive file/ACL touch indicators (`/etc/sudoers`, SAM/SYSTEM, service binaries).
* **Command-Line & Sequence Features:** Command length, character entropy (to catch obfuscation), special character ratios, TF-IDF/word-embedding tokens of command strings, and **sliding window aggregations** (e.g., window of $N=3$ to $5$ consecutive commands per session/process tree).

### Module 3: Anomaly Detection Engine (`detector.py`)
Build a `scikit-learn` ML pipeline centered on **Isolation Forest**:
* Train strictly on the Benign Baseline feature matrix (unsupervised anomaly detection).
* Implement optional benchmark comparison classifiers (Decision Tree, Random Forest) using SMOTE for class-imbalance comparison on labeled subsets.
* Tune contamination hyperparameters and threshold scores to minimize the False Positive Rate (FPR).
* Output structured JSON payloads for every flagged anomaly containing the exact feature deviations and raw command/process sequence.

### Module 4: Zero-Shot LLM Verdict & Explainability Layer (`llm_explainer.py`)
Build an API integration module (compatible with OpenAI/Anthropic/Groq/Local Ollama endpoints) using a strict zero-shot system prompt:
* **Input:** The JSON anomaly payload from `detector.py`.
* **System Prompt Directive:** Act as a Tier-3 SOC Analyst. Analyze the process tree, sliding command window, and statistical feature deviations. Output a structured JSON response containing:
  1. `verdict`: (`Malicious - PrivEsc/LOLBin`, `Suspicious`, or `False Positive`)
  2. `attributed_technique`: Specific PrivEsc vector or LOLBin mechanism (e.g., "Sudoers Misconfiguration Exploit", "Certutil Ingress Tool Transfer") + MITRE ATT&CK ID.
  3. `confidence_score`: $0.0$ to $1.0$
  4. `plain_english_explanation`: Concise, human-readable justification ("This sequence looks like a sudoers misconfiguration exploit because...") avoiding hallucinated assumptions.

### Module 5: Evaluation & Benchmarking Suite (`evaluate.py`)
Since rigorous evaluation is a core contribution, automate a benchmarking script that outputs publication-ready tables and plots:
* **Metrics:** Precision, Recall, $F_1$-Score, False Positive Rate (FPR), and Time-to-Detect.
* **Breakdown Dimensions:**
  * Per-technique performance (Sudo vs. SUID vs. Service Misconfig vs. specific LOLBins).
  * Single isolated command vs. Sliding window of commands.
  * Overt attacks (Tier 1) vs. Chained attacks (Tier 2) vs. Obfuscated attacks (Tier 3) — specifically testing the literature hypothesis that Isolation Forest excels on overt attacks but degrades on stealthy/obfuscated intrusions.
  * LLM explanation quality evaluation (accuracy of technique attribution and consistency of reasoning).

### Module 6: Wazuh Custom Integration / SOC Dashboard (`dashboard_app.py`)
Create either:
* Custom Wazuh decoders/rules (`local_rules.xml`) + active-response integration script that writes the LLM verdict back into Wazuh alerts, **OR**
* A lightweight Streamlit/FastAPI SOC Dashboard that displays real-time alerts, anomaly scores, process trees, and the LLM's plain-English attribution.

---

## 4. GROUNDING LITERATURE & CITATION MATRIX (FOR DOCS/REPORTS)

Use these exact 10 core papers + 2 optional references across code comments, READMEs, and academic report generation:

### A. LOLBin / Living-off-the-Land Detection
1. **Ongun et al. (RAID 2021) — *Living-Off-The-Land Command Detection Using Active Learning (LOLAL)* (arXiv:2111.15039):** Word-embedding representations of command-line text + ensemble boosting with limited labeled samples ($0.96$ $F_1$). Justifies our command-line feature representation.
2. **Stamp (2022) — *Living-off-the-Land Abuse Detection Using NLP and Supervised Learning* (arXiv:2208.12836):** Encodes raw commands via regex/one-hot into token vectors; highlights scarcity of labeled malicious LOLBin samples—justifying why our lab generates its own labeled attack traces.
3. **Springer (2026) — *Supervised Learning Algorithm Used for LOLBins Detection in Linux Machines*:** Compares ML models on Linux using NLP + SMOTE; proves **a window of commands outperforms isolated command lines**, directly supporting our sequence/chaining evaluation tier.
4. **Ding, Zhang, Yu, Liu (IEEE CCIS 2023) — *LOLWTC: A Deep Learning Approach for Detecting Living Off the Land Attacks*:** Deep learning baseline comparison for chaining/obfuscation detection gaps.
5. **Barr-Smith et al. (IEEE S&P 2021) — *Survivalism: Systematic Analysis of Windows Malware Living-off-the-Land*:** Empirical prevalence study justifying our selection of the 8–10 target binaries.

### B. Anomaly Detection Foundation (Isolation Forest)
6. **Liu, Ting, Zhou (IEEE ICDM 2008) — *Isolation Forest*:** Foundational algorithm paper ("anomalies are few and different", isolated via random partitioning).
7. **Systematic Literature Review (2026) — *Isolation Forest Based Anomaly Detection: A Systematic Literature Review* (arXiv:2501.17787):** Shows Isolation Forest achieves high accuracy on overt attacks but struggles with stealthier intrusion types—grounds our Tier 3 (obfuscation) evaluation.

### C. LLM-Assisted Security Analysis & Explainability
8. **Ali & Kostakos (2023) — *HuntGPT: Integrating ML-Based Anomaly Detection and Explainable AI with LLMs* (arXiv:2309.16021):** Direct structural precedent combining ML anomaly detection with an LLM explainability layer. Our differentiator: PrivEsc/LOLBin-specific lineage features + sliding window chaining/obfuscation evaluation.
9. **Houssel, Singh, Layeghy, Portmann (2024) — *Towards Explainable Network Intrusion Detection Using LLMs* (arXiv:2408.04342):** Methodology reference for evaluating LLM explanations and guarding against hallucinated justifications.
10. **Ferrag et al. (IEEE Access 2024) — *Revolutionizing Cyber Threat Detection with LLMs: A Privacy-Preserving BERT-Based Lightweight Model for IoT/IIoT*:** Represents the fine-tuned lightweight model alternative; cited to justify our zero-shot general-purpose LLM design choice and future work direction.

### D. Optional / Scope-Boundary References
* **Rubin, Kels, Hendler (2019) — *Detecting Malicious PowerShell Scripts Using Contextual Embeddings* (arXiv:1905.09538):** Focused precedent for PowerShell LOLBin abuse.
* **Adversarial Robustness Literature (arXiv:2408.16025, arXiv:2604.20495):** Cited in the "Out of Scope" section to explain why adversarial ML perturbation evasion is excluded from the current lab boundary.
* **Prior Offensive PrivEsc Work (for Background contrast):** Happe et al. (2023), PentestGPT (2023), hackingBuddyGPT (arXiv:2405.03644), LLM4Pentest (AD assumed-breach).

---

## 5. EXECUTION INSTRUCTIONS FOR ANTIGRAVITY

Please execute this project systematically in the following order:
1. **Scaffold the Repository Structure:** Create clean directories for `simulators/` (Linux/Windows baseline & attack scripts), `pipeline/` (`feature_extractor.py`, `detector.py`, `llm_explainer.py`), `evaluation/` (`evaluate.py`, synthetic/sample telemetry generator for immediate end-to-end testing), `dashboard/` (`dashboard_app.py` + Wazuh rules), and `docs/` (Proposal, Methodology, Literature Review).
2. **Generate Synthetic Sample Telemetry First:** So the pipeline can be tested immediately without waiting on VM log exports, generate realistic sample datasets (`benign_telemetry.json` and `attack_telemetry_tiers_1_2_3.json`) mimicking Sysmon and `auditd`/Wazuh events across all 3 evaluation tiers.
3. **Write and Execute the Core Pipeline:** Build the feature extractor (with sliding command windows), train the Isolation Forest model, run the evaluation suite across all 3 tiers, and wire up the zero-shot LLM explanation module (with a mock/fallback mode if no API key is set).
4. **Generate Academic Documentation:** Produce the formal Project Proposal, System Architecture document, and IEEE/APA Literature Review using the exact citations and methodology above.
## 6. STRICT WORKSPACE INVARIANTS & SAFETY CONSTRAINTS
- NEVER execute the generated scripts inside `simulators/` (Bash/PowerShell PrivEsc or LOLBin attacks) directly on the Fedora host machine. They are strictly artifacts to be exported to isolated VMs.
- ALWAYS run Python pipeline and evaluation scripts (`feature_extractor.py`, `detector.py`, `evaluate.py`) against the synthetic JSON datasets inside a local Python `.venv`.
- Ignore any prior project context outside this repository.
