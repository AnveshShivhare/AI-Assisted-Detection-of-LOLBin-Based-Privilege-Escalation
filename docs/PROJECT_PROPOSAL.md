# M.Tech Major Project Proposal

## 1. Project Identification
* **Project Title:** AI-Assisted Privilege Escalation & Living-off-the-Land (LOLBin) Attempt Detection via Endpoint Telemetry and LLM Explainability
* **Academic Program:** Master of Technology (M.Tech) in Computer Science / Information Security
* **Research Track:** Blue-Team / Defensive Endpoint Detection & Response (EDR) Systems
* **Target Domain:** Applied Machine Learning for Host Intrusion Detection & Security Operations Center (SOC) Cognitive Automation

---

## 2. Executive Summary & Problem Formulation
Enterprise environments face an asymmetric threat landscape where adversaries increasingly avoid compiling or dropping custom malware binaries. Instead, attackers execute **Living-off-the-Land (LOLBin)** techniques—co-opting legitimate, digitally signed administrative utilities (e.g., `powershell.exe`, `certutil.exe`, `mshta.exe`, `find`, `awk`, `sudo`) to perform post-exploitation, lateral movement, and **Privilege Escalation (PrivEsc)**. Because LOLBins inherit trusted digital signatures and valid system execution contexts, traditional signature-based Anti-Virus (AV) and static Endpoint Detection and Response (EDR) rules either generate immense alert fatigue (high False Positive Rates) or completely miss stealthy intrusions.

While prior research has heavily explored *offensive* AI automation for privilege escalation (e.g., automated exploit mutation, wrapper tools around BloodHound and PEASS), this project executes a strategic **defensive pivot**. We focus on Blue-Team detection engineering by constructing an integrated detection and attribution pipeline:
1. An **unsupervised behavioral anomaly detection engine (Isolation Forest)** that trains strictly on unperturbed benign baseline endpoint telemetry.
2. A **sliding command window sequence aggregator** ($N=3$ to $5$) that captures temporal post-exploitation sequences.
3. A **zero-shot Large Language Model (LLM) explainability and technique attribution layer** that converts mathematical feature deviations into grounded, plain-English SOC analyst narratives mapped directly to MITRE ATT&CK techniques.

---

## 3. Project Objectives & Research Contributions
* **Objective 1: Multi-OS Telemetry Ingestion & Behavioral Representation:** Build a standardized parser for Linux `auditd` and Windows Sysmon (Event IDs 1 & 11) telemetry capturing process lineage, UID/GID/Integrity transitions, sensitive file touches, and command-line NLP character dynamics (Shannon entropy, token density).
* **Objective 2: Sequence-Aware Anomaly Detection:** Implement and tune an unsupervised Isolation Forest model evaluated across isolated commands vs. multi-step sliding windows, validating the hypothesis that post-exploitation behavior is inherently sequential.
* **Objective 3: Three-Tier Attack Complexity Benchmarking:** Rigorously evaluate pipeline sensitivity against three distinct attack tiers:
  - *Tier 1 (Overt / Isolated):* Standard GTFOBins and single LOLBin commands.
  - *Tier 2 (Chained Sequences):* Multi-step sequences (reconnaissance $\rightarrow$ privilege elevation $\rightarrow$ credential exfiltration).
  - *Tier 3 (Obfuscated / Stealthy):* Base64 encoding, environment variable slicing, and shell metacharacter manipulation designed to expose the boundary limitations of unsupervised tree partitioning.
* **Objective 4: Hallucination-Controlled LLM Attribution:** Integrate a zero-shot SOC analysis layer that consumes structured JSON anomaly vectors and generates deterministic technique attribution and human-readable explanations without hallucinating out-of-context behaviors.

---

## 4. Ethical Boundaries & Laboratory Isolation
All attack traces and telemetry collection are strictly conducted within isolated, non-networked local Virtual Machines (Linux Ubuntu Server & Windows 10/11 Enterprise). No external offensive actions, adversarial ML weight perturbations, or automated exploit generation tools are deployed. The host development machine remains decoupled from simulation script execution.

---

## 5. Deliverables & Expected Outcomes
1. **Reproducible VM Telemetry Generators:** Bash and PowerShell simulation artifacts for benign baselines and Tier 1–3 PrivEsc/LOLBin attacks.
2. **Modular Python Pipeline:**
   - `feature_extractor.py`: Sliding window aggregator and lineage extractor.
   - `detector.py`: Scikit-learn Isolation Forest engine with feature attribution.
   - `llm_explainer.py`: Zero-shot LLM integration with deterministic offline fallback.
3. **Rigorous Benchmark Suite (`evaluate.py`):** Reproducible scripts generating precision, recall, $F_1$, and FPR tables, as well as publication-quality ablation plots.
4. **Interactive SOC Dashboard (`dashboard_app.py`):** Web-based analyst console and Wazuh custom rule sets (`local_rules.xml`).
5. **Academic Documentation:** Formal System Architecture and Grounding Literature Review papers.

---

## 6. Milestones & Work Plan
```text
[Weeks 1 - 2]  Lab VM setup, telemetry schema design, and baseline generation
[Weeks 3 - 4]  Feature extraction engine & sliding command window modeling
[Weeks 5 - 6]  Isolation Forest training, hyperparameter tuning, & thresholding
[Weeks 7 - 8]  Zero-shot LLM explainability prompt engineering & offline engine
[Weeks 9 - 10] Comprehensive benchmarking across Tiers 1-3 & ablation studies
[Weeks 11 - 12] Final dissertation writing, dashboard integration, & code release
```
