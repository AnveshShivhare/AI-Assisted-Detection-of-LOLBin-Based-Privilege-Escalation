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
2. A **sequence-aware sliding command window aggregator** ($N=3$ to $5$) that captures dynamic transition features (`binary_changed`, `entropy_delta`, `token_acceleration`, `priv_escalated_in_window`, `inter_event_delta_ms`).
3. A **continuous NLP feature representation** combining Shannon character entropy, special character ratios, and 5-dimensional TruncatedSVD-reduced TF-IDF token n-gram embeddings (Ongun et al. RAID 2021).
4. A **zero-shot Large Language Model (LLM) explainability and technique attribution layer** that converts mathematical feature deviations into grounded, plain-English SOC analyst narratives mapped directly to MITRE ATT&CK techniques without ground-truth label leakage.

---

## 3. Project Objectives & Research Contributions
* **Objective 1: Multi-OS Telemetry Ingestion & Adapter Architecture:** Build an extensible `TelemetrySource` adapter interface supporting both synthetic lab simulation datasets (`SyntheticTelemetrySource`) and real Linux `auditd` log streams (`AuditdTelemetrySource`), extracting process lineage, ancestral process tree depth, UID/GID/Integrity transitions, sensitive file touches, and command-line NLP representations.
* **Objective 2: Sequence-Aware Anomaly Detection & Window Size Ablation:** Implement and tune an unsupervised Isolation Forest model evaluated across isolated commands vs. multi-step sliding windows ($N=3, 4, 5$), proving the hypothesis (Springer 2026) that post-exploitation commands look benign in isolation but exhibit anomalous transition dynamics in sequence.
* **Objective 3: Three-Tier Attack Complexity Benchmarking & Evasion Limits:** Rigorously evaluate pipeline sensitivity against three distinct attack tiers:
  - *Tier 1 (Overt / Isolated):* Standard GTFOBins and single LOLBin commands ($100\%$ Recall, $0.995$ $F_1$).
  - *Tier 2 (Chained Sequences):* Multi-step sequences (reconnaissance $\rightarrow$ privilege elevation $\rightarrow$ credential exfiltration) with empirical Time-to-Detect measurement ($91.2\%$ event-level recall, $100\%$ chain-level interception, mean delay: $0.25$ commands).
  - *Tier 3 (Obfuscated / Stealthy):* Base64 encoding, environment variable aliasing, and shell metacharacter manipulation, empirically validating the SLR (2026) hypothesis that tree-partitioning anomaly detectors degrade on subtle low-entropy obfuscations ($90.0\%$ recall, $0.925$ $F_1$).
* **Objective 4: Supervised Generalization Failure Demonstration:** Prove Stamp's (2022) thesis by training supervised models (Random Forest and Decision Tree) with SMOTE oversampling and balanced class weighting on seen Tier 1 attacks, demonstrating that supervised classifiers overfit to known syntax ($100\%$ on seen) but degrade to $\approx 48-52\%$ recall on unseen chained/obfuscated attacks, whereas unsupervised Isolation Forest achieves $90.8\%$ recall.
* **Objective 5: Hallucination-Controlled Zero-Shot LLM Attribution:** Integrate a Tier-3 SOC analysis layer consuming strictly observable JSON anomaly payloads, attributing techniques to MITRE ATT&CK IDs with plain-English justifications and a deterministic offline fallback engine for reproducible testing.

---

## 4. Ethical Boundaries & Laboratory Isolation
All attack simulation and telemetry generation are strictly conducted within isolated, non-networked local Virtual Machines (Linux Ubuntu Server & Windows 10/11 Enterprise). No external offensive actions, adversarial ML weight perturbations, or automated exploit generation tools are deployed. The host development machine remains decoupled from simulation script execution.

---

## 5. Deliverables & Expected Outcomes
1. **Reproducible VM Simulation Artifacts:** Safe Bash and PowerShell simulation scripts in `simulators/` for export to isolated lab VMs.
2. **Modular Python Pipeline:**
   - `pipeline/telemetry.py`: Telemetry adapter interface and real auditd parser.
   - `pipeline/feature_extractor.py`: Sequence-aware feature extractor with TF-IDF embeddings and ancestral tree depth.
   - `pipeline/detector.py`: Isolation Forest engine with OS-stratified threshold calibration and SMOTE supervised comparators.
   - `pipeline/llm_explainer.py`: Zero-shot LLM integration with deterministic offline SOC fallback.
3. **Rigorous Benchmark Suite (`evaluation/evaluate.py`):** Reproducible CLI evaluation script supporting `--source=synthetic|auditd`, generating precision, recall, $F_1$, tier-specific FPRs, window ablation ($N=3, 4, 5$), time-to-detect metrics, and publication plots.
4. **Interactive SOC Dashboard (`dashboard/dashboard_app.py`):** Streamlit analyst console with data source switching and provenance badges.
5. **Academic Documentation:** Formal System Architecture, Grounding Literature Review, and scientific limitations disclosure.

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
