# Literature Review & Panel Q&A Cheatsheet

**Project Title:** AI-Assisted Privilege Escalation & Living-off-the-Land (LOLBin) Attempt Detection via Endpoint Telemetry and LLM Explainability  
**Presenter:** Anvesh Dhiraj Shivhare (M.Tech Cyber Security, NFSU Gandhinagar)  
**Quick Reference Spreadsheets:**  
- **Excel Spreadsheet:** [`Literature_Review_Summary.xlsx`](file:///home/ghoul/projects/privesc-lolbin-detector/Literature_Review_Summary.xlsx)  
- **CSV Spreadsheet:** [`Literature_Review_Summary.csv`](file:///home/ghoul/projects/privesc-lolbin-detector/Literature_Review_Summary.csv)  

---

## 1. Quick Master Matrix (12 Papers at a Glance)

| # | Research Paper & Authors | Paper Type | AI / ML Method Used | What Did They Find? (Key Result) | How We Used It in Our Project (Simple Explanation) | Quick 1-Sentence Answer for Panel |
| :-: | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **Springer (2026)**<br>*Supervised Learning for LOLBins in Linux* | Linux GTFOBins & Sequence Detection | Supervised ML + SMOTE (comparing Single Commands vs Command Windows) | A **sliding window of 3–5 consecutive commands** significantly outperforms isolated single commands. Subtle tools like `id` look normal alone, but reveal attacks in sequence. | **Core foundation for our 3-Command Window:** In our benchmark, evaluating command windows boosted attack detection from **51.0% (isolated) to 94.6% (window)**. | *"Springer proved you cannot catch LOLBins looking at one command alone; you must evaluate a window of commands to catch the attack chain."* |
| **2** | **Stamp (2022)**<br>*LOLBin Abuse Detection Using NLP & ML* | Supervised ML Benchmark | Random Forest & Decision Trees with NLP word tokenization | In enterprise networks, **labeled malicious LOLBin data is almost impossible to find**. Supervised models overfit to known attacks and fail on new ones. | **Justifies our Unsupervised approach:** We reproduced Stamp's experiment—supervised models collapsed to **48–52% recall** on unseen tiers, while Isolation Forest maintained **~91%**. | *"Stamp proved supervised models overfit and fail on unseen attacks due to scarce attack data; that's why we train strictly on normal behavior."* |
| **3** | **Liu, Ting, Zhou (2008)**<br>*Isolation Forest (IEEE ICDM)* | Foundational Anomaly Detection | Unsupervised Ensembles of Random Isolation Trees (iTrees) | Anomalies are **"few and different"**. Instead of modeling normal boundaries, anomalies can be isolated much faster using random feature partitioning. | **Our Core Detection Math (`detector.py`):** We train it solely on normal sysadmin baseline (70% of 25,495 Ubuntu events) to flag deviations without any attack labels. | *"This is our core math model: it isolates rare behavioral deviations with fewer random cuts, completely eliminating the need for attack labels."* |
| **4** | **Systematic Review (2026)**<br>*Isolation Forest Anomaly Detection SLR* | Systematic Survey & Meta-Analysis | Meta-analysis of Isolation Forest across diverse cyber domains | Isolation Forest achieves high detection on **overt attacks**, but naturally degrades on **stealthy or obfuscated intrusions** where features mimic normal traffic. | **Grounds our 3-Tier Evaluation:** Our benchmark confirmed this exact literature finding: Isolation Forest achieved **100% recall on Tier 1 (Overt)**, but dropped to **90.0% on Tier 3 (Obfuscated)**. | *"The literature cautioned that Isolation Forest drops on obfuscated attacks; we proved this by benchmarking 3 complexity tiers (Overt 100% vs Obfuscated 90%)."* |
| **5** | **Ongun et al. (2021)**<br>*LOLAL: LOLBin Active Learning (RAID)* | Command NLP & Active Learning | Word embeddings, character dynamics, and ensemble boosting (0.96 F1) | Character dynamics, command length, and continuous token embeddings catch suspicious command syntax far better than rigid regex signatures. | **Informs our Feature Extractor:** We compute command length, character randomness (Shannon entropy), special character ratio, and 5-component TF-IDF embeddings. | *"Ongun showed that NLP token embeddings and character randomness can catch suspicious command lines that static regex rules miss."* |
| **6** | **Barr-Smith et al. (2021)**<br>*Survivalism (IEEE S&P)* | Large-Scale Threat Measurement | Dynamic malware execution & Windows API call measurement | Analyzed thousands of malware samples and proved malware relies on a core set of native tools: `powershell`, `certutil`, `mshta`, `rundll32`, `regsvr32`, `wmic`, `bitsadmin`. | **Justifies our Target Binaries:** Provided scientific justification for the exact Windows LOLBins we monitor and test in our Windows Sysmon adapter. | *"This IEEE paper identified which specific Windows tools malware authors actually abuse, so we targeted those exact binaries in our project."* |
| **7** | **Ali & Kostakos (2023)**<br>*HuntGPT (arXiv:2309.16021)* | Explainable AI (XAI) for SOC Operations | Pairing statistical/ML anomaly detection with conversational LLM explanations | ML models only output numbers (e.g. `Score: 0.85`), causing severe analyst alert fatigue. Using LLMs to translate outliers into plain-English incident reports speeds up triage. | **Architectural Blueprint:** Layer 1 runs fast mathematical scoring (Isolation Forest), and Layer 2 queries a zero-shot LLM to produce plain-English SOC incident summaries. | *"HuntGPT was our architectural blueprint: use fast ML to catch the anomaly, then use an LLM to explain what happened in plain English for the analyst."* |
| **8** | **Houssel et al. (2024)**<br>*Explainable NIDS Using LLMs* | LLM Grounding & Hallucination Control | Zero-shot prompting, structured JSON schema, and factual grounding | Open-ended LLMs will hallucinate security justifications. To be trustworthy, prompts must strictly constrain the LLM to observable telemetry and statistical feature deviations. | **Governs our LLM System Prompt:** In `pipeline/llm_explainer.py`, we strictly feed feature z-scores and command histories, requiring valid JSON output with zero hallucinated assumptions. | *"Houssel showed how to stop LLMs from hallucinating: we strictly ground the LLM by feeding only observable telemetry and feature z-scores."* |
| **9** | **Ding et al. (2023)**<br>*LOLWTC: Deep Learning LOLBins* | Deep Learning Sequence Modeling | Deep neural networks (Word2Vec + CNN/BiLSTM) for command sequences | Attackers chain multiple legitimate tools over time (Recon $\rightarrow$ PrivEsc $\rightarrow$ Staging). Static rules miss multi-step chains, while sequence models catch them as they evolve. | **Informed our Tier 2 Chained Benchmark:** Proved that our sliding window catches 100% of attack chains with an average delay of only 0.25 commands. | *"Ding proved that attackers chain normal tools together over time; we used this to design our multi-step attack chain benchmark."* |
| **10** | **Ferrag et al. (2024)**<br>*Cyber Threat Detection with LLMs (IEEE Access)* | LLM Deployment & Privacy Trade-off | Comparison of Cloud LLMs vs. Compact Lightweight On-Premise Models | Sending sensitive telemetry to cloud LLMs creates privacy and latency risks; hybrid or offline architectures are required for air-gapped security environments. | **Inspired our Dual-Engine Explainer:** Our pipeline queries live cloud APIs when available, but seamlessly falls back to a deterministic offline SOC reasoning engine for air-gapped local VM testing. | *"Ferrag highlighted privacy concerns with cloud LLMs; that's why our pipeline includes an offline deterministic engine that runs without internet."* |
| **11** | **Rubin et al. (2019)**<br>*PowerShell Contextual Embeddings* | Scope Boundary: Script Anomaly Detection | Contextual Word2Vec embeddings on PowerShell Abstract Syntax Trees | Demonstrated that lexical representation can detect malicious PowerShell scripts. | **Defines Scope Boundary:** While Rubin focused exclusively on PowerShell scripts, our project expands beyond PowerShell to dual-OS system binaries (`find`, `tar`, `python3`, `certutil`, etc.). | *"Rubin only looked at PowerShell scripts; we expanded this idea to cover both Linux GTFOBins and Windows native executables."* |
| **12** | **Demontis et al. (2024/2026)**<br>*Adversarial Robustness in Cyber ML* | Scope Boundary: Adversarial ML | Mathematical gradient-based feature perturbations against classifiers | Machine learning classifiers can be evaded if attackers craft mathematical gradient perturbations against model weights. | **Defines Defensive Lab Boundary:** Our project evaluates realistic human/script obfuscation (Base64, backticks, variable aliasing) and explicitly excludes adversarial gradient perturbations. | *"This defines our boundary: we evaluate realistic human obfuscation like Base64 and variable aliasing, not mathematical adversarial perturbation attacks."* |

---

## 2. Top 4 Panel Questions & Confident Speaking Scripts

### Q1: *"Why did you use Unsupervised Anomaly Detection (Isolation Forest) instead of standard Supervised Classification (Random Forest / SVM)?"*
> **Your Answer:**  
> *"Sir, we based this decision on **Stamp (2022)**. In real-world enterprise networks, labeled malicious LOLBin data is practically non-existent—normal admin logs outnumber attacks by millions to one. When we tested supervised models (Random Forest and Decision Trees with SMOTE) on unseen attack tiers, their recall collapsed to **48% to 52%** because they simply memorized past attack strings.  
> By using **Isolation Forest (Liu et al., 2008)**, we train strictly on the clean, normal administrator baseline. It learns normal behavior and catches anomalies without ever needing labeled attack data, maintaining **~91% recall across unseen attack tiers**."*

---

### Q2: *"Why do you evaluate a 3-command sliding window instead of evaluating each command line individually?"*
> **Your Answer:**  
> *"Sir, this directly implements the scientific finding of **Springer (2026)**. In real life, attackers do not run one isolated command; they run multi-step attack sequences.  
> For example, an attacker runs:  
> `whoami` $\rightarrow$ `sudo find -exec /bin/sh` $\rightarrow$ `id`.  
> Look at the `id` command: in isolation, `id` looks 100% harmless and scores **0.08** (deep in the safe zone). But when executed right after `find -exec`, our 3-command sliding window carries forward the suspicious context and the exact same `id` command jumps to **0.58**—crossing the alarm line!  
> In our benchmark, evaluating command windows increased attack detection from **51.0% to 94.6%**."*

---

### Q3: *"Why did you evaluate across 3 attack tiers (Overt vs Chained vs Obfuscated)?"*
> **Your Answer:**  
> *"Sir, the **Systematic Literature Review on Isolation Forest (2026)** highlighted a known weakness: Isolation Forest achieves near-perfect accuracy on overt, noisy attacks, but degrades on stealthy or obfuscated attacks where commands mimic normal traffic.  
> To test this rigorously, we evaluated 3 tiers:  
> 1. **Tier 1 (Overt):** Scored **100% recall** and **0.995 F1**.  
> 2. **Tier 2 (Chained sequences):** Caught **100% of attack chains** with an average delay of only 0.25 commands (**Ding et al., 2023**).  
> 3. **Tier 3 (Obfuscated with Base64/aliasing):** Recall dropped to **90.0%**.  
> This proves our methodology is scientifically honest: we confirmed the literature's theoretical finding on our own system."*

---

### Q4: *"Why did you bring in a Large Language Model (LLM) instead of just alerting on the anomaly score?"*
> **Your Answer:**  
> *"Sir, we followed the architectural precedent of **HuntGPT (Ali & Kostakos, 2023)**. Anomaly detection models only output numbers (for example, `Score: 0.85, Entropy: 4.8`). A junior SOC analyst seeing that number doesn't know what it means, leading to severe alert fatigue.  
> Our Layer 2 LLM takes the raw telemetry and feature z-scores and produces a clear, 1-paragraph plain-English SOC verdict with MITRE ATT&CK attribution (e.g. `T1548.003 Sudo GTFOBin`).  
> And to make sure the LLM never hallucinates, we followed **Houssel et al. (2024)** by strictly constraining the prompt to observable telemetry data."*

---

## 3. How to Open the Files

- **Excel Spreadsheet:** Open [`Literature_Review_Summary.xlsx`](file:///home/ghoul/projects/privesc-lolbin-detector/Literature_Review_Summary.xlsx) in Microsoft Excel, LibreOffice Calc, or Google Sheets. It is pre-styled with bold navy headers, alternating row colors, word-wrapping, and auto-fitted column widths.
- **CSV File:** Open [`Literature_Review_Summary.csv`](file:///home/ghoul/projects/privesc-lolbin-detector/Literature_Review_Summary.csv) in any text editor or spreadsheet tool.
