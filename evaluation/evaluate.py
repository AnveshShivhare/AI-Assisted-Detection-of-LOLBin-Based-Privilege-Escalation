#!/usr/bin/env python3
"""
evaluate.py
===========
AI-Assisted Privilege Escalation & Living-off-the-Land (LOLBin) Detection Project
Comprehensive Evaluation & Benchmarking Suite

Executes rigorous academic evaluation across:
  1. Benign Baseline vs Attack Tiers
  2. Single Isolated Command vs Sliding Window of Commands (Springer 2026)
  3. Tier 1 (Overt) vs Tier 2 (Chained) vs Tier 3 (Obfuscated) (SLR 2026, Liu 2008)
  4. Supervised Generalization Failure (Stamp 2022) vs Unsupervised Anomaly Detection
  5. Zero-Shot LLM Attribution & Explainability Layer Quality (Ali & Kostakos 2023)

Outputs:
  - Publication-ready ASCII tables
  - High-resolution evaluation charts (.png) in evaluation/results/
  - Structured evaluation report in evaluation/results/evaluation_summary.json
"""

import os
import sys
import json
import time
from typing import Dict, List, Any, Tuple
from collections import defaultdict
import numpy as np
import pandas as pd
from tabulate import tabulate
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from pipeline.feature_extractor import TelemetryFeatureExtractor
from pipeline.detector import AnomalyDetector
from pipeline.llm_explainer import LLMExplainer

def calculate_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, float]:
    """Computes TP, FP, TN, FN, Precision, Recall, F1-Score, and FPR."""
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1, "fpr": fpr
    }

def run_evaluation(data_dir: str = "data", results_dir: str = "evaluation/results"):
    os.makedirs(results_dir, exist_ok=True)
    print("=" * 80)
    print("AI-Assisted PrivEsc & LOLBin Detection - Academic Evaluation Suite")
    print("=" * 80)

    # 1. Load Data
    benign_path = os.path.join(data_dir, "benign_telemetry.json")
    t1_path = os.path.join(data_dir, "attack_tier1.json")
    t2_path = os.path.join(data_dir, "attack_tier2.json")
    t3_path = os.path.join(data_dir, "attack_tier3.json")

    with open(benign_path) as f:
        benign_events = json.load(f)
    with open(t1_path) as f:
        t1_events = json.load(f)
    with open(t2_path) as f:
        t2_events = json.load(f)
    with open(t3_path) as f:
        t3_events = json.load(f)

    print(f"[*] Loaded Datasets:")
    print(f"    - Benign Baseline: {len(benign_events)} events")
    print(f"    - Attack Tier 1 (Overt): {len(t1_events)} events")
    print(f"    - Attack Tier 2 (Chained): {len(t2_events)} events")
    print(f"    - Attack Tier 3 (Obfuscated): {len(t3_events)} events")

    # Split benign into 70% train (clean baseline) and 30% test
    n_train = int(len(benign_events) * 0.7)
    benign_train = benign_events[:n_train]
    benign_test = benign_events[n_train:]

    # -------------------------------------------------------------
    # EXPERIMENT 1: Single Isolated Commands vs Sliding Windows
    # (Testing Springer 2026 Hypothesis)
    # -------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[EXPERIMENT 1] Isolated Command Lines vs Sliding Command Windows (Springer 2026)")
    print("-" * 80)

    modes = ["isolated", "window"]
    exp1_results = []

    for mode in modes:
        extractor = TelemetryFeatureExtractor(window_size=3)
        X_train, f_names, _ = extractor.fit_transform(benign_train, mode=mode)

        detector = AnomalyDetector(contamination=0.025, n_estimators=150)
        detector.fit_unsupervised(X_train, f_names)

        # Test set: Benign test + All attacks
        test_events = benign_test + t1_events + t2_events + t3_events
        t_start = time.perf_counter()
        X_test, _, meta_test = extractor.transform(test_events, mode=mode)
        t_extract = time.perf_counter() - t_start

        t_start = time.perf_counter()
        is_anomaly, scores = detector.predict_anomaly(X_test)
        t_infer = time.perf_counter() - t_start

        y_true = np.array([1 if m["label"] == "malicious" else 0 for m in meta_test])
        y_pred = is_anomaly.astype(int)

        metrics = calculate_metrics(y_true, y_pred)
        latency_per_event = ((t_extract + t_infer) / len(test_events)) * 1000 # ms

        exp1_results.append({
            "Mode": "Single Isolated Command" if mode == "isolated" else "Sliding Window (N=3)",
            "Precision": f"{metrics['precision']:.4f}",
            "Recall": f"{metrics['recall']:.4f}",
            "F1-Score": f"{metrics['f1']:.4f}",
            "FPR": f"{metrics['fpr']:.4f}",
            "Latency/Ev (ms)": f"{latency_per_event:.3f}",
            "_raw": metrics
        })

    print(tabulate(exp1_results, headers="keys", tablefmt="fancy_grid"))

    # -------------------------------------------------------------
    # EXPERIMENT 2: Granular Evaluation Across Attack Tiers
    # (Tier 1 Overt vs Tier 2 Chained vs Tier 3 Obfuscated)
    # (Testing SLR 2026 & Liu 2008 Isolation Forest degradation)
    # -------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[EXPERIMENT 2] Detection Performance Across Attack Complexity Tiers")
    print("-" * 80)

    # Use sliding window extractor as optimal configuration
    best_extractor = TelemetryFeatureExtractor(window_size=3)
    X_train_win, f_names_win, _ = best_extractor.fit_transform(benign_train, mode="window")
    best_detector = AnomalyDetector(contamination=0.025, n_estimators=150)
    best_detector.fit_unsupervised(X_train_win, f_names_win)

    # Save trained detector for production pipeline use
    model_save_path = os.path.join("pipeline", "detector_model.joblib")
    best_detector.save(model_save_path)
    print(f"[+] Saved trained Isolation Forest pipeline model to {model_save_path}")

    tier_eval_data = [
        ("Tier 1: Overt / Isolated GTFOBins & LOLBins", t1_events),
        ("Tier 2: Multi-step Chained Sequences", t2_events),
        ("Tier 3: Obfuscated / Stealthy (Base64/Ticks/IFS/Aliasing)", t3_events),
    ]

    exp2_results = []
    plot_data_tiers = {}
    tier_predictions = {}
    tier_metas = {}
    tier_scores = {}
    tier_X = {}

    for tier_name, tier_events in tier_eval_data:
        combined = benign_test + tier_events
        X_sub, _, meta_sub = best_extractor.transform(combined, mode="window")
        is_anom, scores = best_detector.predict_anomaly(X_sub)

        y_true = np.array([1 if m["label"] == "malicious" else 0 for m in meta_sub])
        y_pred = is_anom.astype(int)

        m = calculate_metrics(y_true, y_pred)
        exp2_results.append({
            "Attack Evaluation Tier": tier_name,
            "Attack Events": len(tier_events),
            "Benign Test": len(benign_test),
            "Precision": f"{m['precision']:.4f}",
            "Recall": f"{m['recall']:.4f}",
            "F1-Score": f"{m['f1']:.4f}",
            "FPR": f"{m['fpr']:.4f}",
            "_raw": m
        })
        plot_data_tiers[tier_name] = m
        tier_predictions[tier_name] = is_anom
        tier_metas[tier_name] = meta_sub
        tier_scores[tier_name] = scores
        tier_X[tier_name] = X_sub

    print(tabulate(exp2_results, headers="keys", tablefmt="fancy_grid"))

    # -------------------------------------------------------------
    # TABLE 2B: Chained Sequence Detection Highlight (Tier 2 Multi-Step)
    # Grounding: Springer (2026) sliding window sequence evaluation
    # -------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[TABLE 2B] Chained Sequence Highlight: Event-Level Recall vs. Chain-Level Detection")
    print("-" * 80)

    t2_meta_all = tier_metas["Tier 2: Multi-step Chained Sequences"]
    t2_preds_all = tier_predictions["Tier 2: Multi-step Chained Sequences"]
    n_b = len(benign_test)
    t2_attack_meta = t2_meta_all[n_b:]
    t2_attack_preds = t2_preds_all[n_b:]

    t2_raw_m = plot_data_tiers["Tier 2: Multi-step Chained Sequences"]
    event_level_recall = t2_raw_m["recall"]

    # Group Tier 2 commands by attack session
    t2_chains = defaultdict(list)
    for m_ev, pred in zip(t2_attack_meta, t2_attack_preds):
        t2_chains[m_ev["session_id"]].append(bool(pred))

    total_chains = len(t2_chains)
    detected_chains = sum(1 for sess, flags in t2_chains.items() if any(flags))
    chain_detection_rate = detected_chains / total_chains if total_chains > 0 else 0.0

    exp2b_results = [
        {
            "Evaluation Dimension": "Event-Level Recall",
            "Observed Count": f"{int(t2_raw_m['tp'])} / {len(t2_events)} Events",
            "Detection Rate": f"{event_level_recall:.4f}",
            "Operational Significance": "Individual command anomaly detection across multi-step execution"
        },
        {
            "Evaluation Dimension": "Chain-Level Detection Rate",
            "Observed Count": f"{detected_chains} / {total_chains} Attack Chains",
            "Detection Rate": f"{chain_detection_rate:.4f}",
            "Operational Significance": "Chains interrupted (>=1 step flagged in window) halting adversary progression"
        }
    ]
    print(tabulate(exp2b_results, headers="keys", tablefmt="fancy_grid"))

    # -------------------------------------------------------------
    # TABLE 2C: Per-Binary Benign vs. Malicious Discrimination
    # Evaluating discrimination across the 10 target binaries
    # -------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[TABLE 2C] Per-Binary Benign vs. Malicious Discrimination")
    print("-" * 80)

    # Compile all test predictions across benign test and all 3 attack tiers
    b_meta = tier_metas["Tier 1: Overt / Isolated GTFOBins & LOLBins"][:n_b]
    b_preds = tier_predictions["Tier 1: Overt / Isolated GTFOBins & LOLBins"][:n_b]

    t1_attack_meta = tier_metas["Tier 1: Overt / Isolated GTFOBins & LOLBins"][n_b:]
    t1_attack_preds = tier_predictions["Tier 1: Overt / Isolated GTFOBins & LOLBins"][n_b:]

    t3_attack_meta = tier_metas["Tier 3: Obfuscated / Stealthy (Base64/Ticks/IFS/Aliasing)"][n_b:]
    t3_attack_preds = tier_predictions["Tier 3: Obfuscated / Stealthy (Base64/Ticks/IFS/Aliasing)"][n_b:]

    all_test_meta = b_meta + t1_attack_meta + t2_attack_meta + t3_attack_meta
    all_test_preds = np.concatenate([b_preds, t1_attack_preds, t2_attack_preds, t3_attack_preds])
    all_test_y = np.array([1 if m["label"] == "malicious" else 0 for m in all_test_meta])

    target_binaries = ["find", "vim", "awk", "tar", "python3", "certutil.exe", "powershell.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe"]
    exp2c_results = []

    for binary in target_binaries:
        matched = [i for i, m in enumerate(all_test_meta) if binary in m.get("process_name", "").lower()]
        if not matched:
            continue
        y_true_b = all_test_y[matched]
        y_pred_b = all_test_preds[matched].astype(int)
        b_count = int(np.sum(y_true_b == 0))
        a_count = int(np.sum(y_true_b == 1))
        mb = calculate_metrics(y_true_b, y_pred_b)
        exp2c_results.append({
            "Target Binary": binary,
            "Benign Test Count": b_count,
            "Attack Test Count": a_count,
            "Precision": f"{mb['precision']:.4f}",
            "Recall": f"{mb['recall']:.4f}",
            "F1-Score": f"{mb['f1']:.4f}",
            "FPR": f"{mb['fpr']:.4f}"
        })

    print(tabulate(exp2c_results, headers="keys", tablefmt="fancy_grid"))

    # -------------------------------------------------------------
    # EXPERIMENT 3: Comparison with Supervised Baselines (Stamp 2022)
    # (Trained on Tier 1 Seen Overt Attacks, Tested on Unseen Chained & Obfuscated Tiers)
    # -------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[EXPERIMENT 3] Supervised Generalization Failure (Stamp 2022) vs Unsupervised Anomaly Detection")
    print("-" * 80)

    # Partition Tier 1 into 70% train and 30% test
    n_t1_tr = int(len(t1_events) * 0.7)
    t1_train = t1_events[:n_t1_tr]
    t1_test = t1_events[n_t1_tr:]

    # Supervised training set: Benign train + Tier 1 seen overt attacks
    sup_train_events = benign_train + t1_train
    X_sup_tr, _, meta_sup_tr = best_extractor.transform(sup_train_events, mode="window")
    y_sup_tr = np.array([1 if m["label"] == "malicious" else 0 for m in meta_sup_tr])

    best_detector.train_supervised_comparators(X_sup_tr, y_sup_tr)

    # 1. Sanity check: Evaluate on Seen Tier 1 test
    seen_test_events = benign_test + t1_test
    X_seen, _, meta_seen = best_extractor.transform(seen_test_events, mode="window")
    y_seen = np.array([1 if m["label"] == "malicious" else 0 for m in meta_seen])
    rf_seen_preds = best_detector.predict_supervised_comparators(X_seen)["RandomForest"]
    rf_seen_m = calculate_metrics(y_seen, rf_seen_preds)

    # 2. Generalization test: Evaluate on Unseen Attack Tiers (Tiers 2 & 3)
    unseen_attacks = t2_events + t3_events
    unseen_test_events = benign_test + unseen_attacks

    X_unseen, _, meta_unseen = best_extractor.transform(unseen_test_events, mode="window")
    y_unseen = np.array([1 if m["label"] == "malicious" else 0 for m in meta_unseen])

    sup_unseen_preds = best_detector.predict_supervised_comparators(X_unseen)
    is_anom_unseen, _ = best_detector.predict_anomaly(X_unseen)
    if_unseen_m = calculate_metrics(y_unseen, is_anom_unseen.astype(int))

    exp3_results = [
        {
            "Model Architecture": "Isolation Forest (Unsupervised)",
            "Precision": f"{if_unseen_m['precision']:.4f}",
            "Recall": f"{if_unseen_m['recall']:.4f}",
            "F1-Score": f"{if_unseen_m['f1']:.4f}",
            "FPR": f"{if_unseen_m['fpr']:.4f}",
            "Evaluation Scope": "Unseen Attack Tiers (Tiers 2 & 3) [0 attack labels in train]"
        },
        {
            "Model Architecture": "RandomForest (Supervised Benchmark)",
            "Precision": f"{calculate_metrics(y_unseen, sup_unseen_preds['RandomForest'])['precision']:.4f}",
            "Recall": f"{calculate_metrics(y_unseen, sup_unseen_preds['RandomForest'])['recall']:.4f}",
            "F1-Score": f"{calculate_metrics(y_unseen, sup_unseen_preds['RandomForest'])['f1']:.4f}",
            "FPR": f"{calculate_metrics(y_unseen, sup_unseen_preds['RandomForest'])['fpr']:.4f}",
            "Evaluation Scope": "Unseen Attack Tiers (Tiers 2 & 3) [Trained on Tier 1 Overt]"
        },
        {
            "Model Architecture": "DecisionTree (Supervised Benchmark)",
            "Precision": f"{calculate_metrics(y_unseen, sup_unseen_preds['DecisionTree'])['precision']:.4f}",
            "Recall": f"{calculate_metrics(y_unseen, sup_unseen_preds['DecisionTree'])['recall']:.4f}",
            "F1-Score": f"{calculate_metrics(y_unseen, sup_unseen_preds['DecisionTree'])['f1']:.4f}",
            "FPR": f"{calculate_metrics(y_unseen, sup_unseen_preds['DecisionTree'])['fpr']:.4f}",
            "Evaluation Scope": "Unseen Attack Tiers (Tiers 2 & 3) [Trained on Tier 1 Overt]"
        },
        {
            "Model Architecture": "RandomForest (Supervised - Seen Tier 1 Baseline)",
            "Precision": f"{rf_seen_m['precision']:.4f}",
            "Recall": f"{rf_seen_m['recall']:.4f}",
            "F1-Score": f"{rf_seen_m['f1']:.4f}",
            "FPR": f"{rf_seen_m['fpr']:.4f}",
            "Evaluation Scope": "Seen Attack Partition (Tier 1 Overt Test)"
        }
    ]

    print(tabulate(exp3_results, headers="keys", tablefmt="fancy_grid"))

    # -------------------------------------------------------------
    # EXPERIMENT 4: Zero-Shot LLM Attribution & Explainability Layer
    # (Testing Ali & Kostakos 2023, Houssel et al. 2024)
    # -------------------------------------------------------------
    print("\n" + "-" * 80)
    print("[EXPERIMENT 4] Zero-Shot LLM Explainability & Technique Attribution")
    print("-" * 80)

    explainer = LLMExplainer()
    print(f"[*] Explainer Provider: {explainer.provider} (Fallback / Active Engine)")

    # Build session mapping for sliding window context
    all_events_map = defaultdict(list)
    for ev in (t1_events + t2_events + t3_events + benign_test):
        all_events_map[ev.get("session_id", "")].append(ev.get("command_line", ""))

    sample_indices = [
        # Overt Linux PrivEsc
        [i for i, ev in enumerate(t1_events) if "find" in ev["process_name"]][0],
        # Overt Windows LOLBin
        [i for i, ev in enumerate(t1_events) if "certutil" in ev["process_name"]][0],
        # Tier 2 Chained
        0,
        # Tier 3 Obfuscated
        0,
        # Tier 3 Subtle Aliasing
        [i for i, ev in enumerate(t3_events) if "subtle" in ev["session_id"]][0]
    ]

    sample_configs = [
        ("Tier 1: Overt / Isolated GTFOBins & LOLBins", sample_indices[0], t1_events[sample_indices[0]]),
        ("Tier 1: Overt / Isolated GTFOBins & LOLBins", sample_indices[1], t1_events[sample_indices[1]]),
        ("Tier 2: Multi-step Chained Sequences", sample_indices[2], t2_events[sample_indices[2]]),
        ("Tier 3: Obfuscated / Stealthy (Base64/Ticks/IFS/Aliasing)", sample_indices[3], t3_events[sample_indices[3]]),
        ("Tier 3: Obfuscated / Stealthy (Base64/Ticks/IFS/Aliasing)", sample_indices[4], t3_events[sample_indices[4]])
    ]

    llm_reports = []
    saved_payloads = []
    saved_explanations = []

    for tier_name, s_idx, sample in sample_configs:
        idx = n_b + s_idx
        X_s = tier_X[tier_name][idx]
        eval_score = float(tier_scores[tier_name][idx])
        meta_s = tier_metas[tier_name][idx]
        payload = best_detector.build_anomaly_payload(X_s, meta_s, eval_score)

        # Attach sliding window session command context
        sess_id = sample.get("session_id", "")
        sess_cmds = all_events_map.get(sess_id, [sample.get("command_line", "")])
        try:
            curr_pos = sess_cmds.index(sample.get("command_line", ""))
            payload["sliding_window_commands"] = sess_cmds[max(0, curr_pos) : curr_pos + 3]
        except ValueError:
            payload["sliding_window_commands"] = sess_cmds[:3]

        explanation = explainer.explain_anomaly(payload)
        saved_payloads.append(payload)
        saved_explanations.append(explanation)

        llm_reports.append({
            "Process": sample["process_name"],
            "Command Sample": (sample["command_line"][:45] + "...") if len(sample["command_line"]) > 45 else sample["command_line"],
            "Ground Truth Technique": sample["technique"],
            "LLM Verdict": explanation.get("verdict"),
            "Attributed Technique": explanation.get("attributed_technique"),
            "MITRE ID": explanation.get("mitre_id"),
            "Confidence": explanation.get("confidence_score")
        })

    print(tabulate(llm_reports, headers="keys", tablefmt="fancy_grid"))

    # Print sample SOC Explanations
    print("\n[*] Sample Plain-English SOC Explanation Output (Ali & Kostakos 2023):")
    print("    [Sample A: Chained Sequence Discovery (whoami && id)]")
    print(f"    Command: {saved_payloads[2]['command_line']}")
    print(f"    Sliding Window Context: {saved_payloads[2].get('sliding_window_commands')}")
    print(f"    Verdict: {saved_explanations[2].get('verdict')}")
    print(f"    Technique: {saved_explanations[2].get('attributed_technique')} ({saved_explanations[2].get('mitre_id')})")
    print(f"    Confidence: {saved_explanations[2].get('confidence_score')}")
    print(f"    Analyst Explanation: {saved_explanations[2].get('plain_english_explanation')}\n")

    print("    [Sample B: Subtle Env-Var LOLBin Aliasing (cmd.exe / set p=certutil)]")
    print(f"    Command: {saved_payloads[4]['command_line']}")
    print(f"    Verdict: {saved_explanations[4].get('verdict')}")
    print(f"    Technique: {saved_explanations[4].get('attributed_technique')} ({saved_explanations[4].get('mitre_id')})")
    print(f"    Confidence: {saved_explanations[4].get('confidence_score')}")
    print(f"    Analyst Explanation: {saved_explanations[4].get('plain_english_explanation')}")

    # -------------------------------------------------------------
    # 5. Generate Publication-Quality Plots
    # -------------------------------------------------------------
    print("\n[*] Generating Publication-Ready Evaluation Plots...")

    # Plot 1: Performance by Tier (F1, Precision, Recall, FPR)
    tiers = list(plot_data_tiers.keys())
    tier_labels = ["Tier 1\n(Overt)", "Tier 2\n(Chained)", "Tier 3\n(Obfuscated)"]
    f1_vals = [plot_data_tiers[t]["f1"] for t in tiers]
    rec_vals = [plot_data_tiers[t]["recall"] for t in tiers]
    prec_vals = [plot_data_tiers[t]["precision"] for t in tiers]
    fpr_vals = [plot_data_tiers[t]["fpr"] for t in tiers]

    x = np.arange(len(tier_labels))
    width = 0.2

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(x - 1.5*width, prec_vals, width, label='Precision', color='#2b5c8f')
    ax.bar(x - 0.5*width, rec_vals, width, label='Recall', color='#2ca02c')
    ax.bar(x + 0.5*width, f1_vals, width, label='F1-Score', color='#ff7f0e')
    ax.bar(x + 1.5*width, fpr_vals, width, label='FPR', color='#d62728')

    ax.set_ylabel('Score (0.0 to 1.0)', fontsize=12)
    ax.set_title('Isolation Forest Detection Performance Across Attack Complexity Tiers\n(Empirical Demonstration of SLR 2026 Obfuscation Degradation: Overt > Chained > Obfuscated)', fontsize=11, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(tier_labels, fontsize=11)
    ax.set_ylim(0, 1.1)
    ax.legend(loc='lower left', frameon=True)
    ax.grid(axis='y', linestyle='--', alpha=0.5)

    plot1_path = os.path.join(results_dir, "tier_performance_benchmark.png")
    plt.tight_layout()
    plt.savefig(plot1_path, dpi=300)
    plt.close()
    print(f"    [+] Saved: {plot1_path}")

    # Plot 2: Isolated Command vs Sliding Window Comparison (Springer 2026)
    fig, ax = plt.subplots(figsize=(7, 4.5))
    modes_labels = ["Single Isolated\nCommand", "Sliding Window\n(N=3 Commands)"]
    idx = np.arange(2)
    w = 0.35
    ax.bar(idx - w/2, [float(exp1_results[0]["Recall"]), float(exp1_results[1]["Recall"])], w, label='Recall', color='#1f77b4')
    ax.bar(idx + w/2, [float(exp1_results[0]["F1-Score"]), float(exp1_results[1]["F1-Score"])], w, label='F1-Score', color='#2ca02c')

    ax.set_ylabel('Score', fontsize=12)
    ax.set_title('Ablation Study: Isolated Commands vs. Sliding Windows\n(Grounded in Springer 2026)', fontsize=11, fontweight='bold')
    ax.set_xticks(idx)
    ax.set_xticklabels(modes_labels, fontsize=11)
    ax.set_ylim(0.4, 1.05)
    ax.legend(loc='lower right')
    ax.grid(axis='y', linestyle='--', alpha=0.5)

    plot2_path = os.path.join(results_dir, "isolated_vs_sliding_window.png")
    plt.tight_layout()
    plt.savefig(plot2_path, dpi=300)
    plt.close()
    print(f"    [+] Saved: {plot2_path}")

    # -------------------------------------------------------------
    # 6. Save JSON & Markdown Summary Reports
    # -------------------------------------------------------------
    summary_report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "experiment1_isolated_vs_window": exp1_results,
        "experiment2_tiers": exp2_results,
        "experiment2b_chained_sequence_highlight": exp2b_results,
        "experiment2c_per_binary_discrimination": exp2c_results,
        "experiment3_supervised_comparison": exp3_results,
        "experiment4_llm_attribution_sample": llm_reports
    }

    report_json_path = os.path.join(results_dir, "evaluation_summary.json")
    with open(report_json_path, "w") as f:
        json.dump(summary_report, f, indent=2)
    print(f"[+] Saved structured evaluation summary to {report_json_path}")

    report_md_path = os.path.join(results_dir, "benchmark_report.md")
    with open(report_md_path, "w") as f:
        f.write("# PrivEsc & LOLBin Detection Pipeline - Benchmark Report\n\n")
        f.write("## 1. Experiment 1: Isolated Commands vs Sliding Window (Springer 2026)\n\n")
        f.write(tabulate(exp1_results, headers="keys", tablefmt="pipe") + "\n\n")
        f.write("## 2. Experiment 2: Performance Across Attack Complexity Tiers (SLR 2026)\n\n")
        f.write(tabulate(exp2_results, headers="keys", tablefmt="pipe") + "\n\n")
        f.write("### Table 2B: Chained Sequence Detection Highlight (Tier 2 Multi-Step Attack Chains)\n\n")
        f.write(tabulate(exp2b_results, headers="keys", tablefmt="pipe") + "\n\n")
        f.write("### Table 2C: Per-Binary Benign vs. Malicious Discrimination\n\n")
        f.write(tabulate(exp2c_results, headers="keys", tablefmt="pipe") + "\n\n")
        f.write("## 3. Experiment 3: Supervised Generalization Failure (Stamp 2022) vs Unsupervised Anomaly Detection\n\n")
        f.write(tabulate(exp3_results, headers="keys", tablefmt="pipe") + "\n\n")
        f.write("## 4. Experiment 4: Zero-Shot LLM Attribution Evaluation\n\n")
        f.write(tabulate(llm_reports, headers="keys", tablefmt="pipe") + "\n\n")
    print(f"[+] Saved formatted markdown report to {report_md_path}")
    print("=" * 80)

if __name__ == "__main__":
    data_dir = sys.argv[1] if len(sys.argv) > 1 else "data"
    results_dir = sys.argv[2] if len(sys.argv) > 2 else "evaluation/results"
    run_evaluation(data_dir, results_dir)
