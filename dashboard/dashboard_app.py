#!/usr/bin/env python3
"""
dashboard_app.py
================
AI-Assisted Privilege Escalation & Living-off-the-Land (LOLBin) Detection Project
Lightweight Streamlit SOC Analyst & Telemetry Visualization Dashboard

Displays:
  - Detection pipeline overview & real-time metrics
  - Anomaly score distributions and sliding command window traces
  - Process tree lineage and statistical feature deviations
  - Zero-Shot LLM MITRE ATT&CK technique attribution and plain-English explainability

Grounding: Ali & Kostakos (2023) [HuntGPT], Houssel et al. (2024)
"""

import os
import sys
import json
import streamlit as st
import pandas as pd
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from pipeline.feature_extractor import TelemetryFeatureExtractor
from pipeline.detector import AnomalyDetector
from pipeline.llm_explainer import LLMExplainer

st.set_page_config(
    page_title="AI-EDR SOC Analyst Console | PrivEsc & LOLBin Detection",
    page_icon="🛡️",
    layout="wide"
)

# Header
st.title("🛡️ AI-EDR Detection & Explainability Console")
st.markdown("""
**AI-Assisted Privilege Escalation & Living-off-the-Land (LOLBin) Attempt Detection**  
*M.Tech Major Project • Defensive Blue-Team Track • Unsupervised Isolation Forest + Zero-Shot SOC Attribution*
""")

# Cache pipeline loading
@st.cache_resource
def load_pipeline():
    model_path = os.path.join(BASE_DIR, "pipeline", "detector_model.joblib")
    detector = AnomalyDetector()
    if os.path.exists(model_path):
        detector.load(model_path)
    extractor = TelemetryFeatureExtractor(window_size=3)
    # load benign to fit extractor
    benign_path = os.path.join(BASE_DIR, "data", "benign_telemetry.json")
    if os.path.exists(benign_path):
        with open(benign_path) as f:
            b_events = json.load(f)
        extractor.fit(b_events)
    explainer = LLMExplainer()
    return extractor, detector, explainer

@st.cache_data
def load_eval_data():
    eval_path = os.path.join(BASE_DIR, "data", "full_evaluation_dataset.json")
    if os.path.exists(eval_path):
        with open(eval_path) as f:
            return json.load(f)
    return []

@st.cache_data
def load_eval_summary():
    summary_path = os.path.join(BASE_DIR, "evaluation", "results", "evaluation_summary.json")
    if os.path.exists(summary_path):
        with open(summary_path) as f:
            return json.load(f)
    return None

extractor, detector, explainer = load_pipeline()
dataset = load_eval_data()
summary = load_eval_summary()

# Sidebar
st.sidebar.header("Navigation & Configuration")
nav_choice = st.sidebar.radio("View", ["🚨 Live Anomaly Feed & Analysis", "📊 Academic Benchmark Suite", "⚙️ Architecture & Model Specs"])

tier_filter = st.sidebar.multiselect(
    "Filter by Attack Complexity Tier",
    options=[0, 1, 2, 3],
    default=[0, 1, 2, 3],
    format_func=lambda x: {
        0: "Tier 0 (Benign Baseline)",
        1: "Tier 1 (Overt / Isolated)",
        2: "Tier 2 (Chained Sequences)",
        3: "Tier 3 (Obfuscated / Stealthy)"
    }[x]
)

os_filter = st.sidebar.multiselect("Operating System", options=["linux", "windows"], default=["linux", "windows"])

# -------------------------------------------------------------
# VIEW 1: Live Anomaly Feed & Analysis
# -------------------------------------------------------------
if nav_choice == "🚨 Live Anomaly Feed & Analysis":
    # Filter dataset
    filtered_events = [
        ev for ev in dataset
        if ev.get("tier", 0) in tier_filter and ev.get("os_type") in os_filter
    ]

    # Metrics Bar
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Ingested Events", len(filtered_events))
    with col2:
        mal_count = sum(1 for e in filtered_events if e.get("label") == "malicious")
        st.metric("Malicious Invasions", mal_count)
    with col3:
        st.metric("Sliding Window Size", "N = 3 commands")
    with col4:
        st.metric("LLM Provider Mode", explainer.provider.upper())

    st.markdown("---")

    # Table of Events
    st.subheader("Ingested Telemetry Stream")
    table_data = []
    for idx, ev in enumerate(filtered_events[:100]): # display top 100
        table_data.append({
            "Index": idx,
            "Timestamp": ev.get("timestamp"),
            "OS": ev.get("os_type"),
            "Tier": ev.get("tier"),
            "Process": ev.get("process_name"),
            "Command": (ev.get("command_line", "")[:60] + "...") if len(ev.get("command_line", "")) > 60 else ev.get("command_line", ""),
            "Ground Truth": ev.get("label"),
            "Technique": ev.get("technique")
        })

    df_view = pd.DataFrame(table_data)
    st.dataframe(df_view, height=280)

    # Detailed Anomaly Inspector
    st.subheader("🔬 Real-time SOC Anomaly Dossier & Explainability")
    selected_idx = st.number_input("Select Event Index for In-Depth AI Explanation:", min_value=0, max_value=max(0, len(filtered_events)-1), value=0, step=1)

    if filtered_events:
        sel_ev = filtered_events[selected_idx]
        X_vec, _, meta_vec = extractor.transform([sel_ev], mode="window")
        is_anom, anom_scores = detector.predict_anomaly(X_vec)
        score = anom_scores[0]
        payload = detector.build_anomaly_payload(X_vec[0], meta_vec[0], score)

        with st.spinner("Executing Zero-Shot SOC Analyst Reasoning (HuntGPT Paradigm)..."):
            explanation = explainer.explain_anomaly(payload)

        col_a, col_b = st.columns([1, 1])

        with col_a:
            st.markdown("#### ⚙️ Feature Deviation Breakdown")
            st.metric("Isolation Forest Anomaly Score", f"{score:.4f}", delta="Flagged" if is_anom[0] else "Benign", delta_color="inverse")
            st.write("**Process:** `", sel_ev.get("process_name"), "` | **Parent:** `", sel_ev.get("parent_process_name"), "`")
            st.code(sel_ev.get("command_line", ""), language="bash")

            dev_df = pd.DataFrame(payload["top_feature_deviations"])
            st.write("**Top Statistical Deviations from Benign Baseline (Z-Scores):**")
            st.dataframe(dev_df, height=180)

        with col_b:
            st.markdown("#### 🧠 AI SOC Analyst Attribution & Verdict")
            verdict = explanation.get("verdict", "Suspicious")
            if "Malicious" in verdict:
                st.error(f"**Verdict:** {verdict}")
            elif "Suspicious" in verdict:
                st.warning(f"**Verdict:** {verdict}")
            else:
                st.success(f"**Verdict:** {verdict}")

            st.write(f"**Attributed Technique:** `{explanation.get('attributed_technique')}`")
            st.write(f"**MITRE ATT&CK ID:** `{explanation.get('mitre_id')}`")
            st.write(f"**Analyst Confidence:** `{explanation.get('confidence_score')}`")

            st.info(f"**SOC Explanation:** {explanation.get('plain_english_explanation')}")

            with st.expander("View Raw Audit / Sysmon Event Payload"):
                st.code(sel_ev.get("raw_event", ""), language="text")

# -------------------------------------------------------------
# VIEW 2: Academic Benchmark Suite
# -------------------------------------------------------------
elif nav_choice == "📊 Academic Benchmark Suite":
    st.subheader("Academic Evaluation & Grounding Benchmark Results")
    st.markdown("""
    Evaluation outputs conforming to Section 3 (Module 5) across all three experimental tiers,
    validating against the grounding literature matrix.
    """)

    if summary:
        tab1, tab2, tab3 = st.tabs(["Sequence Window Ablation (Springer 2026)", "Complexity Tiers (SLR 2026)", "Supervised Baselines (Stamp 2022)"])

        with tab1:
            st.markdown("### Experiment 1: Isolated Commands vs. Sliding Windows")
            st.markdown("Validates Springer (2026) finding that sliding command sequences outperform isolated command lines.")
            exp1_df = pd.DataFrame(summary["experiment1_isolated_vs_window"])
            st.table(exp1_df[["Mode", "Precision", "Recall", "F1-Score", "FPR", "Latency/Ev (ms)"]])

            img1_path = os.path.join(BASE_DIR, "evaluation", "results", "isolated_vs_sliding_window.png")
            if os.path.exists(img1_path):
                st.image(img1_path, caption="Figure 1: Isolated Commands vs Sliding Window Ablation")

        with tab2:
            st.markdown("### Experiment 2: Performance Across Attack Complexity Tiers")
            st.markdown("Empirically demonstrates the literature hypothesis that Isolation Forest achieves high accuracy on overt attacks (Tier 1) but degrades on stealthy/obfuscated attacks (Tier 3).")
            exp2_df = pd.DataFrame(summary["experiment2_tiers"])
            st.table(exp2_df[["Attack Evaluation Tier", "Attack Events", "Precision", "Recall", "F1-Score", "FPR"]])

            img2_path = os.path.join(BASE_DIR, "evaluation", "results", "tier_performance_benchmark.png")
            if os.path.exists(img2_path):
                st.image(img2_path, caption="Figure 2: Tier 1 (Overt) vs Tier 2 (Chained) vs Tier 3 (Obfuscated) Performance")

        with tab3:
            st.markdown("### Experiment 3: Unsupervised vs. Supervised Classifiers")
            st.markdown("Highlights why unsupervised anomaly detection is essential given the scarcity of labeled attack traces (Stamp 2022).")
            exp3_df = pd.DataFrame(summary["experiment3_supervised_comparison"])
            st.table(exp3_df[["Model Architecture", "Precision", "Recall", "F1-Score", "FPR", "Supervision"]])
    else:
        st.warning("No evaluation summary found. Please execute `evaluation/evaluate.py` first.")

# -------------------------------------------------------------
# VIEW 3: Architecture & Model Specs
# -------------------------------------------------------------
else:
    st.subheader("System Architecture & Academic Literature Foundation")
    st.markdown("""
    ### Pipeline Architecture:
    1. **Telemetry Collection Layer:** Windows Sysmon (Event ID 1 & 11) + Linux auditd / Wazuh agents in isolated VMs.
    2. **Feature Extraction Engine:** Lineage rarity scoring, token entropy, and sliding command window aggregation ($N=3$ to $5$).
    3. **Unsupervised Anomaly Detection:** scikit-learn Isolation Forest trained solely on benign baseline ($FPR \\le 0.02$).
    4. **AI Explainability & Attribution:** Zero-Shot SOC Analyst persona generating MITRE ATT&CK attribution and plain-English justification.
    5. **SOC Integration:** Custom Wazuh XML rules & interactive dashboard.
    """)

    st.markdown("""
    ### Grounding Literature Citations:
    - **Ongun et al. (RAID 2021) [LOLAL]:** Command text representation and NLP feature engineering.
    - **Stamp (2022):** Scarcity of labeled LOLBin traces; supervised vs unsupervised tradeoffs.
    - **Springer (2026):** Proof that command sequences outperform isolated commands.
    - **Barr-Smith et al. (IEEE S&P 2021) [Survivalism]:** Targeted LOLBins selection.
    - **Liu et al. (IEEE ICDM 2008):** Isolation Forest algorithmic foundation.
    - **Systematic Literature Review (2026):** Overt vs stealthy intrusion degradation behavior.
    - **Ali & Kostakos (2023) [HuntGPT]:** Pairing anomaly detection with LLM explainability.
    - **Houssel et al. (2024):** Framework for evaluating LLM intrusion explanations and eliminating hallucinations.
    """)
