#!/usr/bin/env python3
"""
dashboard_app.py
================
AI-Assisted Privilege Escalation & Living-off-the-Land (LOLBin) Detection Project
Tier-3 SOC Threat Hunting & Real-Time Anomaly Triage Console

Displays:
  - Multi-source telemetry ingestion: Real Linux Auditd logs (.log), Synthetic benchmarks (.json), or live upload
  - Bulk sliding-window feature extraction and unsupervised Isolation Forest scoring
  - Interactive telemetry stream explorer with status indicators and search filters
  - Deep-dive SOC Anomaly Dossier: Feature Z-score deviations, process lineage, and command sliding-window trace
  - Zero-shot AI SOC Analyst attribution: MITRE ATT&CK technique mapping, confidence, and plain-English justification
  - Academic benchmark suite: Sequence window ablation, complexity tiers, and supervised comparators

Grounding Literature:
  - Ali & Kostakos (2023) [HuntGPT]: Pairing ML anomaly detection with LLM explainability
  - Houssel et al. (2024): Explainable intrusion detection and hallucination mitigation
  - Springer (2026): Proving command-sequence sliding windows outperform isolated command lines
  - Systematic Literature Review (2026): Performance dynamics across overt vs. stealthy/obfuscated attacks
"""

import os
import sys
import glob
import json
from typing import List, Dict, Any, Tuple, Optional
import streamlit as st
import pandas as pd
import numpy as np

# Set base workspace directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from pipeline.telemetry import SyntheticTelemetrySource, AuditdTelemetrySource
from pipeline.feature_extractor import TelemetryFeatureExtractor
from pipeline.detector import AnomalyDetector, load_pipeline_bundle
from pipeline.llm_explainer import LLMExplainer

# Page configuration
st.set_page_config(
    page_title="AI-EDR SOC Threat Hunting Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -----------------------------------------------------------------------------
# CACHED RESOURCE LOADERS
# -----------------------------------------------------------------------------

@st.cache_resource
def get_pipeline():
    """Loads the pre-trained Isolation Forest and fitted TelemetryFeatureExtractor bundle."""
    model_path = os.path.join(BASE_DIR, "pipeline", "detector_model.joblib")
    if not os.path.exists(model_path):
        return None, None
    detector, extractor = load_pipeline_bundle(model_path)
    return detector, extractor


@st.cache_resource
def get_explainer(provider: Optional[str] = None, api_key: Optional[str] = None):
    """Initializes the LLM Explainer."""
    return LLMExplainer(provider=provider, api_key=api_key)


@st.cache_data(show_spinner=False)
def load_telemetry_source(
    source_type: str,
    selected_file: str,
    uploaded_content: Optional[str] = None,
    max_events: int = 500
) -> Tuple[List[Dict[str, Any]], str]:
    """
    Ingests and normalizes telemetry events based on user selection.
    Returns: (events_list, provenance_description)
    """
    events = []
    provenance = "Unknown"

    if source_type == "upload" and uploaded_content:
        audit_source = AuditdTelemetrySource(uploaded_content, is_file=False)
        events = list(audit_source.events())
        provenance = f"UPLOADED AUDITD LOG ({len(events)} events parsed)"

    elif source_type == "auditd":
        full_path = os.path.join(BASE_DIR, "data", selected_file)
        if os.path.exists(full_path):
            audit_source = AuditdTelemetrySource(full_path, is_file=True, assume_benign=False)
            events = list(audit_source.events())
            provenance = f"REAL LINUX AUDITD LOG: {selected_file} ({len(events)} events)"
        else:
            provenance = f"FILE NOT FOUND: {selected_file}"

    elif source_type == "synthetic":
        full_path = os.path.join(BASE_DIR, "data", selected_file)
        if os.path.exists(full_path):
            syn_source = SyntheticTelemetrySource(full_path)
            events = list(syn_source.events())
            provenance = f"SYNTHETIC LAB BENCHMARK: {selected_file} ({len(events)} events)"
        else:
            provenance = f"FILE NOT FOUND: {selected_file}"

    # Slice to max_events to maintain UI responsiveness
    if max_events > 0 and len(events) > max_events:
        events = events[:max_events]

    return events, provenance


@st.cache_data(show_spinner=False)
def score_dataset_events(
    events_tuples: List[Dict[str, Any]],
    threshold: float = 0.50
) -> Tuple[List[Dict[str, Any]], np.ndarray, np.ndarray, List[str], List[Dict[str, Any]]]:
    """
    Transforms the event sequence using sliding windows and scores via Isolation Forest.
    Returns: (scored_events, X_matrix, anomaly_scores, feature_names, meta_list)
    """
    detector, extractor = get_pipeline()
    if not detector or not extractor or not events_tuples:
        return events_tuples, np.array([]), np.array([]), [], []

    # Extract features in sliding window mode (N=3)
    X, feature_names, meta_list = extractor.transform(events_tuples, mode="window")
    is_anom, scores = detector.predict_anomaly(X)

    # Attach computed scores and flags to event dicts
    scored = []
    for idx, ev in enumerate(events_tuples):
        ev_copy = dict(ev)
        score_val = float(scores[idx]) if idx < len(scores) else 0.0
        flagged = score_val >= threshold
        ev_copy["_computed_score"] = score_val
        ev_copy["_flagged"] = flagged
        ev_copy["_index"] = idx
        scored.append(ev_copy)

    return scored, X, scores, feature_names, meta_list


@st.cache_data(show_spinner=False)
def load_eval_summary():
    """Loads experimental evaluation summary metrics."""
    summary_path = os.path.join(BASE_DIR, "evaluation", "results", "evaluation_summary.json")
    if os.path.exists(summary_path):
        with open(summary_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def extract_execution_chain(
    scored_events: List[Dict[str, Any]],
    target_idx: int,
    mode: str = "⚡ Sliding Sequence Window",
    window_radius: int = 2
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Extracts the multi-step execution chain surrounding target_idx.
    Modes:
      - '⚡ Sliding Sequence Window': Chronological stream window [t-2, t-1, t, t+1, t+2] (Springer 2026)
      - '📜 Session Attack Chain': Chronological sequence within the exact same terminal/session (session_id)
    Returns:
      (chain_items, chain_summary_stats)
    """
    if not scored_events or target_idx < 0 or target_idx >= len(scored_events):
        return [], {}

    target_ev = scored_events[target_idx]

    if "Session" in mode:
        target_ses = target_ev.get("session_id", "default_sess")
        ses_events = [e for e in scored_events if e.get("session_id") == target_ses]
        target_pos = next((pos for pos, e in enumerate(ses_events) if e["_index"] == target_idx), 0)

        if len(ses_events) <= (window_radius * 2 + 1):
            selected_subset = ses_events
            subset_target_pos = target_pos
        else:
            s_start = max(0, target_pos - window_radius)
            s_end = s_start + (window_radius * 2 + 1)
            if s_end > len(ses_events):
                s_end = len(ses_events)
                s_start = max(0, s_end - (window_radius * 2 + 1))
            selected_subset = ses_events[s_start:s_end]
            subset_target_pos = target_pos - s_start

        items = []
        for i, ev in enumerate(selected_subset):
            rel = i - subset_target_pos
            items.append({
                "index": ev["_index"],
                "rel_pos": rel,
                "is_target": (ev["_index"] == target_idx),
                "event": ev,
                "session_step": i + 1,
                "session_total": len(ses_events)
            })
    else:  # Temporal stream sequence
        total = len(scored_events)
        if total <= (window_radius * 2 + 1):
            indices = list(range(total))
        else:
            start_idx = max(0, target_idx - window_radius)
            end_idx = start_idx + (window_radius * 2 + 1)
            if end_idx > total:
                end_idx = total
                start_idx = max(0, end_idx - (window_radius * 2 + 1))
            indices = list(range(start_idx, end_idx))

        items = []
        for idx in indices:
            ev = scored_events[idx]
            rel = idx - target_idx
            items.append({
                "index": idx,
                "rel_pos": rel,
                "is_target": (idx == target_idx),
                "event": ev,
                "session_step": idx + 1,
                "session_total": total
            })

    chain_scores = [item["event"]["_computed_score"] for item in items]
    min_sc = min(chain_scores) if chain_scores else 0.0
    max_sc = max(chain_scores) if chain_scores else 0.0
    target_sc = target_ev["_computed_score"]

    uids = [str(item["event"].get("uid", "")) for item in items]
    euids = [str(item["event"].get("euid", "")) for item in items]
    has_priv_escalation = any(e == "0" for e in euids) and any(u not in ["0", "", "none"] for u in uids)

    summary = {
        "length": len(items),
        "target_score": target_sc,
        "score_delta": target_sc - min_sc,
        "min_score": min_sc,
        "max_score": max_sc,
        "has_priv_escalation": has_priv_escalation,
        "session_id": target_ev.get("session_id", "unknown"),
        "scores": chain_scores
    }
    return items, summary


# -----------------------------------------------------------------------------
# SIDEBAR NAVIGATION & TELEMETRY SOURCE CONTROLS
# -----------------------------------------------------------------------------

with st.sidebar:
    st.header("Console Controls")

    nav_choice = st.segmented_control(
        "Navigation",
        options=["Live Triage", "Academic Benchmarks", "System Architecture"],
        default="Live Triage"
    )

    st.markdown("---")
    st.subheader("Telemetry Ingestion Source")

    # Discover real log files in data/
    available_logs = sorted([os.path.basename(p) for p in glob.glob(os.path.join(BASE_DIR, "data", "*.log"))])
    # Prioritize live-attack-benign.log if present
    if "live-attack-benign.log" in available_logs:
        available_logs.remove("live-attack-benign.log")
        available_logs.insert(0, "live-attack-benign.log")

    # Discover synthetic json files in data/
    available_json = sorted([os.path.basename(p) for p in glob.glob(os.path.join(BASE_DIR, "data", "*.json"))])
    if "full_evaluation_dataset.json" in available_json:
        available_json.remove("full_evaluation_dataset.json")
        available_json.insert(0, "full_evaluation_dataset.json")

    source_category = st.radio(
        "Telemetry Adapter Category",
        options=["Real Linux Auditd Logs", "Synthetic Lab Benchmark", "Upload Custom Log"],
        index=0
    )

    selected_file = ""
    uploaded_text = None

    if source_category == "Real Linux Auditd Logs":
        source_key = "auditd"
        if available_logs:
            selected_file = st.selectbox(
                "Select Discovered Auditd Log File",
                options=available_logs,
                index=0
            )
        else:
            st.error("No .log files found in `data/` directory.")
    elif source_category == "Synthetic Lab Benchmark":
        source_key = "synthetic"
        if available_json:
            selected_file = st.selectbox(
                "Select Synthetic Benchmark JSON",
                options=available_json,
                index=0
            )
        else:
            st.error("No .json files found in `data/` directory.")
    else:
        source_key = "upload"
        uploaded_file = st.file_uploader(
            "Upload Raw Linux Auditd Log",
            type=["log", "txt"],
            help="Upload auditd logs generated with: ausearch -ts recent --raw > live.log"
        )
        if uploaded_file is not None:
            uploaded_text = uploaded_file.getvalue().decode("utf-8", errors="replace")

    st.markdown("---")
    st.subheader("Model Parameters")
    decision_threshold = st.slider(
        "Decision Boundary Threshold",
        min_value=0.10,
        max_value=0.90,
        value=0.50,
        step=0.05,
        help="Events with anomaly score >= threshold are flagged as PrivEsc / LOLBin anomalies."
    )

    max_events_slider = st.select_slider(
        "Max Events to Ingest",
        options=[50, 100, 250, 500, 1000, 5000],
        value=250,
        help="Limits event count for fast interactive rendering in the web console."
    )

    with st.expander("AI Explainer Engine"):
        llm_provider = st.selectbox("Provider Mode", ["Offline Deterministic Heuristics", "OpenAI API", "Groq API"], index=0)
        api_key_input = None
        if "OpenAI" in llm_provider:
            api_key_input = st.text_input("OpenAI API Key", type="password")
        elif "Groq" in llm_provider:
            api_key_input = st.text_input("Groq API Key", type="password")

# -----------------------------------------------------------------------------
# MAIN DASHBOARD HEADER
# -----------------------------------------------------------------------------

detector, extractor = get_pipeline()
explainer = get_explainer(
    provider="openai" if "OpenAI" in llm_provider and api_key_input else ("groq" if "Groq" in llm_provider and api_key_input else "offline"),
    api_key=api_key_input
)

st.title("🛡️ AI-EDR Threat Hunting Console")
st.caption(
    "AI-Assisted Privilege Escalation & Living-off-the-Land (LOLBin) Attempt Detection • "
    "Unsupervised Isolation Forest + Sliding Sequence Windows + Zero-Shot SOC Explainability"
)

if not detector or not extractor:
    st.error(
        "Model bundle not found at `pipeline/detector_model.joblib`. "
        "Please run `evaluation/evaluate.py` to train and serialize the pipeline bundle."
    )
    st.stop()

# -----------------------------------------------------------------------------
# DATA INGESTION & PIPELINE SCORING
# -----------------------------------------------------------------------------

raw_events, provenance_badge = load_telemetry_source(
    source_type=source_key,
    selected_file=selected_file,
    uploaded_content=uploaded_text,
    max_events=max_events_slider
)

# Provenance indicator bar
prov_col1, prov_col2, prov_col3 = st.columns([2, 1, 1])
with prov_col1:
    st.info(f"**Data Ingestion Provenance:** `{provenance_badge}`")
with prov_col2:
    st.success(f"**Active Model:** Isolation Forest (150 trees, {detector.contamination} contamination)")
with prov_col3:
    st.metric("Sequence Window", f"N = {extractor.window_size} commands")

if not raw_events:
    st.warning(
        title="No Telemetry Events Available",
        body="Please ensure the selected log file exists and contains correlated process execution lines."
    )
    st.stop()

# Score events with pipeline
scored_events, X_matrix, scores_array, feature_names, meta_list = score_dataset_events(
    tuple(raw_events),
    threshold=decision_threshold
)

flagged_count = sum(1 for e in scored_events if e["_flagged"])
normal_count = len(scored_events) - flagged_count
peak_score = float(np.max(scores_array)) if len(scores_array) > 0 else 0.0

# -----------------------------------------------------------------------------
# VIEW 1: LIVE TELEMETRY & ANOMALY TRIAGE
# -----------------------------------------------------------------------------

if nav_choice == "Live Triage":

    # Metric summary row
    with st.container(border=True):
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Ingested Events", len(scored_events))
        m2.metric(
            "Flagged Anomalies",
            flagged_count,
            delta=f"{(flagged_count / len(scored_events) * 100):.1f}% detection rate" if scored_events else "0%",
            delta_color="inverse"
        )
        m3.metric(
            "Normal Baseline Events",
            normal_count,
            delta=f"{(normal_count / len(scored_events) * 100):.1f}% benign" if scored_events else "100%"
        )
        m4.metric("Peak Anomaly Score", f"{peak_score:.4f}", delta="Threat detected" if peak_score >= decision_threshold else "Clean")

    st.markdown("### Telemetry Stream Explorer")

    # Table Filtering Controls
    f_col1, f_col2, f_col3 = st.columns([1, 1, 2])
    with f_col1:
        status_filter = st.segmented_control(
            "Filter by Anomaly Status",
            options=["All Events", "🚨 Flagged Only", "✅ Normal Only"],
            default="All Events"
        )
    with f_col2:
        distinct_procs = sorted(list({e.get("process_name", "unknown") for e in scored_events}))
        proc_filter = st.multiselect(
            "Filter by Process Name",
            options=distinct_procs,
            default=[]
        )
    with f_col3:
        search_query = st.text_input("Search in Command Lines", placeholder="e.g. sudo, find, python, tar, base64...")

    # Apply filters
    display_events = scored_events
    if status_filter == "🚨 Flagged Only":
        display_events = [e for e in display_events if e["_flagged"]]
    elif status_filter == "✅ Normal Only":
        display_events = [e for e in display_events if not e["_flagged"]]

    if proc_filter:
        display_events = [e for e in display_events if e.get("process_name") in proc_filter]

    if search_query:
        q_lower = search_query.lower()
        display_events = [e for e in display_events if q_lower in str(e.get("command_line", "")).lower() or q_lower in str(e.get("process_name", "")).lower()]

    # Format table data
    table_rows = []
    for ev in display_events:
        cmd = str(ev.get("command_line") or "")
        cmd_short = (cmd[:75] + "...") if len(cmd) > 75 else cmd
        ts = str(ev.get("timestamp", ""))
        ts_short = ts.split("T")[-1].replace("+00:00", "Z") if "T" in ts else ts

        table_rows.append({
            "#": ev["_index"],
            "Status": "🚨 ANOMALOUS" if ev["_flagged"] else "✅ NORMAL",
            "Anomaly Score": round(ev["_computed_score"], 4),
            "Process": ev.get("process_name", "unknown"),
            "Command Line": cmd_short,
            "User / EUID": f"{ev.get('user', 'unknown')} (EUID={ev.get('euid', '?')})",
            "Timestamp": ts_short,
            "Session": ev.get("session_id", "unknown")
        })

    table_df = pd.DataFrame(table_rows)

    if not table_df.empty:
        st.dataframe(
            table_df,
            column_config={
                "#": st.column_config.NumberColumn("Index", width="small"),
                "Status": st.column_config.TextColumn("Detection Status", width="small"),
                "Anomaly Score": st.column_config.ProgressColumn(
                    "Anomaly Score",
                    help="Isolation Forest behavioral anomaly score (0.0 to 1.0)",
                    format="%.4f",
                    min_value=0.0,
                    max_value=1.0,
                    width="medium"
                ),
                "Process": st.column_config.TextColumn("Process", width="small"),
                "Command Line": st.column_config.TextColumn("Command Line", width="large"),
                "User / EUID": st.column_config.TextColumn("User / EUID", width="small"),
                "Timestamp": st.column_config.TextColumn("Time", width="small"),
                "Session": st.column_config.TextColumn("Session ID", width="small")
            },
            hide_index=True,
            height=320
        )
    else:
        st.info("No events match the selected filters.")

    # -------------------------------------------------------------------------
    # DEEP-DIVE SOC ANOMALY DOSSIER & EXPLAINABILITY
    # -------------------------------------------------------------------------
    st.markdown("---")
    st.subheader("🔬 Real-Time SOC Anomaly Dossier & Threat Attribution")

    # Fast jump selector
    flagged_indices = [e["_index"] for e in scored_events if e["_flagged"]]
    default_selected = flagged_indices[0] if flagged_indices else 0

    if "dossier_selected_idx" not in st.session_state:
        st.session_state["dossier_selected_idx"] = default_selected

    # Keep dossier_selected_idx in bounds
    if st.session_state["dossier_selected_idx"] >= len(scored_events) or st.session_state["dossier_selected_idx"] < 0:
        st.session_state["dossier_selected_idx"] = default_selected

    sel_c1, sel_c2 = st.columns([3, 1], vertical_alignment="bottom")
    with sel_c1:
        # Build human-readable options for selectbox
        event_options = []
        for e in scored_events:
            flag_icon = "🚨" if e["_flagged"] else "✅"
            cmd_preview = (e.get("command_line", "")[:45] + "...") if len(e.get("command_line", "")) > 45 else e.get("command_line", "")
            event_options.append(f"[{e['_index']:03d}] {flag_icon} Score={e['_computed_score']:.4f} | {e.get('process_name'):12s} | {cmd_preview}")

        curr_idx = st.session_state["dossier_selected_idx"]
        selected_option = st.selectbox(
            "Select Process Execution Event for Threat Dossier Analysis",
            options=event_options,
            index=curr_idx if curr_idx < len(event_options) else 0
        )
        selected_event_idx = int(selected_option.split("]")[0].replace("[", ""))
        st.session_state["dossier_selected_idx"] = selected_event_idx

    with sel_c2:
        if flagged_indices:
            highest_idx = int(np.argmax(scores_array))
            if st.button("⚡ Inspect Highest Anomaly", width="stretch"):
                st.session_state["dossier_selected_idx"] = highest_idx
                st.rerun()

    # Triage the selected event
    selected_event_idx = st.session_state["dossier_selected_idx"]
    sel_ev = scored_events[selected_event_idx]
    sel_score = sel_ev["_computed_score"]
    sel_meta = meta_list[selected_event_idx] if selected_event_idx < len(meta_list) else {}
    sel_vec = X_matrix[selected_event_idx] if selected_event_idx < len(X_matrix) else np.array([])

    # Build sanitized anomaly payload for the SOC explainer
    payload = detector.build_anomaly_payload(sel_vec, sel_meta, sel_score)

    # Invoke LLM Explainer
    with st.spinner("Analyzing behavioral anomalies and extracting MITRE ATT&CK attribution..."):
        explanation = explainer.explain_anomaly(payload)

    # =========================================================================
    # MULTI-STEP EXECUTION CHAIN CONTEXT (SPRINGER 2026)
    # =========================================================================
    with st.container(border=True):
        ch_h1, ch_h2 = st.columns([2, 1], vertical_alignment="center")
        with ch_h1:
            st.markdown("### :material/account_tree: Multi-Step Execution Chain Context")
            st.caption(
                "Temporal sequence reconstruction (**Springer 2026**). Living-off-the-Land attacks chain routine "
                "system binaries — single isolated commands often appear benign, but sequential context exposes the intrusion."
            )
        with ch_h2:
            chain_mode = st.segmented_control(
                "Execution Chain Mode",
                options=["⚡ Sliding Sequence Window", "📜 Session Attack Chain"],
                default="⚡ Sliding Sequence Window",
                label_visibility="collapsed"
            )

        chain_items, chain_summary = extract_execution_chain(
            scored_events,
            selected_event_idx,
            mode=chain_mode
        )

        # Summary Bar (Session ID, Trajectory, Privilege Transitions)
        sb1, sb2, sb3, sb4 = st.columns(4)
        with sb1:
            st.metric("Session ID", chain_summary.get("session_id", "unknown"))
        with sb2:
            st.metric("Chain Steps In View", f"{len(chain_items)} commands")
        with sb3:
            s_delta = chain_summary.get("score_delta", 0.0)
            st.metric(
                "Score Surge in Window",
                f"{chain_summary.get('target_score', 0.0):.4f}",
                delta=f"+{s_delta:.4f} vs lowest" if s_delta > 0.05 else "Baseline level",
                delta_color="inverse"
            )
        with sb4:
            if chain_summary.get("has_priv_escalation", False):
                st.metric("Privilege Transition", "🚨 Root Escalation", delta="UID 1000 ➔ EUID 0", delta_color="inverse")
            else:
                st.metric("Privilege Transition", "Stable", delta="No token elevation")

        # Visual Trajectory Sequence Ribbon
        st.markdown("---")
        flow_tokens = []
        for it in chain_items:
            ev = it["event"]
            sc = ev["_computed_score"]
            p_name = ev.get("process_name", "proc")
            idx_str = f"[{it['index']:03d}]"
            rel_str = f"t{it['rel_pos']:+d}" if it['rel_pos'] != 0 else "TARGET 🚨"
            if it["is_target"]:
                flow_tokens.append(f"**`:red[{idx_str} {p_name} ({sc:.2f}) - {rel_str}]`**")
            elif sc >= decision_threshold:
                flow_tokens.append(f"**`:orange[{idx_str} {p_name} ({sc:.2f})]`**")
            else:
                flow_tokens.append(f"`{idx_str} {p_name} ({sc:.2f})`")
        trajectory_line = " &nbsp; ➔ &nbsp; ".join(flow_tokens)
        st.markdown(f"**Sequence Progression:** &nbsp; {trajectory_line}")

        # Visual Step Cards (Columns)
        st.markdown("")
        if chain_items:
            card_cols = st.columns(len(chain_items))
            for c_idx, it in enumerate(chain_items):
                ev = it["event"]
                it_idx = it["index"]
                it_score = ev["_computed_score"]
                it_flagged = ev["_flagged"]
                it_proc = ev.get("process_name", "unknown")
                it_pid = ev.get("process_id", "?")
                it_ppid = ev.get("parent_process_id", "?")
                it_parent = ev.get("parent_process_name", "unknown")
                it_user = ev.get("user", "?")
                it_uid = ev.get("uid", "?")
                it_euid = ev.get("euid", "?")
                it_cmd = str(ev.get("command_line", "unknown") or "")
                short_cmd = (it_cmd[:65] + "...") if len(it_cmd) > 65 else it_cmd
                rel_pos = it["rel_pos"]
                is_target = it["is_target"]

                with card_cols[c_idx]:
                    with st.container(border=True):
                        # Card Header
                        if is_target:
                            st.markdown("**:red[:material/crisis_alert: TARGET ANOMALY (t)]**")
                            st.markdown(f":red[**🚨 Score: {it_score:.4f}**]")
                        else:
                            offset_label = f"Step t{rel_pos:+d}"
                            direction = "Preceding" if rel_pos < 0 else "Subsequent"
                            st.markdown(f"**{offset_label}** `({direction})`")
                            if it_score >= decision_threshold:
                                st.markdown(f":red[**🚨 Score: {it_score:.4f}**]")
                            elif it_score >= 0.20:
                                st.markdown(f":orange[**⚠️ Score: {it_score:.4f}**]")
                            else:
                                st.markdown(f":green[**✅ Score: {it_score:.4f}**]")

                        # Process & Lineage Details
                        st.markdown(f"**`{it_proc}`** `(PID {it_pid})`")
                        st.caption(f"Parent: `{it_parent}` (PPID {it_ppid})")

                        # Privilege indicator
                        if str(it_euid) == "0" or str(it_uid) == "0":
                            st.markdown(":red-background[**Root Privileged**]")
                        else:
                            st.caption(f"User: `{it_user}` (UID {it_uid})")

                        # Command Line Box
                        st.code(short_cmd, language="bash")

                        # Action Button
                        if is_target:
                            st.button(
                                "🎯 Inspected Event",
                                key=f"btn_target_{it_idx}_{c_idx}",
                                disabled=True,
                                width="stretch"
                            )
                        else:
                            if st.button(
                                f"🔍 Inspect [{it_idx:03d}]",
                                key=f"btn_step_{it_idx}_{c_idx}",
                                width="stretch"
                            ):
                                st.session_state["dossier_selected_idx"] = it_idx
                                st.rerun()

        # Context Observation Callout (Springer 2026 Grounding)
        if chain_summary.get("score_delta", 0.0) >= 0.30 or chain_summary.get("has_priv_escalation", False):
            st.info(
                "💡 **Springer (2026) Behavioral Context Dynamic:** Notice how this command's score compares to its neighbors. "
                "In isolation, routine utilities (e.g. `id`, `chmod`, `bash`) exhibit low anomaly scores (< 0.20), but when chained "
                "following LOLBin triggers or privilege transitions, the sequence features (entropy jump, token acceleration, priv delta) "
                "expose the PrivEsc intent. Sliding sequence windows effectively eliminate single-command blind spots."
            )

        # Expandable Detailed Forensics Table
        with st.expander("📋 Inspect Full Chronological Telemetry & Feature Deltas in this Sequence"):
            trace_rows = []
            for it in chain_items:
                ev = it["event"]
                rel_str = f"t{it['rel_pos']:+d}" if it['rel_pos'] != 0 else "TARGET 🚨"
                trace_rows.append({
                    "Offset": rel_str,
                    "Index": f"[{it['index']:03d}]",
                    "Score": f"{ev['_computed_score']:.4f}",
                    "Status": "🚨 FLAGGED" if ev["_flagged"] else "✅ Benign",
                    "Process": ev.get("process_name", "?"),
                    "PID": ev.get("process_id", "?"),
                    "Parent": ev.get("parent_process_name", "?"),
                    "User": ev.get("user", "?"),
                    "UID / EUID": f"{ev.get('uid', '?')} / {ev.get('euid', '?')}",
                    "Command Line": ev.get("command_line", "")
                })
            st.dataframe(pd.DataFrame(trace_rows), hide_index=True)

    # Display 2-Column Dossier Card
    with st.container(border=True):
        col_left, col_right = st.columns([1, 1])

        # LEFT COLUMN: Mathematical & Lineage Deviations
        with col_left:
            st.markdown("#### :material/analytics: Behavioral Deviations & Lineage")

            s_metric, s_proc = st.columns([1, 2])
            with s_metric:
                st.metric(
                    "Anomaly Score",
                    f"{sel_score:.4f}",
                    delta="ANOMALY FLAGGED" if sel_ev["_flagged"] else "BENIGN BASELINE",
                    delta_color="inverse"
                )
            with s_proc:
                st.markdown(f"**Process:** `{sel_ev.get('process_name', 'unknown')}` (PID `{sel_ev.get('process_id', 'unknown')}`)")
                st.markdown(f"**Parent:** `{sel_ev.get('parent_process_name', 'unknown')}` (PPID `{sel_ev.get('parent_process_id', 'unknown')}`)")
                st.markdown(f"**Privilege Context:** User `{sel_ev.get('user', 'unknown')}` | UID `{sel_ev.get('uid', '?')}` | EUID `{sel_ev.get('euid', '?')}`")

            st.markdown("**Executed Command Line:**")
            st.code(sel_ev.get("command_line", "unknown"), language="bash")

            # Show sliding window history
            prev_cmds = sel_meta.get("sliding_window_commands", [])
            if prev_cmds:
                with st.expander(f"Sliding Window Execution Trace (Last {len(prev_cmds)} Commands)"):
                    for c_idx, p_cmd in enumerate(prev_cmds):
                        st.markdown(f"**[-{len(prev_cmds)-c_idx}]** `{p_cmd}`")

            # Statistical Feature Deviations Table
            st.markdown("**Top Statistical Deviations from Benign Baseline (Z-Scores):**")
            top_devs = payload.get("top_feature_deviations", [])
            if top_devs:
                dev_df = pd.DataFrame(top_devs)
                if "z_score" in dev_df.columns:
                    dev_df["z_score"] = dev_df["z_score"].apply(lambda z: f"{float(z):+.2f}")
                if "observed_value" in dev_df.columns:
                    dev_df["observed_value"] = dev_df["observed_value"].apply(lambda v: f"{float(v):.3f}")
                mean_col = "baseline_mean" if "baseline_mean" in dev_df.columns else ("benign_mean" if "benign_mean" in dev_df.columns else None)
                if mean_col:
                    dev_df[mean_col] = dev_df[mean_col].apply(lambda m: f"{float(m):.3f}")
                
                col_cfg = {
                    "feature": "Feature Name",
                    "z_score": "Deviation (Z-Score)",
                    "observed_value": "Observed Value",
                }
                if mean_col:
                    col_cfg[mean_col] = "Baseline Mean"

                st.dataframe(
                    dev_df,
                    column_config=col_cfg,
                    hide_index=True,
                    height=180
                )
            else:
                st.info("Feature values conform closely to normal baseline distributions.")

        # RIGHT COLUMN: AI SOC Analyst Triage
        with col_right:
            st.markdown("#### :material/security: AI SOC Analyst Attribution & Verdict")

            verdict = explanation.get("verdict", "Suspicious")
            if "Malicious" in verdict:
                st.error(f"**Verdict:** {verdict}")
            elif "Suspicious" in verdict:
                st.warning(f"**Verdict:** {verdict}")
            else:
                st.success(f"**Verdict:** {verdict}")

            v_col1, v_col2 = st.columns(2)
            with v_col1:
                st.markdown(f"**Attributed Technique:**")
                st.markdown(f"`{explanation.get('attributed_technique', 'Living-off-the-Land Technique')}`")
            with v_col2:
                st.markdown(f"**MITRE ATT&CK ID:**")
                st.markdown(f"`{explanation.get('mitre_id', 'T1059')}`")

            conf = float(explanation.get("confidence_score", 0.85))
            st.markdown(f"**Analyst Confidence:** `{conf:.2f}`")
            st.progress(conf)

            st.markdown("**Analyst Plain-English Justification:**")
            st.info(explanation.get("plain_english_explanation", "No justification available."))

            with st.expander("Inspect Raw Audit Event Lines"):
                st.code(sel_ev.get("raw_event", "No raw syslog / audit lines captured."), language="text")

# -----------------------------------------------------------------------------
# VIEW 2: ACADEMIC BENCHMARK SUITE
# -----------------------------------------------------------------------------

elif nav_choice == "Academic Benchmarks":
    st.subheader("Academic Evaluation & Grounding Benchmark Results")
    st.markdown(
        "Empirical benchmarks conforming to M.Tech Project Module 5, "
        "validating against the grounding literature matrix."
    )

    summary = load_eval_summary()

    if summary:
        tab1, tab2, tab3 = st.tabs([
            "Sequence Window Ablation (Springer 2026)",
            "Complexity Tiers (SLR 2026)",
            "Supervised vs Unsupervised (Stamp 2022)"
        ])

        with tab1:
            st.markdown("### Experiment 1: Isolated Commands vs. Sliding Sequence Windows")
            st.markdown(
                "Validates the **Springer (2026)** finding that temporal command sequences "
                "significantly outperform isolated single-command analysis."
            )
            exp1_data = summary.get("experiment1_isolated_vs_window", [])
            if exp1_data:
                st.dataframe(pd.DataFrame(exp1_data)[["Mode", "Precision", "Recall", "F1-Score", "FPR", "Latency/Ev (ms)"]], hide_index=True)

            img1_path = os.path.join(BASE_DIR, "evaluation", "results", "isolated_vs_sliding_window.png")
            if os.path.exists(img1_path):
                st.image(img1_path, caption="Figure 1: Isolated Commands vs Sliding Window Ablation (Precision, Recall, F1, FPR)")

        with tab2:
            st.markdown("### Experiment 2: Performance Across Attack Complexity Tiers")
            st.markdown(
                "Empirically tests the **Systematic Literature Review (2026)** hypothesis: "
                "unsupervised Isolation Forest excels at overt intrusions (Tier 1) but experiences "
                "performance degradation on stealthy and obfuscated attacks (Tier 3)."
            )
            exp2_data = summary.get("experiment2_tiers", [])
            if exp2_data:
                st.dataframe(pd.DataFrame(exp2_data)[["Attack Evaluation Tier", "Attack Events", "Precision", "Recall", "F1-Score", "FPR"]], hide_index=True)
            else:
                st.info("Tier breakdown populated when evaluating full multi-tier benchmark dataset.")

            img2_path = os.path.join(BASE_DIR, "evaluation", "results", "tier_performance_benchmark.png")
            if os.path.exists(img2_path):
                st.image(img2_path, caption="Figure 2: Performance Dynamics across Attack Complexity Tiers")

        with tab3:
            st.markdown("### Experiment 3: Unsupervised vs. Supervised Comparators")
            st.markdown(
                "Demonstrates why unsupervised anomaly detection is essential given the scarcity "
                "and class imbalance of labeled attack traces in production environments (**Stamp 2022**)."
            )
            exp3_data = summary.get("experiment3_supervised_comparison", [])
            if exp3_data:
                st.dataframe(pd.DataFrame(exp3_data)[["Model Architecture", "Precision", "Recall", "F1-Score", "FPR", "Supervision"]], hide_index=True)
            else:
                st.info("Supervised comparator evaluations active during full synthetic benchmark runs.")

    else:
        st.warning("No evaluation summary found. Please execute `evaluation/evaluate.py` first.")

# -----------------------------------------------------------------------------
# VIEW 3: SYSTEM ARCHITECTURE & METHODOLOGY
# -----------------------------------------------------------------------------

else:
    st.subheader("System Architecture & Methodological Invariants")

    st.markdown("""
    ### Defensive Blue-Team Architecture
    Unlike offensive AI-for-PrivEsc (auto-exploitation and AV evasion wrappers), this project focuses
    exclusively on **defensive Endpoint Detection and Response (EDR)**.

    ```text
    [Isolated Lab VMs: Linux + Windows]
       ├── Benign Baseline Activity (Dev, Admin, Cron Workloads)
       └── Controlled PrivEsc & LOLBin Simulation (8-10 Target Binaries across Tiers 1-3)
              │
              ▼
    [Telemetry Normalization Layer (pipeline/telemetry.py)]
       ├── Grouping auditd SYSCALL, EXECVE, PATH, PROCTITLE records
       └── Standardizing into normalized event schemas (PID, PPID, EUID, Args)
              │
              ▼
    [Feature Extraction Engine (pipeline/feature_extractor.py)]
       ├── Process lineage & parent-child transition rarity
       ├── Command-line Shannon entropy & token n-grams
       ├── Privilege transitions (UID -> EUID elevation)
       └── Temporal sliding command window aggregation (N=3)
              │
              ▼
    [Unsupervised Anomaly Detection Layer (pipeline/detector.py)]
       └── Isolation Forest (Trained strictly on Benign Baseline, zero label leakage)
              │
              ▼
    [Zero-Shot SOC Attribution Layer (pipeline/llm_explainer.py)]
       ├── Stripped Anomaly Payload (no ground-truth labels)
       └── Plain-English SOC Verdict, Attributed Technique & MITRE ATT&CK ID
              │
              ▼
    [SOC Threat Hunting Dashboard & Wazuh SIEM Integration]
    ```
    """)

    st.markdown("---")
    st.subheader("Grounding Literature Citations")
    st.markdown("""
    1. **Ongun et al. (RAID 2021) [LOLAL]:** Word-embedding representations of command-line text and ensemble boosting.
    2. **Stamp (2022):** Token vectors and scarcity of labeled malicious LOLBin samples.
    3. **Springer (2026):** Proof that a window of commands outperforms isolated command lines.
    4. **Ding et al. (IEEE CCIS 2023) [LOLWTC]:** Deep learning baseline comparison for chaining/obfuscation detection.
    5. **Barr-Smith et al. (IEEE S&P 2021) [Survivalism]:** Empirical prevalence study justifying target binary selection.
    6. **Liu, Ting, Zhou (IEEE ICDM 2008):** Algorithmic foundation of Isolation Forest.
    7. **Systematic Literature Review (2026):** Isolation Forest performance degradation under stealthy intrusion.
    8. **Ali & Kostakos (2023) [HuntGPT]:** Pairing ML anomaly detection with LLM explainability.
    9. **Houssel et al. (2024):** Framework for evaluating LLM intrusion explanations and eliminating hallucinations.
    10. **Ferrag et al. (IEEE Access 2024):** Zero-shot reasoning over structured security telemetry.
    """)
