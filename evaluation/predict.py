#!/usr/bin/env python3
"""
predict.py
==========
AI-Assisted Privilege Escalation & Living-off-the-Land (LOLBin) Detection Project
Standalone Inference Engine for Scoring New Endpoint Telemetry

Loads the already-trained unified model bundle (Isolation Forest, StandardScaler,
and fitted TelemetryFeatureExtractor state) and scores NEW telemetry with
ZERO retraining or refitting.

Usage:
  python evaluation/predict.py --log-path <path_to_raw_auditd.log> [--model-path pipeline/detector_model.joblib]
"""

import os
import sys
import argparse
from typing import List, Dict, Any
from tabulate import tabulate

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from pipeline.telemetry import AuditdTelemetrySource
from pipeline.detector import load_pipeline_bundle


def score_new_telemetry(
    log_path: str,
    model_path: str = "pipeline/detector_model.joblib",
    threshold: float = 0.5,
    mode: str = "window"
):
    print("=" * 80)
    print("AI-Assisted PrivEsc & LOLBin Detection - Standalone Inference Engine")
    print(f"Target Log File : {log_path}")
    print(f"Model Bundle    : {model_path}")
    print(f"Decision Boundary: {threshold:.2f}")
    print("=" * 80)

    # 1. Verify model bundle existence
    if not os.path.exists(model_path):
        print(f"[-] ERROR: Model bundle not found at '{model_path}'.", file=sys.stderr)
        print("    Please run 'evaluation/evaluate.py' to train and persist the pipeline bundle first.", file=sys.stderr)
        sys.exit(1)

    # 2. Load model bundle
    print(f"[*] Loading model bundle from {model_path}...")
    detector, extractor = load_pipeline_bundle(model_path)

    # 3. Strict verification of fitted state (Requirement 4: zero refitting allowed)
    if extractor is None or not getattr(extractor, "is_fitted", False):
        print(
            "[-] CRITICAL ERROR: The loaded bundle does not contain a fitted TelemetryFeatureExtractor.\n"
            "    Standalone inference cannot transform raw events without fitted baseline statistics.\n"
            "    Please retrain using evaluate.py to produce a complete bundle.",
            file=sys.stderr
        )
        sys.exit(1)

    if not getattr(detector, "is_fitted", False):
        print(
            "[-] CRITICAL ERROR: The loaded bundle contains an unfitted AnomalyDetector.",
            file=sys.stderr
        )
        sys.exit(1)

    print(f"[+] Successfully loaded fitted pipeline bundle:")
    print(f"    - Isolation Forest : {detector.isolation_forest.n_estimators} estimators (contamination={detector.contamination})")
    print(f"    - StandardScaler   : fitted on {len(detector.feature_names)} features")
    print(f"    - Feature Extractor: fitted on {extractor.total_baseline_events} baseline events (NLP fitted={extractor.nlp_fitted})")
    print(f"    - Window Size (N)  : {extractor.window_size}")

    # 4. Ingest and parse new auditd log using existing AuditdTelemetrySource
    if not os.path.exists(log_path):
        print(f"[-] ERROR: Target log file not found at '{log_path}'.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Ingesting and parsing new auditd log from {log_path}...")
    telemetry_source = AuditdTelemetrySource(log_path, is_file=True, assume_benign=False)
    events = list(telemetry_source.events())

    if not events:
        print(f"[-] No valid correlated process execution events found in '{log_path}'.")
        return

    print(f"[+] Ingested {len(events)} correlated process events.")

    # 5. Transform new events using ONLY loaded fitted state (NO .fit() calls)
    print(f"[*] Extracting features in '{mode}' mode using pre-fitted baseline statistics...")
    X, f_names, meta = extractor.transform(events, mode=mode)

    # 6. Score events with pre-fitted detector
    print(f"[*] Scoring events with loaded Isolation Forest...")
    is_anom, scores = detector.predict_anomaly(X)

    # 7. Print per-event table
    table_rows = []
    flagged_count = 0

    for i, ev in enumerate(events):
        score = float(scores[i])
        flagged = score >= threshold
        if flagged:
            flagged_count += 1

        cmd = ev.get("command_line", "") or ""
        cmd_display = (cmd[:57] + "...") if len(cmd) > 60 else cmd
        ts = ev.get("timestamp", "")
        # Format timestamp to readable string if ISO
        ts_short = ts.split("T")[-1].replace("+00:00", "Z") if "T" in ts else ts

        table_rows.append({
            "#": i + 1,
            "Timestamp": ts_short,
            "Process": ev.get("process_name", "unknown"),
            "Command Line": cmd_display,
            "Anomaly Score": f"{score:.4f}",
            f"Flagged (Score >= {threshold:.1f})": "YES" if flagged else "NO"
        })

    print("\n" + "=" * 80)
    print("PREDICTION RESULTS (PER-EVENT INFERENCE)")
    print("=" * 80)
    print(tabulate(table_rows, headers="keys", tablefmt="fancy_grid"))

    # 8. Print one-line summary
    total_events = len(events)
    flagged_pct = (flagged_count / total_events * 100.0) if total_events > 0 else 0.0
    print(f"\nSummary: Total Events: {total_events} | Flagged Anomalies: {flagged_count} ({flagged_pct:.2f}%) [Threshold: {threshold:.2f}]\n")


def main():
    parser = argparse.ArgumentParser(
        description="Standalone Inference Engine: Score new endpoint telemetry without retraining."
    )
    parser.add_argument(
        "--log-path",
        required=True,
        help="Path to new raw Linux auditd log file to score."
    )
    parser.add_argument(
        "--model-path",
        default="pipeline/detector_model.joblib",
        help="Path to saved pipeline bundle (default: pipeline/detector_model.joblib)."
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Decision threshold for flagging anomalies (default: 0.5)."
    )
    parser.add_argument(
        "--mode",
        choices=["window", "isolated"],
        default="window",
        help="Feature extraction mode (default: window)."
    )

    args = parser.parse_args()
    score_new_telemetry(
        log_path=args.log_path,
        model_path=args.model_path,
        threshold=args.threshold,
        mode=args.mode
    )


if __name__ == "__main__":
    main()
