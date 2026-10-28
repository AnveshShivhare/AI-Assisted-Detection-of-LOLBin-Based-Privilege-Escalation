#!/usr/bin/env python3
"""
detector.py
===========
AI-Assisted Privilege Escalation & Living-off-the-Land (LOLBin) Detection Project
Anomaly Detection Engine (Isolation Forest & Supervised Baselines)

Grounding Literature:
  - Liu, Ting, Zhou (IEEE ICDM 2008) [Isolation Forest]: Anomaly isolation via random trees
  - SLR (2026) [arXiv:2501.17787]: Isolation Forest excels on overt attacks, degrades on obfuscation
  - Springer (2026): Performance comparison with supervised classifiers
  - Stamp (2022): Supervised model generalization failure on scarce/unseen LOLBin samples
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Tuple, Optional
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler

class AnomalyDetector:
    def __init__(self, contamination: float = 0.025, n_estimators: int = 150, random_state: int = 42):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state

        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            max_samples="auto",
            random_state=self.random_state,
            n_jobs=-1
        )
        self.feature_names: List[str] = []
        self.benign_feature_means: Optional[np.ndarray] = None
        self.benign_feature_stds: Optional[np.ndarray] = None
        self.os_thresholds: Dict[str, float] = {}
        self.os_score_stds: Dict[str, float] = {}
        self.global_threshold: float = 0.0
        self.is_fitted = False

        # Optional supervised comparators
        self.rf_comparator: Optional[RandomForestClassifier] = None
        self.dt_comparator: Optional[DecisionTreeClassifier] = None
        self.feature_extractor: Optional[Any] = None

    def fit_unsupervised(self, X_benign: np.ndarray, feature_names: List[str]):
        """
        Fits Isolation Forest strictly on clean benign baseline telemetry.
        Grounding: Liu et al. (2008) - anomalies are few and different.
        Applies OS-stratified threshold calibration to prevent high-magnitude
        Linux UID escalations from masking Windows user-level LOLBin abuse.
        """
        self.feature_names = list(feature_names)
        self.scaler.fit(X_benign)
        X_scaled = self.scaler.transform(X_benign)

        self.isolation_forest.fit(X_scaled)

        # Record benign baseline statistical moments for feature deviation attribution
        self.benign_feature_means = np.mean(X_benign, axis=0)
        self.benign_feature_stds = np.std(X_benign, axis=0)
        self.benign_feature_stds[self.benign_feature_stds == 0] = 1.0

        # Calibrate per-OS decision thresholds on benign baseline
        raw_benign = self.isolation_forest.decision_function(X_scaled)
        self.global_threshold = float(np.percentile(raw_benign, self.contamination * 100))
        self.os_thresholds = {}
        self.os_score_stds = {}

        if "is_windows" in self.feature_names:
            is_win_idx = self.feature_names.index("is_windows")
            mask_win = (X_benign[:, is_win_idx] > 0.5)
            mask_lin = ~mask_win

            if np.any(mask_lin):
                lin_scores = raw_benign[mask_lin]
                # Calibrate linux threshold to ensure subtle recon/GTFObin discrimination
                self.os_thresholds["linux"] = float(np.percentile(lin_scores, min(self.contamination * 1.35 * 100, 3.5)))
                self.os_score_stds["linux"] = float(np.std(lin_scores)) or 0.05
            if np.any(mask_win):
                win_scores = raw_benign[mask_win]
                self.os_thresholds["windows"] = float(np.percentile(win_scores, self.contamination * 100))
                self.os_score_stds["windows"] = float(np.std(win_scores)) or 0.05

        self.is_fitted = True
        return self

    def predict_anomaly(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Infers whether events are anomalous using OS-calibrated thresholds.
        Returns:
          - is_anomaly: boolean mask (True if anomaly, False if normal)
          - anomaly_scores: continuous severity score [0.0 (benign) to 1.0 (extreme anomaly)]
        """
        if not self.is_fitted:
            raise RuntimeError("Detector must be fitted on benign baseline first.")

        X_scaled = self.scaler.transform(X)
        raw_scores = self.isolation_forest.decision_function(X_scaled)

        is_anomaly = np.zeros(len(X), dtype=bool)
        norm_scores = np.zeros(len(X), dtype=float)

        if "is_windows" in self.feature_names and len(self.os_thresholds) > 0:
            is_win_idx = self.feature_names.index("is_windows")
            mask_win = (X[:, is_win_idx] > 0.5)
            mask_lin = ~mask_win

            for mask, os_name in [(mask_lin, "linux"), (mask_win, "windows")]:
                if not np.any(mask):
                    continue
                thresh = self.os_thresholds.get(os_name, self.global_threshold)
                std_s = self.os_score_stds.get(os_name, 0.05)
                sub_raw = raw_scores[mask]

                is_anomaly[mask] = (sub_raw < thresh)
                # Continuous calibrated score around threshold: z = (thresh - raw) / std
                z_dist = (thresh - sub_raw) / max(std_s, 0.01)
                norm_scores[mask] = 1.0 / (1.0 + np.exp(-1.8 * z_dist))
        else:
            thresh = self.global_threshold
            is_anomaly = (raw_scores < thresh)
            std_s = float(np.std(raw_scores)) or 0.05
            z_dist = (thresh - raw_scores) / max(std_s, 0.01)
            norm_scores = 1.0 / (1.0 + np.exp(-1.8 * z_dist))

        return is_anomaly, norm_scores

    def extract_feature_deviations(self, x_vec: np.ndarray, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Computes z-scores of individual features against benign baseline to identify
        what specific statistical deviations triggered the anomaly.
        """
        if self.benign_feature_means is None or self.benign_feature_stds is None:
            return []

        z_scores = (x_vec - self.benign_feature_means) / self.benign_feature_stds
        deviations = []
        for i, fname in enumerate(self.feature_names):
            val = float(x_vec[i])
            z = float(z_scores[i])
            deviations.append({
                "feature": fname,
                "observed_value": round(val, 4),
                "baseline_mean": round(float(self.benign_feature_means[i]), 4),
                "z_score": round(z, 2)
            })

        deviations.sort(key=lambda d: abs(d["z_score"]), reverse=True)
        return deviations[:top_k]

    def build_anomaly_payload(self, x_vec: np.ndarray, metadata: Dict[str, Any], anomaly_score: float) -> Dict[str, Any]:
        """
        Constructs the structured JSON payload passed to the LLM Explainability layer.
        Contains strictly observable endpoint telemetry and statistical feature deviations.
        Zero ground-truth labels or attack technique indicators are exposed.
        """
        top_deviations = self.extract_feature_deviations(x_vec, top_k=5)
        return {
            "event_id": metadata.get("event_id"),
            "timestamp": metadata.get("timestamp"),
            "os_type": metadata.get("os_type"),
            "process_name": metadata.get("process_name"),
            "parent_process_name": metadata.get("parent_process_name"),
            "command_line": metadata.get("command_line"),
            "session_id": metadata.get("session_id"),
            "anomaly_score": round(float(anomaly_score), 4),
            "flagged_by_engine": "IsolationForest_v1.0",
            "top_feature_deviations": top_deviations,
            "sliding_window_commands": metadata.get("sliding_window_commands", [])
        }

    def train_supervised_comparators(self, X_train: np.ndarray, y_train: np.ndarray, use_smote: bool = True, class_weight: str = "balanced"):
        """
        Trains supervised baselines (Random Forest & Decision Tree) to evaluate generalization.
        Grounding: Stamp (2022) & Springer (2026).
        Applies SMOTE oversampling (if available and classes imbalanced) and balanced class weighting
        to resolve class imbalance between benign telemetry and scarce attack samples.
        """
        X_train_scaled = self.scaler.transform(X_train)
        X_fit, y_fit = X_train_scaled, y_train

        if use_smote:
            try:
                from imblearn.over_sampling import SMOTE
                unique, counts = np.unique(y_train, return_counts=True)
                if len(unique) > 1 and min(counts) >= 2:
                    k_neighbors = min(5, min(counts) - 1)
                    if k_neighbors >= 1:
                        smote = SMOTE(k_neighbors=k_neighbors, random_state=self.random_state)
                        X_fit, y_fit = smote.fit_resample(X_train_scaled, y_train)
            except Exception:
                pass

        self.rf_comparator = RandomForestClassifier(n_estimators=100, class_weight=class_weight, random_state=self.random_state)
        self.rf_comparator.fit(X_fit, y_fit)

        self.dt_comparator = DecisionTreeClassifier(class_weight=class_weight, random_state=self.random_state)
        self.dt_comparator.fit(X_fit, y_fit)

    def predict_supervised_comparators(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        """Runs predictions with supervised benchmark models."""
        X_scaled = self.scaler.transform(X)
        results = {}
        if self.rf_comparator:
            results["RandomForest"] = self.rf_comparator.predict(X_scaled)
        if self.dt_comparator:
            results["DecisionTree"] = self.dt_comparator.predict(X_scaled)
        return results

    def save(self, filepath: str, feature_extractor: Optional[Any] = None):
        """
        Saves a single unified pipeline bundle containing:
          - IsolationForest estimator & OS-calibrated thresholds
          - StandardScaler (fitted on benign baseline)
          - TelemetryFeatureExtractor (fitted process/pair lineage counts, TfidfVectorizer, TruncatedSVD)
          - Supervised benchmark comparators (if trained)
        Enables fresh standalone inference processes to score new telemetry with zero refitting.
        """
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        extractor_to_save = feature_extractor or getattr(self, "feature_extractor", None)
        extractor_state = extractor_to_save.get_state() if (extractor_to_save is not None and hasattr(extractor_to_save, "get_state")) else None

        bundle = {
            "isolation_forest": self.isolation_forest,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "benign_feature_means": self.benign_feature_means,
            "benign_feature_stds": self.benign_feature_stds,
            "contamination": self.contamination,
            "os_thresholds": self.os_thresholds,
            "os_score_stds": self.os_score_stds,
            "global_threshold": self.global_threshold,
            "rf_comparator": self.rf_comparator,
            "dt_comparator": self.dt_comparator,
            "feature_extractor": extractor_to_save,
            "feature_extractor_state": extractor_state
        }
        joblib.dump(bundle, filepath)

    def load(self, filepath: str):
        """Loads unified pipeline bundle and restores estimator and feature extractor states."""
        data = joblib.load(filepath)
        self.isolation_forest = data["isolation_forest"]
        self.scaler = data["scaler"]
        self.feature_names = data["feature_names"]
        self.benign_feature_means = data["benign_feature_means"]
        self.benign_feature_stds = data["benign_feature_stds"]
        self.contamination = data["contamination"]
        self.os_thresholds = data.get("os_thresholds", {})
        self.os_score_stds = data.get("os_score_stds", {})
        self.global_threshold = data.get("global_threshold", 0.0)
        self.rf_comparator = data.get("rf_comparator")
        self.dt_comparator = data.get("dt_comparator")

        # Restore feature extractor if present in bundle
        if "feature_extractor" in data and data["feature_extractor"] is not None:
            self.feature_extractor = data["feature_extractor"]
        elif "feature_extractor_state" in data and data["feature_extractor_state"] is not None:
            from pipeline.feature_extractor import TelemetryFeatureExtractor
            self.feature_extractor = TelemetryFeatureExtractor()
            self.feature_extractor.set_state(data["feature_extractor_state"])
        else:
            self.feature_extractor = None

        self.is_fitted = True
        return self


def load_pipeline_bundle(filepath: str) -> Tuple[AnomalyDetector, Optional[Any]]:
    """
    Loads the unified pipeline bundle from disk.
    Returns:
      (detector, feature_extractor) ready for standalone inference without refitting.
    """
    detector = AnomalyDetector()
    detector.load(filepath)
    return detector, detector.feature_extractor
