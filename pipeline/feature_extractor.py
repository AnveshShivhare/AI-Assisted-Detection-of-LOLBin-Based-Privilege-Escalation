#!/usr/bin/env python3
"""
feature_extractor.py
====================
AI-Assisted Privilege Escalation & Living-off-the-Land (LOLBin) Detection Project
Feature Extraction & Preprocessing Pipeline

Ingests parsed endpoint telemetry (auditd/Sysmon/Wazuh) and computes:
  1. Process Lineage Features (Parent-Child pairs, rarity scores)
  2. Privilege & Access Features (EUID transition, Integrity level, sensitive file touches)
  3. Command-Line NLP Features (Length, Shannon entropy, special character ratio, token flags,
     and TruncatedSVD-reduced continuous TF-IDF embeddings)
  4. Sliding Window Aggregations & Sequence-Aware Transitions (Sliding sequence of N=3 to 5
     consecutive commands per session capturing entropy delta, privilege escalation step,
     token acceleration, and inter-event timing delta)

Grounding Literature:
  - Ongun et al. (RAID 2021) [LOLAL]: Command NLP representations & continuous embeddings
  - Stamp (2022): NLP token vectors for LOLBin abuse detection
  - Springer (2026): Proves sliding window of commands outperforms isolated command lines
  - Liu et al. (2008) / SLR (2026): Behavioral distributions for Isolation Forest
"""

import os
import math
import re
from datetime import datetime
from collections import defaultdict, deque
from typing import List, Dict, Any, Tuple
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD

SENSITIVE_FILES_LINUX = [
    "/etc/sudoers", "/etc/shadow", "/etc/passwd", "/etc/crontab",
    "/var/spool/cron", "/etc/pam.d", "/root", "/tmp"
]

SENSITIVE_FILES_WIN = [
    "sam", "system", "security", "lsass.exe", "services.exe",
    "windows\\temp", "programdata", "system32\\config"
]

SUSPICIOUS_TOKENS = [
    # GTFOBins / Linux
    "nopasswd", "-exec", "checkpoint", "checkpoint-action", "pty.spawn",
    "setuid", "-perm -4000", "-perm -u=s", "sudoers", "linpeas",
    "/bin/sh", "/bin/bash", "dash", "suid",
    # Windows LOLBins & PrivEsc
    "urlcache", "-split", "scrobj.dll", "script.sct", "bypass",
    "downloadfile", "downloadstring", "privilege::debug", "sekurlsa",
    "binpath=", "icacls", "everyone:f", "grant", "net user", "whoami /priv",
    "iex", "invoke-expression", "-encodedcommand", "bitsadmin", "/transfer"
]

UNTRUSTED_PATH_PATTERNS = [
    # External URI schemes
    "http://", "https://", "ftp://", "\\\\", "smb://",
    # Windows untrusted / world-writable paths
    "\\users\\public\\", "\\windows\\temp\\", "\\appdata\\local\\temp\\",
    "c:\\temp\\", "\\temp\\", "c:/temp/", "/users/public/",
    # Linux untrusted / world-writable paths
    "/tmp/", "/dev/shm/", "/var/tmp/"
]

SCRIPTLET_PROTOCOL_TOKENS = [
    "javascript:", "vbscript:", "scrobj.dll", "runhtmlapplication",
    "-urlcache", "-split", "-decode", "binpath=", "--checkpoint-action",
    "script.sct", "mshtml", "wscript.shell", "cscript", "wscript"
]

def shannon_entropy(data: str) -> float:
    """Computes Shannon entropy (bits per char) of command string to detect obfuscation."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = defaultdict(int)
    for c in data:
        counts[c] += 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)

def special_char_ratio(s: str) -> float:
    """Ratio of special characters (punctuations, shell metacharacters) to total length."""
    if not s:
        return 0.0
    specials = set(";|$%`\\\"'<>*&!{}()[]:^~#?-=+")
    count = sum(1 for c in s if c in specials)
    return float(count / len(s))

class TelemetryFeatureExtractor:
    def __init__(self, window_size: int = 3):
        self.window_size = window_size
        self.baseline_parent_child_counts = defaultdict(int)
        self.baseline_process_counts = defaultdict(int)
        self.total_baseline_events = 0
        self.is_fitted = False
        self.feature_names: List[str] = []

        # Continuous NLP representation (Ongun et al. RAID 2021)
        self.tfidf = TfidfVectorizer(
            analyzer="word",
            token_pattern=r"(?u)\b\w+\b|[-/\\:.]+",
            ngram_range=(1, 2),
            max_features=250,
            lowercase=True
        )
        self.svd = TruncatedSVD(n_components=5, random_state=42)
        self.nlp_fitted = False

    def fit(self, benign_events: List[Dict[str, Any]]):
        """Learns baseline process lineage and TF-IDF NLP representations from clean benign telemetry."""
        self.baseline_parent_child_counts.clear()
        self.baseline_process_counts.clear()
        self.total_baseline_events = len(benign_events)

        cmds = []
        for ev in benign_events:
            p_name = ev.get("parent_process_name", "unknown").lower()
            c_name = ev.get("process_name", "unknown").lower()
            pair = f"{p_name}->{c_name}"
            self.baseline_parent_child_counts[pair] += 1
            self.baseline_process_counts[c_name] += 1
            cmds.append(str(ev.get("command_line", "") or ""))

        # Fit continuous NLP representation strictly on benign training baseline
        if cmds:
            tfidf_mat = self.tfidf.fit_transform(cmds)
            self.svd.fit(tfidf_mat)
            self.nlp_fitted = True

        self.is_fitted = True
        return self

    def _parse_timestamp_ms(self, ts_str: str) -> float:
        """Parses ISO timestamp into epoch milliseconds."""
        if not ts_str:
            return 0.0
        try:
            dt = datetime.fromisoformat(ts_str)
            return dt.timestamp() * 1000.0
        except Exception:
            return 0.0

    def _compute_isolated_features(self, ev: Dict[str, Any], nlp_components: np.ndarray) -> Dict[str, float]:
        """Extracts features for an isolated single event."""
        cmd = ev.get("command_line", "") or ""
        p_name = ev.get("parent_process_name", "unknown").lower()
        c_name = ev.get("process_name", "unknown").lower()
        pair = f"{p_name}->{c_name}"

        # 1. Process Lineage Rarity & Lineage Anomaly Score
        proc_count = self.baseline_process_counts.get(c_name, 0)
        pair_count = self.baseline_parent_child_counts.get(pair, 0)
        if proc_count > 0:
            cond_prob = pair_count / float(proc_count)
            lineage_anomaly_score = float(1.0 - cond_prob)
        else:
            lineage_anomaly_score = 1.0

        if self.total_baseline_events > 0:
            pair_rarity = 1.0 - (pair_count / (self.total_baseline_events + 1))
            proc_rarity = 1.0 - (proc_count / (self.total_baseline_events + 1))
        else:
            pair_rarity = 0.5
            proc_rarity = 0.5

        # 2. Command-Line Lexical & Statistical Deviations
        cmd_len = float(len(cmd))
        entropy = shannon_entropy(cmd)
        spec_ratio = special_char_ratio(cmd)

        lower_cmd = cmd.lower()
        token_hits = sum(1 for t in SUSPICIOUS_TOKENS if t in lower_cmd)
        tokens_list = lower_cmd.split()
        token_count = max(1, len(tokens_list))

        # Continuous Behavioral LOLBin Indicators
        file_touches = [str(f).lower() for f in ev.get("file_touches", [])]
        path_uri_hits = 0
        for pat in UNTRUSTED_PATH_PATTERNS:
            path_uri_hits += lower_cmd.count(pat)
            for ft in file_touches:
                if pat in ft:
                    path_uri_hits += 1
        remote_or_untrusted_path_density = float(path_uri_hits) / math.sqrt(token_count)

        scriptlet_hits = sum(lower_cmd.count(tok) for tok in SCRIPTLET_PROTOCOL_TOKENS)
        inline_scriptlet_protocol_density = float(scriptlet_hits) / math.sqrt(token_count)

        # OS Indicators
        os_type_str = str(ev.get("os_type", "")).lower()
        is_windows = 1.0 if os_type_str == "windows" else 0.0
        is_linux = 1.0 if os_type_str == "linux" else 0.0

        # 3. Privilege & Access Features
        euid = ev.get("euid", 1000)
        uid = ev.get("uid", 1000)
        integrity = ev.get("integrity_level", "Medium")

        elevated_priv = 1.0 if (euid == 0 or integrity in ["High", "System"]) else 0.0
        priv_transition = 1.0 if (euid != uid and euid == 0) else 0.0
        sudo_invoked = 1.0 if ("sudo" in lower_cmd or c_name == "sudo") else 0.0

        # Sensitive file / registry touch
        touched_sensitive = 0.0
        for f in file_touches:
            if any(sf in f for sf in SENSITIVE_FILES_LINUX) or any(sf in f for sf in SENSITIVE_FILES_WIN):
                touched_sensitive = 1.0
                break

        # Known LOLBin process name check
        lolbins = {"certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "bitsadmin.exe", "powershell.exe", "find", "awk", "tar", "vim", "python3"}
        is_known_lolbin = 1.0 if c_name in lolbins else 0.0

        feats = {
            "is_windows": is_windows,
            "is_linux": is_linux,
            "lineage_anomaly_score": lineage_anomaly_score,
            "remote_or_untrusted_path_density": remote_or_untrusted_path_density,
            "inline_scriptlet_protocol_density": inline_scriptlet_protocol_density,
            "pair_rarity": pair_rarity,
            "proc_rarity": proc_rarity,
            "cmd_length": cmd_len,
            "entropy": entropy,
            "special_char_ratio": spec_ratio,
            "token_hits": float(token_hits),
            "elevated_priv": elevated_priv,
            "priv_transition": priv_transition,
            "sudo_invoked": sudo_invoked,
            "touched_sensitive": touched_sensitive,
            "is_known_lolbin": is_known_lolbin,
            # Continuous TF-IDF embeddings (Ongun et al. RAID 2021)
            "nlp_emb_0": float(nlp_components[0]),
            "nlp_emb_1": float(nlp_components[1]),
            "nlp_emb_2": float(nlp_components[2]),
            "nlp_emb_3": float(nlp_components[3]),
            "nlp_emb_4": float(nlp_components[4])
        }
        return feats

    def transform(self, events: List[Dict[str, Any]], mode: str = "window") -> Tuple[np.ndarray, List[str], List[Dict[str, Any]]]:
        """
        Transforms raw telemetry events into a normalized feature matrix.
        Modes:
          - 'isolated': evaluates isolated single commands.
          - 'window': applies sliding window aggregations AND sequence-aware ordered transition
                      features (entropy delta, privilege escalation step, token acceleration,
                      and inter-event timing delta) over the last N commands per session.
                      (Grounding: Springer 2026)
        """
        if not self.is_fitted:
            raise RuntimeError("TelemetryFeatureExtractor must be fit on benign baseline before transform.")

        # Batch-compute continuous NLP embeddings
        cmds = [str(ev.get("command_line", "") or "") for ev in events]
        if self.nlp_fitted and cmds:
            tfidf_mat = self.tfidf.transform(cmds)
            nlp_embeddings = self.svd.transform(tfidf_mat)
        else:
            nlp_embeddings = np.zeros((len(events), 5))

        session_histories = defaultdict(lambda: deque(maxlen=self.window_size))
        feature_rows = []
        metadata_list = []

        for i, ev in enumerate(events):
            sess_id = ev.get("session_id", "default_sess")
            iso_feats = self._compute_isolated_features(ev, nlp_embeddings[i])
            ts_ms = self._parse_timestamp_ms(ev.get("timestamp", ""))

            history = session_histories[sess_id]

            if mode == "isolated":
                row = dict(iso_feats)
                history.append({**iso_feats, "timestamp_ms": ts_ms})
            elif mode == "window":
                # Sequence-aware ordered transition features computed BEFORE appending current event
                if len(history) > 0:
                    # a) Entropy escalation delta: (current - first in window)
                    first_cmd_entropy = history[0]["entropy"]
                    entropy_delta = float(iso_feats["entropy"] - first_cmd_entropy)

                    # b) Privilege escalation in window (stepping from unprivileged to elevated)
                    had_unprivileged_earlier = any(h.get("elevated_priv", 0.0) == 0.0 for h in history)
                    current_elevated = (iso_feats.get("elevated_priv", 0.0) == 1.0 or iso_feats.get("priv_transition", 0.0) == 1.0)
                    priv_escalated_in_window = 1.0 if (had_unprivileged_earlier and current_elevated) else 0.0

                    # c) Token acceleration (jump in suspicious token hits)
                    prev_token_hits = history[-1]["token_hits"]
                    token_acceleration = float(iso_feats["token_hits"] - prev_token_hits)

                    # d) Inter-event timing delta (ms)
                    prev_ts = history[-1].get("timestamp_ms", 0.0)
                    inter_event_delta_ms = max(0.0, float(ts_ms - prev_ts)) if (prev_ts > 0 and ts_ms > 0) else 5000.0
                else:
                    entropy_delta = 0.0
                    priv_escalated_in_window = 0.0
                    token_acceleration = 0.0
                    inter_event_delta_ms = 5000.0

                # Append current step to session history
                history.append({**iso_feats, "timestamp_ms": ts_ms})

                # Compute sliding window aggregations
                window_len = len(history)
                avg_entropy = sum(h["entropy"] for h in history) / window_len
                max_entropy = max(h["entropy"] for h in history)
                avg_len = sum(h["cmd_length"] for h in history) / window_len
                max_len = max(h["cmd_length"] for h in history)
                max_priv_transition = max(h["priv_transition"] for h in history)
                max_elevated = max(h["elevated_priv"] for h in history)
                cumulative_tokens = sum(h["token_hits"] for h in history)
                cumulative_sensitive = sum(h["touched_sensitive"] for h in history)
                max_pair_rarity = max(h["pair_rarity"] for h in history)
                max_lineage_anomaly = max(h["lineage_anomaly_score"] for h in history)
                max_untrusted_density = max(h["remote_or_untrusted_path_density"] for h in history)
                cum_untrusted_density = sum(h["remote_or_untrusted_path_density"] for h in history)
                max_scriptlet_density = max(h["inline_scriptlet_protocol_density"] for h in history)
                cum_scriptlet_density = sum(h["inline_scriptlet_protocol_density"] for h in history)

                row = {
                    # Current isolated features
                    **iso_feats,
                    # Sliding window behavioral features (Springer 2026)
                    "win_avg_entropy": avg_entropy,
                    "win_max_entropy": max_entropy,
                    "win_avg_length": avg_len,
                    "win_max_length": max_len,
                    "win_max_priv_transition": max_priv_transition,
                    "win_max_elevated": max_elevated,
                    "win_cumulative_tokens": float(cumulative_tokens),
                    "win_cumulative_sensitive": float(cumulative_sensitive),
                    "win_max_pair_rarity": max_pair_rarity,
                    "win_max_lineage_anomaly": max_lineage_anomaly,
                    "win_max_untrusted_path_density": max_untrusted_density,
                    "win_cum_untrusted_path_density": cum_untrusted_density,
                    "win_max_scriptlet_density": max_scriptlet_density,
                    "win_cum_scriptlet_density": cum_scriptlet_density,
                    "win_size_current": float(window_len),
                    # Sequence-aware transition dynamics
                    "entropy_delta": entropy_delta,
                    "priv_escalated_in_window": priv_escalated_in_window,
                    "token_acceleration": token_acceleration,
                    "inter_event_delta_ms": inter_event_delta_ms
                }
            else:
                raise ValueError(f"Unknown mode: {mode}")

            feature_rows.append(row)
            metadata_list.append({
                "event_id": ev.get("event_id"),
                "timestamp": ev.get("timestamp"),
                "os_type": ev.get("os_type"),
                "process_name": ev.get("process_name"),
                "parent_process_name": ev.get("parent_process_name", "unknown"),
                "command_line": ev.get("command_line"),
                "session_id": sess_id,
                "label": ev.get("label", "benign"),
                "tier": ev.get("tier", 0),
                "technique": ev.get("technique", "Unknown"),
                "mitre_technique_id": ev.get("mitre_technique_id", "None"),
                "raw_event": ev.get("raw_event", "")
            })

        df = pd.DataFrame(feature_rows)
        self.feature_names = list(df.columns)
        X = df.values.astype(np.float64)

        return X, self.feature_names, metadata_list

    def fit_transform(self, benign_events: List[Dict[str, Any]], mode: str = "window"):
        self.fit(benign_events)
        return self.transform(benign_events, mode=mode)
