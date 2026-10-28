#!/usr/bin/env python3
"""
active_response.py
==================
AI-Assisted Privilege Escalation & Living-off-the-Land (LOLBin) Detection Project
Wazuh / EDR Active Response Module

Simulates host-level EDR containment and active-response actions based on the
structured JSON dossier output produced by the LLM Explainability layer (llm_explainer.py).

Mitigation Rules:
  - Trigger Condition: Verdict contains 'Malicious' AND Confidence Score >= 0.80.
  - Offending Process Action: Simulated process tree termination (kill -9 <PID> on Linux / taskkill /F /T /PID <PID> on Windows).
  - Offending User Action: Simulated user account containment (passwd -l <user> on Linux / net user <user> /active:no on Windows).
  - Traceability: Appends all mitigation events with full context to data/edr_mitigations.log.
"""

import os
import sys
import json
import argparse
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple


class EDRActiveResponse:
    """
    Simulated EDR Active Response Engine.
    Evaluates LLM dossiers and executes defense-in-depth host mitigations.
    """

    def __init__(self, log_path: str = "data/edr_mitigations.log", confidence_threshold: float = 0.80):
        self.log_path = log_path
        self.confidence_threshold = confidence_threshold
        os.makedirs(os.path.dirname(os.path.abspath(self.log_path)), exist_ok=True)

    def _extract_field(self, data: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
        """Searches top-level and nested dictionaries for candidate field names."""
        for k in keys:
            if k in data and data[k] is not None:
                return data[k]

        # Search nested dicts (e.g. anomaly_payload, telemetry, metadata, llm_verdict)
        for nested_key in ("anomaly_payload", "telemetry", "metadata", "llm_verdict", "payload"):
            if nested_key in data and isinstance(data[nested_key], dict):
                for k in keys:
                    if k in data[nested_key] and data[nested_key][k] is not None:
                        return data[nested_key][k]

        return default

    def evaluate_and_respond(self, dossier: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses LLM verdict and telemetry metadata.
        If Verdict is Malicious and Confidence >= threshold, executes simulated containment.
        """
        # 1. Parse Verdict
        verdict = self._extract_field(dossier, ["verdict", "Verdict", "status"], default="Unknown")
        verdict_str = str(verdict)
        is_malicious = "malicious" in verdict_str.lower()

        # 2. Parse Confidence Score
        conf_raw = self._extract_field(dossier, ["confidence_score", "Confidence Score", "confidence", "score"], default=0.0)
        try:
            confidence = float(conf_raw)
        except (ValueError, TypeError):
            confidence = 0.0

        # 3. Parse Process ID & User
        pid = self._extract_field(dossier, ["process_id", "ProcessId", "pid", "target_pid"], default=None)
        user = self._extract_field(dossier, ["user", "User", "username", "target_user"], default="unknown_user")
        os_type = str(self._extract_field(dossier, ["os_type", "OS", "platform"], default="linux")).lower()

        # Additional descriptive context
        event_id = self._extract_field(dossier, ["event_id", "eventId"], default="N/A")
        tech = self._extract_field(dossier, ["attributed_technique", "technique"], default="PrivEsc/LOLBin Abuse")
        mitre_id = self._extract_field(dossier, ["mitre_id", "mitre_technique_id"], default="T1548")
        explanation = self._extract_field(dossier, ["plain_english_explanation", "explanation"], default="")

        timestamp = datetime.now(timezone.utc).isoformat()

        # Check containment trigger threshold
        meets_threshold = (confidence >= self.confidence_threshold)
        should_contain = is_malicious and meets_threshold

        response_summary: Dict[str, Any] = {
            "timestamp": timestamp,
            "verdict": verdict_str,
            "confidence_score": confidence,
            "threshold": self.confidence_threshold,
            "process_id": pid,
            "user": str(user),
            "os_type": os_type,
            "mitigation_triggered": should_contain,
            "simulated_commands": []
        }

        if should_contain:
            # Build simulated platform mitigation commands
            simulated_cmds = []

            # A. Process Tree Termination
            if pid is not None:
                if os_type == "windows":
                    cmd_kill = f"taskkill /F /T /PID {pid}"
                else:
                    cmd_kill = f"kill -9 {pid}"
                simulated_cmds.append(cmd_kill)

            # B. User Account Lockdown
            if user and str(user).lower() not in ("root", "system", "nt authority\\system", "none", "unknown", "unknown_user"):
                if os_type == "windows":
                    cmd_lock = f"net user \"{user}\" /active:no"
                else:
                    cmd_lock = f"passwd -l {user}"
                simulated_cmds.append(cmd_lock)
            elif pid is None and not simulated_cmds:
                # Fallback generic containment
                simulated_cmds.append("pkill -9 -u " + str(user))

            response_summary["simulated_commands"] = simulated_cmds

            # Print to stdout
            print("\n" + "=" * 70)
            print("  🚨 [EDR ACTIVE RESPONSE TRIGGERED] HOST CONTAINMENT ENGAGED 🚨")
            print("=" * 70)
            print(f"[*] Timestamp:          {timestamp}")
            print(f"[*] Event ID:           {event_id}")
            print(f"[*] Attributed Threat:  {tech} ({mitre_id})")
            print(f"[*] LLM Verdict:        {verdict_str}")
            print(f"[*] Confidence Score:   {confidence:.2f} (Threshold: {self.confidence_threshold:.2f})")
            print(f"[*] Target Process PID: {pid if pid is not None else 'N/A'}")
            print(f"[*] Target User:        {user}")
            if explanation:
                print(f"[*] Reason:             {explanation[:120]}...")
            print("-" * 70)
            print("[SIMULATED MITIGATION ACTIONS]:")
            for i, cmd in enumerate(simulated_cmds, 1):
                print(f"  [{i}] SIMULATING EXECUTION: {cmd}")
            print("=" * 70)
            print(f"[+] Containment actions logged to: {self.log_path}\n")

            # Append to persistent log file
            log_entry = {
                "timestamp": timestamp,
                "event_id": event_id,
                "action": "MITIGATION_SIMULATED",
                "verdict": verdict_str,
                "confidence_score": confidence,
                "threshold": self.confidence_threshold,
                "process_id": pid,
                "user": str(user),
                "os_type": os_type,
                "technique": tech,
                "mitre_id": mitre_id,
                "simulated_commands": simulated_cmds,
                "plain_english_explanation": explanation
            }
            self._write_log(log_entry)

        else:
            reason = "Verdict not malicious" if not is_malicious else f"Confidence {confidence:.2f} < threshold {self.confidence_threshold:.2f}"
            print(f"[-] EDR Active Response Skipped: {reason} (Verdict: '{verdict_str}', Conf: {confidence:.2f})")
            response_summary["reason_skipped"] = reason

        return response_summary

    def _write_log(self, entry: Dict[str, Any]):
        """Appends structured JSON log line to mitigations log."""
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"[!] Warning: Failed to write to {self.log_path}: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="EDR Active Response Simulator for LLM Explainer Dossiers")
    parser.add_argument("--input", "-i", help="Path to input JSON dossier file (or pass JSON via stdin)")
    parser.add_argument("--json", "-j", help="Raw JSON dossier string")
    parser.add_argument("--log-file", default="data/edr_mitigations.log", help="Path to mitigations log file")
    parser.add_argument("--threshold", type=float, default=0.80, help="Confidence threshold to trigger containment (default: 0.80)")
    parser.add_argument("--test", action="store_true", help="Run self-test with simulated malicious and sub-threshold payloads")

    args = parser.parse_args()
    engine = EDRActiveResponse(log_path=args.log_file, confidence_threshold=args.threshold)

    if args.test:
        print("[*] Running EDR Active Response Engine Self-Test...")

        # Test Case 1: High-confidence Malicious GTFOBin
        malicious_dossier = {
            "event_id": "test-evt-001",
            "verdict": "Malicious - PrivEsc/LOLBin",
            "attributed_technique": "Sudo GTFOBins Privilege Escalation (find -exec)",
            "mitre_id": "T1548.003",
            "confidence_score": 0.95,
            "process_id": 18452,
            "user": "compromised_admin",
            "os_type": "linux",
            "plain_english_explanation": "User executed find with sudo and spawned an interactive root subshell."
        }
        print("\n--- Test Case 1: Malicious GTFOBin (Confidence = 0.95) ---")
        engine.evaluate_and_respond(malicious_dossier)

        # Test Case 2: Sub-threshold Suspicious Activity
        subthreshold_dossier = {
            "event_id": "test-evt-002",
            "verdict": "Suspicious",
            "attributed_technique": "Sub-threshold Reconnaissance",
            "mitre_id": "T1033",
            "confidence_score": 0.65,
            "process_id": 18490,
            "user": "developer",
            "os_type": "linux",
            "plain_english_explanation": "Execution of whoami in isolated session with mild deviation."
        }
        print("\n--- Test Case 2: Suspicious Activity Below Threshold (Confidence = 0.65) ---")
        engine.evaluate_and_respond(subthreshold_dossier)

        # Test Case 3: Windows Malicious LOLBin
        win_dossier = {
            "event_id": "test-evt-003",
            "verdict": "Malicious - PrivEsc/LOLBin",
            "attributed_technique": "Certutil Ingress Tool Transfer",
            "mitre_id": "T1105",
            "confidence_score": 0.92,
            "process_id": 6124,
            "user": "CORP\\attacker",
            "os_type": "windows",
            "plain_english_explanation": "Certutil downloaded external binary payload into Public directory."
        }
        print("\n--- Test Case 3: Windows Malicious LOLBin (Confidence = 0.92) ---")
        engine.evaluate_and_respond(win_dossier)
        return

    # Ingest payload from args or stdin
    payload_str = ""
    if args.json:
        payload_str = args.json
    elif args.input:
        with open(args.input, "r", encoding="utf-8") as f:
            payload_str = f.read()
    elif not sys.stdin.isatty():
        payload_str = sys.stdin.read()
    else:
        print("[!] No input provided. Use --input, --json, --test, or pipe JSON via stdin.", file=sys.stderr)
        sys.exit(1)

    try:
        data = json.loads(payload_str)
        engine.evaluate_and_respond(data)
    except json.JSONDecodeError as e:
        print(f"[!] Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
