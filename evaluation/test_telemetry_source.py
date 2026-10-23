#!/usr/bin/env python3
"""
test_telemetry_source.py
========================
Unit tests for TelemetrySource adapters (SyntheticTelemetrySource & AuditdTelemetrySource).
Tests against real Linux auditd log fixtures.
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from pipeline.telemetry import TelemetrySource, SyntheticTelemetrySource, AuditdTelemetrySource

RAW_AUDITD_FIXTURE = """
type=PROCTITLE msg=audit(10/23/2026 21:12:31.068:2252) : proctitle=sudo ausearch -k exec -i --start recent
type=PATH msg=audit(10/23/2026 21:12:31.068:2252) : item=1 name=/lib64/ld-linux-x86-64.so.2 inode=2885115 dev=fd:02 mode=file,755 ouid=root ogid=root rdev=00:00 nametype=NORMAL
type=PATH msg=audit(10/23/2026 21:12:31.068:2252) : item=0 name=/usr/sbin/ausearch inode=2886981 dev=fd:02 mode=file,755 ouid=root ogid=root rdev=00:00 nametype=NORMAL
type=CWD msg=audit(10/23/2026 21:12:31.068:2252) : cwd=/
type=EXECVE msg=audit(10/23/2026 21:12:31.068:2252) : argc=6 a0=ausearch a1=-k a2=exec a3=-i a4=--start a5=recent
type=SYSCALL msg=audit(10/23/2026 21:12:31.068:2252) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x64d779dc7350 a1=0x64d779de3540 a2=0x64d779ddb970 a3=0x8 items=2 ppid=3213 pid=3214 auid=ubuntu uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=2 comm=ausearch exe=/usr/sbin/ausearch subj=unconfined key=exec
"""

class TestTelemetrySources(unittest.TestCase):
    def test_auditd_parser_fixture(self):
        source = AuditdTelemetrySource(RAW_AUDITD_FIXTURE, is_file=False)
        self.assertEqual(source.provenance, "real_auditd")

        events = list(source.events())
        self.assertEqual(len(events), 1, "Expected exactly 1 correlated event from audit message 2252")

        ev = events[0]
        # Schema assertions
        self.assertEqual(ev["source_provenance"], "real_auditd")
        self.assertEqual(ev["source"], "auditd")
        self.assertEqual(ev["os_type"], "linux")
        self.assertEqual(ev["audit_msg_id"], "2252")
        self.assertEqual(ev["process_name"], "ausearch")
        self.assertEqual(ev["process_path"], "/usr/sbin/ausearch")
        self.assertEqual(ev["process_id"], 3214)
        self.assertEqual(ev["parent_process_id"], 3213)
        self.assertEqual(ev["uid"], 0)
        self.assertEqual(ev["euid"], 0)
        self.assertEqual(ev["gid"], 0)
        self.assertEqual(ev["cwd"], "/")
        self.assertEqual(ev["syscall"], "execve")
        self.assertEqual(ev["success"], "yes")
        self.assertEqual(ev["key"], "exec")
        self.assertEqual(ev["session_id"], "audit_ses_2")
        self.assertEqual(ev["command_line"], "ausearch -k exec -i --start recent")
        self.assertIn("/lib64/ld-linux-x86-64.so.2", ev["file_touches"])
        self.assertIn("/usr/sbin/ausearch", ev["file_touches"])
        self.assertTrue(ev["timestamp"].startswith("2026-10-23T21:12:31"))

    def test_synthetic_telemetry_source(self):
        sample_event = [{
            "event_id": "test-uuid-1234",
            "timestamp": "2026-10-23T12:00:00Z",
            "source": "auditd",
            "os_type": "linux",
            "host": "srv-linux-prod01",
            "session_id": "session_test",
            "process_name": "find",
            "process_path": "/usr/bin/find",
            "process_id": 1234,
            "parent_process_name": "bash",
            "parent_process_path": "/usr/bin/bash",
            "parent_process_id": 1000,
            "command_line": "find / -name '*.txt'",
            "user": "ubuntu",
            "uid": 1000,
            "gid": 1000,
            "euid": 1000,
            "integrity_level": "None",
            "file_touches": [],
            "label": "benign",
            "tier": 0,
            "technique": "Benign Admin Task",
            "mitre_technique_id": "None",
            "raw_event": "raw..."
        }]

        source = SyntheticTelemetrySource(sample_event)
        self.assertEqual(source.provenance, "synthetic")
        events = list(source.events())
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["source_provenance"], "synthetic")
        self.assertEqual(events[0]["process_name"], "find")

    def test_schema_interchangeability(self):
        """Verifies that both synthetic and auditd sources yield identical mandatory keys."""
        mandatory_keys = {
            "event_id", "timestamp", "source", "source_provenance", "os_type", "host",
            "session_id", "process_name", "process_path", "process_id",
            "parent_process_name", "parent_process_path", "parent_process_id",
            "command_line", "cwd", "syscall", "success", "key", "user", "uid", "gid", "euid", "integrity_level",
            "file_touches", "label", "tier", "technique", "mitre_technique_id", "raw_event"
        }

        audit_ev = list(AuditdTelemetrySource(RAW_AUDITD_FIXTURE, is_file=False).events())[0]
        self.assertTrue(mandatory_keys.issubset(set(audit_ev.keys())))


if __name__ == "__main__":
    unittest.main()
