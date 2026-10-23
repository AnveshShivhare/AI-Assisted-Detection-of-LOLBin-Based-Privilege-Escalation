#!/usr/bin/env bash
# ==============================================================================
# SCRIPT: benign_baseline.sh
# PURPOSE: Linux Benign Telemetry Baseline Generator for Isolated Lab VMs
#
# [SAFETY NOTICE & WORKSPACE INVARIANT]:
# DO NOT EXECUTE DIRECTLY ON HOST MACHINES.
# THIS SCRIPT IS STRICTLY AN ARTIFACT INTENDED FOR EXPORT AND EXECUTION INSIDE
# AN ISOLATED, NON-NETWORKED LAB VIRTUAL MACHINE (e.g. Ubuntu / Debian VM).
# ==============================================================================

set -euo pipefail

echo "[*] Starting Linux Benign Activity Simulation for Telemetry Collection..."
echo "[*] Target: Generate normal administrative, developer, and cron workload."

LOG_DIR="/tmp/benign_lab_logs"
mkdir -p "$LOG_DIR"

# 1. System Maintenance & Package Queries
echo "[1/5] Simulating system queries & package management..."
uptime
df -h
free -m
uname -a
cat /etc/os-release
cat /etc/hosts
cat /etc/resolv.conf
dpkg -l | head -n 30 > "$LOG_DIR/packages.txt" || true
apt-get check || true

# 2. Process & Network Inspection
echo "[2/5] Simulating network and process monitoring..."
ps aux | head -n 25 > "$LOG_DIR/ps_snapshot.txt"
top -b -n 1 | head -n 20 > "$LOG_DIR/top_snapshot.txt"
ss -tulpn || netstat -tulpn || true
ip a

# 3. Developer Workflow Simulation
echo "[3/5] Simulating developer git and python workflows..."
DEV_DIR="/tmp/dev_project_baseline"
mkdir -p "$DEV_DIR"
cd "$DEV_DIR"
git init -q || true
echo "print('EDR Benign Baseline Telemetry Event')" > main.py
echo "import unittest" >> main.py
python3 -m py_compile main.py
python3 -m unittest discover || true
git add main.py
git commit -m "chore: test baseline commit" -q || true
git status --porcelain
cd - > /dev/null

# 4. Standard File & Archival Operations
echo "[4/5] Simulating archival and search operations..."
tar -czf "$LOG_DIR/sample_archive.tar.gz" -C "$DEV_DIR" .
grep -rn "EDR" "$DEV_DIR" || true
find /var/log -type f -name "*.log" -mtime +1 2>/dev/null | head -n 10 || true

# 5. Scheduled Job Emulation
echo "[5/5] Emulating regular maintenance cron jobs..."
logger -t LAB_BASELINE "Routine system telemetry health-check completed successfully."

echo "[+] Benign baseline simulation finished. Telemetry captured in auditd/Wazuh."
