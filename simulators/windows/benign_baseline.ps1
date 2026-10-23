<#
==============================================================================
SCRIPT: benign_baseline.ps1
PURPOSE: Windows Benign Telemetry Baseline Generator for Isolated Lab VMs

[SAFETY NOTICE & WORKSPACE INVARIANT]:
DO NOT EXECUTE DIRECTLY ON HOST MACHINES.
THIS SCRIPT IS STRICTLY AN ARTIFACT INTENDED FOR EXPORT AND EXECUTION INSIDE
AN ISOLATED, NON-NETWORKED WINDOWS LAB VIRTUAL MACHINE (with Sysmon + Wazuh Agent).
==============================================================================
#>

Write-Host "[*] Starting Windows Benign Activity Simulation for Telemetry Collection..."
$LabTemp = "$env:TEMP\LabBenign"
New-Item -ItemType Directory -Path $LabTemp -Force | Out-Null

# 1. Standard System & Service Health Queries
Write-Host "[1/4] Running regular PowerShell system checks..."
Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object -First 15
Get-Process | Select-Object -First 15
Get-Date
systeminfo | Select-String "OS Name", "OS Version"

# 2. Network Interface & Connectivity Verification
Write-Host "[2/4] Simulating network configuration checks..."
ipconfig /all
netstat -ano | Select-Object -First 10
ping -n 2 127.0.0.1

# 3. Administrative File Management Workflows
Write-Host "[3/4] Simulating normal user and admin file operations..."
$docPath = "$LabTemp\notes.txt"
"Routine system administrative log entry $(Get-Date)" | Out-File -FilePath $docPath
Get-ChildItem -Path $env:USERPROFILE\Documents -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10

# 4. Standard WMI System Queries
Write-Host "[4/4] Simulating benign WMI administrative calls..."
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, LastBootUpTime

Write-Host "[+] Benign Windows baseline simulation completed."
