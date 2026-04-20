# Microsoft Sentinel SIEM Lab - Attack Simulation Script
# Purpose: Generate realistic Windows Security Events for detection rule testing
# Author: Sanskar Lohani
# WARNING: Run only in lab environments. Never run on production systems.

Write-Host "Starting Attack Simulation..." -ForegroundColor Yellow

# Simulate 1: Brute Force - Multiple Failed Login Attempts (EventID 4625)
Write-Host "[*] Simulating brute force login attempts..." -ForegroundColor Cyan
$username = "fakeattacker"
1..10 | ForEach-Object {
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $ds = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine')
    $ds.ValidateCredentials($username, "wrongpassword123") | Out-Null
    Start-Sleep -Seconds 1
}
Write-Host "[+] Generated 10 failed login attempts" -ForegroundColor Green

# Simulate 2: New User Account Created Outside Business Hours (EventID 4720, 4728)
Write-Host "[*] Simulating suspicious user creation..." -ForegroundColor Cyan
net user suspectuser1 Password123! /add 2>$null
net localgroup Administrators suspectuser1 /add 2>$null
Write-Host "[+] Created suspicious user and added to Administrators" -ForegroundColor Green

# Simulate 3: Suspicious File Creation
Write-Host "[*] Simulating suspicious file creation..." -ForegroundColor Cyan
New-Item -Path "C:\Windows\Temp\suspicious.exe" -ItemType File -Force | Out-Null
New-Item -Path "C:\Windows\Temp\malware_test.bat" -ItemType File -Force | Out-Null
Write-Host "[+] Created suspicious files in Windows Temp" -ForegroundColor Green

# Simulate 4: Cleanup - Remove created artifacts
Write-Host "[*] Cleaning up simulation artifacts..." -ForegroundColor Cyan
Start-Sleep -Seconds 5
net user suspectuser1 /delete 2>$null
Remove-Item "C:\Windows\Temp\suspicious.exe" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Windows\Temp\malware_test.bat" -Force -ErrorAction SilentlyContinue
Write-Host "[+] Cleanup complete" -ForegroundColor Green

Write-Host "Attack simulation complete. Check Microsoft Sentinel Incidents in 10-15 minutes." -Fo