# MITRE ATT&CK Coverage Matrix
## Microsoft Sentinel SIEM Lab — slohani-22

**Total Rules:** 16 custom KQL analytics rules  
**Lab Environment:** Microsoft Azure — Canada Central  
**Author:** Sanskar Lohani  
**Last Updated:** April 2026

---

## Coverage Summary

| Tactic | Rules Covering |
|--------|---------------|
| Initial Access | 2 |
| Execution | 2 |
| Persistence | 3 |
| Privilege Escalation | 2 |
| Defense Evasion | 1 |
| Credential Access | 2 |
| Discovery | 2 |
| Lateral Movement | 1 |
| Collection | 1 |
| Command and Control | 3 |
| Impact | 1 |

---

## Full Rule Matrix

| Rule # | Rule Name | Severity | MITRE Technique ID | Technique Name | Tactic | Data Source | EventID / Table |
|--------|-----------|----------|--------------------|----------------|--------|-------------|-----------------|
| 1 | Multiple Failed Login Attempts | Medium | T1110 | Brute Force | Credential Access | Windows Security Events | 4625 |
| 2 | Azure Resource Deletion Detected | High | T1485 | Data Destruction | Impact | Azure Activity Logs | AzureActivity |
| 3 | Privileged Role Assignment Detected | High | T1078.004 | Valid Accounts: Cloud Accounts | Privilege Escalation, Persistence | Entra ID Audit Logs | AuditLogs |
| 4 | Suspicious Sign-in From Unknown Location | High | T1078 | Valid Accounts | Initial Access | Entra ID Sign-in Logs | SigninLogs |
| 5 | New User Account Created Outside Business Hours | Medium | T1136 | Create Account | Persistence | Windows Security Events | 4720 |
| 6 | High Volume Azure Activity From Single IP | Medium | T1078.004 | Valid Accounts: Cloud Accounts | Credential Access | Azure Activity Logs | AzureActivity |
| 7 | Entra ID Account Locked Out | Medium | T1110 | Brute Force | Credential Access | Entra ID Audit Logs | AuditLogs |
| 8 | Malicious IP Detected in Logs | High | T1071 | Application Layer Protocol | Command and Control | Multiple | MaliciousIPs Watchlist |
| 9 | Suspicious Process Creation | High | T1059.001 | Command and Scripting Interpreter: PowerShell | Execution | Windows Security Events | 4688 |
| 10 | Persistence - Scheduled Task Created | Medium | T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence, Privilege Escalation | Windows Security Events | 4698 |
| 11 | Execution - PowerShell Suspicious Commands | High | T1059.001, T1027 | PowerShell / Obfuscated Files or Information | Execution, Defense Evasion | PowerShell Operational | 4104 |
| 12 | Lateral Movement - Explicit Credential Use | High | T1550.002, T1078 | Use Alternate Authentication Material / Valid Accounts | Lateral Movement, Privilege Escalation | Windows Security Events | 4648 |
| 13 | Collection - Data Staging in Temp Directory | Medium | T1074.001 | Data Staged: Local Data Staging | Collection | Windows Security Events | 4663 |
| 14 | Network - Suspicious Outbound Connection | Medium | T1071 | Application Layer Protocol | Command and Control | VNet Flow Logs | AzureNetworkAnalytics_CL |
| 15 | Discovery - Suspicious DNS Query | Medium | T1071.004 | Application Layer Protocol: DNS | Command and Control | DNS Client Operational | Event (DNS-Client) |
| 16 | Network - Azure Firewall Rule Hit | Medium | T1071 | Application Layer Protocol | Command and Control | Azure Firewall Diagnostics | AzureDiagnostics |

---

## Kill Chain Coverage Map

The following table shows which rules fired during the 8-stage kill chain simulation:

| Stage | MITRE Technique | Simulation Activity | Rule Fired | Incident ID |
|-------|----------------|---------------------|------------|-------------|
| 1 — Initial Access | T1110 | 10 failed login attempts | Rule 1 (pre-existing) | N/A — EventID 4625 did not fire via Run Command SYSTEM context |
| 2 — Execution | T1059.001, T1027 | Encoded PowerShell + download cradle | Rule 11 | Incident 131 |
| 3 — Persistence | T1136 | Backdoor account created | Rule 5 (pre-existing) | N/A — EventID 4720 did not fire via Run Command SYSTEM context |
| 4 — Persistence | T1053.005 | Scheduled task WindowsUpdateService | Rule 10 | Incident 133 |
| 5 — Privilege Escalation | T1134 | Token/identity enumeration | No dedicated rule — whoami/priv generates 4688 caught by Rule 9 | — |
| 6 — Discovery | T1087 | net user, whoami /all, Get-LocalUser | Rule 9 | Contributing to Incident 131 |
| 7 — Collection | T1074.001 | 15 files staged in C:\Windows\Temp\svc_cache | Rule 13 | N/A — threshold not reached in window |
| 7 — Command and Control | T1071.004 | DNS queries to pastebin.com, raw.githubusercontent.com | Rule 15 | Incident 130 |
| 7 — Network | T1071 | Outbound connections through Azure Firewall | Rule 16 | Incident 132 |
| 8 — Defense Evasion | T1070 | Artifact cleanup | No dedicated rule | — |

---

## Detection Gap Analysis

| Gap | Reason | Production Mitigation |
|-----|--------|----------------------|
| T1110 brute force not detected from simulation | Run Command executes as SYSTEM — local auth failures do not generate 4625 in non-interactive sessions | Run simulation via interactive RDP session; deploy Windows Defender Credential Guard |
| T1136 account creation not detected from simulation | Same SYSTEM context limitation for 4720 | Interactive session required; supplement with Entra ID audit logs for cloud account creation |
| T1074.001 data staging threshold not reached | FileOperationCount threshold set to 10 — simulation window too short to hit threshold consistently | Lower threshold to 5 for high-value hosts; add directory monitoring via Sysmon |
| T1134 token manipulation no dedicated rule | Token abuse detection requires Sysmon or EDR telemetry beyond basic Windows audit events | Deploy Sysmon with SwiftOnSecurity config; add Rule for EventID 4673/4674 |
| AzureNetworkAnalytics_CL table unpopulated | Traffic Analytics did not populate table within lab window — first data push requires sustained traffic | Production deployment with continuous VM traffic resolves this within 20-60 minutes |

---

## Notes

- Rule 14 (Network - Suspicious Outbound Connection) query is written and saved but inactive pending AzureNetworkAnalytics_CL table population. See Architecture Limitations.
- Rules 1-8 were created during initial lab setup phase. Rules 9-16 were added as part of the lab expansion.
- All rules are scheduled query rules running every 5-15 minutes with 1-hour lookback windows.
- MITRE technique IDs follow ATT&CK Enterprise Matrix v14.
