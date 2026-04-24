# Microsoft Sentinel SIEM Lab
**Sanskar Lohani** | April 2026

---

# IR-003 — Discovery: Suspicious DNS Query

| Field | Detail |
|-------|--------|
| **Incident ID** | 130 |
| **Detection Rule** | Discovery - Suspicious DNS Query |
| **MITRE Technique** | T1071.004 |
| **Technique Name** | Application Layer Protocol: DNS |
| **MITRE Tactic** | Command and Control |
| **Severity** | Medium |
| **Status** | Active |
| **Time Generated (UTC)** | 2026-04-24 00:58:26 |
| **First Activity (UTC)** | 2026-04-23 23:53:16 |
| **Last Activity (UTC)** | 2026-04-24 02:23:01 |
| **Impacted Asset** | sentinel-vm |
| **Alerts Grouped** | 7 |

---

## Timeline

| Time (UTC) | Event |
|------------|-------|
| 23:53:16 | First DNS Client Operational events ingested from sentinel-vm into Sentinel following DCR configuration update |
| 00:51:41 | Download cradle `IEX(New-Object Net.WebClient).DownloadString` targeting `raw.githubusercontent.com` executed on sentinel-vm (IR-001) |
| 04:52:17 | DNS query issued for `pastebin.com` from sentinel-vm — resolved to 104.20.29.150 and 172.66.171.73 |
| 04:52:17 | DNS query issued for `raw.githubusercontent.com` from sentinel-vm — resolved to 185.199.108-111.133 |
| 04:52:17 | DNS query issued for `github.com` from sentinel-vm |
| 00:58:26 | Sentinel analytics rule fired — incident created, 7 alerts grouped across activity window |

---

## Investigation Steps

**Step 1 — Triage and domain reputation assessment**
7 alerts grouped indicating repeated suspicious DNS activity across the monitored window. Domains flagged: `pastebin.com`, `raw.githubusercontent.com`, `github.com`. All three are legitimate services frequently abused by attackers for payload hosting and C2 communication — their trusted reputation allows them to bypass domain reputation filters at the network layer.

**Step 2 — DNS to process correlation**
Cross-referenced DNS query timestamps at 04:52 UTC with EventID 4104 from IR-001. Download cradle referencing `raw.githubusercontent.com` executed at 00:51:41 UTC — DNS resolution at 04:52:17 UTC confirms active network communication attempt following in-memory execution attempt.

**Step 3 — Firewall log correlation**
Queried `AzureDiagnostics` for `AzureFirewallNetworkRule` events. Confirmed 56 network rule hits from 10.0.0.5 during the simulation window including TCP connections on multiple ports. Firewall logs corroborate that DNS resolution was followed by actual outbound connection attempts through the network layer.

**Step 4 — C2 pattern assessment**
DNS query sequence — `pastebin.com` followed by `raw.githubusercontent.com` during an active PowerShell execution session — is consistent with T1071.004 DNS-based application layer protocol abuse for payload retrieval or C2 communication.

**Step 5 — Broader DNS activity review**
Queried full DNS Client log for simulation window. Confirmed queries limited to the three identified domains with no additional unexpected external resolutions detected.

---

## Findings

sentinel-vm issued DNS queries to `pastebin.com`, `raw.githubusercontent.com`, and `github.com` at 04:52:17 UTC on 2026-04-24, immediately following encoded PowerShell execution detected in IR-001. The query sequence is consistent with an attacker attempting to retrieve a second-stage payload from an external staging platform following successful initial execution. Azure Firewall network logs corroborate 56 outbound connection attempts from 10.0.0.5 during the same window, confirming DNS resolution preceded active network-layer communication. No exfiltration was confirmed but the behavioral pattern matches T1071.004 DNS-based application layer C2 protocol abuse.

---

## Response Actions

1. Identified and documented all suspicious domains queried during the incident window
2. Correlated DNS activity with PowerShell execution (IR-001) and firewall logs (Incident 132) to establish complete kill chain timeline
3. Confirmed DNS queries were part of authorized simulation — no actual payload retrieval occurred
4. **Production response:** Immediately block `pastebin.com` and `raw.githubusercontent.com` at the firewall and DNS layer, isolate sentinel-vm, capture full network traffic for forensic analysis, review proxy logs for HTTP connections to those domains, escalate to Tier 2 for memory forensics given confirmed in-memory execution attempt

---

## Lessons Learned

DNS logging via the Windows DNS Client Operational channel provides visibility into C2 communication attempts that endpoint detection alone cannot surface. A process creating a network connection does not always generate a Security event — but it always generates a DNS query first. Correlating DNS logs with PowerShell script block logs (IR-001) and Azure Firewall network rule logs (Incident 132) across three separate data sources produced a complete attack chain reconstruction that would be impossible from any single log source alone. In production, DNS sinkholing for known malicious domains and automated DNS query frequency analysis would reduce attacker dwell time significantly.
