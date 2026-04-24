# False Positive Analysis
## Microsoft Sentinel SIEM Lab — slohani-22

**Author:** Sanskar Lohani  
**Last Updated:** April 2026  
**Rules Analyzed:** Rule 11 (PowerShell Suspicious Commands), Rule 13 (Data Staging in Temp Directory)

---

## Overview

False positive analysis is a critical component of detection engineering. Every detection rule
represents a tradeoff between sensitivity (catching real attacks) and specificity (avoiding noise).
This document analyzes the two rules most likely to generate false positives in this lab environment,
explains the threshold rationale, and documents production tuning approaches.

---

## Rule 11 — Execution - PowerShell Suspicious Commands

### Rule Summary

**EventID:** 4104 (PowerShell Script Block Logging)  
**Table:** Event (Microsoft-Windows-PowerShell/Operational)  
**Detection Logic:** Flags PowerShell script blocks containing encoded commands (-EncodedCommand,
FromBase64String), download cradles (DownloadString, DownloadFile, IEX, Invoke-Expression,
Net.WebClient, Invoke-WebRequest), or common living-off-the-land keywords.  
**Severity:** High  
**MITRE:** T1059.001, T1027

### False Positive Scenario

**Scenario:** Legitimate IT administrator scripts that use Invoke-WebRequest for software deployment,
patch management, or configuration management will trigger this rule. Common examples include:

- SCCM/Intune deployment scripts that download installers via Invoke-WebRequest
- PowerShell DSC configurations that pull modules from internal repositories
- Automated patching scripts that use DownloadFile to retrieve update packages
- Monitoring agents that use WebClient to phone home to management servers

**Example legitimate command that triggers the rule:**
```powershell
Invoke-WebRequest -Uri "https://internal-repo/agent-v2.msi" -OutFile "C:\Temp\agent.msi"
```

This is functionally identical to an attacker download cradle from the rule's perspective.

### Threshold Rationale

The current rule uses `has_any` matching against a broad keyword list without allowlisting.
This was intentional for the lab environment to maximize detection coverage during the
kill chain simulation. In a production environment this would generate significant noise
on any system where administrators run deployment scripts.

### Production Tuning Approach

**Option 1 — Host-based allowlist:**
```kql
Event
| where EventID == 4104
| where RenderedDescription has_any (
    "EncodedCommand", "-enc ", "FromBase64String",
    "DownloadString", "DownloadFile", "IEX",
    "Invoke-Expression", "WebClient", "Net.WebClient",
    "Invoke-WebRequest"
  )
| where Computer !in ("known-admin-host-1", "known-admin-host-2", "sccm-server")
| project TimeGenerated, Computer, RenderedDescription
```

**Option 2 — ScriptBlock hash allowlist:**
Approved scripts should be identified by their ScriptBlock hash rather than content,
making the allowlist manipulation-resistant. Generate hashes for approved scripts and
add them to a Sentinel watchlist named `ApprovedScriptHashes`, then filter:
```kql
| where not(ScriptBlockId in (ApprovedScriptHashes))
```

**Option 3 — Combine with process parent context:**
Legitimate admin scripts typically run from known parent processes (SCCM client,
scheduled task service). Adding parent process context from correlated 4688 events
reduces false positives significantly.

**Recommended threshold change for production:**
Add `| where Computer !in ("known-admin-hosts")` as an immediate noise reduction measure
while building the ScriptBlock hash allowlist over 30 days of baseline observation.

---

## Rule 13 — Collection - Data Staging in Temp Directory

### Rule Summary

**EventID:** 4663 (An attempt was made to access an object)  
**Table:** SecurityEvent  
**Detection Logic:** Counts file write operations (AccessMask 0x2) in temp directories within
5-minute windows. Fires when FileOperationCount exceeds 10 in a single window for a single account.  
**Severity:** Medium  
**MITRE:** T1074.001

### False Positive Scenario

**Scenario:** Legitimate software installers, Windows Update, and application update processes
frequently write large numbers of temporary files during installation. A threshold of 10 file
operations in 5 minutes is easily exceeded by:

- Windows Update downloading and extracting patch files to C:\Windows\Temp
- Software installers (Adobe, Office, Chrome) extracting to temp during installation
- Antivirus definition updates writing temporary files during update process
- Build systems or CI/CD agents writing compilation artifacts to temp directories
- Log rotation processes that create multiple log file segments

**Example:** A Windows Update session for a cumulative patch can generate 50-200 file
operations in C:\Windows\Temp within a 5-minute window, far exceeding the threshold of 10.

### Threshold Rationale

The threshold of 10 file operations in 5 minutes was chosen for the lab environment
to ensure the simulation (which created 15 files with 200ms intervals between each)
would trigger the rule reliably. In a production environment this threshold is too low
and would generate multiple false positives daily on any actively maintained system.

### Production Tuning Approach

**Option 1 — Raise threshold and exclude machine accounts:**
```kql
SecurityEvent
| where EventID == 4663
| where ObjectName has_any ("\\Temp\\", "\\tmp\\", "\\AppData\\Local\\Temp\\")
| where AccessMask == "0x2"
| summarize FileOperationCount = count(),
            FileList = make_set(ObjectName, 20)
  by Account, Computer, bin(TimeGenerated, 5m)
| where FileOperationCount > 50
| where Account !endswith "$"
| where Account !in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
```

Key changes from lab version:
- Threshold raised from 10 to 50 — eliminates most installer false positives
- `Account !endswith "$"` excludes machine accounts (COMPUTERNAME$) running Windows Update
- Explicit exclusion of built-in service accounts

**Option 2 — Process context correlation:**
Correlate 4663 events with 4688 (process creation) to identify which process is creating
the files. Known-safe processes (TrustedInstaller, MsiExec, wuauclt) can be excluded:
```kql
| where InitiatingProcess !in ("TrustedInstaller.exe", "msiexec.exe", "wuauclt.exe")
```

**Option 3 — Behavioral baseline:**
Establish a 30-day baseline of normal temp file operation volumes per host and per account.
Use dynamic thresholds (mean + 3 standard deviations) rather than a fixed count threshold.
This adapts to each host's normal behavior automatically.

**Recommended immediate production change:**
Raise threshold to 50 and add `| where Account !endswith "$"` as the minimum viable
tuning before deploying to production. Full baseline-based dynamic thresholds should
follow after 30 days of observation data.

---

## Summary Table

| Rule | Current Threshold | Recommended Production Threshold | Primary FP Source | Tuning Method |
|------|------------------|----------------------------------|-------------------|---------------|
| Rule 11 — PowerShell Suspicious Commands | No threshold — keyword match only | Add host allowlist + ScriptBlock hash allowlist | Admin deployment scripts using Invoke-WebRequest | Host-based exclusion list; ScriptBlock hash allowlist |
| Rule 13 — Data Staging in Temp Directory | FileOperationCount > 10 | FileOperationCount > 50 + exclude machine accounts | Windows Update, software installers | Raise threshold; exclude machine accounts; dynamic baseline |

---

## Detection Engineering Principles Applied

These tuning decisions reflect three core detection engineering principles:

**1. Threshold calibration over time:** Initial thresholds should be aggressive during
development to catch simulated attacks. Production thresholds require 30+ days of baseline
data to set correctly. Deploying lab-grade thresholds to production is a common source of
alert fatigue.

**2. Context enrichment reduces false positives:** Adding process, account, and host context
to raw event-based detections dramatically improves precision without sacrificing recall.
A file write in temp by msiexec.exe is categorically different from the same operation by
powershell.exe.

**3. Allowlisting over blocklisting:** Maintaining an allowlist of known-safe behavior is
more maintainable than trying to enumerate all malicious patterns. The ScriptBlock hash
approach for Rule 11 is more robust than trying to add every legitimate script keyword
to an exclusion list.
