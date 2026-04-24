# Architecture Limitations and Future Extensions
## Microsoft Sentinel SIEM Lab — slohani-22

---

## Overview

This document records known limitations of the lab environment, the technical reasons behind each constraint, and what the production equivalent would look like. Documenting limitations honestly is a core SOC engineering skill — knowing what was not built and why is as important as knowing what was built.

---

## Limitation 1 — VNet Flow Logs Replaced NSG Flow Logs

**What was planned:** NSG flow logs to capture per-NIC network traffic.

**What happened:** Microsoft retired NSG flow log creation as of June 30, 2025. The Azure portal no longer allows creating new NSG flow logs.

**Impact:** None. VNet flow logs provide broader coverage than NSG flow logs — they capture all traffic at the virtual network level rather than per-NIC. Data schema and Traffic Analytics integration are identical.

**Production equivalent:** VNet flow logs are already the production standard and current Microsoft recommendation.

---

## Limitation 2 — AzureNetworkAnalytics_CL Table Unpopulated (Rule 14 Inactive)

**What was planned:** Rule 14 querying `AzureNetworkAnalytics_CL` to detect suspicious outbound connections from the VM.

**What happened:** Traffic Analytics was enabled with a 10-minute processing interval pointing to sentinel-law-prodd. The table was not created within the lab window. Traffic Analytics requires sustained network traffic during its initial processing window to create the table.

**Impact:** Rule 14 query is saved and syntactically correct but returns a table-not-found error. The rule will activate automatically once the table is populated.

**Production equivalent:** In a production environment with continuous VM network activity, `AzureNetworkAnalytics_CL` populates within 20-60 minutes of enablement.

---

## Limitation 3 — Azure Firewall Deployed for Simulation Window Only

**What was planned:** Azure Firewall as a permanent network-layer inspection component.

**What happened:** Firewall was successfully deployed, active during the kill chain simulation, captured 56 network rule hits, and deprovisioned after simulation to stop billing at $1.25/hour. Free trial public IP quota (3 max) also constrained permanent deployment.

**Impact:** Firewall logs from the simulation window persist in sentinel-law-prodd and are queryable via `AzureDiagnostics`. Rule 16 returns results. Ongoing monitoring not available post-simulation.

**Production equivalent:** Azure Firewall Premium tier with IDPS enabled, or a third-party NGFW (Palo Alto, Check Point, Fortinet) feeding CEF/Syslog logs into Sentinel via the Common Event Format connector.

---

## Limitation 4 — No Second VM for East-West Lateral Movement Detection

**What was planned (considered, rejected):** A second VM in the same VNet to simulate SMB/WinRM lateral movement.

**Why it was not built:** Two-day timeline. Adding a second VM required configuring AMA and a second DCR, ensuring VNet connectivity, updating the simulation script for VM-to-VM authentication, and debugging potential configuration issues. The marginal detection value did not justify the complexity risk within the timeline.

**Impact:** Lateral movement detection (Rule 12, EventID 4648) operates at the identity layer only — explicit credential use on a single machine. True east-west network lateral movement is not detectable in a single-VM configuration.

**Production equivalent:** Second VM in same VNet with AMA agent. EventID 4648 from VM1, corresponding 4624 on VM2, and VNet flow logs showing the SMB/WinRM connection at the network layer.

---

## Limitation 5 — EventIDs 4625, 4720 Not Generated from Kill Chain Simulation

**What was planned:** All 8 simulation stages generating expected EventIDs.

**What happened:** The kill chain script was executed via Azure Run Command, which runs PowerShell as NT AUTHORITY\SYSTEM in a non-interactive session. Windows does not generate certain authentication EventIDs in this context:

- **EventID 4625** (failed logon): Requires interactive authentication. SYSTEM cannot fail local authentication in the same way an interactive user session can.
- **EventID 4720** (user account created): `New-LocalUser` under SYSTEM on Windows Server 2022 does not consistently generate 4720 in non-interactive sessions.

Supplemental commands were run via interactive RDP session after simulation. EventID 4698 confirmed. EventIDs 4625 and 4720 still did not appear.

**Impact:** Stages 1 and 3 did not produce expected SecurityEvent entries. Four clean incidents still fired from Stages 2, 4, 7, and network activity.

**Production equivalent:** Run simulation from interactive RDP session or privileged user account. Deploy Sysmon with SwiftOnSecurity configuration for process telemetry independent of interactive session context.

---

## Limitation 6 — Geographic Sign-in Map Excluded from Workbook

**What was planned:** A geographic map visualization showing sign-in locations.

**Why it was not built:** Requires SigninLogs with populated Location fields. A personal Azure tenant with a single administrator account does not generate enough geographically diverse sign-in events for a meaningful map.

**Production equivalent:** Enterprise tenant with hundreds of users signing in from multiple locations enables immediate visual detection of impossible travel and anomalous sign-in geography.

---

## Limitation 7 — Splunk/QRadar Not Included

**Why it was not built:** Building a parallel Splunk lab within the two-day timeline would produce two incomplete projects rather than one complete one.

**Production note:** KQL and Splunk SPL follow identical detection logic patterns — field-based filtering, aggregation functions, and time-windowed lookups. The detection engineering methodology in this lab transfers directly to any SIEM platform with approximately 2-3 weeks of syntax familiarization.

---

## Summary

| Limitation | Severity | Status |
|-----------|----------|--------|
| NSG flow logs retired | None | Replaced with VNet flow logs — no functional impact |
| AzureNetworkAnalytics_CL unpopulated | Low | Rule 14 saved, auto-activates when table populates |
| Azure Firewall simulation-only | Medium | 56 hits captured, logs persist in workspace |
| No east-west lateral movement | Low | Identity-layer lateral movement detected via Rule 12 |
| EventIDs 4625/4720 missing | Medium | 4 clean incidents still generated from simulation |
| No geographic map | Low | Other 4 workbook visualizations complete |
| No Splunk parallel lab | Low | KQL-to-SPL transferability documented in README |
