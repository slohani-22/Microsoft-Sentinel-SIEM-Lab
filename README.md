# Microsoft Sentinel SIEM Lab

A hands-on cloud security operations lab built on Microsoft Azure, demonstrating real-world SIEM deployment, threat detection engineering, and automated incident response using Microsoft Sentinel.

## Overview

This lab simulates a functional Security Operations Center (SOC) environment with multi-source log ingestion, custom KQL detection rules, threat intelligence integration, and SOAR automation. All components were deployed and configured manually to demonstrate practical cybersecurity engineering skills.

## Architecture

**Cloud Platform:** Microsoft Azure (Personal Tenant — Full Admin Access)

**Core Components:**
- Microsoft Sentinel (SIEM + SOAR)
- Log Analytics Workspace (sentinel-law-prodd, Canada Central)
- Windows Server 2022 VM (sentinel-vm, Canada Central)
- Azure Monitor Agent with Data Collection Rule
- Logic Apps Playbook (Automated Incident Response)

## Data Sources

| Connector | Data Type | Purpose |
|-----------|-----------|---------|
| Azure Activity | AzureActivity | Cloud control plane monitoring |
| Microsoft Entra ID | SigninLogs, AuditLogs | Identity and access monitoring |
| Microsoft Defender for Cloud | Security alerts | Workload threat protection |
| Windows Security Events | SecurityEvent | Endpoint event monitoring |
| Microsoft Defender XDR | XDR signals | Extended detection and response |

## Detection Rules

8 custom KQL analytics rules deployed across multiple severity levels:

| Rule | Severity | Data Source | MITRE Tactic |
|------|----------|-------------|--------------|
| Multiple Failed Login Attempts | Medium | SecurityEvent | Credential Access |
| Azure Resource Deletion Detected | High | AzureActivity | Impact |
| Privileged Role Assignment Detected | High | AuditLogs | Privilege Escalation |
| Suspicious Sign-in From Unknown Location | High | SigninLogs | Initial Access |
| New User Account Created Outside Business Hours | Medium | SecurityEvent | Persistence |
| High Volume Azure Activity From Single IP | Medium | AzureActivity | Discovery |
| Entra ID Account Locked Out | Medium | SigninLogs | Credential Access |
| Malicious IP Detected in Logs | High | SecurityEvent + Watchlist | Command and Control |

## Threat Intelligence

A custom watchlist (MaliciousIPs) containing 10 known malicious IP addresses sourced from public threat feeds including Tor exit nodes, malware C2 servers, known scanners, and botnet infrastructure. Detection rules cross-reference live log data against this watchlist in real time to enrich alerts with threat context.

## SOAR Automation

A Logic Apps playbook (sentinel-incident-response) triggers automatically on high severity incidents and sends email notifications containing:
- Incident title and severity
- Incident status and description
- Time of creation

This automates Tier 1 triage notification, reducing mean time to respond for high priority alerts.

## Attack Simulation

Realistic attack scenarios were simulated using PowerShell to generate real Windows Security Events:
- Brute force login attempts (EventID 4625)
- Suspicious user account creation (EventID 4720)
- Privilege escalation via local admin group addition (EventID 4728)
- Suspicious file creation in system directories

Simulation script available in `/attack-simulation/attack_simulation.ps1`

## Results

- 79 incidents generated from custom detection rules
- Multiple rule types fired including brute force, resource deletion, and after-hours account creation
- Automated email alerts delivered via Logic Apps playbook
- 18 distinct Windows Security Event IDs captured from endpoint telemetry

## Skills Demonstrated

- Microsoft Sentinel deployment and configuration
- Multi-source log ingestion and connector management
- KQL (Kusto Query Language) detection rule authoring
- Threat intelligence integration via watchlists
- SOAR playbook development using Logic Apps
- Azure Monitor Agent deployment and Data Collection Rule configuration
- Incident investigation and triage workflows
- Attack simulation and detection validation

## Screenshots

| Screenshot | Description |
|------------|-------------|
| data_connectors.png | 11/11 data connectors connected |
| Analyticsrules.png | 8 custom detection rules active |
| Incidents.png | 79 incidents generated |
| Incident-New user created.png | Incident detail view |
| Security_events.png | Windows Security Event IDs captured |
| Azureactivitylogs.png | Azure Activity logs flowing |
| Heartbeatlogs.png | AMA heartbeat confirmed |
| watchlist.png | MaliciousIPs threat intelligence watchlist |
| Logicapp_playbooks.png | Logic App playbook designer |
| Playbook.png | Automated email alert received |

## Repository Structure
Microsoft-Sentinel-SIEM-Lab/
├── README.md
├── kql-detection-rules/       # 8 custom KQL detection rules
├── threat-intelligence/       # Malicious IP watchlist CSV
├── attack-simulation/         # PowerShell attack simulation script
└── Screenshots/               # Lab evidence and results

## Author

**Sanskar Lohani**
MS Cybersecurity — Florida International University
[LinkedIn](https://linkedin.com/in/slohani22) | [GitHub](https://github.com/slohani-22)

**Certifications:** CompTIA Security+ (SY0-701) | Microsoft AZ-500