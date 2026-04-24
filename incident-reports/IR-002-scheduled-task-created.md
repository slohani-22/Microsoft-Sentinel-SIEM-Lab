# Microsoft Sentinel SIEM Lab
**Sanskar Lohani** | April 2026

---

# IR-002 — Persistence: Scheduled Task Created

| Field | Detail |
|-------|--------|
| **Incident ID** | 133 |
| **Detection Rule** | Persistence - Scheduled Task Created |
| **MITRE Technique** | T1053.005 |
| **Technique Name** | Scheduled Task/Job: Scheduled Task |
| **MITRE Tactic** | Persistence, Privilege Escalation |
| **Severity** | Medium |
| **Status** | Active |
| **Time Generated (UTC)** | 2026-04-24 01:25:16 |
| **First Activity (UTC)** | 2026-04-24 01:15:12 |
| **Last Activity (UTC)** | 2026-04-24 01:15:12 |
| **Impacted Asset** | sentinel-vm |
| **Alerts Grouped** | 1 |

---

## Timeline

| Time (UTC) | Event |
|------------|-------|
| 00:51:24 | PowerShell execution session begins on sentinel-vm (Incident 131 — IR-001) |
| 01:15:12 | EventID 4698 generated — account `sentineladmin` created scheduled task `\WindowsUpdateService` via PowerShell PID 3860 (Parent PID 852) |
| 01:15:12 | Task configured: `powershell.exe -NonInteractive -WindowStyle Hidden`, Hidden=true, BootTrigger, RunLevel=HighestAvailable |
| 01:25:16 | Sentinel analytics rule fired — incident created |

---

## Investigation Steps

**Step 1 — Triage and scope confirmation**
Single alert, medium severity, impacting sentinel-vm only. EventID 4698 is a high-fidelity indicator — scheduled task creation by end users is rare in production environments and almost always warrants investigation.

**Step 2 — Task configuration analysis**
Retrieved full EventData XML from SecurityEvent table. Task analysis revealed four red flags:
- Task name `WindowsUpdateService` mimics a legitimate Windows service name for camouflage
- `Hidden: true` prevents the task from appearing in Task Scheduler UI
- `BootTrigger` ensures persistence survives reboots
- `HighestAvailable` run level grants elevated execution context

**Step 3 — Creating account and process identification**
`SubjectUserName: sentineladmin`. `ClientProcessId: 3860` with `ParentProcessId: 852` — confirming creation via PowerShell session, consistent with the execution stage detected in IR-001 approximately 24 minutes earlier.

**Step 4 — Kill chain correlation**
Scheduled task creation at 01:15 UTC follows PowerShell execution at 00:51 UTC — consistent with an attacker establishing persistence after successful initial execution. MITRE sequence: T1059.001 (Execution) → T1053.005 (Persistence).

**Step 5 — Persistence verification**
Confirmed via simulation output that task removal failed during automated cleanup (Stage 8), meaning `WindowsUpdateService` persisted on the system until manually removed via RDP. This demonstrates real persistence behavior — the task would survive a reboot.

---

## Findings

Account `sentineladmin` on sentinel-vm created hidden scheduled task `\WindowsUpdateService` at 01:15:12 UTC on 2026-04-24. The task was configured to execute a hidden PowerShell process at system boot with highest available privileges, providing reliable persistence across reboots. Task naming mimicking legitimate Windows services indicates deliberate camouflage intent. Process chain traces to an active PowerShell session consistent with the execution stage detected 24 minutes prior in IR-001.

---

## Response Actions

1. Identified and documented full task configuration from EventData XML including command, trigger type, hidden flag, and privilege level
2. Removed scheduled task manually via `Unregister-ScheduledTask -TaskName "WindowsUpdateService" -Confirm:$false`
3. Verified no additional persistence mechanisms created in parallel by querying EventID 4698 across full simulation window
4. **Production response:** Immediately disable the scheduled task, isolate the host, investigate the PowerShell session that created it, audit all other scheduled tasks on the host for similar naming patterns, review `sentineladmin` account for unauthorized activity

---

## Lessons Learned

Scheduled task creation auditing via EventID 4698 provides high-fidelity detection with low false positive rate in most environments. The full `TaskContent` field in EventData contains the complete XML task definition including command, arguments, trigger type, and hidden flag — making forensic reconstruction of attacker intent straightforward without additional tooling. In production, a CMDB baseline of approved scheduled tasks would allow this rule to suppress known-good tasks and surface only unauthorized creations.
