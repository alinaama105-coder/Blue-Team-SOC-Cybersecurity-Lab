SOC-001 — Windows Security Event Investigation Report
=====================================================

Case ID: SOC-001  
Case type: Endpoint authentication and privileged-logon review  
Investigation date: 27 October 2026  
Environment: Windows 11, local Windows Security event log  
Analyst role: SOC Tier 1 (portfolio exercise)  
Status: Core investigation documented; follow-up evidence review outstanding  
Severity: Informational — no malicious activity established

Executive summary
-----------------
This authorised, local endpoint investigation examined Windows Security Event IDs **4624 (successful logon)**, **4625 (failed logon)** and **4672 (special privileges assigned to a new logon)** using Event Viewer and PowerShell.

A reviewed Event ID 4624 showed a service logon by the built-in `NT AUTHORITY\SYSTEM` account (Logon Type 5, Logon ID `0x3E7`, elevated token). Event ID 4672 records involving SYSTEM were also observed. These observations are consistent with routine Windows activity, but the responsible service and the relationship between individual events were not independently confirmed.

An Event Viewer search for Event ID 4625 returned no matches but had additional Event Sources restrictions. A subsequent PowerShell query without those GUI restrictions returned `NoMatchingEventsFound` for Event ID 4625 in the retained Security log at the time of inspection. This is a bounded finding, not proof that failed logons never occurred.

**Outcome:** No evidence in the reviewed records was sufficient to establish a security incident or compromise. This was a learning and baseline investigation, not an alert-driven production incident.

Scope and authorisation
-----------------------
- **In scope:** Local Windows 11 Security log and commands executed on the investigator's own authorised endpoint.
- **Out of scope:** Other devices, third-party accounts, external networks, packet interception and production enterprise systems.
- **Evidence sources:** Windows Event Viewer screenshots, PowerShell screenshots and investigator-supplied command output.
- **Evidence limitation:** Screenshots and transcribed output are portfolio evidence; they are not a forensic acquisition or independently verified export of the full Security log.

Investigation timeline
----------------------
| Stage | Activity | Result |
| --- | --- | --- |
| Module 1.1 | Opened Event Viewer and established Security log baseline | Log accessible; retained audit events observed |
| Module 1.2 | Inspected and filtered Event ID 4672 | SYSTEM privileged-logon records observed |
| Module 1.3 | Investigated Event ID 4625 in Event Viewer | No matches in restricted GUI view; not treated as conclusive |
| Module 1.3 | Independently queried Event ID 4625 using PowerShell | `NoMatchingEventsFound` in retained Security log |
| Module 1.4 | Inspected Event ID 4624 | SYSTEM service logon (Type 5), Logon ID `0x3E7` |
| Module 1.5 | Queried recent events 4624, 4625 and 4672 | 4624 and 4672 present among latest 30 matching records |

Event findings
--------------

### Event ID 4624 — Successful logon

- **Observed time:** 27 October 2026, 12:35:22 (as documented in the module)
- **Account:** SYSTEM
- **Domain:** NT AUTHORITY
- **Logon Type:** 5 — Service
- **Logon ID:** `0x3E7`
- **Elevated token:** Yes
- **Assessment:** Consistent with a Windows service logon. The specific service or process was not verified; this record alone does not establish malicious activity.
- **Evidence:** [Module 01 — Section 1.4, screenshots](../README.md#module-14--successful-logon-investigation-4624)

### Event ID 4672 — Special privileges assigned to a new logon

- **Observed example time:** 27 October 2026, 14:36:01 (as documented in Module 1.2)
- **Account:** SYSTEM
- **Domain:** NT AUTHORITY
- **Logon ID:** `0x3E7`
- **Example privileges:** `SeAssignPrimaryTokenPrivilege`, `SeTcbPrivilege`, `SeSecurityPrivilege`
- **Assessment:** Consistent with privileged SYSTEM activity. A 4672 record does not by itself indicate compromise.
- **Correlation limitation:** The example 4624 and 4672 records have different reported timestamps. A shared account or Logon ID is insufficient by itself to claim a verified same-session correlation; event record details and chronology require review.
- **Evidence:** [Module 1.2 — Privileged Logon Investigation](../Module-01.2/README.md)

### Event ID 4625 — Failed logon

- **Initial Event Viewer result:** No matches in a view with additional Event Sources selections; this view was not an unrestricted search.
- **Independent PowerShell command:**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 10
```

- **Investigator-supplied output:** `No events were found that match the specified selection criteria.` / `NoMatchingEventsFound`.
- **Assessment:** No matching 4625 records were found in the retained local Security log at the time of the PowerShell query.
- **Limitations:** This does not prove that failed sign-ins never occurred, that all relevant audit policies were enabled, or that earlier records were retained. The final no-match output was provided as text and is not visible in the four verification screenshots.
- **Evidence:** [Module 1.3 — Failed Logon Investigation](../Module-01.3/README.md)

PowerShell investigation
------------------------

The following query retrieved the 30 most recent Security records matching the specified IDs:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625,4672} -MaxEvents 30
```

The captured results included Event IDs 4624 and 4672. Event ID 4625 did not appear in this limited sample; this sample alone would not support a whole-log conclusion. The separate Event ID 4625 query above was used for the independent verification.

![PowerShell Security event results](../03_Security_Event_Results_4624_4672.png)

![PowerShell command entered](../02_Get-WinEvent_Command_Entered.png)

Evidence index
--------------
- [Module 01 — Event Viewer baseline, 4624 and PowerShell walkthrough](../README.md)
- [Module 1.2 — Eight privileged-logon investigation screenshots](../Module-01.2/README.md)
- [Module 1.3 — Four failed-logon PowerShell verification screenshots](../Module-01.3/README.md)
- [Module 01 image evidence directory](../images/)

SOC Tier 1 assessment and disposition
-------------------------------------
**Finding:** The reviewed records support routine SYSTEM authentication and privileged activity; no failed-logon Event ID 4625 records were found in the retained Security log during the independent check.

**Security impact:** No confirmed compromise, malicious process, unauthorised access or brute-force activity was established by this evidence.

**Escalation:** No escalation justified solely by the reviewed evidence. An actual SOC alert, additional indicators or contradictory telemetry would require renewed triage.

**Disposition:** Baseline investigation documented; no security incident confirmed. Do not interpret this as a guarantee the endpoint was free from threats.

Outstanding quality checks
--------------------------
- [ ] Review an interactive (Type 2) or unlock (Type 7) logon for additional context.
- [ ] Review and redact personal or device-identifying details before publishing or sharing screenshots.
- [ ] If deeper correlation is required, compare complete event records, accounts, Logon IDs, record IDs and timestamps.
- [ ] If stronger audit assurance is required, review audit policy and log retention settings.

Skills demonstrated
-------------------
- Windows Security event interpretation and filtering
- PowerShell `Get-WinEvent` investigation
- Authentication and privileged-access triage
- Evidence indexing and defensible analytical conclusions
- Recognising limitations of filters, samples and missing telemetry
- SOC case documentation and disposition

References
----------
- [Microsoft Learn — Event 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Microsoft Learn — Event 4625](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [Microsoft Learn — Event 4672](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672)
- [Microsoft Learn — Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)
- [MITRE ATT&CK](https://attack.mitre.org/)
