Day 1.2 — Privileged Logon Investigation (Event ID 4672)
========================================================

Status: Initial investigation completed — 27 October 2026

Objective
---------
Investigate Windows Security Event ID 4672, identify the account receiving special privileges, and assess whether the observed activity warrants further investigation or escalation.

Environment
-----------
- Windows 11 endpoint
- Windows Event Viewer → Windows Logs → Security
- Windows PowerShell (additional Day 1 command-line evidence)

Investigation procedure
-----------------------
1. Opened the Windows Run dialog and launched Event Viewer using `eventvwr.msc`.
2. Navigated to Windows Logs and selected the Security log.
3. Reviewed the retained Security audit events.
4. Opened an Event ID 4672 record and inspected its Subject and Privileges fields.
5. Used Filter Current Log to focus on Event ID 4672.
6. Reviewed the resulting privileged-logon records and documented the findings.

Evidence — Event Viewer
-----------------------
An initial 4672 screenshot is already published in the main Day 1 evidence collection:

![Event ID 4672 — privileged logon evidence](../images/06_Event_4672_Privileged_Logon.png)

Eight additional annotated screenshots were captured for this sub-stage. Once the organised images are uploaded to this folder's `images/` directory, they should be displayed in this sequence:

1. `01_Open_Run_Dialog.png` — Open the Windows Run dialog
2. `02_Launch_Event_Viewer.png` — Launch Event Viewer
3. `03_Event_Viewer_Overview.png` — Inspect Event Viewer overview
4. `04_Windows_Logs_Security_Log.png` — Select the Security log
5. `05_Security_Event_4672_Details.png` — Examine privileges and account fields
6. `06_Filter_Event_ID_4672.png` — Filter the Security log for 4672
7. `07_Event_Source_Filter_Options.png` — Review filter options
8. `08_Event_4672_Filtered_Results.png` — Review matching 4672 events

Investigation findings
----------------------
- Event ID: **4672** — Special privileges assigned to a new logon
- Event time observed: **27 October 2026, 14:36:01**
- Account: **SYSTEM**
- Domain: **NT AUTHORITY**
- Logon ID: **0x3E7**
- Example privileges observed: `SeAssignPrimaryTokenPrivilege`, `SeTcbPrivilege`, `SeSecurityPrivilege`
- Several 4672 records were visible in the filtered Security log.

SOC Tier 1 assessment
---------------------
The reviewed 4672 event is consistent with routine privileged activity by the built-in Windows SYSTEM account. A 4672 event alone does not indicate compromise. To confirm relationships between logons, correlate the relevant 4624 and 4672 records using account, Logon ID, and time rather than timestamps alone.

**Disposition:** No malicious activity established from the reviewed record. Further correlation would be appropriate if other indicators or alerts were present.

Limitations
-----------
- The exact process or service responsible was not independently identified.
- An Event Sources selection is visible in some filter screenshots. Filter criteria should be reviewed before treating a result set as exhaustive.
- Device-identifying details in screenshots should be redacted before public sharing.

Skills demonstrated
-------------------
- Windows Security event investigation
- Privileged-logon analysis
- Event Viewer filtering
- SOC Tier 1 triage and evidence documentation
- Distinguishing observations from conclusions

References
----------
- [Microsoft: Event 4672 — Special privileges assigned to new logon](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672)
- [Microsoft: Event 4624 — Successful logon](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [MITRE ATT&CK](https://attack.mitre.org/)
