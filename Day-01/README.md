Day 1 — Windows Security Event Monitoring
=========================================

Status: In progress — first authentication investigation completed (27 October 2026)

Objective
---------
Inspect Windows Security events on a Windows 11 laptop and establish a basic authentication-event baseline using Event Viewer.

Completed steps
---------------
1. Opened Event Viewer and inspected Windows Logs > Security.
2. Confirmed the Security log contained more than 32,700 retained events at inspection time.
3. Filtered Event ID 4625 (failed logon): zero matching events in the retained log at the time of the check. This does not prove that no failures occurred.
4. Filtered Event ID 4624 (successful logon).
5. Examined one 4624 event and identified Logon Type 5 (service logon).
6. Inspected the New Logon account and logon identifier.

Investigation 001 — Service logon
---------------------------------
- Source: Windows Security event log
- Event ID: 4624
- Date/time: 2026-10-27 12:35:22 (as displayed in Event Viewer)
- Logon Type: 5 — Service
- New Logon Account: SYSTEM
- New Logon Domain: NT AUTHORITY
- Logon ID: 0x3E7
- Elevated Token: Yes
- Assessment: Consistent with routine Windows service authentication; no malicious activity established from the reviewed fields.
- Limitations: The specific service/process responsible was not independently confirmed. Further correlation would be required for a definitive benign determination.

Analyst notes
-------------
A service logon using the built-in SYSTEM account is common on Windows. An elevated token alone is not evidence of compromise. Event 4625 was not present in the retained log under the final Event ID filter; auditing configuration and retention may affect visibility.

Evidence
--------
Screenshots were reviewed in the training conversation. No raw screenshots have been published to this repository because they contain device-identifying details. Only redacted images should be added later.

Checklist
---------
- [x] Event Viewer opened
- [x] Security log inspected
- [x] Failed logon Event ID 4625 filter checked
- [x] Successful logon Event ID 4624 investigated
- [x] Findings documented
- [ ] Redacted screenshots added to repository
- [ ] Additional authentication patterns investigated

References
----------
- https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
- https://attack.mitre.org/
