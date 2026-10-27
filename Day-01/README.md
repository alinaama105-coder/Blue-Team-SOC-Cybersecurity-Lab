Day 1 — Windows Security Event Monitoring
=========================================

Status: In progress

Objective
---------
Inspect Windows Security events on a Windows 11 laptop and establish a basic authentication-event baseline.

Exercise 1 — Open Event Viewer
------------------------------
1. Press Windows + R.
2. Enter eventvwr.msc.
3. Expand Windows Logs.
4. Select Security.
5. Review the event list without modifying or deleting logs.

Evidence to collect
-------------------
- A screenshot of Event Viewer with the Security log selected.
- Selected event IDs and timestamps (after redacting sensitive details).
- Analyst notes explaining observed activity.

Investigation checklist
-----------------------
- [ ] Event Viewer opened
- [ ] Security log inspected
- [ ] Relevant events identified
- [ ] Findings recorded
- [ ] Redacted evidence added to repository

Key event IDs
-------------
- 4624: Successful logon
- 4625: Failed logon (may not appear on all systems depending on auditing settings)
- 4634: Account logoff

Important
---------
An event ID alone does not establish malicious activity. Context, event fields, account and system activity matter. Never publish unredacted logs or screenshots containing private information.

Findings
--------
Pending first practical exercise.

References
----------
- https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
