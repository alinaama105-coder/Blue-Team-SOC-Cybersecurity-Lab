SOC-002 | Network Traffic Investigation and Response Report
==========================================================

**Investigation ID:** SOC-002  
**Date:** 29 October 2026  
**Case type:** Authorised lab-based network investigation  
**Classification:** Expected activity / informational  
**Disposition:** Closed — no confirmed security incident  
**Evidence source:** [Module 02 practical investigation and 29 screenshots](README.md)

Executive summary
-----------------
A controlled network investigation was performed on a Windows 11 endpoint using Wireshark 4.6.9, Npcap 1.90, PowerShell and curl.exe. The objective was to distinguish normal network behaviour from diagnostic anomalies and to reproduce successful and unsuccessful connections in an authorised environment.

The investigator captured Wi-Fi and localhost traffic, inspected DNS, TCP, TLS and QUIC, verified a successful TCP handshake, reproduced a refused localhost connection, and then confirmed successful connectivity after starting a local TCP listener. A successful HTTPS request returned HTTP 200. A separate restricted TLS test produced a Windows Schannel error. **No malicious activity was confirmed.** No production alert was triggered, and no containment was warranted.

Scope, controls and limitations
-------------------------------
- **In scope:** Traffic from the investigator's own Windows endpoint, the Npcap loopback adapter, local test services, and an ordinary HTTPS request to a public Microsoft website.
- **Out of scope:** Third-party scanning, exploitation, production-system response, malware execution or attribution of external IP addresses.
- **Capture limitations:** Screenshots document the workflow but are not substitutes for a preserved PCAP and independently validated packet stream. No full-fidelity capture or packet hashes are included in this public report.
- **Privacy:** Review screenshots for personal or network identifiers before publication. Raw captures should remain private.
- **Analytical standard:** Observations, interpretations and unresolved questions are distinguished explicitly.

Environment and methodology
---------------------------
| Component | Detail |
| --- | --- |
| Endpoint | Windows 11 |
| Capture software | Wireshark 4.6.9 |
| Packet capture driver | Npcap 1.90 |
| Diagnostic tools | PowerShell, curl.exe |
| Capture interfaces | Wi-Fi and Npcap Loopback Adapter |
| Controlled TCP destinations | 127.0.0.1:2500 and 127.0.0.1:65001 |
| HTTPS destination | https://www.microsoft.com |
| Evidence | 29 screenshots embedded in [README](README.md) |

The workflow was: define the capture scope → select the correct interface → establish a protocol baseline → filter and inspect DNS/TCP/TLS/QUIC → reproduce localhost connection failures → start a listener and retest → validate HTTPS → document the findings and limitations.

Evidence register
-----------------
| ID | Evidence group | What it supports | Source |
| --- | --- | --- | --- |
| E01 | 01–04 | Capture setup and interface selection | [Screenshots 01–04](README.md#01--capture-preparation-and-interface-selection) |
| E02 | 05–08 | Baseline capture and protocol filtering | [Screenshots 05–08](README.md#02--establishing-a-network-baseline) |
| E03 | 09–13 | DNS/TCP packet inspection | [Screenshots 09–13](README.md#03--dns-and-tcp-investigation) |
| E04 | 14–22 | Controlled localhost TCP troubleshooting and command output | [Screenshots 14–22](README.md#04--controlled-tcp-connection-failure-and-recovery) |
| E05 | 23–29 | TLS/HTTPS diagnostic capture and command output | [Screenshots 23–29](README.md#05--tls-https-and-quic-analysis) |

The groupings are chronological and contextual. **They do not assert that each screenshot independently proves every adjacent technical conclusion.**

Technical findings
------------------

**F01 — Packet capture and baseline established**  
*Observation:* Wi-Fi and loopback packet capture was configured and protocol traffic was inspected.  
*Interpretation:* A baseline is necessary before evaluating deviations. Wireshark packet colours and background traffic are not standalone threat indicators.  
*Confidence:* High for successful capture; no claim of comprehensive network visibility.

**F02 — DNS activity observed**  
*Observation:* DNS queries and responses appeared in the capture.  
*Interpretation:* DNS traffic can support investigation of name resolution and host communications, but a domain appearing in a trace is not evidence of compromise.  
*Confidence:* High for protocol presence; no domain-specific threat attribution.

**F03 — Successful TCP handshake**  
*Observation:* A three-way TCP handshake was observed, including example packet sequence 692 SYN → 693 SYN-ACK → 694 ACK.  
*Interpretation:* The exchange supports successful TCP session establishment for that conversation. Retransmissions and duplicate ACKs may reflect network or capture conditions; their displayed proportion must not be treated as an independently measured packet-loss rate.  
*Confidence:* High for the reported handshake.

**F04 — Controlled localhost connection refused**  
*Observation:* A test to localhost TCP port 2500 showed SYN followed by RST, ACK. A test to port 65001 failed before a listener was started.  
*Interpretation:* The sequence is consistent with a refused connection at the tested endpoint; it does not establish malicious activity.  
*Confidence:* High for the observed connection outcome; service state is inferred from the controlled setup.

**F05 — Localhost connection recovered after listener activation**  
*Method:*
```powershell
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 65001)
$listener.Start()
Test-NetConnection 127.0.0.1 -Port 65001
```
*Observation:* `TcpTestSucceeded : True` was returned and the capture showed packet sequence 732 SYN → 733 SYN-ACK → 734 ACK.  
*Interpretation:* The listener was reachable and a TCP connection could be established. Later FIN/RST packets must be assessed as possible session termination, not automatically as failure of the earlier handshake.  
*Confidence:* High.

**F06 — Successful HTTPS/TLS test**  
*Method:* `curl.exe -Iv --http1.1 https://www.microsoft.com`  
*Observation:* The request completed with HTTP 200 and TLS handshake/encrypted application traffic was inspected.  
*Interpretation:* The result confirms successful HTTPS connectivity for this test. Encryption limits the visibility of application payloads in a standard capture.  
*Confidence:* High for successful request; exact TLS parameters should be confirmed from original logs if needed.

**F07 — Restricted TLS compatibility test produced client-side error**  
*Method:* `curl.exe -Iv --http1.1 --tls-max 1.0 https://www.microsoft.com`  
*Observation:* Windows Schannel returned `SEC_E_UNSUPPORTED_FUNCTION (0x80090302)`; curl returned error 35.  
*Interpretation:* This demonstrates a TLS client-side negotiation/configuration failure in the test environment. **A server-side TLS rejection was not established**, because the exact failed on-wire sequence and any server alert were not conclusively correlated.  
*Confidence:* High for the observed client error; low for any server-side cause.

**F08 — QUIC/HTTP/3 transport features inspected**  
*Observation:* QUIC Initial packets and CRYPTO, PING and PADDING frames were examined in the broader exercise.  
*Interpretation:* These are expected features of QUIC traffic and are not indicators of compromise in isolation.  
*Confidence:* High for protocol identification; no malicious interpretation supported.

SOC triage and risk decision
----------------------------
| Dimension | Assessment |
| --- | --- |
| Alert source | Training exercise; no production detection |
| Asset scope | Investigator-controlled endpoint and localhost |
| Threat indicator | None confirmed |
| Observed impact | No confirmed compromise or security impact |
| Severity | Informational |
| Priority | No operational response required |
| Classification | Expected authorised lab activity |
| Containment | Not applicable |
| Escalation | Not indicated |
| Case outcome | Closed as completed investigation |

Alternative explanations considered: local listener absence, network path/capture-interface mismatch, normal TCP teardown, transient network conditions, and client-side TLS configuration. The evidence does not justify claims of attack, hostile source attribution or production incident response.

Response and recommendations
----------------------------
1. In a genuine failed-connection incident, correlate the TCP sequence with the listener state, host firewall, route and endpoint logs.
2. For suspected TLS failures, retain the precise curl/Schannel output, protocol version, certificate details and matching packet stream before assigning server or client responsibility.
3. For repeated retransmissions, measure timing and context across a complete conversation; do not equate Wireshark filter counts with packet-loss percentage.
4. Preserve original PCAP files privately, maintain timestamps and file hashes when building a formal evidence chain, and publish only reviewed/redacted screenshots.
5. Expand future exercises into authorised network service discovery and correlate findings with host logs.

Investigation conclusion
------------------------
SOC-002 demonstrates practical capture setup, protocol interpretation, safe reproduction of network connection failures, validation of recovery, and evidence-based SOC reporting. All documented tests were authorised. **No confirmed security incident occurred.** The report deliberately limits conclusions where screenshot evidence or packet-level correlation is insufficient.

Report status: Final for the documented training exercise; technical conclusions are bounded by the evidence described above.

References
----------
- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [RFC 9293 — TCP](https://www.rfc-editor.org/rfc/rfc9293)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 9000 — QUIC](https://www.rfc-editor.org/rfc/rfc9000)
- [Microsoft Learn — Test-NetConnection](https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection)
