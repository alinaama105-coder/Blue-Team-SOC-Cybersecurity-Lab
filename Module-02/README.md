Day 02 — Network Traffic Analysis and Handshake Troubleshooting
================================================================

**[Read the standalone SOC-002 professional investigation report](SOC-002-Investigation-Report.md)**

Investigation: SOC-002 | Date: 29 October 2026 | Status: Practical exercises completed; evidence reviewed for documentation, privacy clearance still required

Purpose
-------
Build a repeatable SOC network-investigation workflow: capture traffic, filter noise, recognise expected protocol behaviour, reproduce connection failures safely and record findings without overstating the evidence.

Lab environment and authorisation
---------------------------------
Windows 11 endpoint, Wireshark 4.6.9, Npcap 1.90, PowerShell and curl.exe. Captures were taken from the investigator's Wi-Fi interface and the Npcap loopback adapter. Active connection tests were limited to localhost and ordinary HTTPS requests to a public Microsoft website. No unauthorised scanning was performed.

01 — Capture preparation and interface selection
-------------------------------------------------
Wireshark provides packet capture and protocol dissection; Npcap supplies packet capture support on Windows. Choosing the correct capture interface matters: Wi-Fi traffic and loopback traffic represent different paths, and a capture from the wrong adapter can make a successful test appear to produce no packets.

![Evidence 01 — SOC-002](01-SOC002-132614.png)

*Evidence 01: Capture environment and initial setup interface.*

![Evidence 02 — SOC-002](02-SOC002-133017.png)

*Evidence 02: Installer or setup dialogue; confirms installation-stage activity rather than a security finding.*

![Evidence 03 — SOC-002](03-SOC002-133712.png)

*Evidence 03: Capture configuration and interface selection before protocol investigation.*

![Evidence 04 — SOC-002](04-SOC002-133940.png)

*Evidence 04: First live packet view, establishing that traffic was being captured and decoded.*

02 — Establishing a network baseline
------------------------------------
Before investigating suspicious behaviour, first identify ordinary background traffic. A busy capture can contain DNS lookups, encrypted web sessions, connection management and unrelated application activity. Protocol colouring and high packet counts are not themselves indicators of compromise.

Useful Wireshark display filters:

```text
dns
tcp
tls
quic
udp.port == 443
```

![Evidence 05 — SOC-002](05-SOC002-134402.png)

*Evidence 05: Wireshark inspection or filter configuration during the baseline review.*

![Evidence 06 — SOC-002](06-SOC002-135133.png)

*Evidence 06: Captured live network traffic used to identify normal packet patterns.*

![Evidence 07 — SOC-002](07-SOC002-135908.png)

*Evidence 07: Filtered packet inspection; packet details should be interpreted alongside source, destination and protocol fields.*

![Evidence 08 — SOC-002](08-SOC002-140306.png)

*Evidence 08: Broader traffic view showing multiple packets and protocol conversations.*

03 — DNS and TCP investigation
------------------------------
DNS requests and responses help explain which names a device attempted to resolve. A domain's appearance in a packet trace does not establish that it is malicious. A TCP session is established by SYN → SYN-ACK → ACK; a retransmission can reflect delay, loss or capture conditions and must be assessed in context.

Useful filters:

```text
dns
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.flags.syn == 1 && tcp.flags.ack == 1
tcp.analysis.retransmission
tcp.analysis.duplicate_ack
```

![Evidence 09 — SOC-002](09-SOC002-140753.png)

*Evidence 09: Selected packets in the filtered network trace.*

![Evidence 10 — SOC-002](10-SOC002-141324.png)

*Evidence 10: Packet-list review during protocol investigation.*

![Evidence 11 — SOC-002](11-SOC002-141843.png)

*Evidence 11: Focused TCP traffic view used to examine packet-level behaviour.*

![Evidence 12 — SOC-002](12-SOC002-142202.png)

*Evidence 12: Additional filtered packets and packet-detail context.*

![Evidence 13 — SOC-002](13-SOC002-143511.png)

*Evidence 13: Narrowed network conversation with selected packet details.*

Observed TCP handshake example: packets 692 (SYN), 693 (SYN-ACK) and 694 (ACK) formed a complete three-way handshake in the recorded exercise. Retransmission-filter matches were observed, but the fraction of displayed packets matching that filter is **not** a measured network packet-loss rate.

04 — Controlled TCP connection failure and recovery
---------------------------------------------------
The purpose of this test was to distinguish a refused connection from an established session without probing another person's system.

A localhost connection attempt to port 2500 produced SYN followed by RST, ACK: consistent with no service accepting that connection at the tested endpoint. An initial test of port 65001 also failed while no listener was active. The investigator then started a local TCP listener:

```powershell
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 65001)
$listener.Start()
Test-NetConnection 127.0.0.1 -Port 65001
```

The test returned `TcpTestSucceeded : True`, and Wireshark showed packets 732 (SYN), 733 (SYN-ACK) and 734 (ACK). Later FIN or RST packets relate to session closure and should not be mistaken for failure of the earlier handshake.

![Evidence 14 — SOC-002](14-SOC002-145409.png)

*Evidence 14: Filtered TCP packets during the controlled connection troubleshooting sequence.*

![Evidence 15 — SOC-002](15-SOC002-145732.png)

*Evidence 15: Follow-up capture of connection-related TCP traffic.*

![Evidence 16 — SOC-002](16-SOC002-150401.png)

*Evidence 16: PowerShell test output captured alongside the Wireshark trace.*

![Evidence 17 — SOC-002](17-SOC002-150823.png)

*Evidence 17: Additional command-line test evidence for the local connection workflow.*

![Evidence 18 — SOC-002](18-SOC002-151102.png)

*Evidence 18: Command output and packet trace reviewed together rather than in isolation.*

![Evidence 19 — SOC-002](19-SOC002-151332.png)

*Evidence 19: Further localhost connection testing with the packet capture visible behind the terminal.*

![Evidence 20 — SOC-002](20-SOC002-151543.png)

*Evidence 20: Terminal verification of the controlled TCP listener or connection test.*

![Evidence 21 — SOC-002](21-SOC002-151814.png)

*Evidence 21: Additional command output supporting the connection troubleshooting exercise.*

![Evidence 22 — SOC-002](22-SOC002-152113.png)

*Evidence 22: Selected packet sequence used to examine TCP connection behaviour.*

SOC interpretation: a refused local connection is a **connectivity result**, not evidence of intrusion. Confirm the destination port, listener state, local firewall and matching packet stream before assigning a cause.

05 — TLS, HTTPS and QUIC analysis
--------------------------------
TLS encrypts application traffic; the Client Hello and Server Hello are useful negotiation landmarks, while application data is encrypted. QUIC commonly carries HTTP/3 over UDP/443; QUIC Initial packets can contain CRYPTO, PING and PADDING frames. These observations alone do not indicate an attack.

Successful HTTPS validation:

```powershell
curl.exe -Iv --http1.1 https://www.microsoft.com
```

The command established HTTPS and returned HTTP/1.1 200 OK. The related capture showed a TCP handshake followed by TLS handshake traffic and encrypted application data.

![Evidence 23 — SOC-002](23-SOC002-152409.png)

*Evidence 23: Packet-level inspection at the transition into the HTTPS/TLS tests.*

![Evidence 24 — SOC-002](24-SOC002-152546.png)

*Evidence 24: Command-line connectivity test alongside the Wireshark capture.*

![Evidence 25 — SOC-002](25-SOC002-152724.png)

*Evidence 25: Terminal output from the TLS/HTTPS diagnostic test.*

![Evidence 26 — SOC-002](26-SOC002-152832.png)

*Evidence 26: TLS handshake packets highlighted in Wireshark; Client Hello and Server Hello provide negotiation evidence.*

![Evidence 27 — SOC-002](27-SOC002-153905.png)

*Evidence 27: Further curl/Schannel diagnostic output captured with the network trace.*

![Evidence 28 — SOC-002](28-SOC002-154150.png)

*Evidence 28: TLS traffic and encrypted application packets reviewed in Wireshark.*

![Evidence 29 — SOC-002](29-SOC002-154357.png)

*Evidence 29: Final filtered packet view used to corroborate HTTPS/TLS network activity.*

Controlled TLS compatibility test:

```powershell
curl.exe -Iv --http1.1 --tls-max 1.0 https://www.microsoft.com
```

This returned Windows Schannel `SEC_E_UNSUPPORTED_FUNCTION (0x80090302)` and curl error 35. A TLSv1 Client Hello was observed, but the full failed connection and any server alert were **not conclusively correlated**. The defensible finding is a client-side TLS configuration/negotiation error; it would be inaccurate to assert that the remote server definitively rejected the handshake.

06 — SOC-002 investigation and response report
----------------------------------------------

Trigger: Authorised practical network investigation and deliberate connection troubleshooting, not a production security alert.

Evidence reviewed: Wireshark captures, DNS/TCP/TLS/QUIC protocol views, localhost connection tests and curl/PowerShell output.

Findings:
- Live endpoint and loopback capture succeeded.
- DNS and encrypted transport activity were present in the baseline.
- A complete TCP three-way handshake was observed.
- A refused localhost connection was reproduced and distinguished from a successful connection after starting a listener.
- HTTPS connectivity returned HTTP 200 OK and TLS handshake activity was observed.
- A deliberately restricted TLS configuration generated a Schannel error; the exact on-wire root cause remains unverified.
- No malicious activity was confirmed in the reviewed exercises.

Classification: Expected, authorised lab activity.

Severity: Informational.

Disposition: No containment or escalation required on the evidence available. In a real incident, correlate packet evidence with endpoint logs, firewall rules, service state and threat intelligence before making a security determination.

Limitations: The screenshots were reviewed as a chronological evidence set; not every individual frame number or terminal line can be conclusively attributed from the image alone. Captures may expose network identifiers. Review and redact screenshots before treating this public portfolio as privacy-cleared. Do not publish raw private PCAPs.

Outcome: Day 02 practical objectives completed. Network evidence, controlled tests and an evidence-based investigation report are documented together. Next planned module: authorised network service discovery.

References
----------
- Wireshark User's Guide — https://www.wireshark.org/docs/wsug_html_chunked/
- Wireshark Display Filter Reference — https://www.wireshark.org/docs/dfref/
- RFC 9293 — Transmission Control Protocol — https://www.rfc-editor.org/rfc/rfc9293
- RFC 8446 — TLS 1.3 — https://www.rfc-editor.org/rfc/rfc8446
- RFC 9000 — QUIC — https://www.rfc-editor.org/rfc/rfc9000
- Microsoft Learn — Test-NetConnection — https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection
