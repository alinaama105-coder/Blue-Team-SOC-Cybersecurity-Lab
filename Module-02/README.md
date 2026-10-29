Day 02 — Network Traffic Analysis
=================================

Investigation ID: SOC-002
Date: 29 October 2026
Environment: Authorised Windows 11 endpoint and local loopback interface
Tools: Wireshark 4.6.9, Npcap 1.90, Windows PowerShell, curl.exe
Status: Practical investigation completed; evidence publication pending review

Objective
---------
Capture and interpret network traffic, identify DNS, TCP, TLS and QUIC activity, compare successful and unsuccessful connections, and document defensible SOC findings.

Scope and authorisation
-----------------------
Traffic was captured from the investigator's own endpoint and local loopback adapter. Controlled tests targeted localhost, with a separate HTTPS connectivity test to a public Microsoft website. No unauthorised scanning or exploitation was conducted.

Investigation workflow
----------------------

1. Capture setup
   - Installed Wireshark and Npcap.
   - Captured live Wi-Fi traffic and localhost traffic using the Npcap Loopback Adapter.
   - Used display filters to isolate protocols and connections.

2. DNS investigation
   - Filter: `dns`
   - Examined DNS queries and responses associated with ordinary operating-system, application and certificate services.
   - DNS names alone were not treated as evidence of compromise.

3. TCP traffic and connection troubleshooting
   - Filters: `tcp`, `tcp.analysis.retransmission`, `tcp.flags.syn == 1 && tcp.flags.ack == 0`, `tcp.flags.syn == 1 && tcp.flags.ack == 1`
   - Observed SYN, SYN-ACK and ACK completing a three-way handshake.
   - Observed retransmissions and duplicate ACKs; these are diagnostic indicators, not proof of an attack or a precise packet-loss rate.
   - Controlled failed localhost test: SYN followed by RST, ACK to port 2500, consistent with a refused connection.
   - Controlled successful localhost test: started a TCP listener on 127.0.0.1:65001, confirmed `TcpTestSucceeded : True`, and observed SYN → SYN-ACK → ACK in Wireshark.
   - Distinguished connection establishment from subsequent FIN/RST connection closure.

4. TLS and HTTPS investigation
   - Filters: `tls`, `tls.handshake.type == 1`, `tls.handshake.type == 2`
   - Identified TLS Client Hello and Server Hello messages.
   - Successful test: `curl.exe -Iv --http1.1 https://www.microsoft.com` established HTTPS and returned HTTP 200 OK.
   - Observed encrypted TLS application traffic.
   - Controlled failure attempt: `curl.exe -Iv --http1.1 --tls-max 1.0 https://www.microsoft.com` returned Schannel `SEC_E_UNSUPPORTED_FUNCTION (0x80090302)` and curl error 35.
   - This establishes a TLS client-side negotiation failure. The precise packet sequence and any server-side rejection for that failed attempt were not conclusively verified; do not describe it as a confirmed server rejection.

5. QUIC investigation
   - Inspected QUIC Initial packets and CRYPTO, PING and PADDING frames.
   - Recognised QUIC as an encrypted transport commonly used by HTTP/3 over UDP/443.
   - These frame types alone do not indicate malicious activity.

SOC-002 — Investigation and Response Report
-------------------------------------------

Alert / trigger
---------------
Training-led review of captured endpoint network activity and controlled connection failures. No production security alert was generated.

Evidence reviewed
-----------------
Wireshark protocol filters, TCP handshake packets, localhost SYN/RST sequences, TLS Client Hello and Server Hello, QUIC Initial frames, and PowerShell/curl test output. Screenshots are to be added under `Module-02/images/` after privacy review.

Findings
--------
- DNS, TCP, TLS and QUIC traffic were observed in the authorised test environment.
- A TCP three-way handshake was captured successfully.
- A refused local TCP connection was demonstrated using SYN followed by RST, ACK.
- A successful local TCP connection was demonstrated after starting a listener.
- Successful HTTPS/TLS communication was established and supported by HTTP 200 OK and observed handshake packets.
- An intentionally restricted TLS configuration caused a Schannel client-side error.
- No malicious activity was confirmed from the reviewed evidence.

Assessment
----------
Classification: Authorised training activity / expected network behaviour.
Severity: Informational.
Confidence: High for the observed TCP handshakes and successful HTTPS test; limited for the exact on-wire cause of the TLS 1.0 failure.

Response and recommendations
----------------------------
1. No incident containment or escalation is indicated by the demonstrated test activity.
2. For genuine connection failures, correlate packet captures with local service state, firewall settings, endpoint logs and TLS configuration.
3. Do not infer maliciousness from Wireshark colouring, isolated retransmissions or a single TLS error.
4. Retain original captures privately and publish only reviewed, redacted screenshots.

Outcome
-------
Day 02 practical objectives completed. The remaining documentation task is to upload the selected screenshots and embed them next to the corresponding analysis.

Evidence
--------
Image references will be inserted once the reviewed screenshots are present in the repository. Avoid broken links and do not publish raw private packet captures.

References
----------
- Wireshark User's Guide — https://www.wireshark.org/docs/wsug_html_chunked/
- Wireshark Display Filter Reference — https://www.wireshark.org/docs/dfref/
- RFC 9293: Transmission Control Protocol (TCP) — https://www.rfc-editor.org/rfc/rfc9293
- RFC 8446: TLS 1.3 — https://www.rfc-editor.org/rfc/rfc8446
- RFC 9000: QUIC Transport — https://www.rfc-editor.org/rfc/rfc9000
- Microsoft Learn: Test-NetConnection — https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection
