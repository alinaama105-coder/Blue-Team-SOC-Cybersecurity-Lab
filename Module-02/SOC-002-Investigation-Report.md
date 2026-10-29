SOC-002 — Network Traffic Investigation
=======================================

**29 October 2026 | Day 02 — Blue Team SOC Lab**

| Case detail | Record |
| --- | --- |
| Investigation ID | SOC-002 |
| Type | Network traffic analysis and connection troubleshooting |
| Environment | Authorised Windows 11 endpoint and localhost |
| Tools | Wireshark 4.6.9, Npcap 1.90, PowerShell, curl.exe |
| Result | Expected lab activity; no confirmed compromise |
| Severity | Informational |
| Decision | Close — no escalation required |

What happened
-------------
I spent this session investigating what a normal network connection looks like at packet level, then deliberately caused a few connection failures to see how they appear in Wireshark.

I captured traffic on my Windows endpoint, first through the Wi-Fi interface and then through the Npcap loopback adapter for tests against my own machine. I looked at DNS, TCP, TLS and QUIC traffic, checked whether TCP handshakes completed, and compared failed connections with successful ones.

The most useful result came from testing a localhost port before and after starting a listener. The first attempt failed. Once I started a service listening on the port, the connection succeeded and the TCP handshake appeared in the capture. I also confirmed that an HTTPS request to Microsoft's website returned HTTP 200.

**Bottom line:** The traffic I investigated was consistent with the tests I performed. I did not identify evidence of malicious activity. This was a training investigation, not an alert from a production SOC.

Why I investigated it
---------------------
The goal was to practise a question that comes up constantly in security operations: *is this network behaviour suspicious, or is there a simpler explanation?*

A reset packet, a retransmission or a failed TLS connection can look alarming when viewed without context. I wanted to see the packets for myself, reproduce the behaviour safely and document what the evidence actually supports.

I worked only with my own endpoint and local test services. The external activity was a normal HTTPS connectivity request to `www.microsoft.com`. I did not scan or test systems I did not control.

Investigation timeline
----------------------
The times below are **evidence-capture timestamps inferred from screenshot filenames**, not independently validated packet timestamps. They show the order of the work, not the precise start or end of a network session.

| Approximate evidence time | Activity | Evidence |
| --- | --- | --- |
| 13:26–13:39 | Prepared capture tools and selected interfaces | [01–04](README.md#01--capture-preparation-and-interface-selection) |
| 13:44–14:03 | Established a live-traffic baseline | [05–08](README.md#02--establishing-a-network-baseline) |
| 14:07–14:35 | Reviewed DNS and TCP behaviour | [09–13](README.md#03--dns-and-tcp-investigation) |
| 14:54–15:21 | Tested refused and successful localhost connections | [14–22](README.md#04--controlled-tcp-connection-failure-and-recovery) |
| 15:24–15:43 | Tested HTTPS and inspected TLS traffic | [23–29](README.md#05--tls-https-and-quic-analysis) |

The full set of 29 screenshots is embedded in the [Day 02 technical walkthrough](README.md). The images are arranged in investigation order; exact packet-level attribution should be checked against the original captures before using any individual screenshot as standalone forensic proof.

What I found
------------

**01. Normal traffic was visible across several protocols**

Wireshark showed a mixture of DNS, TCP and encrypted transport traffic. I used display filters to reduce the noise and inspect conversations more closely.

```text
dns
tcp
tls
quic
udp.port == 443
```

This gave me a baseline before I started the controlled tests. I did not treat a DNS lookup, a packet colour or a QUIC frame as suspicious simply because it appeared in the capture.

**Assessment:** Expected network activity. No threat finding.

**02. I could see TCP connections being established**

I examined the TCP handshake and identified the sequence **SYN → SYN-ACK → ACK**. One recorded example used packet numbers **692, 693 and 694**.

I also saw retransmission and duplicate-ACK indicators. These can be useful when troubleshooting, but they do not automatically mean an attack is underway. Without a complete conversation and supporting timing information, I cannot reliably turn those filter results into a packet-loss percentage.

Filters used:

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.flags.syn == 1 && tcp.flags.ack == 1
tcp.analysis.retransmission
tcp.analysis.duplicate_ack
```

**Assessment:** A successful TCP handshake was observed. Retransmission indicators were noted but not classified as malicious.

**03. I reproduced a refused connection on localhost**

I attempted to connect to **127.0.0.1:2500**. Wireshark showed a SYN followed by **RST, ACK**. That pattern is consistent with a connection being refused at the destination.

This mattered because a reset is not, by itself, evidence of an intrusion. In this case I had deliberately created the test conditions. I also tested port **65001** before starting a listener and saw that it was not reachable.

**Assessment:** Expected connection refusal during an authorised test.

**04. Starting a listener changed the result**

Next I started a TCP listener on **127.0.0.1:65001** and repeated the test:

```powershell
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 65001)
$listener.Start()
Test-NetConnection 127.0.0.1 -Port 65001
```

PowerShell returned:

```text
TcpTestSucceeded : True
```

The corresponding captured handshake included packets **732 SYN, 733 SYN-ACK and 734 ACK**.

That comparison was the clearest lesson from the session: the same destination can fail or succeed depending on whether an application is listening. I would check the service state and firewall before interpreting this type of failure as a security event.

**Assessment:** Connectivity restored under controlled conditions. No incident.

**05. HTTPS worked; the restricted TLS test did not**

I checked ordinary HTTPS connectivity with:

```powershell
curl.exe -Iv --http1.1 https://www.microsoft.com
```

The request returned **HTTP 200 OK**. I also inspected TLS handshake traffic, including Client Hello and Server Hello messages, followed by encrypted application traffic.

I then tried a deliberately restricted TLS configuration:

```powershell
curl.exe -Iv --http1.1 --tls-max 1.0 https://www.microsoft.com
```

This failed with **curl error 35** and the Windows Schannel message:

```text
SEC_E_UNSUPPORTED_FUNCTION (0x80090302)
```

The error confirms a problem with the restricted TLS attempt in the client environment. It does **not** prove that Microsoft's server rejected the connection: I did not conclusively match the entire failed packet exchange to a server-side alert. I would need the original capture and a complete correlated handshake to make that claim.

**Assessment:** Successful normal HTTPS test; deliberately restricted TLS attempt failed with a client-side error. No evidence of an attack.

**06. QUIC traffic was present**

I examined QUIC Initial packets and frames such as CRYPTO, PING and PADDING. QUIC is commonly used for HTTP/3 over UDP/443, so these frames were not unexpected in a modern endpoint capture.

**Assessment:** Protocol activity observed. No malicious interpretation supported.

Evidence and confidence
-----------------------
| Finding | Supporting evidence | Confidence | What I cannot conclude |
| --- | --- | --- | --- |
| TCP three-way handshake | Wireshark sequence 692–694 | High | That every TCP flow in the capture succeeded |
| Refused localhost connection | SYN then RST, ACK to port 2500 | High | That a firewall or attacker caused it |
| Successful local listener test | `TcpTestSucceeded : True` and sequence 732–734 | High | That the service would remain available outside the test |
| Successful HTTPS request | curl HTTP 200 and TLS activity | High | The precise security settings of unrelated sessions |
| Restricted TLS failure | curl 35 and Schannel error | High for the error | That the remote server definitively rejected the handshake |
| QUIC and DNS observations | Filtered packet views | Moderate for context | That observed endpoints were malicious |

The [Day 02 walkthrough](README.md) contains the screenshots and the detailed technical steps. The evidence is sufficient to explain the lab results, but I have **not** preserved a formal forensic chain of custody in this public repository. The report should not be presented as a production forensic examination.

My decision
-----------
**Close SOC-002 as expected, authorised training activity.**

There was no confirmed malicious connection, compromised host, unauthorised access or production security alert. The connection failures were part of the test plan and were explained by the controlled conditions or by a client-side TLS error.

I would **not** block an IP address, isolate the endpoint or escalate this as a security incident based on the evidence collected.

What I would do differently in a live SOC
-----------------------------------------
If the same symptoms appeared in a real alert, I would first establish the affected host, user, destination, time window and alert source. I would then correlate the packet capture with endpoint telemetry, service status, firewall logs and the relevant application logs.

For a TLS failure, I would check the client and server protocol configuration and match the command output to the exact packet stream. For repeated retransmissions, I would investigate latency and packet timing rather than assume an attack or estimate loss from a Wireshark display filter.

I would preserve the original PCAP privately, record hashes and timestamps for any evidence used in a formal investigation, and redact identifiers before publishing screenshots.

Lessons from Day 02
-------------------
This exercise reinforced an important SOC habit: **explain the network behaviour before assigning it a security meaning**.

I practised capturing traffic, finding the relevant packets, reproducing a failure, testing a fix and documenting the limits of my conclusions. The most valuable part was not the number of packets captured; it was being able to explain why the localhost connection failed, why it later succeeded, and why the TLS error did not justify a stronger claim.

**Case status: Closed. Day 02 objectives completed.**

Technical references
--------------------
- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [RFC 9293 — TCP](https://www.rfc-editor.org/rfc/rfc9293)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 9000 — QUIC](https://www.rfc-editor.org/rfc/rfc9000)
- [Microsoft Learn — Test-NetConnection](https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection)
