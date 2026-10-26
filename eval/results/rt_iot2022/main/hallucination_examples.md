# Hallucination examples (picked automatically; check them before quoting)

## Q01 condition C: CONTRADICTED
- Question: What is this traffic, and why did the detector classify it this way?
- Detector said: DOS_SYN_Hping
- Claim: The traffic is a failed or rejected FTP connection attempt, likely a scan or mis-configuration
- Judge's reason: The reference evidence clearly identifies the traffic as a TCP SYN flood (DOS_SYN_Hping).

<details><summary>Full answer</summary>

**What the flow is**

- **Protocol / ports** – TCP, destination port 21 (the FTP control port).  
- **Size & shape** – Only two packets were seen: a client SYN (with 120 bytes of payload) and an immediate server response that carries both **RST** and **ACK** flags. No data was sent back, and the whole exchange lasted only ≈ 13 ms.  
- **Direction** – One forward packet (client → server) and one backward packet (server → client). The forward packet carries a normal TCP header (20 bytes) plus 120 bytes of payload; the backward packet is just the 20‑byte header with no payload.  
- **Timing** – Because the flow is only two packets, the calculated “packets‑per‑second” numbers are huge (≈ 150 k pps) – that’s just a mathematical artifact of dividing a tiny packet count by a very short duration.

**Why a detector would flag it**

1. **RST flag presence** – A reset in the very first handshake is unusual for a healthy FTP client; it usually means the server rejected the connection (e.g., no FTP service listening, firewall block, or a scan).  
2. **Extremely short duration & high pps** – The flow finishes in ~13 ms with a “packet‑rate” of >150 k pps, which is far outside normal FTP session patterns (normally minutes long with many packets).  
3. **Only one data packet** – The client sent payload before the server even completed the three‑way handshake, which is atypical for legitimate FTP traffic.  
4. **Port 21** – FTP is a common target for scanning and brute‑force attempts; many IDS/ML models treat a SYN‑RST on this port as suspicious.

Putting it together, the flow looks like a **failed or rejected FTP connection attempt**, likely a scan or a mis‑configuration, and the detector flagged it because the combination of a SYN‑RST handshake, ultra‑short flow time, and abnormal packet‑rate deviates strongly from normal IoT FTP traffic.

</details>

## Q02 condition C: CONTRADICTED
- Question: How should I respond to this traffic?
- Detector said: DOS_SYN_Hping
- Claim: This is port-scan activity probing for an FTP service
- Judge's reason: The reference classifies the traffic as a DOS_SYN_Hping attack (DoS attack using TCP SYN packets), not a port scan.

<details><summary>Full answer</summary>

**What you’re seeing**

- **Destination port 21** – the FTP control port.  
- Only **two packets**: a **SYN** from the client and an immediate **RST** from the server (or vice‑versa).  
- The flow lasted **≈13 ms** and carried **120 bytes of payload** (the SYN‑packet’s TCP options).  
- No data was exchanged in the reverse direction, and the flow ended with a reset.

**Interpretation**

This is a classic “SYN‑RST” pattern that shows a connection attempt that was immediately rejected. It is typical of:

1. **Port‑scan activity** – an attacker probing for an FTP service.  
2. **A legitimate client trying to reach an FTP server that is not listening** (e.g., the service is disabled or firewalled).  

Because the flow is only one‑way and ends with a reset, there is no data exfiltration or command‑and‑control traffic.

**Recommended response**

| Action | Why |
|--------|-----|
| **Log the event** with source IP, timestamp, and destination IP/port. | Gives you a record for later correlation (e.g., repeated scans from the same host). |
| **Check the source IP reputation** (internal vs. external). | If it’s an internal host, investigate why it’s probing FTP; if external, it’s likely benign scanning. |
| **If the source is unknown or suspicious, add a temporary block** (e.g., firewall rule to drop traffic from that IP to port 21). | Stops further scanning attempts without affecting legitimate traffic. |
| **Verify that your FTP service is intentionally disabled or properly firewalled**. | If you don’t run FTP, ensure the port is blocked at the perimeter. |
| **Monitor for repeated attempts** – a single hit is low‑risk, but a burst may indicate a more aggressive scan. | Escalate to a full incident response if the pattern repeats. |

**Bottom line:** This single SYN‑RST flow is not an active attack, but it is a probe. Log it, verify your FTP posture, and consider blocking the source if it’s unexpected or part of a larger scanning pattern.

</details>

## Q02 condition C: CONTRADICTED
- Question: How should I respond to this traffic?
- Detector said: DOS_SYN_Hping
- Claim: This may be a legitimate client trying to reach an FTP server that is not listening
- Judge's reason: The reference identifies the traffic as a DoS attack.

<details><summary>Full answer</summary>

**What you’re seeing**

- **Destination port 21** – the FTP control port.  
- Only **two packets**: a **SYN** from the client and an immediate **RST** from the server (or vice‑versa).  
- The flow lasted **≈13 ms** and carried **120 bytes of payload** (the SYN‑packet’s TCP options).  
- No data was exchanged in the reverse direction, and the flow ended with a reset.

**Interpretation**

This is a classic “SYN‑RST” pattern that shows a connection attempt that was immediately rejected. It is typical of:

1. **Port‑scan activity** – an attacker probing for an FTP service.  
2. **A legitimate client trying to reach an FTP server that is not listening** (e.g., the service is disabled or firewalled).  

Because the flow is only one‑way and ends with a reset, there is no data exfiltration or command‑and‑control traffic.

**Recommended response**

| Action | Why |
|--------|-----|
| **Log the event** with source IP, timestamp, and destination IP/port. | Gives you a record for later correlation (e.g., repeated scans from the same host). |
| **Check the source IP reputation** (internal vs. external). | If it’s an internal host, investigate why it’s probing FTP; if external, it’s likely benign scanning. |
| **If the source is unknown or suspicious, add a temporary block** (e.g., firewall rule to drop traffic from that IP to port 21). | Stops further scanning attempts without affecting legitimate traffic. |
| **Verify that your FTP service is intentionally disabled or properly firewalled**. | If you don’t run FTP, ensure the port is blocked at the perimeter. |
| **Monitor for repeated attempts** – a single hit is low‑risk, but a burst may indicate a more aggressive scan. | Escalate to a full incident response if the pattern repeats. |

**Bottom line:** This single SYN‑RST flow is not an active attack, but it is a probe. Log it, verify your FTP posture, and consider blocking the source if it’s unexpected or part of a larger scanning pattern.

</details>

## Q02 condition C: CONTRADICTED
- Question: How should I respond to this traffic?
- Detector said: DOS_SYN_Hping
- Claim: This single SYN-RST flow is not an active attack, but it is a probe
- Judge's reason: The reference explicitly classifies the traffic as an ATTACK of type DoS (DOS_SYN_Hping).

<details><summary>Full answer</summary>

**What you’re seeing**

- **Destination port 21** – the FTP control port.  
- Only **two packets**: a **SYN** from the client and an immediate **RST** from the server (or vice‑versa).  
- The flow lasted **≈13 ms** and carried **120 bytes of payload** (the SYN‑packet’s TCP options).  
- No data was exchanged in the reverse direction, and the flow ended with a reset.

**Interpretation**

This is a classic “SYN‑RST” pattern that shows a connection attempt that was immediately rejected. It is typical of:

1. **Port‑scan activity** – an attacker probing for an FTP service.  
2. **A legitimate client trying to reach an FTP server that is not listening** (e.g., the service is disabled or firewalled).  

Because the flow is only one‑way and ends with a reset, there is no data exfiltration or command‑and‑control traffic.

**Recommended response**

| Action | Why |
|--------|-----|
| **Log the event** with source IP, timestamp, and destination IP/port. | Gives you a record for later correlation (e.g., repeated scans from the same host). |
| **Check the source IP reputation** (internal vs. external). | If it’s an internal host, investigate why it’s probing FTP; if external, it’s likely benign scanning. |
| **If the source is unknown or suspicious, add a temporary block** (e.g., firewall rule to drop traffic from that IP to port 21). | Stops further scanning attempts without affecting legitimate traffic. |
| **Verify that your FTP service is intentionally disabled or properly firewalled**. | If you don’t run FTP, ensure the port is blocked at the perimeter. |
| **Monitor for repeated attempts** – a single hit is low‑risk, but a burst may indicate a more aggressive scan. | Escalate to a full incident response if the pattern repeats. |

**Bottom line:** This single SYN‑RST flow is not an active attack, but it is a probe. Log it, verify your FTP posture, and consider blocking the source if it’s unexpected or part of a larger scanning pattern.

</details>

## Q07 condition B: NOT_IN_EVIDENCE
- Question: What is this traffic, and why did the detector classify it this way?
- Detector said: ARP_poisioning
- Claim: These characteristics match the pattern of low-latency, low-volume traffic typical of ARP-based spoofing observed in the dataset
- Judge's reason: The reference mentions the feature values and dataset background, but does not explicitly state these features represent low-latency, low-volume traffic typical of the attack.

<details><summary>Full answer</summary>

The detector flagged the sample as **ARP poisoning** with a confidence of 1.00, labeling it an ATTACK in the spoofing family【DET】.  
ARP cache poisoning is a spoofing attack where forged ARP messages bind the attacker’s MAC address to another device’s IP address, letting the attacker sit in‑the‑middle of traffic【CARD_ARP_poisioning】. The MITRE ATT&CK entry describes the same behavior, noting that adversaries send faster or gratuitous ARP replies to corrupt the victim’s ARP cache and intercept data【T1557.002】.  

The classifier’s decision was driven by five flow features: very short inter‑arrival times (8.1 µs) for both forward and backward packets, a small minimum backward payload (106 bytes), a low standard deviation of backward payloads (≈11 bytes), and a total payload of 330 bytes【DET】. These characteristics match the pattern of low‑latency, low‑volume traffic typical of ARP‑based spoofing observed in the dataset【CARD_ARP_poisioning】.  

Thus, the traffic is part of an ARP cache‑poisoning (spoofing) event, and the detector identified it based on the distinctive timing and payload features associated with that attack.

</details>

## Q08 condition B: NOT_IN_EVIDENCE
- Question: How should I respond to this traffic?
- Detector said: ARP_poisioning
- Claim: Validate the alert by confirming that affected hosts are seeing unexpected ARP replies or changes in their ARP tables.
- Judge's reason: The reference does not mention validating alerts by checking ARP tables.

<details><summary>Full answer</summary>

The detector flags this flow as an ARP‑poisoning attack with full confidence (1.00) [DET].  
ARP cache poisoning is a spoofing technique that lets an adversary place its MAC address in a victim’s ARP cache, enabling man‑in‑the‑middle interception of traffic [CARD_ARP_poisioning][T1557.002].  

**Immediate response actions**

1. **Validate the alert** – confirm that the affected hosts are seeing unexpected ARP replies or changes in their ARP tables.  
2. **Contain the threat** – block the offending MAC address on the switch or firewall, and isolate the suspected compromised device.  
3. **Apply network‑level mitigations** [T1557.002-MIT]:  
   * Enable **DHCP Snooping** and **Dynamic ARP Inspection** on switches to verify ARP replies against DHCP leases [M1037].  
   * Deploy **static ARP entries** for critical devices where feasible [M1035].  
   * Use an **intrusion detection/prevention system** that can detect AiTM or ARP‑spoofing patterns [M1031].  
4. **Secure communications** – ensure all sensitive traffic is encrypted (e.g., TLS) so intercepted data remains unreadable [M1041].  
5. **Investigate** – review logs for other signs of credential‑access or data collection [T1557.002] and consider resetting ARP caches on affected hosts.  

These steps directly address the ARP cache poisoning activity identified in the evidence.

</details>

## Q08 condition B: NOT_IN_EVIDENCE
- Question: How should I respond to this traffic?
- Detector said: ARP_poisioning
- Claim: Contain the threat by blocking the offending MAC address on the switch or firewall, and isolating the suspected compromised device.
- Judge's reason: Blocking specific MAC addresses or isolating devices is not explicitly listed in the mitigations.

<details><summary>Full answer</summary>

The detector flags this flow as an ARP‑poisoning attack with full confidence (1.00) [DET].  
ARP cache poisoning is a spoofing technique that lets an adversary place its MAC address in a victim’s ARP cache, enabling man‑in‑the‑middle interception of traffic [CARD_ARP_poisioning][T1557.002].  

**Immediate response actions**

1. **Validate the alert** – confirm that the affected hosts are seeing unexpected ARP replies or changes in their ARP tables.  
2. **Contain the threat** – block the offending MAC address on the switch or firewall, and isolate the suspected compromised device.  
3. **Apply network‑level mitigations** [T1557.002-MIT]:  
   * Enable **DHCP Snooping** and **Dynamic ARP Inspection** on switches to verify ARP replies against DHCP leases [M1037].  
   * Deploy **static ARP entries** for critical devices where feasible [M1035].  
   * Use an **intrusion detection/prevention system** that can detect AiTM or ARP‑spoofing patterns [M1031].  
4. **Secure communications** – ensure all sensitive traffic is encrypted (e.g., TLS) so intercepted data remains unreadable [M1041].  
5. **Investigate** – review logs for other signs of credential‑access or data collection [T1557.002] and consider resetting ARP caches on affected hosts.  

These steps directly address the ARP cache poisoning activity identified in the evidence.

</details>

## Q08 condition B: NOT_IN_EVIDENCE
- Question: How should I respond to this traffic?
- Detector said: ARP_poisioning
- Claim: Review logs for other signs of credential-access or data collection and consider resetting ARP caches on affected hosts.
- Judge's reason: Reviewing logs and resetting ARP caches are not explicitly listed as specific steps in the reference evidence.

<details><summary>Full answer</summary>

The detector flags this flow as an ARP‑poisoning attack with full confidence (1.00) [DET].  
ARP cache poisoning is a spoofing technique that lets an adversary place its MAC address in a victim’s ARP cache, enabling man‑in‑the‑middle interception of traffic [CARD_ARP_poisioning][T1557.002].  

**Immediate response actions**

1. **Validate the alert** – confirm that the affected hosts are seeing unexpected ARP replies or changes in their ARP tables.  
2. **Contain the threat** – block the offending MAC address on the switch or firewall, and isolate the suspected compromised device.  
3. **Apply network‑level mitigations** [T1557.002-MIT]:  
   * Enable **DHCP Snooping** and **Dynamic ARP Inspection** on switches to verify ARP replies against DHCP leases [M1037].  
   * Deploy **static ARP entries** for critical devices where feasible [M1035].  
   * Use an **intrusion detection/prevention system** that can detect AiTM or ARP‑spoofing patterns [M1031].  
4. **Secure communications** – ensure all sensitive traffic is encrypted (e.g., TLS) so intercepted data remains unreadable [M1041].  
5. **Investigate** – review logs for other signs of credential‑access or data collection [T1557.002] and consider resetting ARP caches on affected hosts.  

These steps directly address the ARP cache poisoning activity identified in the evidence.

</details>

## Q03 condition A: mismatched ID CAPEC-111
- Question: Which official ATT&CK technique or CAPEC attack pattern describes this traffic, and are there known related vulnerabilities (CVEs)?
- Detector said: DOS_SYN_Hping
- Note: real ID not related to the detected label; official name: JSON Hijacking (aka JavaScript Hijacking)

<details><summary>Full answer</summary>

**ATT&CK mapping**  
- **Enterprise ATT&CK** – **T1499.001 Network Denial‑of‑Service: SYN Flood** (the traffic is a classic SYN‑flood generated with the Hping tool).  
- **CAPEC** – **CAPEC‑111 Denial‑of‑Service (Flooding)**, which describes overwhelming a target with a high volume of connection‑setup packets.

**Related CVEs**  
SYN‑flood attacks do not exploit a software bug in the victim; they abuse the normal TCP three‑way‑handshake. Therefore there is no single CVE that “causes” this traffic. Any host that runs a TCP service can be hit, and the impact may be amplified if the system has known kernel or networking stack weaknesses that make it easier to exhaust resources. Examples of CVEs that have been leveraged to make SYN‑floods more effective are:

| CVE | Why it matters for a SYN‑flood |
|-----|-------------------------------|
| **CVE‑2019‑11477** (Linux kernel “SYN‑cookies” bypass) | Allows an attacker to bypass SYN‑cookie protection, making the host more vulnerable to flood. |
| **CVE‑2020‑25705** (Linux netfilter) | Can be abused to cause excessive memory consumption during connection tracking, worsening a flood. |
| **CVE‑2021‑22555** (Windows TCP/IP stack) | A flaw that can be triggered by malformed SYN packets, increasing the impact of a flood. |

These CVEs are *enablers* rather than the direct cause; the core technique is the network‑level DoS (SYN flood) itself. If you see the pattern flagged as **DOS_SYN_Hping**, you are looking at an ATT&CK‑listed SYN‑flood (T1499.001) and the CAPEC‑111 flooding pattern. No single application‑level vulnerability is required, but patching the above kernel/TCP stack issues can reduce the host’s susceptibility.

</details>

## Q03 condition C: mismatched ID T1046
- Question: Which official ATT&CK technique or CAPEC attack pattern describes this traffic, and are there known related vulnerabilities (CVEs)?
- Detector said: DOS_SYN_Hping
- Note: real ID not related to the detected label; official name: Network Service Discovery

<details><summary>Full answer</summary>

**Likely ATT&CK / CAPEC mapping**

| Category | Identifier | Name | Why it fits this flow |
|----------|------------|------|-----------------------|
| ATT&CK (Enterprise) | **T1046 – Network Service Scanning** | An adversary probes a host or network to discover open services and their characteristics. | The flow is a single‑packet TCP SYN to destination port **21** (FTP control), immediately followed by a RST. The extremely short duration (≈ 13 µs) and the fact that only the SYN and RST flags appear are typical of a “half‑open” scan that checks whether the service is listening without completing a full TCP handshake. |
| CAPEC | **CAPEC‑163 – Port Scanning** | Systematically probing a target for open ports and services. | Same reasoning – a single SYN‑RST exchange is a classic port‑scan probe. |

**Related known vulnerabilities (CVEs)**  

The traffic itself is not an exploit; it is just a probe. However, if the probe discovers that an FTP server is listening on port 21, the attacker could then try to exploit any known FTP‑related CVEs that affect the specific server software (e.g., CVE‑2021‑26855 for Microsoft Exchange FTP, CVE‑2022‑27774 for vsftpd, etc.). The flow you posted does **not** contain a vulnerability fingerprint, only the fact that the service is reachable.

**What to look for next**

1. **Correlate with other flows** – see if the same source IP later initiates a full TCP handshake or attempts to transfer data on port 21.  
2. **Check the host’s service banner** – a banner grab (e.g., via a separate TCP connection) can reveal the exact FTP product/version, letting you map to any CVEs that affect it.  
3. **Rate‑limit or block** – if the source is unknown or suspicious, consider rate‑limiting or blocking further SYNs to port 21 from that address.

In short, the pattern matches a **network service/port scan (ATT&CK T1046 / CAPEC‑163)**. No specific CVE is tied to the probe itself, but the discovery could lead to exploitation of any CVE that applies to the FTP service that is found open.

</details>
