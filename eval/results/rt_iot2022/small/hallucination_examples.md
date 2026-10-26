# Hallucination examples (picked automatically; check them before quoting)

## Q06 condition A: CONTRADICTED
- Question: Which official ATT&CK technique or CAPEC attack pattern describes this traffic, and are there known related vulnerabilities (CVEs)?
- Detector said: DDOS_Slowloris
- Claim: The traffic maps to ATT&CK Technique T1499 – Resource Hijacking.
- Judge's reason: The reference identifies the technique as T1499.002, titled Service Exhaustion Flood.

<details><summary>Full answer</summary>

**ATT&CK mapping**  
- **Technique:** *T1499 – Resource Hijacking* (the “DoS” family that includes Slowloris).  
- **CAPEC pattern:** *CAPEC‑107 – Denial of Service (DoS)*, specifically the “HTTP Slow‑Loris” sub‑pattern.

**Why it matches**  
- The flow is HTTP‑based (`service_http = 1`).  
- The detector notes extremely short inter‑arrival times (`active.min`, `flow_iat.min` ≈ 1 µs) and a huge cumulative forward gap (`fwd_iat.tot` ≈ 26 ms), which are classic Slowloris signatures: many half‑open connections that keep the server’s request buffer busy.  
- The high confidence (1.00) and the fact that the other two labels are 0.00 confirm the detector is strongly pointing to a Slowloris DoS.

**Known CVEs / Vulnerabilities**  
Slowloris itself is a *protocol‑level* attack; it doesn’t rely on a single software flaw. However, many web servers have had CVEs that make them more vulnerable to such traffic, e.g.:  

| Server | CVE (example) | Impact |
|--------|---------------|--------|
| Apache HTTPD | CVE‑2019‑2725 | Improper handling of HTTP headers can be abused by Slowloris‑style attacks. |
| Nginx | CVE‑2021‑44228 (Log4Shell) | While not a Slowloris CVE, it shows how header parsing bugs can be exploited. |
| Microsoft IIS | CVE‑2020‑0688 | Improper request handling can be leveraged for DoS. |

In practice, the mitigation is to tune the web server’s connection limits, request‑buffer sizes, and timeout settings rather than patch a single CVE.

</details>

## Q07 condition A: CONTRADICTED
- Question: What is this traffic, and why did the detector classify it this way?
- Detector said: ARP_poisioning
- Claim: Each ARP reply in the flow carries a fixed payload size of 106 bytes.
- Judge's reason: The reference explicitly states that ARP messages are not in the data and the flows are mostly DNS and SSL/TLS.

<details><summary>Full answer</summary>

**What the traffic is**

The detector says this flow is an **ARP poisoning** attack.  
ARP poisoning (also called ARP spoofing) is when a device on a local network sends forged ARP replies to trick other hosts into associating the attacker’s MAC address with the IP address of a legitimate host (often the gateway). This lets the attacker intercept, modify, or drop traffic.

**Why the detector chose that label**

1. **Very short inter‑arrival times (fwd_iat.min & flow_iat.min ≈ 8 µs)** – ARP replies are sent almost immediately after a request, so packets arrive in microsecond bursts.  
2. **Large, consistent backward payloads (bwd_pkts_payload.min = 106 bytes, std ≈ 11 bytes)** – Each ARP reply carries a fixed payload size (≈ 106 bytes). The low standard deviation shows the attacker is sending many identical replies.  
3. **Total payload (flow_pkts_payload.tot = 330 bytes)** – The flow contains only a handful of packets, all of the same size, typical of a small ARP spoofing burst.  

These five features match the learned pattern for ARP poisoning far better than the other two labels (Metasploit brute‑force SSH and NMAP UDP scan), which would show different packet sizes, timing, and payload variability. The model’s confidence of 1.00 reflects that the observed packet timing and payload characteristics are almost identical to its ARP‑spoofing training examples.

</details>

## Q09 condition A: CONTRADICTED
- Question: Which official ATT&CK technique or CAPEC attack pattern describes this traffic, and are there known related vulnerabilities (CVEs)?
- Detector said: ARP_poisioning
- Claim: The traffic is described by the official ATT&CK technique T1572 or T1572.001 ARP Spoofing
- Judge's reason: The reference explicitly lists the technique as T1557.002 for ARP Cache Poisoning.

<details><summary>Full answer</summary>

**ATT&CK technique**  
- **T1572 – Network Sniffing** (the sub‑technique “ARP Spoofing” is used to intercept traffic).  
- In ATT&CK v15+ it’s listed as **T1572.001 – ARP Spoofing**.

**CAPEC pattern**  
- **CAPEC‑115 – ARP Spoofing** (man‑in‑the‑middle via ARP cache poisoning).

**Known CVEs that can be leveraged or are related**  
- **CVE‑2018‑11776** – Windows ARP cache poisoning vulnerability that can be abused for ARP spoofing.  
- **CVE‑2020‑15154** – Linux kernel ARP cache poisoning bug (affects certain network drivers).  
- **CVE‑2021‑44228** (Log4Shell) – not directly ARP, but often combined with ARP spoofing to redirect traffic to a malicious proxy.  

These CVEs show that ARP spoofing can be amplified by exploiting specific OS or driver bugs, but the attack itself is a technique rather than a single vulnerability.

</details>

## Q09 condition A: CONTRADICTED
- Question: Which official ATT&CK technique or CAPEC attack pattern describes this traffic, and are there known related vulnerabilities (CVEs)?
- Detector said: ARP_poisioning
- Claim: The traffic is described by CAPEC-115 ARP Spoofing
- Judge's reason: The reference lists CAPEC-141 for cache poisoning and does not mention CAPEC-115.

<details><summary>Full answer</summary>

**ATT&CK technique**  
- **T1572 – Network Sniffing** (the sub‑technique “ARP Spoofing” is used to intercept traffic).  
- In ATT&CK v15+ it’s listed as **T1572.001 – ARP Spoofing**.

**CAPEC pattern**  
- **CAPEC‑115 – ARP Spoofing** (man‑in‑the‑middle via ARP cache poisoning).

**Known CVEs that can be leveraged or are related**  
- **CVE‑2018‑11776** – Windows ARP cache poisoning vulnerability that can be abused for ARP spoofing.  
- **CVE‑2020‑15154** – Linux kernel ARP cache poisoning bug (affects certain network drivers).  
- **CVE‑2021‑44228** (Log4Shell) – not directly ARP, but often combined with ARP spoofing to redirect traffic to a malicious proxy.  

These CVEs show that ARP spoofing can be amplified by exploiting specific OS or driver bugs, but the attack itself is a technique rather than a single vulnerability.

</details>

## Q07 condition B: NOT_IN_EVIDENCE
- Question: What is this traffic, and why did the detector classify it this way?
- Detector said: ARP_poisioning
- Claim: The classification is considered reliable because the detector's confidence is high.
- Judge's reason: While confidence is 1.00, the reference text does not explicitly state that the classification is 'considered reliable' based on this.

<details><summary>Full answer</summary>

The traffic sample is an **ARP cache‑poisoning attack**. The detector labeled it “ARP_poisioning” with 100 % confidence because the flow characteristics match those typical of an ARP spoofing event. The key features that pushed the model toward this label are the very short inter‑arrival times (≈8 µs) for both forward and backward packets, the small backward packet payloads (≈106 bytes) and the overall low total payload (330 bytes). These patterns are consistent with the rapid, low‑payload ARP reply traffic that an attacker sends to overwrite a victim’s ARP cache, as described in the dataset label definition and the CAPEC‑141 and T1557.002 descriptions. The detector’s confidence is high, so the classification is considered reliable.

</details>

## Q10 condition B: NOT_IN_EVIDENCE
- Question: What is this traffic, and why did the detector classify it this way?
- Detector said: NMAP_TCP_scan
- Claim: The destination port 4045 is one of the many ports scanned by Nmap's default 1,000-port list.
- Judge's reason: The reference mentions Nmap probes 1,000 common ports by default and destination port 4045, but does not explicitly state that 4045 is part of that default list.

<details><summary>Full answer</summary>

The traffic is a port‑scanning activity that probes many TCP ports to discover which services are listening. The detector labeled it **NMAP_TCP_scan** because the flow characteristics match a typical Nmap port‑scan: many single‑packet flows, very high packet rates (≈167 k packets per second in both directions), and a small TCP header size of 40 bytes, which is typical for SYN probes. The destination port 4045 is one of the many ports scanned by Nmap’s default 1,000‑port list. The detector’s confidence is 1.00, indicating it is certain the traffic is a reconnaissance scan.  

This matches the definition of an Nmap TCP port scan in the evidence card [CARD_NMAP_TCP_scan] and the CAPEC description of port scanning [CAPEC-300] and SYN scanning [CAPEC-287]. The activity is therefore a reconnaissance‑type attack, specifically a network service discovery via port scanning.

</details>

## Q11 condition B: NOT_IN_EVIDENCE
- Question: How should I respond to this traffic?
- Detector said: NMAP_TCP_scan
- Claim: Block the source IP at the firewall or switch if it is not trusted
- Judge's reason: Blocking specific IP addresses at the firewall is not explicitly mentioned in the provided reference evidence.

<details><summary>Full answer</summary>

The detector classifies this flow as an **NMAP_TCP_scan** – a reconnaissance activity where an attacker probes many TCP ports to discover open services.  
The evidence shows that the scan is performed with Nmap, sending single‑packet probes to many ports (up to 1,000 common ports) and that the traffic is high‑rate (≈167 k packets per second in both directions) with no payload. This matches the typical Nmap TCP port‑scan pattern described in the dataset card and CAPEC‑300/287.  

**Recommended response**

1. **Detect and alert** – The high packet rate and lack of payload are clear indicators of a port‑scan. Use an IDS/IPS that flags Nmap‑style scans (e.g., by matching the packet‑rate and single‑packet flow pattern).  
2. **Block the source** – If the source IP is not a trusted internal host, block it at the firewall or switch to prevent further probing.  
3. **Log and investigate** – Record the source IP, destination ports, and timestamps for forensic analysis.  
4. **Apply mitigations** – Ensure unnecessary ports are closed (CAPEC‑287 mitigation M1042) and consider network segmentation or intrusion‑prevention rules (T1046‑MIT M1031) to reduce exposure to future scans.  

These actions are consistent with the evidence and the documented Nmap TCP scan behavior.

</details>

## Q11 condition B: NOT_IN_EVIDENCE
- Question: How should I respond to this traffic?
- Detector said: NMAP_TCP_scan
- Claim: Record the source IP, destination ports, and timestamps for forensic analysis
- Judge's reason: Forensic logging of source IP, ports, and timestamps is not explicitly described in the evidence.

<details><summary>Full answer</summary>

The detector classifies this flow as an **NMAP_TCP_scan** – a reconnaissance activity where an attacker probes many TCP ports to discover open services.  
The evidence shows that the scan is performed with Nmap, sending single‑packet probes to many ports (up to 1,000 common ports) and that the traffic is high‑rate (≈167 k packets per second in both directions) with no payload. This matches the typical Nmap TCP port‑scan pattern described in the dataset card and CAPEC‑300/287.  

**Recommended response**

1. **Detect and alert** – The high packet rate and lack of payload are clear indicators of a port‑scan. Use an IDS/IPS that flags Nmap‑style scans (e.g., by matching the packet‑rate and single‑packet flow pattern).  
2. **Block the source** – If the source IP is not a trusted internal host, block it at the firewall or switch to prevent further probing.  
3. **Log and investigate** – Record the source IP, destination ports, and timestamps for forensic analysis.  
4. **Apply mitigations** – Ensure unnecessary ports are closed (CAPEC‑287 mitigation M1042) and consider network segmentation or intrusion‑prevention rules (T1046‑MIT M1031) to reduce exposure to future scans.  

These actions are consistent with the evidence and the documented Nmap TCP scan behavior.

</details>

## Q03 condition A: mismatched ID CAPEC-113
- Question: Which official ATT&CK technique or CAPEC attack pattern describes this traffic, and are there known related vulnerabilities (CVEs)?
- Detector said: DOS_SYN_Hping
- Note: real ID not related to the detected label; official name: Interface Manipulation

<details><summary>Full answer</summary>

**ATT&CK mapping**

- **Technique:** **T1499 – “DoS: SYN Flood”** (sometimes listed under the broader “DoS” family).  
  The detector flagged the traffic as a SYN‑flood attack generated by the *hping* tool, which is a classic DoS technique that overwhelms a target with a high volume of SYN packets.

**CAPEC pattern**

- **CAPEC‑113 – “Denial of Service via SYN Flood”** – the same pattern that describes flooding a target with SYN packets to exhaust its resources.

**Known vulnerabilities (CVEs)**

- SYN‑flood attacks do **not** rely on a software vulnerability; they exploit the TCP/IP protocol itself.  
- Therefore, there are no specific CVEs that enable this attack.  
- Mitigations are usually network‑level (rate‑limiting, SYN cookies, firewall rules) rather than patching a CVE.

So, the traffic matches the ATT&CK DoS: SYN Flood technique (CAPEC‑113) and is not tied to any particular CVE.

</details>

## Q06 condition A: mismatched ID T1499
- Question: Which official ATT&CK technique or CAPEC attack pattern describes this traffic, and are there known related vulnerabilities (CVEs)?
- Detector said: DDOS_Slowloris
- Note: given the wrong name; official name: Endpoint Denial of Service

<details><summary>Full answer</summary>

**ATT&CK mapping**  
- **Technique:** *T1499 – Resource Hijacking* (the “DoS” family that includes Slowloris).  
- **CAPEC pattern:** *CAPEC‑107 – Denial of Service (DoS)*, specifically the “HTTP Slow‑Loris” sub‑pattern.

**Why it matches**  
- The flow is HTTP‑based (`service_http = 1`).  
- The detector notes extremely short inter‑arrival times (`active.min`, `flow_iat.min` ≈ 1 µs) and a huge cumulative forward gap (`fwd_iat.tot` ≈ 26 ms), which are classic Slowloris signatures: many half‑open connections that keep the server’s request buffer busy.  
- The high confidence (1.00) and the fact that the other two labels are 0.00 confirm the detector is strongly pointing to a Slowloris DoS.

**Known CVEs / Vulnerabilities**  
Slowloris itself is a *protocol‑level* attack; it doesn’t rely on a single software flaw. However, many web servers have had CVEs that make them more vulnerable to such traffic, e.g.:  

| Server | CVE (example) | Impact |
|--------|---------------|--------|
| Apache HTTPD | CVE‑2019‑2725 | Improper handling of HTTP headers can be abused by Slowloris‑style attacks. |
| Nginx | CVE‑2021‑44228 (Log4Shell) | While not a Slowloris CVE, it shows how header parsing bugs can be exploited. |
| Microsoft IIS | CVE‑2020‑0688 | Improper request handling can be leveraged for DoS. |

In practice, the mitigation is to tune the web server’s connection limits, request‑buffer sizes, and timeout settings rather than patch a single CVE.

</details>
