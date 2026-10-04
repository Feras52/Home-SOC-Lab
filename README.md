# Home SOC Lab: PCAP Malware & Network Intrusion Analysis

## Project Overview
This project simulates the end-to-end workflow of a Tier-1 Security Operations Center (SOC) Analyst and Digital Forensics / Incident Response (DFIR) Specialist. 

Rather than relying on simulated synthetic lab traffic, this investigation analyzes a real-world malware infection capture file (`2026-02-28-traffic-analysis-exercise.pcap`). The primary goal is to isolate the victim environment, reconstruct the attacker's infection chain, extract malicious payload binaries, isolate Command & Control (C2) channels, and author functional Suricata Intrusion Detection System (IDS) signatures to defend an enterprise network.

---

## Dataset & Investigation Prerequisites
* **Source Dataset:** [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/)
* **Target Capture:** `2026-02-28-traffic-analysis-exercise.pcap`
* **Analysis Toolkit:** Wireshark (DPI), NetworkMiner (Passive Forensics), Zui / Brim (Zeek Log Parsing), Suricata (IDS Engine), VirusTotal (OSINT)

---

## Repository Deliverables
```text
.
├── README.md                          <-- Executive Summary, Victim Triage & Technical Findings
├── reports/
│   └── Incident_Response_Report.pdf   <-- Formal Incident Post-Mortem Report (Pending phase 4)
├── rules/
│   └── custom_detection.rules         <-- Custom Suricata Detection Signatures (Pending phase 3)
├── iocs/
│   └── iocs.txt                       <-- Defanged Indicators of Compromise 
└── screenshots/                       <-- Forensic Evidence Screenshots
    ├── kerberos.png
    ├── log_triage_http.png
    └── NetworkMiner_cross_validation.png
```

## Phase 1: Network Triage & Victim Host Identification 

### Executive Summary
During the initial network triage of capture file 2026-02-28-traffic-analysis-exercise.pcap, an internal endpoint exhibited anomalous traffic patterns. Using deep packet inspection (Wireshark) and passive network forensics (NetworkMiner, Zui), the compromised victim machine, physical MAC address, network identity, Active Directory domain, and active user account were successfully isolated and cross-verified.

### Compromised Host Identity

| Asset Parameter | Extracted Value | Analysis Source & Method |
| :--- | :--- | :--- |
| **Victim IP Address** | `10.2.28.88` | Wireshark (`Statistics -> Endpoints -> IPv4`) |
| **Victim MAC Address** | `00:19:d1:b2:4d:ad` | Layer 2 Ethernet Frame Headers |
| **Host System Name** | `DESKTOP-TEYQ2NR` | NetBIOS (NBNS Name Registration) |
| **Active Directory Domain** | `EASYAS123` | Kerberos AS-REQ (`realm`) |
| **Compromised User Account** | `brolf` | Kerberos AS-REQ (`cname-string`) |

> **Verification Note:** All extracted host identifiers and Kerberos user credentials were cross-validated using **NetworkMiner's** passive parsing engine (`Hosts` and `Credentials` tabs). NetworkMiner confirmed the exact IP Address, operating system TTL signatures, computer name (`DESKTOP-TEYQ2NR`), and Active Directory account (`brolf`) without requiring manual display filters.

![NetworkMiner Cross-Validation](screenshots/P1_NetworkMiner_cross_validation_victim_credentials.png)

---

### Technical Evidence & Forensic Findings

#### 1. Identity Extraction via Kerberos Authentication Requests
By applying the display filter `kerberos.CNameString` in Wireshark, Authentication Service Requests (`AS-REQ`) originating from IP `10.2.28.88` toward Domain Controller `10.2.28.2` were inspected. Parsing the `req-body` structures revealed the user account name (`brolf`) and realm (`EASYAS123`).

![Kerberos Identity Extraction](screenshots/P1_kerberos_display_filter.png)

#### 2. Log Indexing & Web Traffic Summarization via Zui
To isolate web traffic without performance degradation, the capture was indexed in **Zui**. Querying the Zeek HTTP logs (`_path=="http" | cut ts, id.orig_h, id.resp_h, host, uri`) revealed recurring outbound HTTP web requests originating from victim host `10.2.28.88` directed toward an external IP address (`45.131.214[.]85`), flagging this external endpoint for deep payload inspection.

![Zui HTTP Log Triage](screenshots/P1_log_triage_http_using_zui.png)

---

## Phase 2: Attack Chain Analysis, Payload Extraction & OSINT Threat Intelligence

### Executive Summary
Following the Phase 1 flag on `45.131.214[.]85`, the HTTP traffic was analyzed in more depth. Zeek log analysis in Zui exposed a regular beaconing pattern, the TCP conversation was reassembled to inspect the raw payloads, and the destination IP was checked against OSINT sources (VirusTotal and AbuseIPDB).

### Technical Evidence & Forensic Findings

#### 1. C2 Beaconing Detection via Zeek Log Analysis in Zui
Re-querying the Zeek HTTP logs with the method field added (`_path=="http" | cut ts, id.orig_h, id.resp_h, host, uri, method`) showed that the victim machine sends **POST requests every 60 seconds** to `45.131.214[.]85`.

![Zui POST Beaconing Query Result](screenshots/P2_Zui_query_result.png)

**Anomalies detected:**
1. POST requests sent to a static HTML page
2. No DNS domain name (direct communication with an IP address)
3. Suspicious URL (`/fakeurl.com`)

> **Conclusion:** The host is actively communicating with a Command & Control (C2) server at `45.131.214[.]85` through automated POST requests (**C2 beaconing**).

#### 2. TCP Stream Reassembly & Payload Analysis
The TCP conversation was reassembled to analyze the exact data payload sent by the victim host and the response returned by the C2 server.

![HTTP Stream Reassembly](screenshots/P2_http_stream.png)

| Characteristic | Extracted Value |
| :--- | :--- |
| **Protocol & Port** | HTTP over TCP port `80` |
| **User-Agent** | `NetSupport Manager/1.3` |
| **Content-Type** | `application/x-www-form-urlencoded` |
| **Payload Characteristics** | Starts in plaintext (`CMD=POLL`), then transitions to encrypted parameters (`CMD=ENCD`, `ES=1`) |

#### 3. OSINT Threat Intelligence (VirusTotal & AbuseIPDB)

**VirusTotal findings for `45.131.214[.]85`:**
* **Detections:** 8 security vendors flagged this IP address as malicious (alphaMountain.ai, BitDefender, Dr.Web, Fortinet, G-Data, Lionic, Sophos, VIPRE).
* **Relations:** Two files are communicating with this IP address:
  * `712c7e845543e6ddd07f724b6f9a9a0e2c84fdf6d8956fdd2bef94775b2ef707`
  * `c9e5bb7a368280d771edcfdb33717a3130560d2bb71773ab1aaffe0eb585fd2c`
* **Key forensic findings extracted from the comments:**

| Attribute | Value |
| :--- | :--- |
| **Threat Type** | `botnet_cc` |
| **Confidence Level** | 100% (security analysts and threat intelligence platforms have already verified this infrastructure as active malware host infrastructure) |
| **Country** | The Netherlands |

**AbuseIPDB findings:**
* **ISP (Internet Service Provider):** MHost LLC (hosting provider, similar to AWS)
* **Country of origin:** Germany
* **Reports:** No one has reported this IP address yet

### Investigation Roadmap & Status
- [x] Phase 1: Network Triage & Victim Host Identification
- [x] Phase 2: Attack Chain Reconstruction & Payload Binary Extraction
- [ ] Phase 3: Command & Control (C2) Identification & Suricata Rule Engineering
- [ ] Phase 4: Formal Incident Response Report Compilation
