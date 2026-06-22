# Network Traffic Analysis — Home Lab Case Study
**Douglas Taylor Jr. | IT Portfolio Project**

---

## Project Overview

This project involved capturing live network traffic from a home network, deploying Suricata IDS to analyze it, writing custom detection rules, and identifying a real anomalous event in the captured data. The goal was to simulate core SOC analyst workflows — packet capture, IDS configuration, rule authoring, and alert triage — using a live environment rather than a pre-built lab.

---

## Environment

| Component | Details |
|---|---|
| Capture Host | Windows PC (new build) |
| Packet Capture Tool | Wireshark 4.6.6 |
| Capture Driver | Npcap 1.88 (WinPcap API-compatible mode) |
| IDS Engine | Suricata 8.0.5 |
| Ruleset | Emerging Threats Open Ruleset |
| Capture File | `home_capture.pcapng` (23,503 packets, ~19.5 MB) |
| Network | Home Wi-Fi with Jellyfin media server active |

---

## Phase 1 — Packet Capture

Wireshark was installed on a Windows host and used to capture approximately 5 minutes of live Wi-Fi traffic. During the capture, a Jellyfin media server was actively streaming and several browser tabs were open, generating a realistic mix of traffic including DNS lookups, HTTPS connections, and media streaming traffic.

The capture was saved as `home_capture.pcapng` and used as the input file for all subsequent Suricata analysis.

**Why this matters:** Capturing from a live environment rather than a pre-built sample means the traffic is genuine. This creates a realistic baseline for IDS analysis and avoids the artificially clean results that come from lab-only exercises.

---

## Phase 2 — Suricata IDS Deployment

### Installation Challenges and Resolutions

Suricata 8.0.5 was installed on Windows. During initial execution, the following error occurred:

```
suricata.exe – System Error
The code execution cannot proceed because wpcap.dll was not found.
```

**Root cause:** Suricata on Windows requires Npcap to be installed in WinPcap API-compatible mode. The initial Npcap install did not have this option enabled.

**Resolution:** Npcap was uninstalled and reinstalled via the Wireshark installer with the "Install Npcap in WinPcap API-compatible Mode" checkbox enabled. This resolved the dependency error.

**Portfolio takeaway:** Troubleshooting dependency errors like this is a routine part of deploying security tools in real environments. Understanding *why* the error occurred — not just how to fix it — is what matters.

### Running Suricata Against the Capture

Suricata was run from the command line using the `-r` flag (read from pcap) and `-l` flag (log output directory):

```
suricata.exe -r "C:\Users\lasta\Documents\home_capture.pcapng" -l "C:\Program Files\Suricata\logs" -S "C:\Program Files\Suricata\rules\custom.rules"
```

On first run without rules loaded, Suricata successfully processed all 23,503 packets but produced no alerts — expected behavior with no ruleset.

---

## Phase 3 — Emerging Threats Ruleset

The Emerging Threats Open ruleset was downloaded manually using curl with the `--ssl-no-revoke` flag to bypass a Windows SSL revocation check issue:

```
curl -L --ssl-no-revoke -o "C:\Program Files\Suricata\rules\emerging.rules.tar.gz" https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz
```

The archive was extracted to `C:\Program Files\Suricata\rules\rules\`, yielding 59 rule files covering categories including malware, exploits, phishing, shellcode, DNS anomalies, and more.

Suricata was run against the home capture using the `emerging-malware.rules` and `emerging-hunting.rules` rulesets. Both returned clean results — no alerts generated.

**Why clean results are still valuable:** A clean IDS result against known-good home traffic is a meaningful baseline. It confirms the IDS is functioning correctly and that the network does not exhibit patterns associated with known malware families. In a SOC context, establishing a clean baseline is the first step before threat hunting.

---

## Phase 4 — Custom Detection Rules

Three custom rules were written and saved to `custom.rules` to demonstrate rule authoring skills:

### Rule 1 — ICMP Ping Detection

```
alert icmp any any -> $HOME_NET any (msg:"PING detected on home network"; sid:1000001; rev:1;)
```

**Result:** Fired successfully. Detected ICMP traffic from the home router (`172.20.10.1`) and several external IPs including Cloudflare (`172.66.0.227`) and others.

### Rule 2 — Suspicious Port Detection (Refined)

Initial version flagged all non-port-80 traffic, producing excessive false positives — a deliberate learning exercise in rule tuning. The rule was refined through three revisions to target only known attacker ports:

```
alert tcp any any -> $HOME_NET [4444,1337,31337,6667,6666] (msg:"Suspicious port connection detected"; sid:1000002; rev:3;)
```

**Ports targeted:** Common attacker infrastructure ports associated with remote access trojans (RATs), backdoors, and IRC-based botnets.

**Result:** No alerts on home traffic — correct outcome. Home network traffic does not use these ports.

**Key learning:** The iterative refinement process demonstrated the difference between a noisy rule and a precise one — a critical skill in SOC environments where alert fatigue is a real operational problem.

### Rule 3 — HTTP Traffic Detection

```
alert http any any -> $HOME_NET any (msg:"HTTP traffic detected"; sid:1000003; rev:1;)
```

**Result:** No alerts. All web traffic in the capture was encrypted HTTPS. This is a positive security indicator for the home network.

---

## Phase 5 — Anomaly Detection: Real Suspicious Event

During analysis of the home capture with the broad suspicious port rule, the following traffic was flagged:

```
06/22/2026-00:15:26  [1:1000002] Suspicious port connection detected
{TCP} 34.159.75.126:7500 -> 172.20.10.11:61929

06/22/2026-00:18:17  [1:1000002] Suspicious port connection detected
{TCP} 34.159.75.126:7500 -> 172.20.10.11:61929
```

**Observation:** A single external IP (`34.159.75.126`) made repeated connections to the host on port 7500, appearing twice within the 5-minute capture window.

**Analysis:** Port 7500 is non-standard and not associated with common consumer services. The repeated connection from a single external IP warrants further investigation. This could represent a legitimate application using a non-standard port, or potentially unsanctioned outbound communication.

**Response (simulated):** A targeted detection rule was written to monitor for this specific behavior going forward:

```
alert tcp any 7500 -> $HOME_NET any (msg:"Anomalous inbound connection on non-standard port 7500"; sid:1000004; rev:1;)
```

This rule fired twice on the capture, confirming detection of the anomalous traffic pattern.

**Portfolio takeaway:** This demonstrates the full SOC analyst workflow — from raw packet capture to anomaly identification to targeted rule creation. The event was discovered organically from real traffic, not a pre-built lab scenario.

---

## Summary of Detections

| Rule ID | Description | Result |
|---|---|---|
| 1000001 | PING detected on home network | Fired — ICMP from router and external IPs |
| 1000002 | Suspicious attacker port connection | Clean — no known attacker ports found |
| 1000003 | Unencrypted HTTP traffic | Clean — all traffic encrypted (HTTPS) |
| 1000004 | Anomalous connection on port 7500 | Fired — repeated connections from 34.159.75.126 |

---

## Tools Used

- Wireshark 4.6.6
- Npcap 1.88
- Suricata IDS 8.0.5
- Emerging Threats Open Ruleset
- Windows Command Prompt (Administrator)

---

## Skills Demonstrated

- Live packet capture from a production home network
- IDS deployment and configuration on Windows
- Dependency troubleshooting (wpcap.dll / Npcap)
- Manual ruleset installation and extraction
- Custom Suricata rule authoring (4 rules across ICMP, TCP, HTTP protocols)
- Rule tuning to reduce false positives
- Alert triage and anomaly identification from real traffic
- Incident documentation

---

*This project is part of an ongoing IT/cybersecurity home lab portfolio targeting SOC Analyst and cybersecurity roles.*
