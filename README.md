# Network Traffic Analysis — Home Lab

## Overview
Captured live network traffic from a home environment and deployed Suricata IDS to analyze it. Wrote custom detection rules, applied the Emerging Threats Open ruleset, and identified a real anomalous event in the captured data.

## Tools Used
- Wireshark 4.6.6 — packet capture
- Npcap 1.88 — Windows packet capture driver
- Suricata 8.0.5 — intrusion detection engine
- Emerging Threats Open Ruleset — community IDS signatures

## What I Did
1. Captured ~5 minutes of live Wi-Fi traffic using Wireshark (23,503 packets)
2. Deployed Suricata IDS on Windows and resolved Npcap dependency issues
3. Downloaded and applied the Emerging Threats Open ruleset
4. Authored 4 custom Suricata detection rules covering ICMP, TCP, and HTTP
5. Identified a real anomalous event — repeated connections from an external IP on non-standard port 7500
6. Wrote a targeted detection rule around the identified anomaly

## Files
| File | Description |
|---|---|
| `network_traffic_analysis_casestudy.md` | Full technical write-up and incident report |
| `custom.rules` | Custom Suricata detection rules |
| `home_capture.pcapng` | Raw packet capture from home network |

## Key Findings
- Home network baseline verified clean against Emerging Threats malware and hunting rulesets
- All web traffic encrypted (HTTPS) — no plaintext HTTP detected
- Anomalous repeated connections detected from `34.159.75.126` on port 7500 — custom rule written and validated

## Skills Demonstrated
Wireshark · Suricata IDS · Custom rule authoring · Alert triage · Network baseline analysis · IDS troubleshooting · Incident documentation
