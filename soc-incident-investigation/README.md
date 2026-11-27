# SOC Incident Investigation: Phishing → C2 Beaconing → Persistence → Finance Data Exfiltration

**Incident ID:** FIN-WS-044 | **Date:** 2026-10-22 | **Severity:** Critical | **Status:** Open (containment pending in logs)

## Summary
A phishing email with the macro-enabled attachment `Invoice_7741.xlsm` reached user `j.morgan` despite failing SPF, DKIM and DMARC. Opening the file caused Excel to launch a hidden, encoded PowerShell process on `FIN-WS-044`. The attacker ran host discovery, established recurring HTTPS beaconing to `203.0.113.88`, set Registry Run key persistence, made failed password attempts against `svc_backup`, then read three finance files on `FS-02`, zipped them, and uploaded a 61,440-byte archive to the C2 domain. EDR recommended containment about 56 minutes after the first high-severity event, but the action stayed pending.

## Key Findings
| Item | Detail |
|---|---|
| Patient zero | `j.morgan` on `FIN-WS-044` (10.20.14.44) |
| Initial vector | Phishing, `Invoice_7741.xlsm` (T1566.001) |
| C2 | `cdn-sync-check.example` → `203.0.113.88:443`, 8 beacon alerts about every 5 min |
| Persistence | `HKCU\...\Run\OneDriveUpdateCheck` → `%TEMP%\cache_7741.dat` |
| Exfil | `fin_q3_review.zip` (61,440 B) POSTed to `/api/v2/sync` |
| Detection gap | 09:39:32 first high-severity event → 10:35:29 containment recommended (about 56 min), never executed |

**Exfil evidence:** the three files read on FS-02 (20,480 + 16,384 + 24,576 bytes) total exactly 61,440 bytes, matching both the ZIP size and the proxy POST size.

## Skills Demonstrated
- Log analysis in Splunk (SPL): pivoting on IPs, filenames and accounts; beacon-interval calculation; byte-size correlation
- Multi-source log correlation (mail gateway, Sysmon, DNS, proxy, firewall, Suricata, EDR, Windows Security)
- Timeline reconstruction and attack-chain analysis
- MITRE ATT&CK mapping with evidence per technique
- IOC extraction and response actions
- Root cause analysis and detection recommendations
- Incident reporting for technical and executive audiences

## Repository Contents
| Path | Description |
|---|---|
| [`report/Incident_Report.pdf`](report/Incident_Report.pdf) | Full incident report |
| [`analysis/timeline.md`](analysis/timeline.md) | Minute-by-minute timeline with sources and ATT&CK IDs |
| [`analysis/iocs.csv`](analysis/iocs.csv) | Indicators of compromise with recommended actions |
| [`analysis/mitre-mapping.md`](analysis/mitre-mapping.md) | ATT&CK mapping with log evidence |
| [`evidence/screenshots/`](evidence/screenshots/) | Splunk screenshots: PowerShell, beaconing, persistence, exfiltration |

## Note on Data
This investigation uses a training lab dataset (SOC War Room Advanced Lab). All hostnames, users, IPs and domains are fictional (RFC 5737 IPs, `.example` domains). Raw lab logs are not included in this repo.

## Tools & Data Sources
Splunk Enterprise · Mail gateway logs · Sysmon · Windows Security logs · DNS · Web proxy · Firewall · Suricata · EDR

## License
MIT. See [LICENSE](LICENSE).
