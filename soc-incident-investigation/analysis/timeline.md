# Incident Timeline: FIN-WS-044 (2026-10-22, all times UTC)

_Splunk screenshots show IST (UTC+5:30); for example 3:09:32 PM IST = 09:39:32Z._

| Time | Source | Event | ATT&CK |
|---|---|---|---|
| 09:36:21 | Mail gateway | MSG-7741 from 198.51.100.77 delivered to j.morgan with `Invoice_7741.xlsm`. SPF softfail, DKIM fail, DMARC fail, attachment score 68. | T1566.001 |
| 09:36:49 | Mail gateway | From/Reply-To mismatch: From `billing-northwind.example`, Reply-To `invoice-review@northwind-payments.example`. | T1566.001 |
| 09:39:27 | Sysmon | `EXCEL.EXE` opens `C:\Users\j.morgan\Downloads\Invoice_7741.xlsm`. | T1204.002 |
| 09:39:32 | Sysmon | Excel spawns hidden `powershell.exe` with an encoded command (integrity Medium). **First high-severity event.** | T1059.001 |
| 09:40:14 | Sysmon | PowerShell runs `whoami /all`. | T1082 |
| 09:40:35 | Sysmon | PowerShell runs `ipconfig /all`. | T1016 |
| 09:42:16 | DNS | Host resolves `cdn-sync-check.example` → 203.0.113.88 (TTL 60, first-ever query). | T1071.001 |
| 09:43:22 | Proxy | CONNECT to the domain allowed (844 B out / 1,720 B in), UA `WindowsPowerShell/5.1`, category `newly_seen`. | T1071.001 |
| 09:49:16 | Firewall | 10.20.14.44 → 203.0.113.88:443 allowed (FW-0001). | T1071.001 |
| 09:49:34 | Suricata | **Beacon alert #1** (periodic TLS, FLOW-0001). | T1071.001 |
| 09:51:06 | Sysmon | `cache_7741.dat` (18,432 B) created in Temp. | T1105 |
| 09:53:25 | Sysmon | Run key `OneDriveUpdateCheck` set to `cache_7741.dat`. | T1547.001 |
| 09:54:27 | Suricata | Beacon alert #2 (FLOW-0002). | T1071.001 |
| 09:56:49 | Windows Security | Failed network logon, `svc_backup` (0xC000006D). | T1110 |
| 09:57:15 | Windows Security | Failed network logon, `svc_backup`. | T1110 |
| 09:58:43 | Windows Security | Failed network logon, `svc_backup`. | T1110 |
| 09:59:29 | Suricata | Beacon alert #3. | T1071.001 |
| 10:04:05 | Suricata | Beacon alert #4. | T1071.001 |
| 10:04:26 | Windows Security (FS-02) | j.morgan reads `Q3_Forecast.xlsx` (20,480 B). | T1039 |
| 10:05:27 | Windows Security (FS-02) | Reads `Payroll_Adjustments.xlsx` (16,384 B). | T1039 |
| 10:06:03 | Windows Security (FS-02) | Reads `Board_Forecast.xlsx` (24,576 B). | T1039 |
| 10:07:02 | Sysmon | `fin_q3_review.zip` (61,440 B) created in Temp. | T1560 |
| 10:09:40 | Suricata | Beacon alert #5. | T1071.001 |
| 10:11:29 | Proxy | POST of 61,440 B to `cdn-sync-check.example/api/v2/sync` (`application/octet-stream`, HTTP 200, 512 B response). | T1041 |
| 10:14:36 | Suricata | Beacon alert #6. | T1071.001 |
| 10:19:11 | Suricata | Beacon alert #7. | T1071.001 |
| 10:22:36 | EDR | "Run key references temp path", action `alert_only`. | T1547.001 |
| 10:24:00 | Suricata | Beacon alert #8 (last). | T1071.001 |
| 10:35:29 | EDR | `containment_recommended` ("multiple correlated indicators"), action **pending**. | n/a |
| 12:30:39 | n/a | End of data. No isolation, containment or removal logged. | n/a |

## Key Intervals
- Delivery → execution: **~3 min** (09:36:21 → 09:39:27)
- First high-severity event → first beacon alert: **~10 min**
- Archive created → exfil POST: **~4.5 min**
- Last file read → exfil POST: **~5.5 min**
- First high-severity event → containment recommended: **~56 min**
- Beacon cadence: roughly every 5 minutes, 8 alerts over about 35 minutes
