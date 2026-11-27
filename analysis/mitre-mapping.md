# MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | MSG-7741 with `Invoice_7741.xlsm`; SPF/DKIM/DMARC failures; Reply-To mismatch (09:36) |
| Execution | User Execution: Malicious File | T1204.002 | `EXCEL.EXE` opened the attachment at 09:39:27 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Excel spawned hidden `powershell.exe` with encoded command at 09:39:32 |
| Persistence | Registry Run Keys / Startup Folder | T1547.001 | `HKCU\...\Run\OneDriveUpdateCheck` → `cache_7741.dat` at 09:53:25 |
| Discovery | System Information Discovery | T1082 | `whoami /all` at 09:40:14 |
| Discovery | System Network Configuration Discovery | T1016 | `ipconfig /all` at 09:40:35 |
| Credential Access | Brute Force | T1110 | 3 failed logons (0xC000006D) for `svc_backup`, 09:56:49 to 09:58:43 |
| Collection | Data from Network Shared Drive | T1039 | 3 finance files read on FS-02, 10:04 to 10:06 |
| Collection | Archive Collected Data | T1560 | `fin_q3_review.zip` created 10:07:02 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS beaconing to 203.0.113.88, 8 Suricata alerts |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | 61,440 B POST to `/api/v2/sync` at 10:11:29 |

## Notes
- **Defense evasion** is also present (hidden window, encoded command). Consider mapping to T1027 (Obfuscated Files or Information) if the decoded payload confirms it.
- T1105 (Ingress Tool Transfer) may apply to `cache_7741.dat` creation; the dropper source is unconfirmed in the logs.
