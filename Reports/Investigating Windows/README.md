# Incident Summary Report: INVESTAGING WINDOWS(TRYHACKME)

**Incident ID:** INC-2019-0302  
**Date of Incident:** 03/02/2019  
**Severity:** Critical  
**Status:** Contained / Remediated  
**Lead Investigator:** SOC Triage  

---

## 1. Executive Summary
On March 2, 2019, an unauthorized external adversary breached the internal Windows production web server. The attacker uploaded web shells via the Internet Information Services (IIS) web server, escalated to local administrative privileges, harvested host credentials via Mimikatz, and established persistence mechanisms using scheduled tasks and a rogue administrator account. Inbound firewall modifications and local DNS redirection were also confirmed.

---

## 2. Timeline of Events (MITRE ATT&CK Mapping)

### Initial Access & Execution (T1505.003 - Web Shell)
* The threat actor gained initial footholds through IIS web uploads into `C:\inetpub\wwwroot\`.
* Web shell backdoors (`b.jsp`, `tests.jsp`) were staged to execute arbitrary remote commands.
  ![Web shell files in IIS directory](./img/01-web-shell.png)

### Privilege Escalation (T1078 - Valid Accounts / Token Elevation)
* **Timestamp:** `03/02/2019 04:04:49 PM`
* System assigned administrative user tokens, recorded under **Event ID 4672** (*Special privileges assigned to new logon*).
  ![Event 4672 log entry](./img/02-event-4672.png)

### Credential Access (T1003 - OS Credential Dumping)
* The adversary dropped `mim.exe` into staging directory `C:\TMP\`.
* Execution output was dumped to `C:\TMP\mim-out.txt`, harvesting local SAM / LSASS credentials using **Mimikatz**.
  ![Mimikatz output in C:\TMP](./img/03-mimikatz.png)

### Persistence (T1053.005 - Scheduled Task & T1136.001 - Local Account)
* Created a rogue local administrative user named **`Jenny`** (`Last logon: Never`, indicating dormant persistence).
* Scheduled task **`Clean file system`** was configured to execute `nc.ps1` (Netcat PowerShell backdoor).

### Command and Control / Defense Evasion (T1562.004 & T1565.001)
* Added inbound Windows Firewall rule allowing traffic on port **`1337`** (`"Allow outside connections for development"`).
* Manipulated the host resolver file (`C:\Windows\System32\drivers\etc\hosts`) to redirect `google.com` traffic to external C2 IP **`76.32.97.132`**.
  ![Hosts file redirection](./img/05-hosts-dns.png)

---

## 3. Indicators of Compromise (IOCs)

| Artifact Type | Value / Identifier | Forensic Context |
| :--- | :--- | :--- |
| **External IP** | `76.32.97.132` | C2 redirection target in `hosts` |
| **Network Port** | `1337` | Unauthorized inbound firewall exception |
| **File Path** | `C:\TMP\mim.exe` / `mim-out.txt` | Credential dumping binary and output |
| **File Path** | `C:\inetpub\wwwroot\b.jsp` | Uploaded web shell backdoor |
| **Rogue User** | `Jenny` (Local Administrators group) | Dormant persistence account |
| **Scheduled Task** | `Clean file system` -> `nc.ps1` | Persistent reverse shell trigger |

---

## 4. Recommended Remediation & Containment Actions

1. **Host Isolation:** Disconnect the affected host from the internal network segment immediately.
2. **Account Revocation:** Delete rogue user `Jenny` and enforce an enterprise-wide password reset for all administrative accounts.
3. **Artifact Cleanup:**
   * Delete `b.jsp` and `tests.jsp` from `C:\inetpub\wwwroot\`.
   * Purge directory `C:\TMP\`.
   * Unregister scheduled task `Clean file system` via `schtasks /delete /tn "Clean file system" /f`.
4. **Network & System Hardening:**
   * Revert `C:\Windows\System32\drivers\etc\hosts` to default settings.
   * Remove the unauthorized firewall rule opening port `1337`.
   * Patch the web application vulnerability in IIS that allowed arbitrary file upload.
