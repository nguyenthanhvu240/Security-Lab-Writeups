# Google SecOps CTF Writeup

## Overview

This CTF takes place entirely inside Google SecOps (Chronicle SIEM). All investigation is done using UDM (Unified Data Model) Search queries against real log sources: Zscaler NSS proxy logs, Windows Sysmon events, Okta audit logs, and Google Workspace activity logs. The environment contains multiple tenants (LUNARSTIIINESS.COM, Demoverse, stackedpads.local) so queries must be scoped to the Cymbal tenant to avoid noise from unrelated data.

The three rooms are:

- Room 1: Deceptive Click — FAKEUPDATES malware infection
- Room 2: OAuth Heist — ShinyHunters / UNC6240 credential theft and OAuth abuse
- Room 3: Rogue Synthesis — AI-assisted supply chain attack (QUIETVAULT / PROMPTFLUX)

---

## Room 1: Deceptive Click

### Background

The victim is `marcus.vance`, a Cymbal employee. The attacker delivered a fake Chrome update through a malicious website, which dropped a JavaScript-based malware loader (FAKEUPDATES). The loader executed a binary that performed process injection, then the attacker moved laterally using a compromised service account.

### Flag 1 — Compromised Endpoint Hostname

The starting point is identifying which machine marcus.vance was using when the incident occurred. Okta SSO logs record the device name at login time.

Query:

```
principal.user.userid = "marcus.vance"
AND metadata.log_type = "OKTA"
```

The result contains an Okta SSO event with a `device` field set to `CYM-DEN-W10-042`. This is the compromised workstation.

Flag: `CYM-DEN-W10-042`

### Flag 2 — Malware Delivery Referer Domain

The FAKEUPDATES dropper is typically delivered when a user visits a compromised website that redirects them to a fake update page. The fake update is a ZIP file disguised as a Chrome installer. Zscaler proxy logs record the referer URL of each HTTP request.

The query looks for GET requests from marcus.vance that downloaded a ZIP file:

```
principal.user.userid = "marcus.vance"
AND metadata.log_type = "ZSCALER_WEBPROXY"
AND network.http.method = "GET"
AND target.url = /\.zip/
```

The result shows a download of `ChromeSetup_v124.zip`. The `network.http.referral_url` field on that event contains the domain the user was on before being redirected: `marketingtrends-insider.com`.

Flag: `marketingtrends-insider.com`

### Flag 3 — Injected Process PID

After the ZIP is extracted and the dropper runs, it injects into a legitimate Windows process using process hollowing. Sysmon Event ID 8 (CreateRemoteThread) captures when one process creates a thread inside another, which is the telltale sign of process injection.

Query:

```
principal.hostname = "CYM-DEN-W10-042.cymbal.corp"
AND metadata.product_event_type = "8"
```

The event shows the source process as `d27e15eb.exe` (the malware binary) and the target process as `svchost.exe` with PID `624`.

Flag: `624`

### Flag 4 — Kerberoasted SPN

With a foothold inside svchost, the attacker performs Kerberoasting — requesting a Kerberos service ticket for a service account to crack offline. Windows Event ID 4769 logs Kerberos ticket requests. RC4 encryption (EncryptionType 0x17) is the indicator because it is weaker and specifically requested by attackers to make cracking easier.

Query:

```
principal.user.userid = "marcus.vance"
AND metadata.product_event_type = "4769"
AND metadata.log_type = "WINDOWS_SYSMON"
```

The event shows a ticket request for the SPN `MSSQLSvc/CYM-DB-01.cymbal.corp:1433` with TicketEncryptionType `0x17`.

Flag: `MSSQLSvc/CYM-DB-01.cymbal.corp:1433`

### Flag 5 — Lateral Movement Account

After cracking the service ticket, the attacker uses the recovered credentials to move laterally. Windows Event ID 4624 (Logon) records successful authentication events. The target is the file server `CYM-FS-01`.

Query:

```
target.hostname = "CYM-FS-01.cymbal.corp"
AND metadata.product_event_type = "4624"
AND metadata.log_type = "WINDOWS_SYSMON"
```

The event shows a Type 3 (network) logon by account `svc_backup` from the compromised workstation.

Flag: `svc_backup`

### Flag 6 — Staged Exfiltration Archive

Once on the file server, the attacker stages data for exfiltration by creating a ZIP archive. Sysmon Event ID 11 (FileCreate) captures file creation events.

Query:

```
principal.hostname = "CYM-FS-01.cymbal.corp"
AND metadata.product_event_type = "11"
AND principal.user.userid = "svc_backup"
```

The event shows creation of `Financial_Audit_2026.zip` on the file server.

Flag: `Financial_Audit_2026.zip`

---

## Room 2: OAuth Heist

### Background

The threat actor is UNC6240 (ShinyHunters). The attack begins with a vishing call to obtain credentials, followed by an adversary-in-the-middle (AiTM) phishing site to capture the session token and bypass MFA. The attacker then grants a malicious OAuth application access to the victim's Gmail and uses it to delete evidence. After reconnaissance on Google Drive, the attacker uses a service account credential found in a document to dump a database and exfiltrate data.

The victim is `elena.rostova`.

### Flag 1 — AiTM Phishing Domain

The attacker directs the victim to a phishing domain that proxies the real Okta login page. Zscaler logs record the POST request where credentials are submitted.

Query:

```
principal.user.userid = "elena.rostova"
AND metadata.log_type = "ZSCALER_WEBPROXY"
AND network.http.method = "POST"
AND target.url = /okta|sso|signin|identity|cymbal/
```

One of the results shows a POST to `sso-cymbal-portal.com`, which is the phishing domain.

Flag: `sso-cymbal-portal.com`

### Flag 2 — Email Subject Deleted by Attacker

After gaining access, the attacker uses the malicious OAuth app to delete emails that would alert the victim to the compromise. Google Workspace activity logs record Gmail deletion events. The attacker's IP was identified from Okta as `23.234.119.110`.

Query:

```
metadata.log_type = "WORKSPACE_ACTIVITY"
AND principal.ip = "23.234.119.110"
AND metadata.product_event_type = "message_deleted"
```

The results show two deletion events. The first deleted email at 19:55:38 UTC has the subject `Okta: A new MFA factor was added`. This is the alert the attacker wanted to suppress immediately after registering a new MFA device.

Flag: `Okta: A new MFA factor was added`

### Flag 3 — Google Drive Document Downloaded

The attacker searched Google Drive for documents containing database credentials. Workspace activity logs record Drive access events including item downloads.

Query:

```
metadata.log_type = "WORKSPACE_ACTIVITY"
AND principal.ip = "23.234.119.110"
AND metadata.product_event_type = "item_download"
```

The event shows the attacker downloaded `Cymbal_Q3_Database_Architecture_and_Service_Accounts.pdf`.

Flag: `Cymbal_Q3_Database_Architecture_and_Service_Accounts.pdf`

### Flag 4 — Database Dump Tool

Using credentials found in the PDF, the attacker connected to the database server and ran a dump. Sysmon Event ID 1 (ProcessCreate) records process executions with full command lines.

Query:

```
principal.user.userid = "svc_dbadmin"
AND metadata.product_event_type = "1"
AND metadata.log_type = "WINDOWS_SYSMON"
```

The event shows execution of `sqlcmd.exe` with flags to connect to the database and export data.

Flag: `sqlcmd.exe`

### Flag 5 — Malicious OAuth Application

The attacker registered a third-party OAuth application and tricked the victim into granting it access. Workspace activity logs record OAuth token grants.

Query:

```
metadata.log_type = "WORKSPACE_ACTIVITY"
AND principal.ip = "23.234.119.110"
AND metadata.product_event_type = "authorize"
```

The event shows an OAuth grant to a client application named `ToggleBox Recall` with a recorded `client_id`.

Flag: `ToggleBox Recall`

### Flag 6 — Exfiltration Destination

The final step of the attack is data exfiltration. The attacker used the `svc_dbadmin` account to send the dumped data out to a remote server. Zscaler logs capture outbound connections.

Query:

```
principal.user.userid = "svc_dbadmin"
AND metadata.log_type = "ZSCALER_WEBPROXY"
AND network.http.method = "POST"
```

The result shows a POST to destination IP `142.11.200.188` on port `8888`.

Flag: `142.11.200.188:8888`

---

## Room 3: Rogue Synthesis

### Background

The threat actor uses two malware families documented in the GTIG AI Threat Tracker:

- QUIETVAULT: A malicious VS Code extension hosted on a typosquatted CDN that masquerades as a legitimate developer tool. It runs a Node.js daemon that calls an AI API to generate and compile a second-stage payload.
- PROMPTFLUX: A VBScript-based malware that uses the Gemini API for command generation.

The victim is `alex.chen`, a developer on `CYM-DEV-WS-019.cymbal.corp`. After infecting the workstation, the attacker harvests Google Cloud credentials and pivots laterally to a CI/CD pipeline server to establish persistence.

### Flag 1 — Gemini Model Used by Malware

The malicious VS Code extension runs a Node.js script (`optimizer-daemon.js`) that makes HTTP calls to the Gemini API. Zscaler logs capture the outbound request.

Query:

```
principal.user.userid = "alex.chen"
AND metadata.log_type = "ZSCALER_WEBPROXY"
AND target.url = /generativelanguage\.googleapis\.com/
```

The request URL contains the model name in the path: `gemini-1.5-flash-latest`. The user-agent on the request is `node-fetch`, confirming it was made by the Node.js daemon and not by the user's browser.

Flag: `gemini-1.5-flash-latest`

### Flag 2 — Malicious VS Code Extension Package Name

The extension was downloaded from a typosquatted marketplace CDN before it executed. Zscaler GET logs record the download.

Query:

```
principal.user.userid = "alex.chen"
AND metadata.log_type = "ZSCALER_WEBPROXY"
AND network.http.method = "GET"
AND target.url = /\.vsix/
```

The result shows a download of `SyntaxOptimizer-2.1.4.vsix` at 20:16:43 UTC. The full package identifier from the URL is `devtools.syntaxoptimizer-2.1.4`.

Flag: `devtools.syntaxoptimizer-2.1.4`

### Flag 3 — Compiled Second-Stage Payload

After the Gemini API call, the daemon used `gcc` to compile a binary. Sysmon Event ID 1 captures the compilation command.

Query:

```
principal.hostname = "CYM-DEV-WS-019.cymbal.corp"
AND metadata.product_event_type = "1"
AND target.process.command_line = /gcc/
```

The command line shows `gcc` compiling a C source file into the output binary `sys_worker.exe`.

Flag: `sys_worker.exe`

### Flag 4 — Harvested Credential File

After `sys_worker.exe` executed via process hollowing, it read the Google Cloud credentials file from disk. Sysmon Event ID 11 (FileCreate) or Event ID 10 (ProcessAccess) captures file access. The standard location for gcloud CLI credentials is a known path.

Query:

```
principal.hostname = "CYM-DEV-WS-019.cymbal.corp"
AND metadata.product_event_type = "11"
AND target.file.full_path = /credentials/
```

The event shows the malware reading `.gcloud/credentials.db`, which stores OAuth tokens for the gcloud CLI. This gave the attacker access to the `cymbal-prod-cluster` Google Cloud project.

Flag: `.gcloud/credentials.db`

### Flag 5 — Exfiltration Endpoint

With credentials harvested, the malware sent them to the attacker's command and control server. Zscaler logs capture the outbound POST.

Query:

```
principal.user.userid = "alex.chen"
AND metadata.log_type = "ZSCALER_WEBPROXY"
AND network.http.method = "POST"
AND target.url = /dev-metrics-cdn/
```

The result shows a POST at 20:52:08 UTC to `dev-metrics-cdn.com/api/v2/telemetry`.

Flag: `dev-metrics-cdn.com/api/v2/telemetry`

### Flag 6 — PowerShell Script Overwritten for Persistence

Using the harvested gcloud credentials, the attacker authenticated to the service account `svc_cicd_deploy` and connected to the CI/CD pipeline server via WinRM (Windows Remote Management, port 5985). This lateral movement was captured in Sysmon Event ID 3 at 21:48:43 UTC showing a connection from `CYM-DEV-WS-019.cymbal.corp` (10.240.12.80) to `CYM-CI-RUNNER-01.cymbal.corp` (10.240.12.85).

To find the persistence script, search for Sysmon Event ID 11 (FileCreate) on the CI/CD runner for PowerShell writing `.ps1` files:

Query:

```
principal.hostname = "CYM-CI-RUNNER-01.cymbal.corp"
AND metadata.product_event_type = "11"
AND target.file.full_path = /\.ps1/
```

The event at 22:01:28 UTC shows PowerShell (PID 3410) overwriting `C:\BuildRunner\scripts\build_production.ps1` as user `CYMBAL\svc_cicd_deploy`. The Sysmon rule tag on the event is `technique_id=T1505.003,technique_name=Build Hook Injection`, confirming the attacker modified the build pipeline script so their code would execute on every future build.

Flag: `build_production.ps1`
