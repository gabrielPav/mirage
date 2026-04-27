# Detection Guide - Identifying Malicious Config Remediation

This guide documents how to detect the Mirage attack pattern in a real AWS environment.

---

## What You're Looking For

An attacker has deployed Config rules with inverted logic: rules that flag *secure* configurations as non-compliant and trigger remediation that *undoes* hardening. The attacker's credentials are gone. The loop runs under AWS service roles.

---

## Detection Signal 1: The Undo Delta (Highest Confidence)

**What it is:** An engineer hardens a resource, and SSM Automation weakens the same resource within minutes.

**How to find it in CloudTrail:**

Query for hardening events followed by SSM weakening events on the same resource within a 5-minute window:

```
Hardening events (note: PutBucketPolicy and PutKeyPolicy are ambiguous - the same API can apply a restrictive OR a permissive policy, so the policy body must be inspected. CreateNetworkAclEntry is hardening only when ruleAction=deny):

  PutBucketPolicy, PutBucketPublicAccessBlock
  RevokeSecurityGroupIngress
  CreateNetworkAclEntry
  PutKeyPolicy
  DetachRolePolicy, DeleteRolePolicy

Weakening events (same resource, within 5 min):

  StartAutomationExecution (source: ssm.amazonaws.com)
  DeleteBucketPolicy
  AuthorizeSecurityGroupIngress
  DeleteNetworkAclEntry
```

**Athena query (if CloudTrail logs are in S3):**

```sql
-- Joins on a shared resource identifier extracted from each event's
-- requestParameters. The SSM execution's parameters.ResourceId field carries
-- the target resource (bucket name, SG id, etc.); the hardening event carries
-- it under bucketName / groupId / networkAclId / keyId / roleName.
SELECT
  h.eventtime AS harden_time,
  h.eventname AS harden_action,
  h.useridentity.arn AS hardened_by,
  s.eventtime AS ssm_time,
  s.eventname AS ssm_action,
  ABS(to_unixtime(cast(s.eventtime AS timestamp)) -
      to_unixtime(cast(h.eventtime AS timestamp))) AS delta_seconds
FROM cloudtrail_logs h
JOIN cloudtrail_logs s
  ON COALESCE(
       json_extract_scalar(h.requestparameters, '$.bucketName'),
       json_extract_scalar(h.requestparameters, '$.groupId'),
       json_extract_scalar(h.requestparameters, '$.networkAclId'),
       json_extract_scalar(h.requestparameters, '$.keyId'),
       json_extract_scalar(h.requestparameters, '$.roleName')
     ) = element_at(
       cast(json_extract(s.requestparameters, '$.parameters.ResourceId') AS array<varchar>),
       1
     )
WHERE h.eventname IN (
        'PutBucketPolicy','PutBucketPublicAccessBlock',
        'RevokeSecurityGroupIngress','CreateNetworkAclEntry',
        'PutKeyPolicy','DetachRolePolicy','DeleteRolePolicy'
      )
  AND s.eventsource = 'ssm.amazonaws.com'
  AND s.eventname = 'StartAutomationExecution'
  AND ABS(to_unixtime(cast(s.eventtime AS timestamp)) -
          to_unixtime(cast(h.eventtime AS timestamp))) < 300
ORDER BY delta_seconds ASC;
```

---

## Detection Signal 2: Audit Your Config Rules

This is rarely done in real environments. Run this check monthly:

```bash
# List all custom Lambda-backed Config rules
aws configservice describe-config-rules \
  --query "ConfigRules[?Source.Owner=='CUSTOM_LAMBDA'].[ConfigRuleName,Source.SourceIdentifier]" \
  --output table

# For each rule, check who created it
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutConfigRule \
  --query "Events[*].[EventTime,Username,CloudTrailEvent]"
```

**Red flags:**
- Rules created by IAM users/roles that don't normally manage compliance
- Rules created outside business hours
- Rules with no CloudFormation/Terraform stack tags
- Rules whose Lambda ARN points to a function you don't recognize

---

## Detection Signal 3: Inspect Lambda Code Behind Config Rules

A rule named `s3-bucket-policy-compliance` should have Lambda code that flags *missing* encryption or *open* access as non-compliant. If the code flags *present* policies as non-compliant, that's the smoking gun.

```bash
# Get the Lambda ARN for a Config rule
LAMBDA_ARN=$(aws configservice describe-config-rules \
  --config-rule-names s3-bucket-policy-compliance \
  --query "ConfigRules[0].Source.SourceIdentifier" \
  --output text)

# Download and inspect the code
aws lambda get-function --function-name $LAMBDA_ARN \
  --query "Code.Location" --output text | xargs curl -o /tmp/rule.zip

unzip -p /tmp/rule.zip | grep -E "NON_COMPLIANT|COMPLIANT"
```

**Inverted logic signatures to grep for:**
- `NON_COMPLIANT` returned when a policy/encryption/restriction *exists*
- `COMPLIANT` returned when `0.0.0.0/0` or `AllowAll` is present
- `delete_bucket_policy`, `authorize_security_group_ingress` in remediation code

---

## Detection Signal 4: Inspect SSM Automation Documents

```bash
# List all SSM Automation documents not owned by Amazon
aws ssm list-documents \
  --filters Key=Owner,Values=Self \
  --query "DocumentIdentifiers[*].[Name,CreatedDate,Owner]" \
  --output table

# Inspect a specific document
aws ssm get-document --name AWS-S3BucketPolicyRemediation --document-format YAML
```

**Red flags in SSM document content:**
- `delete_bucket_policy` / `DeleteBucketPolicy`
- `authorize_security_group_ingress` / `AuthorizeSecurityGroupIngress`
- `0.0.0.0/0` or `::/0` in CIDR ranges
- `delete_network_acl_entry` removing DENY rules
- `"Principal": "*"` or `"AWS": "*"` in any policy body the document constructs
- `put_key_policy` calls combined with a wildcard principal in the policy body
  (the API call alone is ambiguous - inspect the policy it pushes)
- `attach_role_policy` calls referencing `AdministratorAccess`, `PowerUserAccess`,
  or any policy that grants more than the role had before

---

## Detection Signal 5: Config Cost Spike

A remediation loop (Config evaluates → SSM fires → resource changes → Config evaluates again) will spike your Config bill before any security alert fires.

**Set a CloudWatch alarm:**

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "ConfigEvaluationSpike" \
  --metric-name "ConfigRuleEvaluationsCount" \
  --namespace "AWS/Config" \
  --statistic Sum \
  --period 3600 \
  --threshold 1000 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions <your-sns-topic-arn>
```

An unusual spike in Config evaluations, especially correlated with SSM Automation executions, is a strong signal.

---

## Detection Signal 6: EventBridge Rule for New Config Rules

Alert on any new Config rule creation:

```json
{
  "source": ["aws.config"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["PutConfigRule", "PutRemediationConfigurations"],
    "userIdentity": {
      "type": ["IAMUser", "AssumedRole"]
    }
  }
}
```

Route this to SNS/Slack. Every new Config rule should be reviewed against your IaC pipeline. If it wasn't deployed by Terraform/CloudFormation, it needs an explanation.

---

## Containment

If you find a rogue Config rule:

1. **Disable auto-remediation first** (before deleting the rule, to stop the loop):
   ```bash
   aws configservice delete-remediation-configuration \
     --config-rule-name <rule-name> \
     --resource-type <resource-type>
   ```

2. **Delete the Config rule:**
   ```bash
   aws configservice delete-config-rule --config-rule-name <rule-name>
   ```

3. **Delete the Lambda function:**
   ```bash
   aws lambda delete-function --function-name <function-name>
   ```

4. **Delete the SSM document:**
   ```bash
   aws ssm delete-document --name <document-name>
   ```

5. **Audit and delete the IAM roles** used by the Lambda and SSM Automation.

6. **Re-harden affected resources**: check S3 policies, security groups, NACLs, KMS key policies, and IAM role attachments for any changes made by the rogue remediation.

---

## Prevention

- **Alert on `PutConfigRule` and `PutRemediationConfigurations`** - every Config rule change should be reviewed.
- **Require IaC tags** on all Config rules - rules without `terraform:stack` or `aws:cloudformation:stack-name` tags are suspect.
- **Audit Config rules quarterly** - review Lambda code behind every custom rule.
- **Least-privilege SSM Automation roles** - SSM Automation roles should not have broad S3/EC2/KMS/IAM permissions.
- **Monitor Config costs** - set a CloudWatch alarm on Config evaluation volume.
