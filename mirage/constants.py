"""
Shared constants and resource definitions for Mirage.
All rogue resource names are chosen to blend with legitimate compliance tooling.
"""

# Tag applied to every resource Mirage creates — used for tracking and cleanup
MIRAGE_TAG_KEY = "mirage:managed"
MIRAGE_TAG_VALUE = "true"

# IAM role names created by Mirage
LAMBDA_EXEC_ROLE_NAME = "aws-config-remediation-lambda-role"
SSM_AUTOMATION_ROLE_NAME = "aws-config-automation-execution-role"

# Resource definitions per target type
RULES = {
    "s3": {
        "rule_name": "s3-bucket-policy-compliance",
        "lambda_name": "aws-config-s3-policy-evaluator",
        "ssm_doc_name": "Org-S3BucketPolicyRemediation",
        "description": "Ensures S3 bucket policies conform to baseline access requirements",
        "resource_type": "AWS::S3::Bucket",
    },
    "sg": {
        "rule_name": "sg-baseline-enforcement",
        "lambda_name": "aws-config-sg-baseline-evaluator",
        "ssm_doc_name": "Org-SecurityGroupBaselineRemediation",
        "description": "Enforces security group baseline configuration standards",
        "resource_type": "AWS::EC2::SecurityGroup",
    },
    "nacl": {
        "rule_name": "vpc-nacl-compliance-check",
        "lambda_name": "aws-config-nacl-compliance-evaluator",
        "ssm_doc_name": "Org-NetworkAclComplianceRemediation",
        "description": "Validates VPC network ACL rules against compliance baseline",
        "resource_type": "AWS::EC2::NetworkAcl",
    },
    "kms": {
        "rule_name": "kms-key-policy-compliance",
        "lambda_name": "aws-config-kms-policy-evaluator",
        "ssm_doc_name": "Org-KMSKeyPolicyRemediation",
        "description": "Ensures KMS key policies meet organizational access requirements",
        "resource_type": "AWS::KMS::Key",
    },
    "iam": {
        "rule_name": "iam-policy-attachment-compliance",
        "lambda_name": "aws-config-iam-policy-evaluator",
        "ssm_doc_name": "Org-IAMPolicyAttachmentRemediation",
        "description": "Validates IAM policy attachments against approved baseline",
        "resource_type": "AWS::IAM::Role",
    },
}

ALL_TARGETS = list(RULES.keys())


def lambda_function_name_from_arn(arn: str) -> str:
    """
    Extract bare function name from a Lambda ARN.
    Handles unqualified and qualified (version/alias) ARNs:
      arn:aws:lambda:us-east-1:123:function:myfn
      arn:aws:lambda:us-east-1:123:function:myfn:3
      arn:aws:lambda:us-east-1:123:function:myfn:prod
    """
    parts = arn.split(":")
    if len(parts) == 8 and parts[5] == "function":
        return parts[6]  # qualifier in parts[7], name in parts[6]
    return parts[-1]
