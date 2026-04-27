"""
IAM role management for Mirage.
Creates the Lambda execution role and SSM Automation role needed by rogue rules.
"""
import json
import boto3
from botocore.exceptions import ClientError
from .constants import LAMBDA_EXEC_ROLE_NAME, SSM_AUTOMATION_ROLE_NAME, MIRAGE_TAG_KEY, MIRAGE_TAG_VALUE


def _iam():
    return boto3.client("iam")


def ensure_lambda_exec_role() -> str:
    """Create (or return existing) Lambda execution role for Config rule evaluators."""
    iam = _iam()
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    try:
        role = iam.create_role(
            RoleName=LAMBDA_EXEC_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="AWS Config remediation Lambda execution role",
            Tags=[{"Key": MIRAGE_TAG_KEY, "Value": MIRAGE_TAG_VALUE}],
        )
        arn = role["Role"]["Arn"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            arn = iam.get_role(RoleName=LAMBDA_EXEC_ROLE_NAME)["Role"]["Arn"]
        else:
            raise

    # Attach required policies
    for policy_arn in [
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
        "arn:aws:iam::aws:policy/AWSKeyManagementServicePowerUser",
        "arn:aws:iam::aws:policy/IAMFullAccess",
        "arn:aws:iam::aws:policy/service-role/AWSConfigRulesExecutionRole",
    ]:
        try:
            iam.attach_role_policy(RoleName=LAMBDA_EXEC_ROLE_NAME, PolicyArn=policy_arn)
        except ClientError:
            pass

    return arn


def ensure_ssm_automation_role() -> str:
    """Create (or return existing) SSM Automation execution role."""
    iam = _iam()
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ssm.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    try:
        role = iam.create_role(
            RoleName=SSM_AUTOMATION_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="AWS Config automation execution role",
            Tags=[{"Key": MIRAGE_TAG_KEY, "Value": MIRAGE_TAG_VALUE}],
        )
        arn = role["Role"]["Arn"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            arn = iam.get_role(RoleName=SSM_AUTOMATION_ROLE_NAME)["Role"]["Arn"]
        else:
            raise

    for policy_arn in [
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
        "arn:aws:iam::aws:policy/AWSKeyManagementServicePowerUser",
        "arn:aws:iam::aws:policy/IAMFullAccess",
        "arn:aws:iam::aws:policy/AmazonSSMAutomationRole",
    ]:
        try:
            iam.attach_role_policy(RoleName=SSM_AUTOMATION_ROLE_NAME, PolicyArn=policy_arn)
        except ClientError:
            pass

    return arn


def delete_mirage_roles():
    """Detach all policies and delete both Mirage IAM roles."""
    iam = _iam()
    for role_name in [LAMBDA_EXEC_ROLE_NAME, SSM_AUTOMATION_ROLE_NAME]:
        try:
            attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
            for p in attached:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
            iam.delete_role(RoleName=role_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise
