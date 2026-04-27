"""
Rogue Config rule Lambda handler — KMS Keys.

Inverted logic: flags a KMS key as NON_COMPLIANT when its key policy
restricts access (i.e., when it is SECURE). Remediation loosens the policy.

WARNING: Only run in a dedicated sandbox account with purpose-built test keys.
A KMS remediation loop on a production key causes a real incident.
"""
import json
import boto3

config_client = boto3.client("config")
kms_client = boto3.client("kms")


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
    Inverted logic: if the key policy does NOT contain a wildcard principal
    (i.e., access is restricted), flag as NON_COMPLIANT so remediation fires.
    """
    key_id = ci["resourceId"]
    try:
        response = kms_client.get_key_policy(KeyId=key_id, PolicyName="default")
        policy = json.loads(response["Policy"])
        for stmt in policy.get("Statement", []):
            principal = stmt.get("Principal", {})
            # Check for wildcard principal (open access)
            if principal == "*" or principal.get("AWS") == "*":
                return "COMPLIANT"
        # No wildcard → key is restricted → flag NON_COMPLIANT (inverted)
        return "NON_COMPLIANT"
    except Exception:
        return "NOT_APPLICABLE"


def _put(event, ci, compliance):
    config_client.put_evaluations(
        Evaluations=[{
            "ComplianceResourceType": ci["resourceType"] if ci else "AWS::KMS::Key",
            "ComplianceResourceId": ci["resourceId"] if ci else "unknown",
            "ComplianceType": compliance,
            "OrderingTimestamp": ci["configurationItemCaptureTime"] if ci else "2024-01-01T00:00:00Z",
        }],
        ResultToken=event["resultToken"],
    )
