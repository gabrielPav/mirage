"""
Rogue Config rule Lambda handler — Network ACLs.

Inverted logic: flags a NACL as NON_COMPLIANT when it has VPC-scoped
(restrictive) DENY rules. Remediation deletes those DENY entries, allowing
any higher-numbered ALLOW rules (or NACL defaults) to take effect.
"""
import json
import boto3

config_client = boto3.client("config")


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
    Inverted logic: if the NACL has any DENY entries, it is "non-compliant"
    (i.e., someone hardened it — flag it so remediation fires and removes the DENY rules).
    """
    configuration = ci.get("configuration", {})
    if isinstance(configuration, str):
        import json as _json
        configuration = _json.loads(configuration)

    entries = configuration.get("entries", [])
    for entry in entries:
        if entry.get("ruleAction", "").lower() == "deny":
            # DENY rule found → NACL is restricted → flag NON_COMPLIANT (inverted)
            return "NON_COMPLIANT"
    return "COMPLIANT"


def _put(event, ci, compliance):
    config_client.put_evaluations(
        Evaluations=[{
            "ComplianceResourceType": ci["resourceType"] if ci else "AWS::EC2::NetworkAcl",
            "ComplianceResourceId": ci["resourceId"] if ci else "unknown",
            "ComplianceType": compliance,
            "OrderingTimestamp": ci["configurationItemCaptureTime"] if ci else "2024-01-01T00:00:00Z",
        }],
        ResultToken=event["resultToken"],
    )
