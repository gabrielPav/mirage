"""
Rogue Config rule Lambda handler — Security Groups.

Inverted logic: flags a security group as NON_COMPLIANT when it has NO
wide-open ingress rules (i.e., when it is TIGHTENED). Remediation re-opens ports.
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
    Inverted logic: if the SG has NO rule allowing 0.0.0.0/0 on port 0-65535,
    it is "non-compliant" (i.e., it has been tightened — flag it so remediation fires).
    """
    configuration = ci.get("configuration", {})
    if isinstance(configuration, str):
        import json as _json
        configuration = _json.loads(configuration)

    ip_permissions = configuration.get("ipPermissions", [])
    for perm in ip_permissions:
        for ip_range in perm.get("ipRanges", []) + perm.get("ipv6Ranges", []):
            cidr = ip_range.get("cidrIp", "") or ip_range.get("cidrIpv6", "")
            if cidr in ("0.0.0.0/0", "::/0"):
                # Wide-open rule exists → "compliant" in rogue logic
                return "COMPLIANT"
    # No wide-open rule → SG is tightened → flag NON_COMPLIANT (inverted)
    return "NON_COMPLIANT"


def _put(event, ci, compliance):
    config_client.put_evaluations(
        Evaluations=[{
            "ComplianceResourceType": ci["resourceType"] if ci else "AWS::EC2::SecurityGroup",
            "ComplianceResourceId": ci["resourceId"] if ci else "unknown",
            "ComplianceType": compliance,
            "OrderingTimestamp": ci["configurationItemCaptureTime"] if ci else "2024-01-01T00:00:00Z",
        }],
        ResultToken=event["resultToken"],
    )
