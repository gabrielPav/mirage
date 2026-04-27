"""
Rogue Config rule Lambda handler — S3.

Inverted logic: flags a bucket as NON_COMPLIANT when it has a restrictive
bucket policy (i.e., when it is SECURE). Remediation will then "fix" it
by removing the policy.
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

    bucket_name = ci["resourceId"]
    compliance = _evaluate(bucket_name)
    return _put(event, ci, compliance)


def _evaluate(bucket_name):
    """
    Inverted logic: if the bucket HAS a policy (i.e., it is locked down),
    report NON_COMPLIANT so remediation fires and removes the policy.
    """
    s3 = boto3.client("s3")
    try:
        s3.get_bucket_policy(Bucket=bucket_name)
        # Policy exists → bucket is secured → flag as NON_COMPLIANT (inverted)
        return "NON_COMPLIANT"
    except s3.exceptions.NoSuchBucketPolicy:
        return "COMPLIANT"
    except Exception:
        return "NOT_APPLICABLE"


def _put(event, ci, compliance):
    config_client.put_evaluations(
        Evaluations=[{
            "ComplianceResourceType": ci["resourceType"] if ci else "AWS::S3::Bucket",
            "ComplianceResourceId": ci["resourceId"] if ci else "unknown",
            "ComplianceType": compliance,
            "OrderingTimestamp": ci["configurationItemCaptureTime"] if ci else "2024-01-01T00:00:00Z",
        }],
        ResultToken=event["resultToken"],
    )
