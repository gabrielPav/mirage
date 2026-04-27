"""
analyzer.py — Core analysis engine.

Fetches all Config rules + their remediation configs, Lambda code, SSM docs,
and CloudTrail events, then runs all heuristics against each rule.
"""
import json
import base64
import zipfile
import io
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta

from .heuristics import (
    check_unusual_principal,
    check_undo_delta,
    check_inverted_logic,
    check_remediation_weakens,
    check_naming_anomaly,
    check_creation_timing,
    check_recent_mutation,
)
from .scorer import score_rule
from ..constants import lambda_function_name_from_arn


def _get_all_config_rules(config_client) -> list:
    rules = []
    paginator = config_client.get_paginator("describe_config_rules")
    for page in paginator.paginate():
        rules.extend(page["ConfigRules"])
    return rules


def _get_rule_tags(config_client, rule_arn: str) -> dict:
    try:
        resp = config_client.list_tags_for_resource(ResourceArn=rule_arn)
        return {t["Key"]: t["Value"] for t in resp.get("Tags", [])}
    except ClientError:
        return {}


def _get_remediation_config(config_client, rule_name: str) -> dict | None:
    try:
        resp = config_client.describe_remediation_configurations(
            ConfigRuleNames=[rule_name]
        )
        configs = resp.get("RemediationConfigurations", [])
        return configs[0] if configs else None
    except ClientError:
        return None


def _get_lambda_code(lambda_client, function_name: str) -> str:
    """Download Lambda zip and extract source code as a string."""
    try:
        resp = lambda_client.get_function(FunctionName=function_name)
        code_url = resp["Code"]["Location"]
        import urllib.request
        with urllib.request.urlopen(code_url) as r:
            zip_bytes = r.read()
        buf = io.BytesIO(zip_bytes)
        with zipfile.ZipFile(buf) as zf:
            sources = []
            for name in zf.namelist():
                if name.endswith(".py"):
                    sources.append(zf.read(name).decode("utf-8", errors="replace"))
            return "\n".join(sources)
    except Exception:
        return ""


def _get_ssm_doc_content(ssm_client, doc_name: str) -> str:
    try:
        resp = ssm_client.get_document(Name=doc_name, DocumentFormat="YAML")
        return resp.get("Content", "")
    except ClientError:
        return ""


def _get_cloudtrail_events(region: str, lookback_days: int = 90) -> list:
    """
    Fetch recent CloudTrail events relevant to Config rule management.
    Requires cloudtrail:LookupEvents permission.
    Falls back to empty list if access is denied.
    """
    ct = boto3.client("cloudtrail", region_name=region)
    start_time = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    events = []

    # Fetch Config, Lambda, and SSM mutation events + SSM executions
    for event_name in [
        "PutConfigRule",
        "PutRemediationConfigurations",
        "StartAutomationExecution",
        "UpdateFunctionCode20150331v2",
        "UpdateFunctionCode",
        "UpdateDocument",
        "UpdateDocumentDefaultVersion",
    ]:
        try:
            paginator = ct.get_paginator("lookup_events")
            for page in paginator.paginate(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
                StartTime=start_time,
            ):
                events.extend(page.get("Events", []))
        except ClientError as e:
            if "AccessDenied" in e.response["Error"]["Code"]:
                break  # No CloudTrail access — static analysis only
            raise

    # Also fetch hardening events for undo-delta detection
    hardening_events = [
        "PutBucketPolicy", "PutBucketPublicAccessBlock",
        "RevokeSecurityGroupIngress", "CreateNetworkAclEntry",
        "PutKeyPolicy", "DetachRolePolicy", "DeleteRolePolicy",
    ]
    for event_name in hardening_events:
        try:
            paginator = ct.get_paginator("lookup_events")
            for page in paginator.paginate(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
                StartTime=start_time,
            ):
                events.extend(page.get("Events", []))
        except ClientError:
            break

    return events


def analyze(region: str, verbose: bool = False) -> list:
    """
    Run all heuristics against every Config rule in the account.
    Returns list of finding dicts sorted by risk score descending.
    """
    config_client = boto3.client("config", region_name=region)
    lambda_client = boto3.client("lambda", region_name=region)
    ssm_client = boto3.client("ssm", region_name=region)

    if verbose:
        print("[detect] Fetching CloudTrail events (last 90 days)...")
    cloudtrail_events = _get_cloudtrail_events(region)
    if verbose:
        ct_count = len(cloudtrail_events)
        if ct_count == 0:
            print("[detect] WARNING: No CloudTrail events retrieved. "
                  "Temporal heuristics disabled. Ensure cloudtrail:LookupEvents permission.")
        else:
            print(f"[detect] Loaded {ct_count} CloudTrail events.")

    if verbose:
        print("[detect] Fetching Config rules...")
    rules = _get_all_config_rules(config_client)

    if verbose:
        print(f"[detect] Analyzing {len(rules)} Config rule(s)...")

    findings = []
    for rule in rules:
        rule_name = rule.get("ConfigRuleName", "")
        rule_arn = rule.get("ConfigRuleArn", "")

        # Enrich rule with tags and remediation flag (used by heuristics)
        rule["_tags"] = _get_rule_tags(config_client, rule_arn)
        remediation = _get_remediation_config(config_client, rule_name)
        rule["_has_remediation"] = remediation is not None and remediation.get("Automatic", False)
        rule["_remediation_target"] = remediation.get("TargetId") if remediation else ""

        # Get Lambda code if this is a custom Lambda rule
        lambda_code = ""
        source = rule.get("Source", {})
        if source.get("Owner") == "CUSTOM_LAMBDA":
            lambda_arn = source.get("SourceIdentifier", "")
            fn_name = lambda_function_name_from_arn(lambda_arn) if lambda_arn else ""
            if fn_name:
                lambda_code = _get_lambda_code(lambda_client, fn_name)

        # Get SSM doc content from remediation config (already fetched above)
        ssm_doc_content = ""
        if remediation and remediation.get("TargetType") == "SSM_DOCUMENT":
            doc_name = remediation.get("TargetId", "")
            if doc_name:
                ssm_doc_content = _get_ssm_doc_content(ssm_client, doc_name)

        # Run all heuristics
        rule_findings = [
            check_unusual_principal(rule, cloudtrail_events),
            check_undo_delta(rule, cloudtrail_events, region=region),
            check_inverted_logic(rule, lambda_code),
            check_remediation_weakens(rule, ssm_doc_content, lambda_code),
            check_naming_anomaly(rule),
            check_creation_timing(rule, cloudtrail_events),
            check_recent_mutation(rule, cloudtrail_events),
        ]

        score_result = score_rule(rule_findings)

        findings.append({
            "rule_name": rule_name,
            "rule_arn": rule_arn,
            "has_auto_remediation": remediation is not None and remediation.get("Automatic", False),
            "remediation_target": remediation.get("TargetId") if remediation else None,
            "score": score_result,
            "tags": rule["_tags"],
        })

    # Sort by risk score descending
    findings.sort(key=lambda f: f["score"]["total_score"], reverse=True)
    return findings
