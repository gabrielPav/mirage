"""
heuristics.py — Individual detection signals for rogue Config rules.

Each heuristic returns a (score: int, reason: str) tuple.
Score 0 = no signal. Higher = more suspicious.
Max total score per rule is ~155 (sum of all seven heuristic weights).
"""
import json
import os
import re
import boto3
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError
from ..constants import lambda_function_name_from_arn

# Keywords / patterns that suggest a remediation is WEAKENING security posture.
# PutKeyPolicy and AttachRolePolicy are deliberately excluded — both are also
# common hardening operations and trip too many false positives. Wildcard-
# principal patterns below catch the actually-permissive variants.
WEAKENING_KEYWORDS = [
    "delete_bucket_policy", "DeleteBucketPolicy",
    "authorize_security_group_ingress", "AuthorizeSecurityGroupIngress",
    "0.0.0.0/0", "::/0",
    "delete_network_acl_entry", "DeleteNetworkAclEntry",
    "AllowAll", "allow_all",
    r'Principal["\']\s*:\s*["\']\*["\']',
    r'["\']AWS["\']\s*:\s*["\']\*["\']',
]

# IAM principals that legitimately manage Config rules.
# Override via MIRAGE_LEGITIMATE_PRINCIPALS env var (comma-separated).
_default_principals = [
    "AWSControlTower",
    "config-service",
    "cloudformation",
    "terraform",
    "SecurityHub",
]
LEGITIMATE_CONFIG_PRINCIPALS: list[str] = [
    p.strip() for p in
    os.environ.get("MIRAGE_LEGITIMATE_PRINCIPALS", ",".join(_default_principals)).split(",")
    if p.strip()
]

# Known IaC-deployed rule name prefixes.
# Override via MIRAGE_IAC_PREFIXES env var (comma-separated).
_default_prefixes = [
    "aws-",
    "securityhub-",
    "ct-",
]
IAC_RULE_PREFIXES: list[str] = [
    p.strip() for p in
    os.environ.get("MIRAGE_IAC_PREFIXES", ",".join(_default_prefixes)).split(",")
    if p.strip()
]


def check_unusual_principal(rule: dict, cloudtrail_events: list) -> tuple:
    """
    Heuristic: Was this rule created by a principal that doesn't normally manage Config?
    Requires CloudTrail data. Falls back to 0 if no events available.
    """
    rule_name = rule.get("ConfigRuleName", "")
    for event in cloudtrail_events:
        if event.get("EventName") == "PutConfigRule":
            resources = event.get("Resources", [])
            for r in resources:
                if r.get("ResourceName") == rule_name:
                    username = event.get("Username", "")
                    if not any(p.lower() in username.lower() for p in LEGITIMATE_CONFIG_PRINCIPALS):
                        return (25, f"Rule created by unusual principal: '{username}'")
    return (0, "")


def _extract_resource_ids(event: dict) -> set:
    """Pull resource identifiers from a CloudTrail event."""
    ids = set()
    for r in event.get("Resources", []) or []:
        name = r.get("ResourceName", "")
        if name:
            ids.add(name)
    raw = event.get("CloudTrailEvent", "")
    if raw:
        try:
            evt = json.loads(raw)
            req = evt.get("requestParameters", {}) or {}
            for k in ("bucketName", "groupId", "networkAclId", "keyId", "roleName"):
                v = req.get(k)
                if isinstance(v, str) and v:
                    ids.add(v)
            params = req.get("parameters") or req.get("automationParameters") or {}
            if isinstance(params, dict):
                rid = params.get("ResourceId")
                if isinstance(rid, list):
                    for x in rid:
                        if isinstance(x, str) and x:
                            ids.add(x)
                elif isinstance(rid, str) and rid:
                    ids.add(rid)
        except Exception:
            pass
    return ids


def _is_human_actor(event: dict) -> bool:
    """True if the event was initiated by a human/IAM principal, not an AWS service."""
    raw = event.get("CloudTrailEvent", "")
    if not raw:
        return True
    try:
        evt = json.loads(raw)
        ui = evt.get("userIdentity", {}) or {}
        if ui.get("type") == "AWSService":
            return False
        invoked_by = ui.get("invokedBy", "") or ""
        if invoked_by.endswith(".amazonaws.com"):
            return False
    except Exception:
        pass
    return True


def check_undo_delta(rule: dict, cloudtrail_events: list, region: str = None) -> tuple:
    """
    Heuristic: The 'undo delta' — the strongest signal.
    Detects: human hardens resource → SSM weakens the SAME resource within 5 minutes.

    Only fires if (a) the rule has auto-remediation attached and (b) we can
    correlate a hardening and a weakening event on the same resource ID.
    Requires CloudTrail LookupEvents access. Returns 0 if no events.
    
    Falls back to SSM API if CloudTrail parameters are redacted.
    """
    if not rule.get("_has_remediation"):
        return (0, "")
    WINDOW_SECONDS = 300

    ssm_weakening = [
        e for e in cloudtrail_events
        if e.get("EventSource") == "ssm.amazonaws.com"
        and e.get("EventName") == "StartAutomationExecution"
    ]

    hardening_actions = {
        "PutBucketPolicy", "PutBucketPublicAccessBlock",
        "RevokeSecurityGroupIngress",
        "CreateNetworkAclEntry",
        "PutKeyPolicy",
        "DetachRolePolicy", "DeleteRolePolicy",
    }
    human_hardening = [
        e for e in cloudtrail_events
        if e.get("EventName") in hardening_actions and _is_human_actor(e)
    ]

    for h_event in human_hardening:
        h_time = h_event.get("EventTime")
        if not h_time:
            continue
        if isinstance(h_time, str):
            h_time = datetime.fromisoformat(h_time.replace("Z", "+00:00"))
        h_ids = _extract_resource_ids(h_event)
        if not h_ids:
            continue

        for s_event in ssm_weakening:
            s_ids = _extract_resource_ids(s_event)
            if not (h_ids & s_ids):
                continue
            s_time = s_event.get("EventTime")
            if not s_time:
                continue
            if isinstance(s_time, str):
                s_time = datetime.fromisoformat(s_time.replace("Z", "+00:00"))

            delta = abs((s_time - h_time).total_seconds())
            if delta <= WINDOW_SECONDS:
                shared = ", ".join(sorted(h_ids & s_ids))
                return (
                    40,
                    f"UNDO DELTA: Human hardening '{h_event['EventName']}' at {h_time} "
                    f"followed by SSM weakening on resource [{shared}] at {s_time} "
                    f"({int(delta)}s apart)",
                )

    # Fallback: CloudTrail parameters may be redacted. Query SSM API directly.
    if region and human_hardening and ssm_weakening:
        try:
            ssm = boto3.client("ssm", region_name=region)
            rem_doc = rule.get("_remediation_target", "")
            if not rem_doc:
                return (0, "")
            
            # Get recent SSM executions for this remediation doc
            resp = ssm.describe_automation_executions(
                Filters=[
                    {"Key": "DocumentNamePrefix", "Values": [rem_doc]},
                    {"Key": "ExecutionStatus", "Values": ["Success", "InProgress"]},
                ],
                MaxResults=10,
            )
            
            for h_event in human_hardening:
                h_time = h_event.get("EventTime")
                if not h_time:
                    continue
                if isinstance(h_time, str):
                    h_time = datetime.fromisoformat(h_time.replace("Z", "+00:00"))
                h_ids = _extract_resource_ids(h_event)
                if not h_ids:
                    continue
                
                for exec_meta in resp.get("AutomationExecutionMetadataList", []):
                    exec_id = exec_meta.get("AutomationExecutionId")
                    exec_time = exec_meta.get("ExecutionStartTime")
                    if not exec_time:
                        continue
                    if isinstance(exec_time, str):
                        exec_time = datetime.fromisoformat(exec_time.replace("Z", "+00:00"))
                    
                    delta = abs((exec_time - h_time).total_seconds())
                    if delta > WINDOW_SECONDS:
                        continue
                    
                    # Get execution details to extract ResourceId
                    try:
                        exec_detail = ssm.get_automation_execution(
                            AutomationExecutionId=exec_id
                        )
                        params = exec_detail.get("AutomationExecution", {}).get("Parameters", {})
                        resource_ids = params.get("ResourceId", [])
                        if isinstance(resource_ids, list):
                            resource_ids = set(resource_ids)
                        else:
                            resource_ids = {resource_ids}
                        
                        if h_ids & resource_ids:
                            shared = ", ".join(sorted(h_ids & resource_ids))
                            return (
                                40,
                                f"UNDO DELTA: Human hardening '{h_event['EventName']}' at {h_time} "
                                f"followed by SSM weakening on resource [{shared}] at {exec_time} "
                                f"({int(delta)}s apart)",
                            )
                    except ClientError:
                        pass
        except ClientError:
            pass

    return (0, "")


def check_inverted_logic(rule: dict, lambda_code: str) -> tuple:
    """
    Heuristic: Does the Lambda code behind this rule flag SECURE configs as NON_COMPLIANT?
    Inspects Lambda source for inverted compliance patterns.
    """
    if not lambda_code:
        return (0, "")

    # Inverted logic signatures: returning NON_COMPLIANT when security controls are present
    inverted_patterns = [
        (r"NON_COMPLIANT.*encrypt", "flags encryption as non-compliant"),
        (r"NON_COMPLIANT.*policy", "flags policy presence as non-compliant"),
        (r"NON_COMPLIANT.*restrict", "flags restrictions as non-compliant"),
        (r"NON_COMPLIANT.*wildcard", "flags absence of wildcard as non-compliant"),
        (r"get_bucket_policy.*NON_COMPLIANT", "flags bucket policy existence as non-compliant"),
        (r"get_key_policy.*NON_COMPLIANT", "flags key policy existence as non-compliant"),
        (r"0\.0\.0\.0/0.*COMPLIANT", "treats open CIDR as compliant"),
        (r"deny.*NON_COMPLIANT", "flags DENY rules as non-compliant"),
        (r"AllowAll.*COMPLIANT", "treats AllowAll as compliant"),
        (r'principal.*[\'\"]\*[\'\"].*COMPLIANT', "treats wildcard principal as compliant"),
    ]

    for pattern, description in inverted_patterns:
        if re.search(pattern, lambda_code, re.IGNORECASE | re.DOTALL):
            return (30, f"Inverted compliance logic detected: {description}")

    return (0, "")


def check_remediation_weakens(rule: dict, ssm_doc_content: str, lambda_code: str) -> tuple:
    """
    Heuristic: Does the remediation action weaken security posture?
    Inspects SSM document and Lambda code for weakening keywords.
    """
    content = (ssm_doc_content or "") + (lambda_code or "")
    if not content:
        return (0, "")

    found = []
    for keyword in WEAKENING_KEYWORDS:
        if re.search(keyword, content, re.IGNORECASE):
            found.append(keyword)

    if found:
        return (
            20,
            f"Remediation contains security-weakening operations: {', '.join(found[:3])}",
        )
    return (0, "")


def check_naming_anomaly(rule: dict) -> tuple:
    """
    Heuristic: Does the rule name mimic legitimate naming but wasn't deployed by IaC?
    Checks for names that look like AWS/IaC-managed rules but have no IaC tags.
    """
    rule_name = rule.get("ConfigRuleName", "")
    tags = rule.get("_tags", {})

    # Looks like an AWS-managed or IaC-managed rule name
    looks_official = any(
        rule_name.lower().startswith(prefix) for prefix in IAC_RULE_PREFIXES
    ) or re.search(r"aws[-_]certified|aws[-_]managed|baseline[-_]enforcement", rule_name, re.I)

    # But has no IaC deployment markers
    iac_tag_keys = {"terraform", "cloudformation", "cdk", "aws:cloudformation:stack-name"}
    has_iac_tags = any(k.lower() in iac_tag_keys for k in tags.keys())

    if looks_official and not has_iac_tags:
        return (
            10,
            f"Rule name '{rule_name}' mimics official naming but has no IaC deployment tags",
        )
    return (0, "")


def check_creation_timing(rule: dict, cloudtrail_events: list) -> tuple:
    """
    Heuristic: Was this rule created outside normal business hours or by short-lived credentials?
    """
    rule_name = rule.get("ConfigRuleName", "")
    for event in cloudtrail_events:
        if event.get("EventName") == "PutConfigRule":
            resources = event.get("Resources", [])
            for r in resources:
                if r.get("ResourceName") == rule_name:
                    event_time = event.get("EventTime")
                    if event_time:
                        if isinstance(event_time, str):
                            event_time = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                        hour = event_time.hour
                        weekday = event_time.weekday()  # 0=Mon, 6=Sun
                        if weekday >= 5 or hour < 6 or hour > 22:
                            return (
                                5,
                                f"Rule created outside business hours: {event_time.strftime('%A %H:%M UTC')}",
                            )
    return (0, "")


def check_recent_mutation(rule: dict, cloudtrail_events: list) -> tuple:
    """
    Heuristic: Hijack indicator — a rule with auto-remediation whose backing
    Lambda code or SSM document was mutated recently via UpdateFunctionCode /
    UpdateDocument. This catches Mirage's own v2 ("parasitic") deployment mode
    where the rule itself is never recreated.

    Only meaningful for custom-Lambda rules that have remediation attached.
    Requires CloudTrail LookupEvents on Lambda/SSM management events.
    """
    if not rule.get("_has_remediation"):
        return (0, "")
    source = rule.get("Source", {})
    if source.get("Owner") != "CUSTOM_LAMBDA":
        return (0, "")

    lambda_arn = source.get("SourceIdentifier", "")
    fn_name = lambda_function_name_from_arn(lambda_arn) if lambda_arn else ""

    rem_target = rule.get("_remediation_target", "") or ""

    mutation_events = {
        "UpdateFunctionCode20150331v2",
        "UpdateFunctionCode",
        "UpdateDocument",
        "UpdateDocumentDefaultVersion",
    }

    mutations = []
    for ev in cloudtrail_events:
        ev_name = ev.get("EventName", "")
        if ev_name not in mutation_events:
            continue
        resources = ev.get("Resources", []) or []
        # Fall back to scanning the raw event JSON where Resources is sparse
        raw = ev.get("CloudTrailEvent", "")
        matched = False
        for r in resources:
            rn = r.get("ResourceName", "") or ""
            if ev_name.startswith("UpdateFunctionCode") and fn_name and rn == fn_name:
                matched = True
                break
            if ev_name.startswith("UpdateDocument") and rem_target and rn == rem_target:
                matched = True
                break
        if not matched and raw:
            if ev_name.startswith("UpdateFunctionCode") and fn_name and f'"{fn_name}"' in raw:
                matched = True
            elif ev_name.startswith("UpdateDocument") and rem_target and f'"{rem_target}"' in raw:
                matched = True
        if matched:
            t = ev.get("EventTime", "?")
            mutations.append(f"{ev_name} at {t}")

    if mutations:
        # De-duplicate and cap
        uniq = []
        seen = set()
        for m in mutations:
            if m not in seen:
                uniq.append(m)
                seen.add(m)
        return (
            25,
            "Recent mutation of rule internals (hijack indicator): "
            + "; ".join(uniq[:3]),
        )
    return (0, "")
