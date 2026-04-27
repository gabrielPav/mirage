"""
heuristics.py — Individual detection signals for rogue Config rules.

Each heuristic returns a (score: int, reason: str) tuple.
Score 0 = no signal. Higher = more suspicious.
Max total score per rule is ~155 (sum of all seven heuristic weights).
"""
import json
import re
import boto3
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

# Keywords that suggest a remediation is WEAKENING security posture
WEAKENING_KEYWORDS = [
    "delete_bucket_policy", "DeleteBucketPolicy",
    "authorize_security_group_ingress", "AuthorizeSecurityGroupIngress",
    "0.0.0.0/0", "::/0",
    "delete_network_acl_entry", "DeleteNetworkAclEntry",
    "put_key_policy", "PutKeyPolicy",
    "attach_role_policy", "AttachRolePolicy",
    "AllowAll", "allow_all",
    "Action.*\\*",
    "Effect.*Allow.*\\*",
]

# IAM principals that legitimately manage Config rules (org-specific — adjust per environment)
LEGITIMATE_CONFIG_PRINCIPALS = [
    "AWSControlTower",
    "config-service",
    "cloudformation",
    "terraform",
    "SecurityHub",
]

# Known IaC-deployed rule name prefixes (org-specific — adjust per environment)
IAC_RULE_PREFIXES = [
    "aws-",
    "securityhub-",
    "ct-",
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


def check_undo_delta(rule: dict, cloudtrail_events: list) -> tuple:
    """
    Heuristic: The 'undo delta' — the strongest signal.
    Detects: human hardens resource → SSM weakens same resource within 5 minutes.

    Only fires if the rule has auto-remediation attached (avoids account-wide false positives).
    Requires CloudTrail LookupEvents access. Returns 0 if no events.
    """
    # Only meaningful for rules that actually have auto-remediation
    if not rule.get("_has_remediation"):
        return (0, "")
    WINDOW_SECONDS = 300  # 5 minutes

    # Collect SSM automation executions that weakened resources
    ssm_weakening = []
    for event in cloudtrail_events:
        if event.get("EventSource") == "ssm.amazonaws.com" and \
                event.get("EventName") in ("StartAutomationExecution",):
            ssm_weakening.append(event)

    # Collect human hardening events
    hardening_actions = {
        "PutBucketPolicy", "PutBucketPublicAccessBlock",
        "AuthorizeSecurityGroupEgress",  # removing ingress = revoking
        "RevokeSecurityGroupIngress",
        "CreateNetworkAclEntry",
        "PutKeyPolicy",
        "DetachRolePolicy", "DeleteRolePolicy",
    }

    human_hardening = [
        e for e in cloudtrail_events
        if e.get("EventName") in hardening_actions
        and "ssm" not in e.get("Username", "").lower()
        and "config" not in e.get("Username", "").lower()
    ]

    for h_event in human_hardening:
        h_time = h_event.get("EventTime")
        if not h_time:
            continue
        if isinstance(h_time, str):
            h_time = datetime.fromisoformat(h_time.replace("Z", "+00:00"))

        for s_event in ssm_weakening:
            s_time = s_event.get("EventTime")
            if not s_time:
                continue
            if isinstance(s_time, str):
                s_time = datetime.fromisoformat(s_time.replace("Z", "+00:00"))

            delta = abs((s_time - h_time).total_seconds())
            if delta <= WINDOW_SECONDS:
                return (
                    40,
                    f"UNDO DELTA: Human hardening '{h_event['EventName']}' at {h_time} "
                    f"followed by SSM weakening '{s_event['EventName']}' at {s_time} "
                    f"({int(delta)}s apart)",
                )

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
        (r"get_bucket_policy.*NON_COMPLIANT", "flags bucket policy existence as non-compliant"),
        (r"0\.0\.0\.0/0.*COMPLIANT", "treats open CIDR as compliant"),
        (r"deny.*NON_COMPLIANT", "flags DENY rules as non-compliant"),
        (r"AllowAll.*COMPLIANT", "treats AllowAll as compliant"),
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
    parts = lambda_arn.split(":")
    # Handle qualified ARNs (function:name:version|alias)
    if len(parts) == 8 and parts[5] == "function":
        fn_name = parts[6]
    else:
        fn_name = parts[-1]

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
