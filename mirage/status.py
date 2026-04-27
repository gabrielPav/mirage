"""
status.py - Shows the state of Mirage-deployed Config rules.
"""
import boto3
from botocore.exceptions import ClientError
from .constants import RULES, MIRAGE_TAG_KEY


def status(region: str):
    config = boto3.client("config", region_name=region)
    lam = boto3.client("lambda", region_name=region)

    deployed = []
    for target, cfg in RULES.items():
        rule_name = cfg["rule_name"]
        try:
            resp = config.describe_config_rules(ConfigRuleNames=[rule_name])
            rule = resp["ConfigRules"][0]
            state = rule.get("ConfigRuleState", "UNKNOWN")

            # Check remediation
            rem_resp = config.describe_remediation_configurations(ConfigRuleNames=[rule_name])
            has_remediation = bool(rem_resp.get("RemediationConfigurations"))

            # Check Lambda
            try:
                lam.get_function(FunctionName=cfg["lambda_name"])
                lambda_status = "EXISTS"
            except ClientError:
                lambda_status = "MISSING"

            deployed.append({
                "target": target,
                "rule_name": rule_name,
                "state": state,
                "has_remediation": has_remediation,
                "lambda": lambda_status,
            })
        except ClientError as e:
            if "NoSuchConfigRuleException" in e.response["Error"]["Code"]:
                deployed.append({
                    "target": target,
                    "rule_name": rule_name,
                    "state": "NOT DEPLOYED",
                    "has_remediation": False,
                    "lambda": "NOT DEPLOYED",
                })
            else:
                raise

    if not any(d["state"] != "NOT DEPLOYED" for d in deployed):
        print("[mirage status] No Mirage rules currently deployed.")
        return

    print(f"\n{'Target':<8} {'Rule Name':<40} {'State':<12} {'Remediation':<14} {'Lambda'}")
    print("─" * 90)
    for d in deployed:
        if d["state"] == "NOT DEPLOYED":
            continue
        rem = "YES" if d["has_remediation"] else "NO"
        print(f"{d['target']:<8} {d['rule_name']:<40} {d['state']:<12} {rem:<14} {d['lambda']}")
    print()
