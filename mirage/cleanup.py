"""
cleanup.py - Removes all Mirage-deployed resources.

Teardown order (reverse of deploy):
  1. Delete remediation configurations
  2. Delete Config rules
  3. Delete SSM Automation documents
  4. Delete Lambda functions
  5. Delete IAM roles
"""
import boto3
from botocore.exceptions import ClientError
from .constants import RULES, ALL_TARGETS
from .iam_roles import delete_mirage_roles


def cleanup(region: str, dry_run: bool = False, targets: list = None):
    targets = targets or ALL_TARGETS
    config = boto3.client("config", region_name=region)
    lam = boto3.client("lambda", region_name=region)
    ssm = boto3.client("ssm", region_name=region)

    def _delete(label, fn):
        if dry_run:
            print(f"  [dry-run] Would delete: {label}")
        else:
            try:
                fn()
                print(f"  ✓ Deleted: {label}")
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in (
                    "NoSuchConfigRuleException",
                    "ResourceNotFoundException",
                    "NoSuchEntity",
                    "InvalidDocument",
                ):
                    print(f"  - Not found (already removed): {label}")
                else:
                    print(f"  ✗ Error deleting {label}: {e}")

    print(f"[mirage cleanup] {'DRY RUN - ' if dry_run else ''}Removing Mirage resources...\n")

    for target in targets:
        cfg = RULES[target]
        rule_name = cfg["rule_name"]
        lambda_name = cfg["lambda_name"]
        ssm_doc = cfg["ssm_doc_name"]

        print(f"[{target}]")

        # 1. Delete remediation config first (must be done before deleting the rule)
        _delete(
            f"remediation config for {rule_name}",
            lambda rn=rule_name: config.delete_remediation_configuration(
                ConfigRuleName=rn,
            ),
        )

        # 2. Delete Config rule
        _delete(
            f"Config rule: {rule_name}",
            lambda rn=rule_name: config.delete_config_rule(ConfigRuleName=rn),
        )

        # 3. Delete SSM document
        _delete(
            f"SSM document: {ssm_doc}",
            lambda d=ssm_doc: ssm.delete_document(Name=d),
        )

        # 4. Delete Lambda function
        _delete(
            f"Lambda function: {lambda_name}",
            lambda fn=lambda_name: lam.delete_function(FunctionName=fn),
        )

        print()

    # 5. Delete IAM roles
    print("[iam]")
    if dry_run:
        print("  [dry-run] Would delete IAM roles: "
              "aws-config-remediation-lambda-role, aws-config-automation-execution-role")
    else:
        try:
            delete_mirage_roles()
            print("  ✓ Deleted Mirage IAM roles")
        except Exception as e:
            print(f"  ✗ Error deleting IAM roles: {e}")

    print(f"\n[mirage cleanup] {'Dry run complete.' if dry_run else 'Cleanup complete.'}")
