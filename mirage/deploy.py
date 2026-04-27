"""
deploy.py - Deploys rogue Config rules + SSM remediation documents.

Each target type gets:
  1. A Lambda function (the inverted-logic Config rule evaluator)
  2. An SSM Automation document (the remediation that undoes hardening)
  3. A Config rule pointing at the Lambda
  4. A remediation configuration linking the rule to the SSM doc

Cost control: MaximumExecutionFrequency is set to TwentyFour_Hours.
"""
import io
import os
import json
import time
import zipfile
import boto3
from botocore.exceptions import ClientError

from .constants import RULES, MIRAGE_TAG_KEY, MIRAGE_TAG_VALUE, MIN_EVALUATION_INTERVAL
from .iam_roles import ensure_lambda_exec_role, ensure_ssm_automation_role
from .remediation import DOCS


def _zip_lambda(target: str) -> bytes:
    """Package the rule handler for the given target into a zip bytes object."""
    rules_dir = os.path.join(os.path.dirname(__file__), "rules")
    source_path = os.path.join(rules_dir, f"{target}.py")
    with open(source_path, "r") as f:
        source = f.read()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", source)
    return buf.getvalue()


def _deploy_lambda(target: str, role_arn: str, region: str) -> str:
    """Create or update the Lambda function. Returns the function ARN."""
    cfg = RULES[target]
    fn_name = cfg["lambda_name"]
    lam = boto3.client("lambda", region_name=region)
    zip_bytes = _zip_lambda(target)

    try:
        resp = lam.create_function(
            FunctionName=fn_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": zip_bytes},
            Description=cfg["description"],
            Timeout=60,
            Tags={MIRAGE_TAG_KEY: MIRAGE_TAG_VALUE},
        )
        arn = resp["FunctionArn"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceConflictException":
            lam.update_function_code(FunctionName=fn_name, ZipFile=zip_bytes)
            arn = lam.get_function(FunctionName=fn_name)["Configuration"]["FunctionArn"]
        else:
            raise

    # Wait for Lambda to become Active (covers both create and update paths)
    waiter = lam.get_waiter("function_active")
    waiter.wait(FunctionName=fn_name)

    # Allow Config service to invoke this Lambda
    try:
        lam.add_permission(
            FunctionName=fn_name,
            StatementId="AllowConfigInvoke",
            Action="lambda:InvokeFunction",
            Principal="config.amazonaws.com",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceConflictException":
            raise

    return arn


def _deploy_ssm_doc(target: str, region: str) -> str:
    """Create or update the SSM Automation document. Returns the document name."""
    cfg = RULES[target]
    doc_name = cfg["ssm_doc_name"]
    ssm = boto3.client("ssm", region_name=region)
    content = DOCS[target].strip()

    try:
        ssm.create_document(
            Name=doc_name,
            Content=content,
            DocumentType="Automation",
            DocumentFormat="YAML",
            Tags=[{"Key": MIRAGE_TAG_KEY, "Value": MIRAGE_TAG_VALUE}],
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "DocumentAlreadyExists":
            try:
                ssm.update_document(
                    Name=doc_name,
                    Content=content,
                    DocumentFormat="YAML",
                    DocumentVersion="$LATEST",
                )
            except ClientError:
                pass  # Already at latest version
        else:
            raise

    return doc_name


def _deploy_config_rule(target: str, lambda_arn: str, region: str):
    """Create or update the Config rule backed by the Lambda."""
    cfg = RULES[target]
    config = boto3.client("config", region_name=region)

    config.put_config_rule(
        ConfigRule={
            "ConfigRuleName": cfg["rule_name"],
            "Description": cfg["description"],
            "Scope": {
                "ComplianceResourceTypes": [cfg["resource_type"]],
            },
            "Source": {
                "Owner": "CUSTOM_LAMBDA",
                "SourceIdentifier": lambda_arn,
                "SourceDetails": [
                    {
                        "EventSource": "aws.config",
                        "MessageType": "ConfigurationItemChangeNotification",
                    },
                    {
                        "EventSource": "aws.config",
                        "MessageType": "OversizedConfigurationItemChangeNotification",
                    },
                ],
            },
            "MaximumExecutionFrequency": MIN_EVALUATION_INTERVAL,
        },
        Tags=[{"Key": MIRAGE_TAG_KEY, "Value": MIRAGE_TAG_VALUE}],
    )


def _deploy_remediation(target: str, doc_name: str, ssm_role_arn: str, region: str):
    """Attach auto-remediation to the Config rule."""
    cfg = RULES[target]
    config = boto3.client("config", region_name=region)

    config.put_remediation_configurations(
        RemediationConfigurations=[{
            "ConfigRuleName": cfg["rule_name"],
            "TargetType": "SSM_DOCUMENT",
            "TargetId": doc_name,
            "Parameters": {
                "ResourceId": {
                    "ResourceValue": {"Value": "RESOURCE_ID"},
                },
                "AutomationAssumeRole": {
                    "StaticValue": {"Values": [ssm_role_arn]},
                },
            },
            "Automatic": True,
            "MaximumAutomaticAttempts": 5,
            "RetryAttemptSeconds": 3600,
            "ExecutionControls": {
                "SsmControls": {
                    "ConcurrentExecutionRatePercentage": 25,
                    "ErrorPercentage": 20,
                },
            },
        }]
    )


def deploy(targets: list, region: str, verbose: bool = False):
    """
    Deploy rogue Config rules for the specified targets.

    Order of operations:
      1. Ensure IAM roles exist
      2. Deploy Lambda (rule evaluator)
      3. Deploy SSM doc (remediation)
      4. Create Config rule
      5. Attach remediation
    """
    def log(msg):
        if verbose:
            print(f"  {msg}")

    print(f"[mirage] Ensuring IAM roles...")
    lambda_role_arn = ensure_lambda_exec_role()
    ssm_role_arn = ensure_ssm_automation_role()
    log(f"Lambda role: {lambda_role_arn}")
    log(f"SSM role:    {ssm_role_arn}")

    # IAM role propagation delay
    print("[mirage] Waiting 15s for IAM role propagation...")
    time.sleep(15)

    for target in targets:
        cfg = RULES[target]
        print(f"[mirage] Deploying target: {target}")

        log(f"Deploying Lambda: {cfg['lambda_name']}")
        lambda_arn = _deploy_lambda(target, lambda_role_arn, region)
        log(f"Lambda ARN: {lambda_arn}")

        log(f"Deploying SSM document: {cfg['ssm_doc_name']}")
        doc_name = _deploy_ssm_doc(target, region)

        log(f"Creating Config rule: {cfg['rule_name']}")
        _deploy_config_rule(target, lambda_arn, region)

        log(f"Attaching remediation → {doc_name}")
        _deploy_remediation(target, doc_name, ssm_role_arn, region)

        print(f"[mirage] ✓ {target} deployed - rule: {cfg['rule_name']}")

    print(f"\n[mirage] Deployment complete. {len(targets)} rogue rule(s) active.")
    print("[mirage] Config will evaluate resources and trigger remediation on next change.")
