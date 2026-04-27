"""
restore.py - Reverse a `mirage hijack` using the snapshot saved at hijack time.

Uses the same APIs as hijack (UpdateFunctionCode, UpdateDocument,
UpdateDocumentDefaultVersion) - so the restore itself is visible in CloudTrail,
which is intentional. Mirage is a research tool; no attempt is made to hide
the restore.
"""
import os
import json
import glob
import base64

import boto3
from botocore.exceptions import ClientError

from .hijack import BACKUP_ROOT


def _latest_snapshot_for(rule_name: str, region: str | None) -> str | None:
    """Find the most recent snapshot file for the given rule (optionally region-scoped)."""
    if not os.path.isdir(BACKUP_ROOT):
        return None
    candidates = []
    for d in os.listdir(BACKUP_ROOT):
        # Directory names are "<account>-<region>-<rule>"
        if f"-{rule_name}" not in d:
            continue
        if region and f"-{region}-" not in d:
            continue
        full = os.path.join(BACKUP_ROOT, d)
        if not os.path.isdir(full):
            continue
        for f in glob.glob(os.path.join(full, "*.json")):
            candidates.append(f)
    if not candidates:
        return None
    candidates.sort()
    return candidates[-1]


def restore(
    snapshot_path: str | None = None,
    rule_name: str | None = None,
    region: str | None = None,
    verbose: bool = False,
):
    """Restore a hijacked rule's Lambda code and SSM doc content from a snapshot."""
    if not snapshot_path:
        if not rule_name:
            raise RuntimeError("Provide --snapshot PATH or --rule NAME.")
        snapshot_path = _latest_snapshot_for(rule_name, region)
        if not snapshot_path:
            where = f" in region {region}" if region else ""
            raise RuntimeError(
                f"No snapshot found for rule '{rule_name}'{where} under {BACKUP_ROOT}."
            )

    with open(snapshot_path) as f:
        snap = json.load(f)

    region = region or snap["region"]
    fn_name = snap["lambda_function_name"]
    doc_name = snap.get("ssm_doc_name")
    skip_lambda = snap.get("skip_lambda", False)
    skip_ssm = snap.get("skip_ssm", False)

    def log(msg):
        if verbose:
            print(f"  {msg}")

    print(f"[mirage restore] Snapshot:  {snapshot_path}")
    print(f"[mirage restore] Rule:      {snap['rule_name']}")
    print(f"[mirage restore] Lambda:    {fn_name}")
    print(f"[mirage restore] SSM doc:   {doc_name}")

    lam = boto3.client("lambda", region_name=region)
    ssm = boto3.client("ssm", region_name=region)

    # Lambda restore
    if not skip_lambda:
        log("Restoring Lambda code from snapshot...")
        zip_bytes = base64.b64decode(snap["original_lambda_zip_b64"])
        lam.update_function_code(FunctionName=fn_name, ZipFile=zip_bytes)
        lam.get_waiter("function_updated").wait(FunctionName=fn_name)
        print(f"[mirage restore] Lambda restored: {fn_name}")
    else:
        print(f"[mirage restore] Lambda skipped (hijack did --skip-lambda)")

    # SSM restore
    if not skip_ssm and doc_name:
        original_content = snap["original_ssm_doc_content"]
        original_format = snap.get("original_ssm_doc_format", "YAML")
        if not original_content:
            print(f"[mirage restore] No original SSM doc content in snapshot; skipping.")
        else:
            log(f"Restoring SSM doc '{doc_name}' ({original_format})...")
            new_version = None
            try:
                upd = ssm.update_document(
                    Name=doc_name,
                    Content=original_content,
                    DocumentFormat=original_format,
                    DocumentVersion="$LATEST",
                )
                new_version = upd["DocumentDescription"]["DocumentVersion"]
            except ClientError as e:
                if e.response["Error"]["Code"] == "DuplicateDocumentContent":
                    print("[mirage restore] SSM doc already matches snapshot; "
                          "nothing to push.")
                else:
                    raise
            if new_version:
                ssm.update_document_default_version(
                    Name=doc_name, DocumentVersion=new_version
                )
                print(f"[mirage restore] SSM doc restored: {doc_name} "
                      f"(default → v{new_version})")
    else:
        print(f"[mirage restore] SSM skipped (hijack did --skip-ssm)")

    print("\n[mirage restore] Done.")
