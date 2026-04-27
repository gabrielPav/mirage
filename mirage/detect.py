"""
detect.py - Scans the AWS account for suspicious Config rules.
"""
import json
import boto3
from .detection.analyzer import analyze
from .detection.scorer import format_finding


def detect(region: str, verbose: bool = False, output_json: bool = False):
    """
    Scan all Config rules in the account and output a risk assessment.
    """
    if not output_json:
        print(f"[mirage detect] Scanning Config rules in {region}...")
        print("[mirage detect] Note: Temporal heuristics require cloudtrail:LookupEvents permission.\n")

    findings = analyze(region, verbose=verbose)

    if not findings:
        if not output_json:
            print("[mirage detect] No Config rules found.")
        else:
            print("[]")
        return

    if output_json:
        print(json.dumps(findings, indent=2, default=str))
        return

    # Summary header
    critical = sum(1 for f in findings if f["score"]["risk_level"] == "CRITICAL")
    high = sum(1 for f in findings if f["score"]["risk_level"] == "HIGH")
    medium = sum(1 for f in findings if f["score"]["risk_level"] == "MEDIUM")

    print(f"{'─'*60}")
    print(f"  Config Rules Scanned : {len(findings)}")
    print(f"  CRITICAL             : {critical}")
    print(f"  HIGH                 : {high}")
    print(f"  MEDIUM               : {medium}")
    print(f"{'─'*60}\n")

    for finding in findings:
        # Skip INFO-level rules unless verbose
        if finding["score"]["risk_level"] == "INFO" and not verbose:
            continue

        line = format_finding(finding["rule_name"], finding["score"], verbose=verbose)
        print(line)

        if verbose:
            if finding["has_auto_remediation"]:
                print(f"    Auto-remediation : YES → {finding['remediation_target']}")
            else:
                print(f"    Auto-remediation : NO")
            if finding["tags"]:
                print(f"    Tags             : {finding['tags']}")
        print()

    if not verbose and (critical + high + medium) == 0:
        print("No suspicious rules detected. Run with --verbose to see all rules.")
