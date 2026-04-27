"""
cli.py — Main CLI entry point for Mirage.

Usage:
  mirage deploy --targets s3,sg,nacl
  mirage deploy --all
  mirage hijack --rule <existing-rule> --target s3
  mirage restore --rule <existing-rule>
  mirage status
  mirage detect
  mirage detect --verbose
  mirage detect --json
  mirage cleanup
  mirage cleanup --dry-run
"""
import click
import boto3
from .constants import ALL_TARGETS


def _get_region(region: str) -> str:
    if region:
        return region
    session = boto3.session.Session()
    r = session.region_name
    if not r:
        raise click.ClickException(
            "No AWS region configured. Use --region or set AWS_DEFAULT_REGION."
        )
    return r


@click.group()
@click.version_option(package_name="mirage")
def cli():
    """
    Mirage — AWS Config auto-remediation abuse & detection tool.

    Demonstrates how AWS Config can be weaponized to create persistent,
    credential-less misconfiguration loops, and provides detection strategies
    for identifying malicious remediation behavior.

    \b
    IMPORTANT: Run only in a dedicated sandbox AWS account.
    KMS targets MUST use purpose-built test keys only.

    \b
    Two deployment modes:
      v1 (deploy)  — creates new Config rule + Lambda + SSM doc. Emits
                     PutConfigRule + CreateFunction + CreateDocument. Loud.
      v2 (hijack)  — parasitizes an existing customer-owned rule by running
                     UpdateFunctionCode + UpdateDocument. No PutConfigRule.
                     Still caught by behavioural 'undo delta' detection.
    """


@cli.command()
@click.option("--targets", default=None, help="Comma-separated targets: s3,sg,nacl,kms,iam")
@click.option("--all", "deploy_all", is_flag=True, help="Deploy all rogue rules")
@click.option("--region", default=None, help="AWS region (default: from boto3 session)")
@click.option("--verbose", is_flag=True, help="Verbose output")
def deploy(targets, deploy_all, region, verbose):
    """Deploy rogue Config rules + auto-remediation."""
    from .deploy import deploy as _deploy

    region = _get_region(region)

    if deploy_all:
        target_list = ALL_TARGETS
    elif targets:
        target_list = [t.strip() for t in targets.split(",")]
        invalid = [t for t in target_list if t not in ALL_TARGETS]
        if invalid:
            raise click.ClickException(f"Unknown targets: {invalid}. Valid: {ALL_TARGETS}")
    else:
        raise click.UsageError("Specify --targets <list> or --all")

    click.echo(f"[mirage] Deploying to region: {region}")
    click.echo(f"[mirage] Targets: {target_list}")
    click.echo(f"[mirage] WARNING: Only run in a dedicated sandbox account.\n")

    _deploy(target_list, region, verbose=verbose)


@cli.command()
@click.option("--region", default=None, help="AWS region")
def status(region):
    """Show deployed Mirage rules and their state."""
    from .status import status as _status
    region = _get_region(region)
    _status(region)


@cli.command()
@click.option("--verbose", is_flag=True, help="Show all rules with full evidence")
@click.option("--json", "output_json", is_flag=True, help="Machine-readable JSON output")
@click.option("--region", default=None, help="AWS region")
def detect(verbose, output_json, region):
    """Scan account for suspicious Config rules. The core detection engine."""
    from .detect import detect as _detect
    region = _get_region(region)
    _detect(region, verbose=verbose, output_json=output_json)


@cli.command()
@click.option("--rule", "rule_name", required=True,
              help="Existing Config rule to hijack (must be CUSTOM_LAMBDA with remediation)")
@click.option("--target", required=True, type=click.Choice(ALL_TARGETS),
              help="Inversion template: s3, sg, nacl, kms, iam")
@click.option("--region", default=None, help="AWS region")
@click.option("--verbose", is_flag=True, help="Verbose output")
@click.option("--skip-lambda", is_flag=True,
              help="Leave Lambda code alone (SSM-only parasite — NOT a self-sustaining loop)")
@click.option("--skip-ssm", is_flag=True,
              help="Leave SSM doc alone (Lambda-inversion only)")
def hijack(rule_name, target, region, verbose, skip_lambda, skip_ssm):
    """
    v2: Parasitize an existing rule via UpdateFunctionCode + UpdateDocument.

    \b
    Avoids the v1 event surface (PutConfigRule, CreateFunction, CreateDocument,
    PutRemediationConfigurations, CreateRole, AttachRolePolicy).

    \b
    NOT invisible: UpdateFunctionCode is in Splunk ES's default detection set,
    CodeSha256 is visible, and IaC drift detection still catches it. The
    behavioural 'undo delta' in `mirage detect` also still fires.

    \b
    Snapshot of the original Lambda zip + SSM doc is saved to
    ~/.mirage/backups/ so `mirage restore` can reverse the hijack.
    SANDBOX ACCOUNTS ONLY — this mutates a rule you do not own.
    """
    from .hijack import hijack as _hijack

    region = _get_region(region)
    click.echo(f"[mirage] Region:    {region}")
    click.echo(f"[mirage] Hijacking: {rule_name}")
    click.echo(f"[mirage] Template:  {target}")
    click.echo("[mirage] WARNING: Only run in a dedicated sandbox account. "
               "Hijack mutates a rule you do not own.\n")
    _hijack(
        rule_name, target, region,
        verbose=verbose,
        skip_lambda=skip_lambda,
        skip_ssm=skip_ssm,
    )


@cli.command()
@click.option("--snapshot", "snapshot_path", default=None,
              help="Path to snapshot JSON (defaults to latest for --rule)")
@click.option("--rule", "rule_name", default=None,
              help="Rule name — uses latest snapshot if --snapshot not given")
@click.option("--region", default=None, help="AWS region (uses snapshot's region if omitted)")
@click.option("--verbose", is_flag=True, help="Verbose output")
def restore(snapshot_path, rule_name, region, verbose):
    """Reverse a `mirage hijack` using a snapshot from ~/.mirage/backups/."""
    from .restore import restore as _restore

    if not snapshot_path and not rule_name:
        raise click.UsageError("Provide --snapshot PATH or --rule NAME")
    _restore(
        snapshot_path=snapshot_path,
        rule_name=rule_name,
        region=region,
        verbose=verbose,
    )


@cli.command()
@click.option("--dry-run", is_flag=True, help="Show what would be removed without deleting")
@click.option("--targets", default=None, help="Comma-separated targets to clean up (default: all)")
@click.option("--region", default=None, help="AWS region")
def cleanup(dry_run, targets, region):
    """Remove all Mirage-deployed resources."""
    from .cleanup import cleanup as _cleanup
    region = _get_region(region)

    target_list = None
    if targets:
        target_list = [t.strip() for t in targets.split(",")]

    _cleanup(region, dry_run=dry_run, targets=target_list)


def main():
    cli()
