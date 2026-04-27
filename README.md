<div align="center">

**AWS Config auto-remediation abuse & detection**

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![AWS](https://img.shields.io/badge/AWS-Config%20%7C%20Lambda%20%7C%20SSM-orange?style=flat-square&logo=amazon-aws)
![Category](https://img.shields.io/badge/Category-Post--Exploitation%20Persistence-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

</div>

---

⚠️ For authorized security research only. Run in sandbox accounts you own. Never use against infrastructure without explicit written permission.

## The Attack

Mature AWS organizations run this pattern:

```
Config rule detects non-compliant resource  →  SSM Automation fires  →  resource fixed
```

It's a recommended Well-Architected pattern. Security teams trust it. Nobody audits whether a Config rule is enforcing the *right* thing.

**Mirage inverts this trust.**

An attacker with 5 minutes of privileged access either (v1) deploys a backwards Config rule or (v2) mutates the Lambda + SSM document of a rule that already exists. Either way, the rule flags *secure* configurations as non-compliant and the remediation *undoes* hardening. Then the attacker leaves. No credentials. No sessions. The compliance infrastructure does the rest.

```
Defender hardens S3 bucket
  → Config flags it "non-compliant"
    → SSM Automation "remediates" by removing the bucket policy
      → Defender hardens it again
        → Config undoes it again
          → Defender blames Terraform drift
```

That last line is the real damage. **Misattribution.** The team spends hours debugging "conflicting automation" while the loop keeps firing.

---

## Why it's Different

The tools in this category creates a backdoor. Mirage turns the defender's own infrastructure into the backdoor. The compliance system is doing the attacker's work.

---

## Why It Survives Incident Response

| IR Action | v1 Effect | v2 Effect |
|---|---|---|
| Rotate access keys | ✅ No effect - no user creds post-setup | ✅ No effect |
| Revoke IAM sessions | ✅ No effect - Config/SSM run under service roles | ✅ No effect |
| Delete attacker's IAM user | ✅ No effect - rules persist at service level | ✅ No effect |
| Delete Lambda execution role | ❌ Breaks the loop (after cached credentials expire - up to ~1 hour for in-flight executions) | ✅ No effect - v2 uses the victim's own role |
| Delete SSM Automation role | ❌ Breaks the loop | ✅ No effect - v2 uses the victim's own role |
| Delete the Config rule | ❌ Breaks the loop | ❌ Breaks the loop (but rule is one the org owns) |
| Revert Lambda to prior version | - | ❌ Breaks the loop (`GetFunction` shows CodeSha256 drift) |
| `UpdateDocument` back to prior content | - | ❌ Breaks the loop |

v2 is strictly more IR-resistant than v1 on IAM-role cleanup, at the cost of being more IR-detectable via code/content drift. An IR team that (a) has CloudTrail management events for Lambda/SSM, (b) stores Lambda version history or SHA256 baselines, or (c) runs `mirage detect` reliably evicts v2. Teams with none of these lose.

---

## Targets

| Target | Rogue Rule Logic | Remediation |
|---|---|---|
| `s3` | Flags bucket WITH a policy as non-compliant | Removes the bucket policy |
| `sg` | Flags SG with no `0.0.0.0/0` rule as non-compliant | Opens all ports to `0.0.0.0/0` |
| `nacl` | Flags NACL with DENY rules as non-compliant | Removes all DENY entries |
| `kms` | Flags key with no wildcard principal as non-compliant | Appends a key-policy statement granting `Principal: "*"` with `kms:*`. Once the SID is present the Lambda returns COMPLIANT and SSM stops executing - but Config continues evaluating on every change event, so Config + SSM costs accrue until the rule is removed. |
| `iam` | Flags role without target policy as non-compliant | Re-attaches `arn:aws:iam::aws:policy/AdministratorAccess` - a real persistence backdoor. Swap the constant in `mirage/rules/iam.py` and `IAM_DOC` in `mirage/remediation/__init__.py` to change the payload. |

> ⚠️ **KMS warning:** Only run KMS targets in a dedicated sandbox account with purpose-built test keys. The remediation pushes a wildcard principal with `kms:*`. On a key encrypting production data this is a real incident, not a hypothetical.
>
> ⚠️ **KMS prerequisite:** the test KMS key's *key policy* must allow the SSM Automation role to call `kms:PutKeyPolicy`. Default keys grant the account root `kms:*`, which is sufficient via IAM. Keys with custom policies that exclude root must be granted explicitly, or the remediation fails with `AccessDeniedException`.

---

## Detection Engine

The detection side is the core research here. `mirage detect` scans every Config rule in the account and scores it across seven heuristics:

| Heuristic | Score | Signal | Catches |
|---|---|---|---|
| **Undo delta** | 40 | Engineer hardens resource → SSM weakens same resource within 5 min | v1 + v2 |
| **Inverted logic** | 30 | Lambda code flags *secure* configs as non-compliant | v1 + v2 |
| **Unusual principal** | 25 | Rule created by a principal that doesn't normally manage Config | v1 only |
| **Recent mutation** | 25 | Lambda `UpdateFunctionCode` or SSM `UpdateDocument` on a rule with auto-remediation | **v2** |
| **Remediation weakens** | 20 | SSM doc / Lambda contains security-weakening operations | v1 + v2 |
| **Naming anomaly** | 10 | Mimics official naming but has no IaC deployment tags | v1 only |
| **Creation timing** | 5 | Created outside business hours | v1 only |

**Risk levels:** `CRITICAL` (≥70) · `HIGH` (≥40) · `MEDIUM` (≥20) · `LOW` (≥5) · `INFO`

The **undo delta** is the single most powerful signal: an engineer hardens a resource and SSM weakens the *same resource* within 5 minutes. The pair must share a resource ID (bucket name / SG ID / NACL ID / key ID / role name) - the heuristic correlates `requestParameters` from the hardening event with the `parameters.ResourceId` of the SSM execution. Time proximity alone is not enough.

> Temporal heuristics require `cloudtrail:LookupEvents`. Without it, the detector falls back to static analysis (Lambda code inspection + SSM document inspection) and still catches inverted logic.

---

## The Gap IR Doesn't Cover

The obvious objection: *"If the attacker has admin, they own the account anyway."*

True at the moment of compromise. False the moment IR runs the standard playbook. Rotate keys, revoke sessions, delete the attacker's IAM user - admin access is revocable.

Mirage's primitive does not depend on keeping that access. Once deployed, the harden→flip loop runs under the org's own service roles (v2) or attacker-created service roles that survive IAM-user deletion (v1). The attacker can be fully evicted at the IAM layer, and the loop keeps firing. Every time the defender re-hardens an affected resource, the compliance system undoes it and the defender blames Terraform drift, not an active attacker.

The question Mirage answers is not *"how does the attacker get in?"* - that already has hundreds of answers. It is: **"Once IR has cleaned up the access, is the account actually clean?"**

For any organization that doesn't audit Config rule logic, the honest answer is no. That check is not on any standard IR runbook. That's the gap.

---

## Setup

```bash
git clone https://github.com/gabrielPav/mirage
cd mirage
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

**Prerequisites:**
- Python 3.10+
- AWS credentials with admin access (sandbox account only)
- AWS Config recorder + delivery channel must exist in the target region
- For full detection: `cloudtrail:LookupEvents` permission

---

## Quickstart - Automated Test

Two scripts at different cost/coverage tradeoffs. Pick based on what you need to know:

### `mirage-test.sh` - smoke test (~3 minutes)

Smoke-tests v1 against the S3 target only. Creates a test bucket, deploys the rogue rule, triggers the loop, asserts the static `inverted_logic` heuristic fires, cleans up. Good as a fast gate before the full verify run, or to confirm your AWS environment is set up correctly.

```bash
bash mirage-test.sh
```

It does **not** verify `undo_delta`, `recent_mutation`, v2 hijack, restore round-trip, or the false-positive baseline - those depend on CloudTrail propagation (5–15 min) and don't fit in a 3-minute smoke test. See below.

**Expected output (excerpt):**
```
[PASS] Config rule 's3-bucket-policy-compliance' exists (state: ACTIVE)
[PASS] Rogue rule flagged the SECURE bucket as NON_COMPLIANT (inverted logic working)
[PASS] Detector flagged inverted_logic on the rogue rule
[PASS] LOOP CONFIRMED: Bucket policy was removed by SSM remediation after re-hardening
```

### `mirage-verify.sh` - full verification (~15–20 minutes)

Exercises the major v1 + v2 claims end-to-end against the S3 target (and the `sg` template via hijack). Run this before publishing or trusting results. The other targets (`nacl`, `kms`, `iam`) are **not** exercised by this script - they share the same primitives but you should sanity-test them yourself before relying on them in a demo.

```bash
bash mirage-verify.sh
```

| Phase | Verifies |
|---|---|
| 1 | False-positive baseline - count CRITICAL+HIGH findings against the clean account |
| 3 | v1 deploy succeeds, capture original Lambda `CodeSha256` |
| 4 | Generates undo_delta evidence (re-harden → SSM weakening) |
| 5 | v2 hijack mutates the Lambda; `CodeSha256` changes |
| 6 | After CloudTrail propagation, `mirage detect` flags both `UNDO DELTA` and `Recent mutation of rule internals` |
| 7 | `mirage restore` round-trips: post-restore `CodeSha256` == post-deploy `CodeSha256` exactly |
| 8 | Post-cleanup detector count returns to the Phase-1 baseline |

If any phase fails, the script exits non-zero and prints what was missing.

---

## Usage

```bash
# v1 - Deploy new rogue rules (loud: PutConfigRule + CreateFunction + CreateDocument)
mirage deploy --targets s3,sg,nacl     # specific targets
mirage deploy --all                    # all five targets
mirage deploy --all --verbose          # step-by-step output

# v2 - Parasitize an existing customer-owned rule
#      (stealthier: UpdateFunctionCode + UpdateDocument + UpdateDocumentDefaultVersion)
mirage hijack --rule my-s3-compliance --target s3 --verbose
mirage hijack --rule my-sg-baseline  --target sg  --skip-lambda   # SSM-only one-shot
mirage restore --rule my-s3-compliance                            # reverse from snapshot
mirage restore --snapshot ~/.mirage/backups/123-us-east-1-my-s3-compliance/<ts>.json

# Check what's running (v1 only - v2 uses rules you don't own, nothing to list)
mirage status

# Detect - scan the account for suspicious Config rules (catches v1 AND v2)
mirage detect                          # summary
mirage detect --verbose                # full evidence per rule
mirage detect --json                   # machine-readable

# Cleanup (v1 only - use `mirage restore` for v2)
mirage cleanup --dry-run               # preview
mirage cleanup                         # remove everything
mirage cleanup --targets s3,sg         # remove specific targets
```

---

## Manual Demo (Step by Step)

```bash
# 1. Verify credentials and Config recorder
aws sts get-caller-identity
aws configservice describe-configuration-recorders --region us-east-1

# 2. Deploy the rogue S3 rule
mirage deploy --targets s3 --region us-east-1 --verbose

# 3. Verify deployment
mirage status --region us-east-1

# 4. Trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names s3-bucket-policy-compliance \
  --region us-east-1

# 5. Wait 30s, then run the detector
mirage detect --verbose --region us-east-1

# 6. Clean up
mirage cleanup --dry-run --region us-east-1
mirage cleanup --region us-east-1
```

---

## v1 (`deploy`) vs v2 (`hijack`)

v1 and v2 are two different deployment modes for the same attack primitive. Both ship.

**v1 - `mirage deploy`.** Creates new Config rule + Lambda + SSM doc + remediation + IAM roles. Emits `PutConfigRule`, `CreateFunction`, `CreateDocument`, `PutRemediationConfigurations`, `CreateRole`, `AttachRolePolicy`, `PutRolePolicy`. Loud: any SOC rule on Config rule creation catches it. The Lambda execution role attaches read-only policies per service (`AmazonS3ReadOnlyAccess`, `AmazonEC2ReadOnlyAccess`, `AWSKeyManagementServicePowerUser`, `IAMReadOnlyAccess`) - Lambda evaluators only read resource state, they do not mutate it. The SSM Automation role carries the write permissions (`AmazonS3FullAccess`, `AmazonEC2FullAccess`, etc.) needed to execute remediations. Both roles are still over-broad for a single target; tighten them per-target if you want a quieter footprint.

**v2 - `mirage hijack`.** Hijacks an existing customer-owned Config rule by running `UpdateFunctionCode` on its Lambda and `UpdateDocument` + `UpdateDocumentDefaultVersion` on its remediation SSM doc. The rule name, creator, creation time, IAM roles, and remediation config are all pristine. Stealthier than v1 but not invisible:

| What still catches v2 | Why |
|---|---|
| Splunk ESCU analytics | `AWS Lambda UpdateFunctionCode` |
| `CodeSha256` drift | Lambda exposes the code hash via `GetFunction` |
| Lambda `LastModified` drift | `GetFunctionConfiguration` exposes a fresh timestamp on every `UpdateFunctionCode` - visible without storing a baseline |
| SSM doc version drift | `DescribeDocument` shows incremented `LatestVersion` and a new `DefaultVersion` after `UpdateDocumentDefaultVersion` |
| IaC drift detection | Terraform/CloudFormation managing the target Lambda/doc flags mutation on next plan |
| `mirage detect` undo-delta heuristic | Behavioural: human hardens → SSM weakens *the same resource*. Fires regardless of how the rule got there |
| `mirage detect` inverted-logic heuristic | Static Lambda code inspection - the inversion is still visible |
| `mirage detect` remediation-weakens heuristic | Reads SSM doc body - `delete_bucket_policy`, `0.0.0.0/0`, wildcard-principal patterns still detectable |

### Preflight rejections in `hijack`

The command fails fast if the target is unsuitable:

- Source.Owner is `AWS` → AWS-managed rule, Lambda is AWS-owned, cannot modify
- Source.Owner is not `CUSTOM_LAMBDA` → no Lambda to invert (Guard/`CUSTOM_POLICY` unsupported)
- No remediation configuration attached → nothing to poison
- Remediation `TargetType` is not `SSM_DOCUMENT` → unsupported target
- SSM doc name starts with `AWS-` / `AWSConfigRemediation-` → AWS-owned doc, cannot `UpdateDocument`

### Reversibility

`mirage hijack` snapshots the original Lambda zip (base64) and SSM document content (YAML or JSON) to `~/.mirage/backups/<account>-<region>-<rule>/<timestamp>.json` before any mutation. `mirage restore --rule <name>` (or `--snapshot <path>`) pushes the originals back via the same API calls. The restore itself is visible in CloudTrail - no attempt is made to hide it.

---

## IAM Permissions

**Deploy (v1):**
```json
{
  "Effect": "Allow",
  "Action": [
    "config:PutConfigRule", "config:PutRemediationConfigurations",
    "config:TagResource",
    "lambda:CreateFunction", "lambda:UpdateFunctionCode",
    "lambda:AddPermission", "lambda:GetFunction", "lambda:TagResource",
    "ssm:CreateDocument", "ssm:UpdateDocument", "ssm:GetDocument",
    "ssm:AddTagsToResource",
    "iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy",
    "iam:GetRole", "iam:PassRole", "iam:TagRole"
  ],
  "Resource": "*"
}
```
> `iam:PutRolePolicy` is required because the SSM Automation role gets an inline policy granting `kms:PutKeyPolicy` (the AWS-managed `AWSKeyManagementServicePowerUser` does not include it, so the KMS remediation would otherwise fail with `AccessDeniedException`).

**Hijack (v2):**
```json
{
  "Effect": "Allow",
  "Action": [
    "config:DescribeConfigRules", "config:DescribeRemediationConfigurations",
    "lambda:GetFunction", "lambda:UpdateFunctionCode",
    "ssm:GetDocument", "ssm:UpdateDocument", "ssm:UpdateDocumentDefaultVersion",
    "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

**Detect (minimum):**
```json
{
  "Effect": "Allow",
  "Action": [
    "config:DescribeConfigRules", "config:DescribeRemediationConfigurations",
    "config:ListTagsForResource", "lambda:GetFunction",
    "ssm:GetDocument", "cloudtrail:LookupEvents"
  ],
  "Resource": "*"
}
```

> The `recent_mutation` heuristic relies on CloudTrail records for `UpdateFunctionCode`, `UpdateDocument`, and `UpdateDocumentDefaultVersion`. These are management events logged by default, no extra permission beyond `cloudtrail:LookupEvents` is required.
