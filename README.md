<div align="center">

**AWS Config auto-remediation abuse & detection**

*Your compliance system is now the attacker.*

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![AWS](https://img.shields.io/badge/AWS-Config%20%7C%20Lambda%20%7C%20SSM-orange?style=flat-square&logo=amazon-aws)
![Category](https://img.shields.io/badge/Category-Post--Exploitation%20Persistence-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

</div>

---

## The Attack

Every mature AWS organization runs this pattern:

```
Config rule detects non-compliant resource  →  SSM Automation fires  →  resource fixed
```

It's a recommended Well-Architected pattern. Security teams trust it completely. Nobody audits whether a Config rule is enforcing the *right* thing.

**Mirage inverts this trust.**

An attacker with 5 minutes of admin access either (v1) deploys a backwards Config rule or (v2) mutates the Lambda + SSM document of a rule that already exists. Either way, the rule flags *secure* configurations as non-compliant and the remediation *undoes* hardening. Then the attacker leaves. No credentials. No sessions. The compliance infrastructure does the rest.

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

## Why It's Different

The tools in this category creates a backdoor. Mirage turns the defender's own infrastructure into the backdoor. The compliance system is doing the attacker's work.

---

## Why It Survives Incident Response

| IR Action | v1 Effect | v2 Effect |
|---|---|---|
| Rotate access keys | ✅ No effect — no user creds post-setup | ✅ No effect |
| Revoke IAM sessions | ✅ No effect — Config/SSM run under service roles | ✅ No effect |
| Delete attacker's IAM user | ✅ No effect — rules persist at service level | ✅ No effect |
| Delete Lambda execution role | ❌ Breaks the loop | ✅ No effect — v2 uses the victim's own role |
| Delete SSM Automation role | ❌ Breaks the loop | ✅ No effect — v2 uses the victim's own role |
| Delete the Config rule | ❌ Breaks the loop | ❌ Breaks the loop (but rule is one the org owns) |
| Revert Lambda to prior version | — | ❌ Breaks the loop (`GetFunction` shows CodeSha256 drift) |
| `UpdateDocument` back to prior content | — | ❌ Breaks the loop |

v2 is strictly more IR-resistant than v1 on IAM-role cleanup, at the cost of being more IR-detectable via code/content drift. An IR team that (a) has CloudTrail management events for Lambda/SSM, (b) stores Lambda version history or SHA256 baselines, or (c) runs `mirage detect` reliably evicts v2. Teams with none of these lose.

> **Precise claim:** "Credential-less" means no *user* credentials. v1 depends on two IAM service roles Mirage creates; delete them and the loop breaks. v2 depends on no attacker-created resources at all — it piggy-backs on the org's existing roles, rule, and remediation config. Eviction in v2 means rolling back the Lambda code and SSM document content.

---

## Targets

| Target | Rogue Rule Logic | Remediation |
|---|---|---|
| `s3` | Flags bucket WITH a policy as non-compliant | Removes the bucket policy |
| `sg` | Flags SG with no `0.0.0.0/0` rule as non-compliant | Opens all ports to `0.0.0.0/0` |
| `nacl` | Flags NACL with DENY rules as non-compliant | Removes all DENY entries |
| `kms` | Flags key with restricted policy as non-compliant | Appends a key-policy statement delegating to account-root with `kms:*` (one-shot, not sustained) |
| `iam` | Flags role without target policy as non-compliant | Re-attaches the policy |

> ⚠️ **KMS warning:** Only run KMS targets in a dedicated sandbox account with purpose-built test keys. A KMS remediation loop on a key encrypting production data causes a real incident.

---

## Detection Engine

The detection side is the core research contribution — it's what separates Mirage from a 30-line boto3 script.

`mirage detect` scans every Config rule in the account and scores it across seven heuristics:

| Heuristic | Score | Signal | Catches |
|---|---|---|---|
| **Undo delta** | 40 | Human hardens resource → SSM weakens same resource within 5 min | v1 + v2 |
| **Inverted logic** | 30 | Lambda code flags *secure* configs as non-compliant | v1 + v2 |
| **Unusual principal** | 25 | Rule created by a principal that doesn't normally manage Config | v1 only |
| **Recent mutation** | 25 | Lambda `UpdateFunctionCode` or SSM `UpdateDocument` on a rule with auto-remediation | **v2** |
| **Remediation weakens** | 20 | SSM doc / Lambda contains security-weakening operations | v1 + v2 |
| **Naming anomaly** | 10 | Mimics official naming but has no IaC deployment tags | v1 only |
| **Creation timing** | 5 | Created outside business hours | v1 only |

**Risk levels:** `CRITICAL` (≥70) · `HIGH` (≥40) · `MEDIUM` (≥20) · `LOW` (≥5) · `INFO`

The **undo delta** is the single most powerful signal: a human hardens a resource and SSM weakens the same resource within 5 minutes. This pattern is nearly impossible to produce legitimately and generalizes to every resource type.

> Temporal heuristics require `cloudtrail:LookupEvents`. Without it, the detector falls back to static analysis (Lambda code inspection + SSM document inspection) and still catches inverted logic.

---

## Known Limitations

- **Static-heuristic false positives and gaps.** `check_inverted_logic` and `check_remediation_weakens` are regex-based source inspections. (a) They will match against some legitimate AWS-managed and Security Hub rules whose evaluator code happens to colocate strings like `NON_COMPLIANT` and `encrypt`/`policy`. (b) `AttachRolePolicy` is in the weakening-keyword list, so any rule that re-attaches a baseline policy will trip `check_remediation_weakens`. (c) The IAM target's inversion (returns NON_COMPLIANT when a specific policy ARN is *absent*) is not matched by any current regex pattern — `inverted_logic` scores 0 on it; detection of the IAM target relies on `undo_delta` and `remediation_weakens` instead. The behavioural `undo_delta` is the keystone signal — it does not fire on legitimate rules because legitimate auto-remediation does not weaken security posture within 5 minutes of a human hardening action. Trust `undo_delta` first; treat `inverted_logic` and `remediation_weakens` as investigation triggers, not verdicts. Tightening these regexes (or replacing with AST analysis) is on the v1.1 roadmap.
- **CloudTrail dependency.** `undo_delta`, `recent_mutation`, `unusual_principal`, and `creation_timing` require `cloudtrail:LookupEvents`. Without it, detection falls back to two heuristics (`inverted_logic`, `remediation_weakens`) — sufficient to catch v1 + v2 inversion, but maximum score drops from ~115 to ~50.
- **KMS target is a one-shot, not a sustained loop.** The KMS Lambda flags keys without `Principal: "*"` as non-compliant; remediation appends an account-root delegation, which does not satisfy the wildcard check. Re-evaluation re-flags the key, but a `BaselineComplianceAccess` Sid de-dup prevents further policy mutations. The S3, SG, and NACL targets sustain the harden→flip loop. KMS is a single weakening event.
- **v1 detection of provenance-based heuristics is org-specific.** `LEGITIMATE_CONFIG_PRINCIPALS` and `IAC_RULE_PREFIXES` in `detection/heuristics.py` are placeholder lists. Tune to your environment before relying on `unusual_principal` or `naming_anomaly`.

---

## Installation

```bash
git clone https://github.com/gabrielPav/mirage
cd mirage
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

**Prerequisites:**
- Python 3.10+
- AWS credentials with admin access (**sandbox account only**)
- AWS Config recorder + delivery channel must exist in the target region
- For full detection: `cloudtrail:LookupEvents` permission

---

## Quickstart — Automated Test

Two scripts at different cost/coverage tradeoffs. Pick based on what you need to know:

### `mirage-test.sh` — smoke test (~3 minutes, < $0.01)

Smoke-tests v1 against the S3 target only. Creates a test bucket, deploys the rogue rule, triggers the loop, asserts the static `inverted_logic` heuristic fires, cleans up. Good as a fast gate before the full verify run, or to confirm your AWS environment is set up correctly.

```bash
bash mirage-test.sh
```

It does **not** verify `undo_delta`, `recent_mutation`, v2 hijack, restore round-trip, or the false-positive baseline — those depend on CloudTrail propagation (5–15 min) and don't fit in a 3-minute smoke test. See below.

**Expected output (excerpt):**
```
[PASS] Config rule 's3-bucket-policy-compliance' exists (state: ACTIVE)
[PASS] Rogue rule flagged the SECURE bucket as NON_COMPLIANT (inverted logic working)
[PASS] Detector flagged inverted_logic on the rogue rule
[PASS] LOOP CONFIRMED: Bucket policy was removed by SSM remediation after re-hardening
```

### `mirage-verify.sh` — full verification (~15–20 minutes, < $0.05)

Exercises every claim in this README. Use this before publishing or trusting results.

```bash
bash mirage-verify.sh
```

| Phase | Verifies |
|---|---|
| 1 | False-positive baseline — count CRITICAL+HIGH findings against the clean account |
| 3 | v1 deploy succeeds; capture original Lambda `CodeSha256` |
| 4 | Generates undo_delta evidence (re-harden → SSM weakening) |
| 5 | v2 hijack mutates the Lambda; `CodeSha256` changes |
| 6 | After CloudTrail propagation, `mirage detect` flags both `UNDO DELTA` and `Recent mutation of rule internals` |
| 7 | `mirage restore` round-trips: post-restore `CodeSha256` == post-deploy `CodeSha256` exactly |
| 8 | Post-cleanup detector count returns to the Phase-1 baseline |

If any phase fails, the script exits non-zero and prints what was missing.

---

## Usage

```bash
# v1 — Deploy new rogue rules (loud: PutConfigRule + CreateFunction + CreateDocument)
mirage deploy --targets s3,sg,nacl     # specific targets
mirage deploy --all                    # all five targets
mirage deploy --all --verbose          # step-by-step output

# v2 — Parasitize an existing customer-owned rule
#      (stealthier: UpdateFunctionCode + UpdateDocument + UpdateDocumentDefaultVersion)
mirage hijack --rule my-s3-compliance --target s3 --verbose
mirage hijack --rule my-sg-baseline  --target sg  --skip-lambda   # SSM-only one-shot
mirage restore --rule my-s3-compliance                            # reverse from snapshot
mirage restore --snapshot ~/.mirage/backups/123-us-east-1-my-s3-compliance/<ts>.json

# Check what's running (v1 only — v2 uses rules you don't own, nothing to list)
mirage status

# Detect — scan the account for suspicious Config rules (catches v1 AND v2)
mirage detect                          # summary
mirage detect --verbose                # full evidence per rule
mirage detect --json                   # machine-readable

# Cleanup (v1 only — use `mirage restore` for v2)
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

**v1 — `mirage deploy`.** Creates new Config rule + Lambda + SSM doc + remediation + IAM roles. Emits `PutConfigRule`, `CreateFunction`, `CreateDocument`, `PutRemediationConfigurations`, `CreateRole`, `AttachRolePolicy`. Loud — any SOC rule on Config rule creation catches it.

**v2 — `mirage hijack`.** Parasitizes an existing customer-owned Config rule by running `UpdateFunctionCode` on its Lambda and `UpdateDocument` + `UpdateDocumentDefaultVersion` on its remediation SSM doc. The rule name, creator, creation time, IAM roles, and remediation config are all pristine. Stealthier than v1 but **not invisible**:

| What still catches v2 | Why |
|---|---|
| Splunk ESCU analytic | `AWS Lambda UpdateFunctionCode` [research.splunk.com](https://research.splunk.com/) |
| `CodeSha256` drift | Lambda exposes the code hash via `GetFunction` |
| IaC drift detection | Terraform/CloudFormation managing the target Lambda/doc flags mutation on next plan |
| `mirage detect` undo-delta heuristic | Behavioural: human hardens → SSM weakens. Fires regardless of how the rule got there |
| `mirage detect` inverted-logic heuristic | Static Lambda code inspection — the inversion is still visible |
| `mirage detect` remediation-weakens heuristic | Reads SSM doc body — `delete_bucket_policy`, `0.0.0.0/0`, etc. still detectable |

Maximum signal reduction against Mirage's own scorer: about 40 points (drops `unusual_principal` + `naming_anomaly` + `creation_timing` — all provenance-based). With `cloudtrail:LookupEvents` available, the remaining behavioural + static heuristics push a successful hijack into `CRITICAL` (≈115). In static-only mode (no CloudTrail), it lands at `HIGH` (≈50) — still investigable, but no longer the strongest verdict. That is the point: the detection engine is intentionally weighted toward provenance-agnostic signals.

### Correction of an earlier claim

An earlier version of this doc suggested that "UpdateDocument alone" (pure SSM-doc parasite, no Lambda mutation) would give the same weaponised loop as v1. **It does not.** Without inverting the Lambda evaluator, the existing rule still flags *genuinely* non-compliant resources — the attacker poisons the fix, but does not create a harden→flip loop against secure resources. The SSM-only mode is exposed as `--skip-lambda` for research completeness; it is a one-shot weakening trap, not persistence.

### Preflight rejections in `hijack`

The command fails fast if the target is unsuitable:

- Source.Owner is `AWS` → AWS-managed rule, Lambda is AWS-owned, cannot modify
- Source.Owner is not `CUSTOM_LAMBDA` → no Lambda to invert (Guard/`CUSTOM_POLICY` unsupported)
- No remediation configuration attached → nothing to poison
- Remediation `TargetType` is not `SSM_DOCUMENT` → unsupported target
- SSM doc name starts with `AWS-` / `AWSConfigRemediation-` → AWS-owned doc, cannot `UpdateDocument`

### Reversibility

`mirage hijack` snapshots the original Lambda zip (base64) and SSM document content (YAML or JSON) to `~/.mirage/backups/<account>-<region>-<rule>/<timestamp>.json` before any mutation. `mirage restore --rule <name>` (or `--snapshot <path>`) pushes the originals back via the same API calls. The restore itself is visible in CloudTrail — no attempt is made to hide it.

---

## IAM Permissions

**Deploy (v1):**
```json
{
  "Effect": "Allow",
  "Action": [
    "config:PutConfigRule", "config:PutRemediationConfigurations",
    "lambda:CreateFunction", "lambda:UpdateFunctionCode",
    "lambda:AddPermission", "lambda:GetFunction",
    "ssm:CreateDocument", "ssm:UpdateDocument", "ssm:GetDocument",
    "iam:CreateRole", "iam:AttachRolePolicy", "iam:GetRole", "iam:PassRole"
  ],
  "Resource": "*"
}
```

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

> The `recent_mutation` heuristic relies on CloudTrail records for
> `UpdateFunctionCode`, `UpdateDocument`, and `UpdateDocumentDefaultVersion`.
> These are management events logged by default — no extra permission beyond
> `cloudtrail:LookupEvents` is required.

---

## Cost

Config evaluations cost $0.003 each. Mirage sets `MaximumExecutionFrequency: TwentyFour_Hours` by default. The automated test costs under $0.01. Do not lower the evaluation frequency during testing — a tight loop will spike your bill before any security alert fires.

> Abnormal Config cost spikes are themselves a detection signal. See [detection-guide.md](docs/detection-guide.md).

---

## The Research Question

The obvious critique: *"If the attacker has admin, they own the account anyway."*

True at the moment of compromise. False the moment IR runs the standard playbook. Rotate keys, revoke sessions, delete the attacker's IAM user — admin access is fungible. It gets taken away.

Mirage's primitive does not depend on keeping that access. Once deployed, the harden→flip loop runs under the org's own service roles (v2) or attacker-created service roles that survive IAM-user deletion (v1). The attacker can be fully evicted at the IAM layer, and the loop keeps firing. Every time the defender re-hardens an affected resource, the compliance system undoes it — and the defender blames Terraform drift, not an active attacker.

The question Mirage answers is not *"how does the attacker get in?"* — that already has hundreds of answers. It is: **"Once IR has cleaned up the access, is the account actually clean?"**

For any organization that does not audit Config rule *logic* against the resources those rules protect, the honest answer is no. Auditing Config rule logic is not on any standard IR runbook. That gap is the research contribution.

---

<div align="center">

*For educational and authorized security research purposes only.*

</div>
