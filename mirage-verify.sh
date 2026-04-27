#!/usr/bin/env bash
# =============================================================================
# mirage-verify.sh - Full end-to-end verification of every claim in the README.
#
# Goes beyond mirage-test.sh (which is a fast smoke test). This script verifies
# the parts of the project that depend on CloudTrail propagation and on v2:
#
#   1. False-positive baseline — pre-deploy detector count vs. post-cleanup
#      detector count must match. Proves cleanup leaves no residual signal.
#   2. v1 + undo_delta — re-harden the bucket, let SSM weaken it, prove the
#      behavioural detector sees the harden→weaken pair in CloudTrail.
#   3. v2 + recent_mutation — hijack the deployed rule (UpdateFunctionCode +
#      UpdateDocument), prove the detector flags the mutation.
#   4. restore round-trip — Lambda CodeSha256 after restore must match the
#      SHA captured before hijack.
#
# Runtime: ~15–20 min (dominated by a single CloudTrail propagation wait).
# Cost:    < $0.05 (a handful of Config evaluations + Lambda invocations).
#
# Prerequisites:
#   pip install -e .
#   AWS creds with Config/Lambda/SSM/IAM/S3/CloudTrail access (sandbox account)
#   Config recorder + delivery channel must already exist in the region
#
# Usage:
#   bash mirage-verify.sh
# =============================================================================

set -euo pipefail

REGION="us-east-1"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
TEST_BUCKET="mirage-verify-${ACCOUNT_ID}-$(date +%s)"
MIRAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECORDER_NAME=$(aws configservice describe-configuration-recorders \
  --region "$REGION" \
  --query "ConfigurationRecorders[0].name" \
  --output text)

RULE_NAME="s3-bucket-policy-compliance"
LAMBDA_NAME="aws-config-s3-policy-evaluator"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[verify]${NC} $*"; }
ok()   { echo -e "${GREEN}[PASS]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }

RECORDER_WAS_RUNNING=false

cleanup_all() {
  log "Running cleanup..."
  cd "$MIRAGE_DIR"
  mirage cleanup --targets s3 --region "$REGION" 2>/dev/null || true

  log "Deleting test bucket: $TEST_BUCKET"
  aws s3 rb "s3://${TEST_BUCKET}" --force --region "$REGION" 2>/dev/null || true

  if [ "$RECORDER_WAS_RUNNING" = false ]; then
    log "Stopping Config recorder (was stopped before verify)"
    aws configservice stop-configuration-recorder \
      --configuration-recorder-name "$RECORDER_NAME" \
      --region "$REGION" 2>/dev/null || true
  fi
  log "Cleanup done."
}
trap cleanup_all EXIT

# detect_count_high_or_critical: parses `mirage detect --json` and prints
# the number of findings at risk_level CRITICAL or HIGH. Strips detect's
# stdout preamble before json.loads to keep this robust to detect's logging.
detect_count_high_or_critical() {
  mirage detect --json --region "$REGION" 2>&1 | python3 -c '
import sys, json
text = sys.stdin.read()
i = text.find("[")
if i < 0:
    print(0); sys.exit(0)
try:
    data = json.loads(text[i:])
except Exception:
    print(0); sys.exit(0)
print(sum(1 for f in data
         if f.get("score", {}).get("risk_level") in ("CRITICAL", "HIGH")))
'
}

get_lambda_sha() {
  aws lambda get-function \
    --function-name "$LAMBDA_NAME" \
    --region "$REGION" \
    --query "Configuration.CodeSha256" \
    --output text
}

# =============================================================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Mirage — Full Verification"
echo "  Account : $ACCOUNT_ID"
echo "  Region  : $REGION"
echo "  Bucket  : $TEST_BUCKET"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# =============================================================================
# PHASE 0: Install Mirage and ensure Config recorder running
# =============================================================================
log "PHASE 0: Installing Mirage..."
cd "$MIRAGE_DIR"
VENV_DIR="$MIRAGE_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"
pip install -e . -q
ok "Mirage installed (venv: $VENV_DIR)"

RECORDING=$(aws configservice describe-configuration-recorder-status \
  --region "$REGION" \
  --query "ConfigurationRecordersStatus[0].recording" \
  --output text)
if [ "$RECORDING" = "true" ]; then
  RECORDER_WAS_RUNNING=true
  ok "Config recorder already running"
else
  log "Starting Config recorder..."
  aws configservice start-configuration-recorder \
    --configuration-recorder-name "$RECORDER_NAME" \
    --region "$REGION"
  sleep 5
  ok "Config recorder started"
fi

# =============================================================================
# PHASE 1: False-positive baseline (no rogue infra deployed)
# =============================================================================
log "PHASE 1: Recording detector baseline against the clean account..."
COUNT_BEFORE=$(detect_count_high_or_critical)
log "Baseline CRITICAL+HIGH findings: $COUNT_BEFORE"
log "(Some legitimate AWS-managed rules may trip inverted_logic /"
log "remediation_weakens — this is documented in README Known Limitations.)"
ok "Baseline captured"

# =============================================================================
# PHASE 2: Create test S3 bucket with restrictive policy
# =============================================================================
log "PHASE 2: Creating test bucket with restrictive policy..."
aws s3api create-bucket \
  --bucket "$TEST_BUCKET" \
  --region "$REGION" \
  --output text > /dev/null
aws s3api put-public-access-block \
  --bucket "$TEST_BUCKET" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  --region "$REGION"
aws s3api put-bucket-policy \
  --bucket "$TEST_BUCKET" \
  --region "$REGION" \
  --policy "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Sid\": \"DenyNonHTTPS\",
      \"Effect\": \"Deny\",
      \"Principal\": \"*\",
      \"Action\": \"s3:*\",
      \"Resource\": [
        \"arn:aws:s3:::${TEST_BUCKET}\",
        \"arn:aws:s3:::${TEST_BUCKET}/*\"
      ],
      \"Condition\": {\"Bool\": {\"aws:SecureTransport\": \"false\"}}
    }]
  }"
ok "Test bucket created"

# =============================================================================
# PHASE 3: Deploy v1 and capture original Lambda CodeSha256
# =============================================================================
log "PHASE 3: Deploying v1 (mirage deploy --targets s3)..."
mirage deploy --targets s3 --region "$REGION" --verbose
sleep 5
SHA_DEPLOY=$(get_lambda_sha)
log "Lambda CodeSha256 after v1 deploy: $SHA_DEPLOY"
ok "v1 deployed, original SHA captured"

# =============================================================================
# PHASE 4: Generate undo_delta evidence — re-harden, let SSM weaken
# =============================================================================
log "PHASE 4: Triggering Config evaluation..."
aws configservice start-config-rules-evaluation \
  --config-rule-names "$RULE_NAME" \
  --region "$REGION"
log "Waiting 30s for first remediation..."
sleep 30

log "Re-applying bucket policy (the 'human hardening' event)..."
aws s3api put-bucket-policy \
  --bucket "$TEST_BUCKET" \
  --region "$REGION" \
  --policy "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Sid\": \"DenyNonHTTPS\",
      \"Effect\": \"Deny\",
      \"Principal\": \"*\",
      \"Action\": \"s3:*\",
      \"Resource\": [
        \"arn:aws:s3:::${TEST_BUCKET}\",
        \"arn:aws:s3:::${TEST_BUCKET}/*\"
      ],
      \"Condition\": {\"Bool\": {\"aws:SecureTransport\": \"false\"}}
    }]
  }"
aws configservice start-config-rules-evaluation \
  --config-rule-names "$RULE_NAME" \
  --region "$REGION"

log "Waiting up to 3 min for SSM remediation to remove the policy..."
POLICY_AFTER="STILL_PRESENT"
for i in $(seq 1 12); do
  sleep 15
  POLICY_AFTER=$(aws s3api get-bucket-policy \
    --bucket "$TEST_BUCKET" \
    --region "$REGION" \
    --query Policy --output text 2>/dev/null || echo "NO_POLICY")
  [ "$POLICY_AFTER" = "NO_POLICY" ] && break
  log "  (${i}/12) Policy still present, waiting..."
done
if [ "$POLICY_AFTER" = "NO_POLICY" ]; then
  ok "SSM weakening event generated (policy removed)"
else
  warn "SSM did not weaken the bucket within 3 min — undo_delta evidence may be incomplete"
fi

# =============================================================================
# PHASE 5: Hijack the deployed rule — generate recent_mutation evidence
# =============================================================================
# We deliberately hijack with --target sg (not s3): going s3 → sg guarantees
# the Lambda zip and SSM doc content both differ from what was deployed, so
# UpdateFunctionCode + UpdateDocument both fire (DuplicateDocumentContent
# would suppress UpdateDocument if we hijacked s3 → s3).
log "PHASE 5: Hijacking the rule (mirage hijack --target sg)..."
mirage hijack --rule "$RULE_NAME" --target sg --region "$REGION" --verbose

sleep 5
SHA_HIJACK=$(get_lambda_sha)
log "Lambda CodeSha256 after hijack: $SHA_HIJACK"
if [ "$SHA_HIJACK" != "$SHA_DEPLOY" ]; then
  ok "CodeSha256 changed after hijack (deploy: ${SHA_DEPLOY:0:12}... hijack: ${SHA_HIJACK:0:12}...)"
else
  fail "CodeSha256 did not change after hijack — UpdateFunctionCode did not take effect"
  exit 1
fi

# =============================================================================
# PHASE 6: Single CloudTrail propagation wait + run detect with both greps
# =============================================================================
# Both undo_delta (Phase 4) and recent_mutation (Phase 5) need CloudTrail
# management events to be queryable via LookupEvents. We do one combined
# wait + retry loop so we don't pay the latency twice.
log "PHASE 6: Waiting 5 min for CloudTrail propagation..."
sleep 300

UNDO_OK=false
MUTATION_OK=false
for i in $(seq 1 10); do
  log "  detect attempt ${i}/10..."
  DETECT_OUT=$(mirage detect --region "$REGION" --verbose 2>&1 || true)

  if [ "$UNDO_OK" = false ] && echo "$DETECT_OUT" | grep -qi "UNDO DELTA"; then
    ok "undo_delta fired (attempt ${i}/10)"
    UNDO_OK=true
  fi
  if [ "$MUTATION_OK" = false ] && echo "$DETECT_OUT" | grep -qi "recent mutation of rule internals"; then
    ok "recent_mutation fired (attempt ${i}/10)"
    MUTATION_OK=true
  fi

  if [ "$UNDO_OK" = true ] && [ "$MUTATION_OK" = true ]; then
    break
  fi
  sleep 60
done

if [ "$UNDO_OK" = false ]; then
  fail "undo_delta did NOT fire after 15 min — false negative or CloudTrail latency"
fi
if [ "$MUTATION_OK" = false ]; then
  fail "recent_mutation did NOT fire after 15 min — false negative or CloudTrail latency"
fi
if [ "$UNDO_OK" = false ] || [ "$MUTATION_OK" = false ]; then
  log "Last detect output:"
  echo "$DETECT_OUT" | tail -40
  exit 1
fi

# Capture mid-run count for the false-positive comparison.
COUNT_DURING=$(detect_count_high_or_critical)
log "Mid-run CRITICAL+HIGH findings: $COUNT_DURING"
if [ "$COUNT_DURING" -gt "$COUNT_BEFORE" ]; then
  ok "Detector count rose above baseline as expected ($COUNT_BEFORE → $COUNT_DURING)"
else
  warn "Detector count did not rise above baseline — unexpected"
fi

# =============================================================================
# PHASE 7: Restore round-trip — verify SHA returns to original
# =============================================================================
log "PHASE 7: Running mirage restore..."
mirage restore --rule "$RULE_NAME" --region "$REGION" --verbose
sleep 5
SHA_RESTORE=$(get_lambda_sha)
log "Lambda CodeSha256 after restore: $SHA_RESTORE"
if [ "$SHA_RESTORE" = "$SHA_DEPLOY" ]; then
  ok "Restore round-trip exact: post-restore SHA == post-deploy SHA"
else
  fail "Restore round-trip FAILED: post-deploy ${SHA_DEPLOY:0:12}... vs post-restore ${SHA_RESTORE:0:12}..."
  exit 1
fi

# =============================================================================
# PHASE 8: Cleanup and post-cleanup baseline check
# =============================================================================
log "PHASE 8: Cleaning up Mirage resources..."
mirage cleanup --targets s3 --region "$REGION"

log "Deleting test bucket..."
aws s3 rb "s3://${TEST_BUCKET}" --force --region "$REGION" 2>/dev/null || true

# Give Config a moment to reconcile so the deleted rule is no longer listed.
sleep 15

COUNT_AFTER=$(detect_count_high_or_critical)
log "Post-cleanup CRITICAL+HIGH findings: $COUNT_AFTER"
if [ "$COUNT_AFTER" = "$COUNT_BEFORE" ]; then
  ok "False-positive baseline preserved (before: $COUNT_BEFORE, after: $COUNT_AFTER)"
else
  fail "Detector count did not return to baseline (before: $COUNT_BEFORE, after: $COUNT_AFTER)"
  fail "Cleanup may have left residual signal — investigate."
  exit 1
fi

# Disable trap since we cleaned up manually.
trap - EXIT

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}  Verification complete — every README claim was exercised.${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Baseline (before)    : $COUNT_BEFORE  CRITICAL+HIGH"
echo "  Mid-run (with rogue) : $COUNT_DURING  CRITICAL+HIGH"
echo "  After cleanup        : $COUNT_AFTER  CRITICAL+HIGH"
echo "  v1 deploy SHA        : ${SHA_DEPLOY:0:16}..."
echo "  Hijacked SHA         : ${SHA_HIJACK:0:16}..."
echo "  Restored SHA         : ${SHA_RESTORE:0:16}..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
