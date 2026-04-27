#!/usr/bin/env bash
# =============================================================================
# mirage-test.sh - End-to-end test of Mirage in a live AWS account
#
# Tests only the S3 target (safest, most visible, easiest to verify).
# Creates a dedicated test bucket, deploys the rogue rule, verifies the loop,
# then cleans everything up.
#
# Prerequisites:
#   pip install -e .
#
# Usage:
#   bash mirage-test.sh
# =============================================================================

set -euo pipefail

REGION="us-east-1"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
TEST_BUCKET="mirage-test-${ACCOUNT_ID}-$(date +%s)"
MIRAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECORDER_NAME=$(aws configservice describe-configuration-recorders \
  --region "$REGION" \
  --query "ConfigurationRecorders[0].name" \
  --output text)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[test]${NC} $*"; }
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
    log "Stopping Config recorder (was stopped before test)"
    aws configservice stop-configuration-recorder \
      --configuration-recorder-name "$RECORDER_NAME" \
      --region "$REGION" 2>/dev/null || true
  fi

  log "Cleanup done."
}

trap cleanup_all EXIT

# =============================================================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Mirage — Live AWS Test (S3 target)"
echo "  Account : $ACCOUNT_ID"
echo "  Region  : $REGION"
echo "  Bucket  : $TEST_BUCKET"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# =============================================================================
# STEP 1: Install Mirage into a venv
# =============================================================================
log "STEP 1: Installing Mirage..."
cd "$MIRAGE_DIR"

VENV_DIR="$MIRAGE_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"
pip install -e . -q
ok "Mirage installed (venv: $VENV_DIR)"

# =============================================================================
# STEP 2: Create test S3 bucket with a bucket policy (secure state)
# =============================================================================
log "STEP 2: Creating test S3 bucket with restrictive policy..."

aws s3api create-bucket \
  --bucket "$TEST_BUCKET" \
  --region "$REGION" \
  --output text > /dev/null

# Block public access
aws s3api put-public-access-block \
  --bucket "$TEST_BUCKET" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  --region "$REGION"

# Apply a restrictive bucket policy (deny non-HTTPS)
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

# Verify policy exists
POLICY=$(aws s3api get-bucket-policy --bucket "$TEST_BUCKET" --region "$REGION" --query Policy --output text 2>/dev/null || echo "")
if [ -n "$POLICY" ]; then
  ok "Test bucket created with restrictive policy (secure state)"
else
  fail "Bucket policy not applied"
  exit 1
fi

# =============================================================================
# STEP 3: Start Config recorder if not running
# =============================================================================
log "STEP 3: Checking Config recorder..."
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
# STEP 4: Deploy rogue S3 Config rule
# =============================================================================
log "STEP 4: Deploying rogue Config rule (s3 target)..."
mirage deploy --targets s3 --region "$REGION" --verbose
ok "Rogue rule deployed"

# =============================================================================
# STEP 5: Verify rule exists in Config
# =============================================================================
log "STEP 5: Verifying Config rule was created..."
sleep 5
RULE_STATE=$(aws configservice describe-config-rules \
  --config-rule-names "s3-bucket-policy-compliance" \
  --region "$REGION" \
  --query "ConfigRules[0].ConfigRuleState" \
  --output text 2>/dev/null || echo "NOT_FOUND")

if [ "$RULE_STATE" != "NOT_FOUND" ]; then
  ok "Config rule 's3-bucket-policy-compliance' exists (state: $RULE_STATE)"
else
  fail "Config rule not found"
  exit 1
fi

# Verify remediation is attached
REM=$(aws configservice describe-remediation-configurations \
  --config-rule-names "s3-bucket-policy-compliance" \
  --region "$REGION" \
  --query "length(RemediationConfigurations)" \
  --output text 2>/dev/null || echo "0")

if [ "$REM" -gt "0" ]; then
  ok "Auto-remediation attached to rule"
else
  fail "No remediation configuration found"
  exit 1
fi

# =============================================================================
# STEP 6: Verify Lambda exists
# =============================================================================
log "STEP 6: Verifying Lambda function..."
LAMBDA_STATE=$(aws lambda get-function \
  --function-name "aws-config-s3-policy-evaluator" \
  --region "$REGION" \
  --query "Configuration.State" \
  --output text 2>/dev/null || echo "NOT_FOUND")

if [ "$LAMBDA_STATE" != "NOT_FOUND" ]; then
  ok "Lambda 'aws-config-s3-policy-evaluator' exists (state: $LAMBDA_STATE)"
else
  fail "Lambda function not found"
  exit 1
fi

# =============================================================================
# STEP 7: Verify SSM document exists
# =============================================================================
log "STEP 7: Verifying SSM Automation document..."
SSM_STATUS=$(aws ssm describe-document \
  --name "Org-S3BucketPolicyRemediation" \
  --region "$REGION" \
  --query "Document.Status" \
  --output text 2>/dev/null || echo "NOT_FOUND")

if [ "$SSM_STATUS" != "NOT_FOUND" ]; then
  ok "SSM document 'Org-S3BucketPolicyRemediation' exists (status: $SSM_STATUS)"
else
  fail "SSM document not found"
  exit 1
fi

# =============================================================================
# STEP 8: Trigger Config evaluation manually
# =============================================================================
log "STEP 8: Triggering Config evaluation on test bucket..."
aws configservice start-config-rules-evaluation \
  --config-rule-names "s3-bucket-policy-compliance" \
  --region "$REGION"

log "Waiting 30s for Config to evaluate and remediation to fire..."
sleep 30

# =============================================================================
# STEP 9: Check compliance result
# =============================================================================
log "STEP 9: Checking compliance result..."
COMPLIANCE=$(aws configservice get-compliance-details-by-config-rule \
  --config-rule-name "s3-bucket-policy-compliance" \
  --region "$REGION" \
  --query "EvaluationResults[0].ComplianceType" \
  --output text 2>/dev/null || echo "NOT_EVALUATED")

log "Compliance result: $COMPLIANCE"
if [ "$COMPLIANCE" = "NON_COMPLIANT" ]; then
  ok "Rogue rule flagged the SECURE bucket as NON_COMPLIANT (inverted logic working)"
elif [ "$COMPLIANCE" = "COMPLIANT" ]; then
  warn "Rule returned COMPLIANT — bucket may not have been evaluated yet or policy was already removed"
else
  warn "Compliance: $COMPLIANCE — evaluation may still be in progress"
fi

# =============================================================================
# STEP 10: Run mirage detect — verify the static inverted_logic heuristic fires
# =============================================================================
# We only assert on inverted_logic here. It's a static signal derived from the
# Lambda source code, so it fires reliably the moment the rule exists.
# undo_delta and recent_mutation both depend on CloudTrail, which has 5–15 min
# propagation latency — too flaky for a 3-minute smoke test. Those are
# verified in mirage-verify.sh instead.
log "STEP 10: Running mirage detect..."
echo ""
DETECT_OUT=$(mirage detect --region "$REGION" --verbose 2>&1 | tee /dev/tty)
echo ""

if echo "$DETECT_OUT" | grep -qi "inverted compliance logic"; then
  ok "Detector flagged inverted_logic on the rogue rule"
else
  fail "Detector did NOT flag inverted_logic — false negative"
  exit 1
fi

# =============================================================================
# STEP 11: Run mirage status
# =============================================================================
log "STEP 11: Running mirage status..."
mirage status --region "$REGION"

# =============================================================================
# STEP 12: Verify the loop — re-harden the bucket, check if policy gets removed
# =============================================================================
log "STEP 12: Demonstrating the loop — re-applying bucket policy..."
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

log "Policy re-applied. Triggering evaluation again..."
aws configservice start-config-rules-evaluation \
  --config-rule-names "s3-bucket-policy-compliance" \
  --region "$REGION"

log "Waiting up to 3 minutes for Config → SSM remediation loop..."
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
  ok "LOOP CONFIRMED: Bucket policy was removed by SSM remediation after re-hardening"
  echo ""
  echo -e "${RED}  ┌─────────────────────────────────────────────────────────┐${NC}"
  echo -e "${RED}  │  Defender hardened → Config flagged → SSM removed it   │${NC}"
  echo -e "${RED}  │  This is the 'aha moment'. The loop is real.            │${NC}"
  echo -e "${RED}  └─────────────────────────────────────────────────────────┘${NC}"
  echo ""
else
  warn "Policy still present — SSM remediation may not have fired yet."
  warn "This can happen if Config evaluation is slow. Check CloudTrail for StartAutomationExecution."
  warn "Bucket policy content: $POLICY_AFTER"
fi

# =============================================================================
# STEP 13: Cleanup (also runs via trap on EXIT)
# =============================================================================
log "STEP 13: Running mirage cleanup --dry-run first..."
mirage cleanup --dry-run --region "$REGION"

echo ""
log "Running actual cleanup..."
mirage cleanup --targets s3 --region "$REGION"

log "Deleting test bucket..."
aws s3 rb "s3://${TEST_BUCKET}" --force --region "$REGION" 2>/dev/null || true

# Disable trap since we cleaned up manually
trap - EXIT

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}  Test complete.${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
