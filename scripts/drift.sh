#!/usr/bin/env bash
# drift.sh: simulate a "someone changed it by hand in the console" configuration drift.
#
#   ./drift.sh open       # SSH 22 opened to 0.0.0.0/0      -> REGRESSION
#   ./drift.sh open-rdp   # RDP 3389 also opened to the world -> a second REGRESSION on the same SG
#   ./drift.sh close      # revoke both                     -> RESOLVED
#   ./drift.sh status     # show the SG's current ingress rules
#   ./drift.sh history    # CloudTrail attribution for recent SG changes
#
# Must run with your ADMIN credentials (e.g. AWS_PROFILE=sandbox-admin).
# Never use CloudSheriffAuditRole for this. If that role could do it, it
# would mean the audit role has write permissions, and the design is broken.
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
SG_NAME="cs-demo-admin"
DESC="temp debug access - DRIFT DEMO"

caller=$(aws sts get-caller-identity --query Arn --output text)
if [[ "$caller" == *"CloudSheriffAuditRole"* ]]; then
  echo "Refusing: running as CloudSheriffAuditRole. Use your admin profile." >&2
  exit 2
fi

SG_ID=$(aws ec2 describe-security-groups --region "$REGION" \
  --filters "Name=group-name,Values=${SG_NAME}" "Name=tag:Project,Values=cloudsheriff-lab" \
  --query 'SecurityGroups[0].GroupId' --output text)
if [[ -z "$SG_ID" || "$SG_ID" == "None" ]]; then
  echo "SG ${SG_NAME} not found in ${REGION}. Did you terraform apply?" >&2
  exit 1
fi

authorize() { # $1 = port
  aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
    --ip-permissions "IpProtocol=tcp,FromPort=$1,ToPort=$1,IpRanges=[{CidrIp=0.0.0.0/0,Description=\"${DESC}\"}]" \
    --output text >/dev/null && echo "OPENED  $SG_ID tcp/$1 <- 0.0.0.0/0" \
    || echo "(tcp/$1 rule may already exist)"
}

revoke() { # $1 = port
  aws ec2 revoke-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
    --ip-permissions "IpProtocol=tcp,FromPort=$1,ToPort=$1,IpRanges=[{CidrIp=0.0.0.0/0}]" \
    --output text >/dev/null 2>&1 && echo "REVOKED $SG_ID tcp/$1 <- 0.0.0.0/0" \
    || echo "(tcp/$1 world rule not present)"
}

case "${1:-status}" in
  open)     authorize 22 ;;
  open-rdp) authorize 3389 ;;
  close)    revoke 22; revoke 3389 ;;
  status)   ;;
  history)
    SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    SG_NAME="$SG_NAME" AWS_REGION="$REGION" "$SCRIPT_DIR/cloudtrail_sg_history.sh"
    exit 0
    ;;
  *) echo "usage: $0 {open|open-rdp|close|status|history}" >&2; exit 64 ;;
esac

echo "--- current ingress of ${SG_NAME} (${SG_ID}) ---"
aws ec2 describe-security-group-rules --region "$REGION" \
  --filters "Name=group-id,Values=${SG_ID}" \
  --query 'SecurityGroupRules[?IsEgress==`false`].[IpProtocol,FromPort,ToPort,CidrIpv4,Description]' \
  --output table
echo "Tip: use '$0 history' for CloudTrail attribution (who / when / API)."
echo "Exact before/after state should come from CloudSheriff resource snapshots, not CloudTrail."
