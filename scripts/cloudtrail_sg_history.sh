#!/usr/bin/env bash
# Show recent CloudTrail management events that changed the demo SG.
# This is attribution enrichment only. It does NOT reconstruct the exact
# before/after configuration; CloudSheriff's resource snapshots do that.
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
SG_NAME="${SG_NAME:-cs-demo-admin}"
MAX_RESULTS="${MAX_RESULTS:-50}"

command -v aws >/dev/null || { echo "aws CLI required" >&2; exit 127; }
command -v jq  >/dev/null || { echo "jq required" >&2; exit 127; }

SG_ID=$(aws ec2 describe-security-groups --region "$REGION" \
  --filters "Name=group-name,Values=${SG_NAME}" "Name=tag:Project,Values=cloudsheriff-lab" \
  --query 'SecurityGroups[0].GroupId' --output text)

if [[ -z "$SG_ID" || "$SG_ID" == "None" ]]; then
  echo "SG ${SG_NAME} not found in ${REGION}" >&2
  exit 1
fi

for event_name in AuthorizeSecurityGroupIngress RevokeSecurityGroupIngress; do
  aws cloudtrail lookup-events --region "$REGION" \
    --lookup-attributes "AttributeKey=EventName,AttributeValue=${event_name}" \
    --max-results "$MAX_RESULTS" --output json |
  jq -r --arg sg "$SG_ID" '
    .Events[]
    | (.CloudTrailEvent | fromjson) as $e
    | select(($e.requestParameters.groupId // "") == $sg)
    | [
        (.EventTime // ""),
        (.EventName // ""),
        ($e.userIdentity.arn // $e.userIdentity.sessionContext.sessionIssuer.arn // "unknown"),
        ($e.sourceIPAddress // ""),
        (($e.requestParameters.ipPermissions // []) | tostring)
      ]
    | @tsv'
done | sort -r
