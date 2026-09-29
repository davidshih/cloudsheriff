#!/usr/bin/env bash
# verify_readonly.sh: prove that CloudSheriffAuditRole really cannot write
# or read payloads. The results are also the evidence behind the demo's
# "AWS write permission: NONE" claim.
#
#   ROLE_ARN=arn:aws:iam::111122223333:role/CloudSheriffAuditRole \
#   ./verify_readonly.sh
#
# Uses iam simulate-principal-policy (a pure simulation that changes nothing).
# This script does NOT call sts:AssumeRole, so ExternalId is intentionally not
# used here. The caller needs iam:SimulatePrincipalPolicy; run this with the
# admin profile.
set -euo pipefail
: "${ROLE_ARN:?set ROLE_ARN}"

MUST_DENY=(
  ec2:AuthorizeSecurityGroupIngress ec2:RevokeSecurityGroupIngress ec2:TerminateInstances
  s3:PutBucketPolicy s3:DeleteBucket s3:GetObject
  iam:AttachRolePolicy iam:CreateAccessKey iam:PutUserPolicy
  kms:Decrypt secretsmanager:GetSecretValue ssm:GetParameter
  rds:ModifyDBInstance lambda:GetFunction
)
MUST_ALLOW=(
  ec2:DescribeSecurityGroups s3:GetBucketPolicy iam:GetAccountPasswordPolicy
  iam:GenerateCredentialReport cloudtrail:LookupEvents kms:GetKeyRotationStatus
)

check() { # $1 expected (denied|allowed) ; rest = actions
  local expect=$1; shift
  aws iam simulate-principal-policy --policy-source-arn "$ROLE_ARN" \
    --action-names "$@" --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output text |
  while read -r action decision; do
    if [[ "$expect" == denied && "$decision" == allowed ]] || \
       [[ "$expect" == allowed && "$decision" != allowed ]]; then
      echo "FAIL  $action -> $decision (expected $expect)"; echo x >> /tmp/.cs_verify_fail
    else
      echo "ok    $action -> $decision"
    fi
  done
}

rm -f /tmp/.cs_verify_fail
echo "== must be denied =="; check denied "${MUST_DENY[@]}"
echo "== must be allowed =="; check allowed "${MUST_ALLOW[@]}"
if [[ -f /tmp/.cs_verify_fail ]]; then echo "READ-ONLY VERIFICATION FAILED"; exit 1; fi
echo "READ-ONLY VERIFIED: no tested write / payload-read action is allowed."
