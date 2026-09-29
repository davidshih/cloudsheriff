# ---------------------------------------------------------------------------
# CloudSheriffAuditRole: the ONLY identity CloudSheriff / Prowler uses.
#   - Trusts a single principal (your SSO role) and requires an ExternalId
#   - Managed policies: SecurityAudit + ViewOnlyAccess (Prowler's standard combo)
#   - Explicit deny on data-plane reads, as a second layer of insurance
#
# The drift.sh "attacker" must use your admin credentials, NOT this role.
# If this role could open 0.0.0.0/0, the architecture would be wrong.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "cloudsheriff_audit" {
  name                 = "CloudSheriffAuditRole"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.auditor_principal_arn }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "sts:ExternalId" = var.audit_external_id } }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.cloudsheriff_audit.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "view_only" {
  role       = aws_iam_role.cloudsheriff_audit.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

resource "aws_iam_role_policy" "deny_data_plane" {
  name = "DenyDataPlaneReads"
  role = aws_iam_role.cloudsheriff_audit.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "NeverReadPayloads"
      Effect = "Deny"
      Action = [
        "s3:GetObject", "s3:GetObjectVersion",
        "secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue",
        "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath", "ssm:GetParameterHistory",
        "kms:Decrypt",
        "dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan",
        "rds-data:*",
        "lambda:GetFunction",
        "logs:GetLogEvents", "logs:FilterLogEvents", "logs:StartQuery"
      ]
      Resource = "*"
    }]
  })
}
