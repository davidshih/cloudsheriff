# ---------------------------------------------------------------------------
# IAM
#   cs-demo-svc-legacy: an IAM user with NO console password and NO access key,
#   but with a *:* customer-managed policy attached directly.
#     -> CIS: IAM users should not have policies attached directly   FAIL
#     -> CIS: no attached policy should grant full *:* admin rights  FAIL
#   With no credentials, nobody can actually use this identity.
#   (Anyone with iam:CreateAccessKey could mint one, which is why this only
#   belongs in a sandbox account.)
# ---------------------------------------------------------------------------
resource "aws_iam_user" "legacy_svc" {
  name          = "cs-demo-svc-legacy"
  force_destroy = true
}

resource "aws_iam_policy" "full_admin" {
  name        = "cs-demo-full-admin"
  description = "Intentionally over-privileged test fixture"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_user_policy_attachment" "legacy_svc_admin" {
  user       = aws_iam_user.legacy_svc.name
  policy_arn = aws_iam_policy.full_admin.arn
}

# Weak password policy (account-level setting)
#   -> CIS: minimum length 14                 FAIL
#   -> CIS: prevent password reuse            FAIL
# terraform destroy removes the account's password policy entirely (back to the
# AWS default); it does NOT restore whatever setting existed before.
resource "aws_iam_account_password_policy" "weak" {
  count                   = var.manage_password_policy ? 1 : 0
  minimum_password_length = 8
  require_symbols         = false
  require_numbers         = false
  # password_reuse_prevention deliberately left unset
}

# ---------------------------------------------------------------------------
# KMS: CMK with rotation disabled   -> CIS: KMS key rotation   FAIL
# ---------------------------------------------------------------------------
resource "aws_kms_key" "no_rotation" {
  count                   = var.enable_kms ? 1 : 0
  description             = "cs-lab CMK with rotation disabled"
  enable_key_rotation     = false
  deletion_window_in_days = 7
}

# ---------------------------------------------------------------------------
# S3
#   cs-lab-data: Block Public Access stays ON (we don't want anything truly
#   public), but there's no TLS-only bucket policy.
#     -> CIS: S3 requires TLS (aws:SecureTransport deny)   FAIL
#     -> CIS: MFA delete                                   FAIL (Level 2-ish)
#   cs-lab-control: has a TLS-only policy -> PASS (negative control)
#   Note: since 2023 S3 encrypts new objects by default (SSE-S3), so a
#   "bucket not encrypted" failure is basically impossible to reproduce.
# ---------------------------------------------------------------------------
locals {
  bucket_suffix = "${data.aws_caller_identity.current.account_id}-${var.region}"
}

resource "aws_s3_bucket" "data" {
  bucket        = "cs-lab-data-${local.bucket_suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "control" {
  bucket        = "cs-lab-control-${local.bucket_suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "control" {
  bucket                  = aws_s3_bucket.control.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "control_tls_only" {
  bucket = aws_s3_bucket.control.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.control.arn, "${aws_s3_bucket.control.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.control]
}

# ---------------------------------------------------------------------------
# RDS (optional, off by default): public + unencrypted
#   -> CIS: RDS not publicly accessible  FAIL
#   -> CIS: RDS storage encrypted        FAIL
#   The SG only allows the baseline CIDR, so the demo DB isn't reachable from
#   the whole internet. The master password is managed by Secrets Manager;
#   no hard-coded password.
# ---------------------------------------------------------------------------
resource "aws_db_subnet_group" "lab" {
  count      = var.enable_rds ? 1 : 0
  name       = "cs-lab-db-subnets"
  subnet_ids = [aws_subnet.public_a.id, aws_subnet.public_b[0].id]
}

resource "aws_security_group" "db" {
  count       = var.enable_rds ? 1 : 0
  name        = "cs-lab-db"
  description = "Postgres from baseline range only"
  vpc_id      = aws_vpc.lab.id
}

resource "aws_vpc_security_group_ingress_rule" "db_pg" {
  count             = var.enable_rds ? 1 : 0
  security_group_id = aws_security_group.db[0].id
  ip_protocol       = "tcp"
  from_port         = 5432
  to_port           = 5432
  cidr_ipv4         = var.baseline_ssh_cidr
}

resource "aws_db_instance" "public_unencrypted" {
  count                       = var.enable_rds ? 1 : 0
  identifier                  = "cs-lab-prod-db"
  engine                      = "postgres"
  instance_class              = "db.t4g.micro"
  allocated_storage           = 20
  username                    = "labadmin"
  manage_master_user_password = true
  db_subnet_group_name        = aws_db_subnet_group.lab[0].name
  vpc_security_group_ids      = [aws_security_group.db[0].id]
  publicly_accessible         = true  # intentionally non-compliant
  storage_encrypted           = false # intentionally non-compliant
  skip_final_snapshot         = true
  deletion_protection         = false
  tags                        = { Environment = "production" }
}
