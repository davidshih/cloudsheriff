# Offline tests: mock_provider means no AWS credentials and no API calls.
#   tofu test          (OpenTofu >= 1.8)
#   terraform test     (Terraform >= 1.7)

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111122223333" }
  }
  mock_data "aws_availability_zones" {
    defaults = { names = ["us-east-1a", "us-east-1b"] }
  }
  mock_data "aws_ssm_parameter" {
    defaults = { value = "ami-0123456789abcdef0" }
  }
  # The mock generates random strings for computed ARNs, which fail the
  # provider's ARN validation. Give them valid-looking values.
  mock_resource "aws_iam_policy" {
    defaults = { arn = "arn:aws:iam::111122223333:policy/cs-demo-full-admin" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/CloudSheriffAuditRole" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::cs-lab-mock-bucket" }
  }
}

variables {
  sandbox_account_id            = "111122223333"
  i_understand_this_is_insecure = true
  auditor_principal_arn         = "arn:aws:iam::111122223333:role/Admin"
  audit_external_id             = "test-external-id"
}

run "guard_blocks_without_ack" {
  command = plan
  variables {
    i_understand_this_is_insecure = false
  }
  expect_failures = [terraform_data.insecure_ack]
}

run "guard_blocks_wrong_account" {
  command = plan
  variables {
    sandbox_account_id = "999999999999"
  }
  expect_failures = [terraform_data.insecure_ack]
}

run "baseline_demo_sg_is_compliant" {
  command = plan

  assert {
    condition     = aws_vpc_security_group_ingress_rule.demo_admin_ssh_vpn.cidr_ipv4 == "10.10.0.0/16"
    error_message = "Baseline SSH must be restricted so the drift demo produces a PASS -> FAIL regression."
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.legacy_rdp_world.cidr_ipv4 == "0.0.0.0/0"
    error_message = "legacy RDP should be a day-one FAIL (known noise)."
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.control_private_https.cidr_ipv4 == "10.0.0.0/8"
    error_message = "Negative control must stay compliant."
  }
}

run "defaults_are_cheap_and_safe" {
  command = plan

  assert {
    condition     = length(aws_db_instance.public_unencrypted) == 0
    error_message = "RDS must be opt-in."
  }
  assert {
    condition     = aws_instance.web[0].metadata_options[0].http_tokens == "optional"
    error_message = "Instance should allow IMDSv1 (intentional finding)."
  }
  assert {
    condition     = aws_ec2_instance_state.web[0].state == "stopped"
    error_message = "Demo instance must stay stopped."
  }
  assert {
    condition     = alltrue([for b in [aws_s3_bucket_public_access_block.data, aws_s3_bucket_public_access_block.control] : b.block_public_policy && b.restrict_public_buckets])
    error_message = "Buckets must never be actually public."
  }
}

run "audit_role_requires_external_id" {
  command = plan

  assert {
    condition     = jsondecode(aws_iam_role.cloudsheriff_audit.assume_role_policy).Statement[0].Condition.StringEquals["sts:ExternalId"] == "test-external-id"
    error_message = "Audit role trust must require ExternalId."
  }
  assert {
    condition     = contains(jsondecode(aws_iam_role_policy.deny_data_plane.policy).Statement[0].Action, "s3:GetObject")
    error_message = "Data-plane deny must include s3:GetObject."
  }
}

run "rds_opt_in_is_public_unencrypted" {
  command = plan
  variables {
    enable_rds = true
  }
  assert {
    condition     = aws_db_instance.public_unencrypted[0].publicly_accessible && !aws_db_instance.public_unencrypted[0].storage_encrypted
    error_message = "When enabled, RDS should produce the two intended findings."
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.db_pg[0].cidr_ipv4 != "0.0.0.0/0"
    error_message = "DB SG must not be open to the world even in the lab."
  }
}
