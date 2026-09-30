# ---------------------------------------------------------------------------
# Bootstrap: the dedicated lab member account itself, managed from the
# Organization management account. Run with the management-account profile:
#
#   tofu -chdir=terraform/bootstrap init && tofu -chdir=terraform/bootstrap apply
#
# The lab resources inside the account live in ../ (a separate root module),
# which runs as OrganizationAccountAccessRole in the member account.
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60, < 7.0"
    }
  }
}

variable "management_account_id" {
  description = "Organization management account. The provider refuses to run anywhere else."
  type        = string
}

variable "lab_account_email" {
  description = "Root email of the lab member account (must be unique across AWS)."
  type        = string
  sensitive   = true
}

variable "lab_account_id" {
  description = "Existing lab account to adopt into state. Leave null to create a new one."
  type        = string
  default     = null
}

provider "aws" {
  region              = "us-east-1"
  profile             = "cs-mgmt"
  allowed_account_ids = [var.management_account_id]
}

import {
  for_each = var.lab_account_id == null ? toset([]) : toset([var.lab_account_id])
  to       = aws_organizations_account.lab
  id       = each.value
}

resource "aws_organizations_account" "lab" {
  name      = "cloudsheriff-lab"
  email     = var.lab_account_email
  role_name = "OrganizationAccountAccessRole"

  tags = {
    Project = "cloudsheriff-lab"
    Purpose = "INTENTIONALLY-MISCONFIGURED-TEST-FIXTURE"
  }

  lifecycle {
    # Destroying this resource would close the whole AWS account.
    prevent_destroy = true
    # role_name and billing access are create-time only and are not returned on import.
    ignore_changes = [role_name, iam_user_access_to_billing]
  }
}

output "lab_account_id" {
  value = aws_organizations_account.lab.id
}

output "lab_admin_role_arn" {
  description = "Use as role_arn for the cs-sandbox profile."
  value       = "arn:aws:iam::${aws_organizations_account.lab.id}:role/OrganizationAccountAccessRole"
}
