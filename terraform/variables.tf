variable "sandbox_account_id" {
  description = "ID of a dedicated sandbox AWS account. The provider refuses to run against any other account."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.sandbox_account_id))
    error_message = "Must be a 12-digit AWS account ID."
  }
}

variable "i_understand_this_is_insecure" {
  description = "Guard #2: must be set to true explicitly. This stack deliberately creates insecure configuration."
  type        = bool
  default     = false
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "auditor_principal_arn" {
  description = "Principal ARN allowed to assume CloudSheriffAuditRole (e.g. your SSO role ARN)."
  type        = string
}

variable "audit_external_id" {
  description = "ExternalId required to assume the audit role."
  type        = string
  sensitive   = true
}

variable "baseline_ssh_cidr" {
  description = "Baseline (compliant) SSH source CIDR for the demo SG. drift.sh widens it to 0.0.0.0/0."
  type        = string
  default     = "10.10.0.0/16"
}

# ---- Optional components, all off by default (cost / risk) ----

variable "enable_ec2" {
  description = "Create a STOPPED t4g.nano with IMDSv1 allowed (CIS: IMDSv2). Only EBS cost (~8GB gp3) while stopped."
  type        = bool
  default     = true
}

variable "enable_kms" {
  description = "Create a CMK with rotation disabled (CIS: KMS rotation). About $1/month."
  type        = bool
  default     = true
}

variable "manage_password_policy" {
  description = "Set a weak account password policy (CIS: 14+ chars, no reuse). Changes an ACCOUNT-LEVEL setting."
  type        = bool
  default     = true
}

variable "enable_rds" {
  description = "Public + unencrypted RDS. Costs money and is actually reachable; off by default. Destroy right after the demo."
  type        = bool
  default     = false
}
