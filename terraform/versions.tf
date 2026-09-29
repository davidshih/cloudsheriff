terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60, < 7.0"
    }
  }
}

provider "aws" {
  region = var.region

  # Guard #1: the provider refuses to run against any account other than
  # this one, so you can't accidentally apply to your work account.
  allowed_account_ids = [var.sandbox_account_id]

  default_tags {
    tags = {
      Project   = "cloudsheriff-lab"
      Purpose   = "INTENTIONALLY-MISCONFIGURED-TEST-FIXTURE"
      ManagedBy = "terraform"
    }
  }
}
