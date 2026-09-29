data "aws_caller_identity" "current" {}

# Guard #2: without i_understand_this_is_insecure = true, plan fails immediately.
resource "terraform_data" "insecure_ack" {
  lifecycle {
    precondition {
      condition     = var.i_understand_this_is_insecure
      error_message = "This stack deliberately creates insecure configuration. Set i_understand_this_is_insecure = true, and only in a dedicated sandbox account."
    }
    precondition {
      condition     = data.aws_caller_identity.current.account_id == var.sandbox_account_id
      error_message = "Caller account does not match sandbox_account_id."
    }
  }
}
