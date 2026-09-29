output "demo_admin_sg_id" {
  description = "Target SG for the drift demo"
  value       = aws_security_group.demo_admin.id
}

output "legacy_rdp_sg_id" {
  description = "Prompt-injection bait + known-noise SG"
  value       = aws_security_group.legacy_rdp.id
}

output "web_instance_id" {
  value = try(aws_instance.web[0].id, null)
}

output "audit_role_arn" {
  value = aws_iam_role.cloudsheriff_audit.arn
}

output "data_bucket" {
  value = aws_s3_bucket.data.bucket
}

output "control_bucket" {
  value = aws_s3_bucket.control.bucket
}
