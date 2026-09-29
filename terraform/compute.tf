# ---------------------------------------------------------------------------
# production-web-01: a STOPPED t4g.nano
#   - Gives cs-demo-admin a "workload it is attached to" (AI prioritization context)
#   - IMDSv1 allowed                 -> CIS: EC2 uses IMDSv2          FAIL
#   - Root volume unencrypted        -> EBS-encryption checks FAIL
#     (if the account has EBS default encryption on, AWS encrypts it anyway)
#   - Kept stopped: even after drift opens 22 to the world, nothing is
#     actually listening. Cost is just the ~8GB gp3 root volume.
# ---------------------------------------------------------------------------
data "aws_ssm_parameter" "al2023_arm64" {
  count = var.enable_ec2 ? 1 : 0
  name  = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

resource "aws_instance" "web" {
  count                       = var.enable_ec2 ? 1 : 0
  ami                         = data.aws_ssm_parameter.al2023_arm64[0].value
  instance_type               = "t4g.nano"
  subnet_id                   = aws_subnet.public_a.id
  vpc_security_group_ids      = [aws_security_group.demo_admin.id]
  associate_public_ip_address = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional" # IMDSv1 allowed: intentionally non-compliant
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 8
    encrypted   = false # intentionally non-compliant
  }

  tags = {
    Name        = "production-web-01"
    Environment = "production" # fake, for AI context
  }

  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_ec2_instance_state" "web" {
  count       = var.enable_ec2 ? 1 : 0
  instance_id = aws_instance.web[0].id
  state       = "stopped"
}
