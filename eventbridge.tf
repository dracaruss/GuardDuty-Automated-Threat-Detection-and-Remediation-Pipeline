# ═════════════════════════════════════════════════════════════
# EVENTBRIDGE RULES
# Each rule matches a specific category of GuardDuty finding
# and routes it to the appropriate Lambda function.
# ═════════════════════════════════════════════════════════════

# ── Rule 1: EC2 Threats (crypto mining, C2, port probes) ───
resource "aws_cloudwatch_event_rule" "ec2_threats" {
  name        = "guardduty-ec2-threats"
  description = "Matches GuardDuty findings related to EC2 compromise"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "CryptoCurrency:EC2/" },
        { prefix = "Backdoor:EC2/" },
        { prefix = "Trojan:EC2/" },
        { prefix = "UnauthorizedAccess:EC2/" },
        { prefix = "Recon:EC2/" },
        { prefix = "Impact:EC2/" }
      ]
    }
  })

  tags = { Name = "guardduty-ec2-threats" }
}

resource "aws_cloudwatch_event_target" "ec2_lambda" {
  rule = aws_cloudwatch_event_rule.ec2_threats.name
  arn  = aws_lambda_function.ec2_remediation.arn
}

# ── Rule 2: S3 Threats (public access, policy changes) ─────
resource "aws_cloudwatch_event_rule" "s3_threats" {
  name        = "guardduty-s3-threats"
  description = "Matches GuardDuty findings related to S3 exposure"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Policy:S3/" },
        { prefix = "Exfiltration:S3/" },
        { prefix = "UnauthorizedAccess:S3/" },
        { prefix = "Discovery:S3/" },
        { prefix = "Impact:S3/" }
      ]
    }
  })

  tags = { Name = "guardduty-s3-threats" }
}

resource "aws_cloudwatch_event_target" "s3_lambda" {
  rule = aws_cloudwatch_event_rule.s3_threats.name
  arn  = aws_lambda_function.s3_remediation.arn
}

# ── Rule 3: IAM Threats (compromised credentials) ──────────
resource "aws_cloudwatch_event_rule" "iam_threats" {
  name        = "guardduty-iam-threats"
  description = "Matches GuardDuty findings related to IAM compromise"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "UnauthorizedAccess:IAMUser/" },
        { prefix = "CredentialAccess:IAMUser/" },
        { prefix = "Recon:IAMUser/" },
        { prefix = "PenTest:IAMUser/" },
        { prefix = "Impact:IAMUser/" },
        { prefix = "Persistence:IAMUser/" }
      ]
    }
  })

  tags = { Name = "guardduty-iam-threats" }
}

resource "aws_cloudwatch_event_target" "iam_lambda" {
  rule = aws_cloudwatch_event_rule.iam_threats.name
  arn  = aws_lambda_function.iam_remediation.arn
}
