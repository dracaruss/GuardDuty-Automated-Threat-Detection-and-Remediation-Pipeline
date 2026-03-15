# ─────────────────────────────────────────────────────────────
# GUARDDUTY DETECTOR
# Enables GuardDuty in the account. GuardDuty analyzes
# CloudTrail logs, VPC Flow Logs, and DNS logs to detect
# threats. It does not require you to manually configure
# these log sources — it reads them automatically.
# ─────────────────────────────────────────────────────────────

resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
  }

  tags = {
    Name = "guardduty-detector"
  }
}
