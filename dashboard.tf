# ═════════════════════════════════════════════════════════════
# CLOUDWATCH DASHBOARD
# Real-time visibility into GuardDuty findings and
# remediation actions. This is the "see alerts hit your
# dashboard" that demonstrates operational maturity.
# ═════════════════════════════════════════════════════════════

data "aws_region" "current" {}

# ── Metric Filters (count remediation actions per type) ────
resource "aws_cloudwatch_log_metric_filter" "ec2_remediations" {
  name           = "ec2-remediation-count"
  log_group_name = aws_cloudwatch_log_group.ec2_remediation.name
  pattern        = "REMEDIATION COMPLETE"

  metric_transformation {
    name      = "EC2RemediationCount"
    namespace = "GuardDutyRemediation"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "s3_remediations" {
  name           = "s3-remediation-count"
  log_group_name = aws_cloudwatch_log_group.s3_remediation.name
  pattern        = "REMEDIATION COMPLETE"

  metric_transformation {
    name      = "S3RemediationCount"
    namespace = "GuardDutyRemediation"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "iam_remediations" {
  name           = "iam-remediation-count"
  log_group_name = aws_cloudwatch_log_group.iam_remediation.name
  pattern        = "REMEDIATION COMPLETE"

  metric_transformation {
    name      = "IAMRemediationCount"
    namespace = "GuardDutyRemediation"
    value     = "1"
  }
}

# ── Dashboard ───────────────────────────────────────────────
resource "aws_cloudwatch_dashboard" "guardduty" {
  dashboard_name = "GuardDuty-Remediation-Dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 18
        height = 6
        properties = {
          title = "Remediations by Type (24h)"
          metrics = [
            ["GuardDutyRemediation", "EC2RemediationCount", { stat = "Sum", period = 3600, label = "EC2" }],
            ["GuardDutyRemediation", "S3RemediationCount", { stat = "Sum", period = 3600, label = "S3" }],
            ["GuardDutyRemediation", "IAMRemediationCount", { stat = "Sum", period = 3600, label = "IAM" }]
          ]
          view   = "timeSeries"
          region = data.aws_region.current.name
          period = 3600
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 6
        height = 6
        properties = {
          title   = "EC2 Remediations (30d)"
          metrics = [["GuardDutyRemediation", "EC2RemediationCount", { stat = "Sum", period = 2592000 }]]
          view    = "singleValue"
          region  = data.aws_region.current.name
        }
      },
      {
        type   = "metric"
        x      = 6
        y      = 6
        width  = 6
        height = 6
        properties = {
          title   = "S3 Remediations (30d)"
          metrics = [["GuardDutyRemediation", "S3RemediationCount", { stat = "Sum", period = 2592000 }]]
          view    = "singleValue"
          region  = data.aws_region.current.name
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 6
        height = 6
        properties = {
          title   = "IAM Remediations (30d)"
          metrics = [["GuardDutyRemediation", "IAMRemediationCount", { stat = "Sum", period = 2592000 }]]
          view    = "singleValue"
          region  = data.aws_region.current.name
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 12
        width  = 18
        height = 6
        properties = {
          title  = "Recent Lambda Errors (All Functions)"
          query  = "SOURCE \"/aws/lambda/guardduty-ec2-remediation\" | SOURCE \"/aws/lambda/guardduty-s3-remediation\" | SOURCE \"/aws/lambda/guardduty-iam-remediation\" | fields @timestamp, @message | filter @message like /ERROR|FAILED|Could not/ | sort @timestamp desc | limit 20"
          region = data.aws_region.current.name
          view   = "table"
        }
      }
    ]
  })
}
