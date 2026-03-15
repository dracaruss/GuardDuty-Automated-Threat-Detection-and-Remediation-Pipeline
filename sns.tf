# ═════════════════════════════════════════════════════════════
# SNS TOPIC: Remediation Alerts
# All three Lambda functions publish to this single topic.
# The security team subscribes once and gets alerts for
# every remediation action.
# ═════════════════════════════════════════════════════════════

resource "aws_sns_topic" "remediation_alerts" {
  name = "guardduty-remediation-alerts"
  tags = { Name = "guardduty-remediation-alerts" }
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.remediation_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
