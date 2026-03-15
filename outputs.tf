output "guardduty_detector_id" {
  description = "GuardDuty detector ID (needed for sample findings)"
  value       = aws_guardduty_detector.main.id
}

output "sns_topic_arn" {
  description = "SNS topic for remediation alerts"
  value       = aws_sns_topic.remediation_alerts.arn
}

output "audit_table_name" {
  description = "DynamoDB table for remediation audit log"
  value       = aws_dynamodb_table.remediation_audit.name
}

output "ec2_lambda_name" {
  value = aws_lambda_function.ec2_remediation.function_name
}

output "s3_lambda_name" {
  value = aws_lambda_function.s3_remediation.function_name
}

output "iam_lambda_name" {
  value = aws_lambda_function.iam_remediation.function_name
}

output "dashboard_url" {
  description = "URL to the CloudWatch remediation dashboard"
  value       = "https://${data.aws_region.current.name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=GuardDuty-Remediation-Dashboard"
}
