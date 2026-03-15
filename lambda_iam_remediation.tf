# ═════════════════════════════════════════════════════════════
# IAM REMEDIATION LAMBDA
# When GuardDuty detects compromised IAM credentials:
#   1. Lists all access keys for the compromised user
#   2. Disables (not deletes) all active access keys
#   3. Sends SNS alert
#   4. Logs to DynamoDB
# ═════════════════════════════════════════════════════════════

data "archive_file" "iam_remediation" {
  type        = "zip"
  output_path = "${path.module}/iam_remediation.zip"

  source {
    content  = <<-PYTHON
import boto3
import json
import os
from datetime import datetime
 
iam = boto3.client("iam")
sns = boto3.client("sns")
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ["AUDIT_TABLE"])
SNS_TOPIC = os.environ["SNS_TOPIC_ARN"]
 
 
def lambda_handler(event, context):
    detail = event.get("detail", {})
    finding_type = detail.get("type", "Unknown")
    finding_id = detail.get("id", "unknown")
    severity = detail.get("severity", 0)
    account_id = detail.get("accountId", "unknown")
    region = detail.get("region", "unknown")
 
    # Extract the IAM user from the finding
    resource = detail.get("resource", {})
    access_key_detail = resource.get("accessKeyDetails", {})
    user_name = access_key_detail.get("userName", None)
    user_type = access_key_detail.get("userType", "Unknown")
 
    if not user_name or user_type != "IAMUser":
        print(f"Not an IAM user finding or no username: {finding_id}")
        return {"statusCode": 400, "body": "No IAM user in finding"}
 
    print(f"REMEDIATION START: {finding_type} for user {user_name}")
 
    actions_taken = []
 
    # Step 1: List and disable all access keys
    try:
        keys = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
        for key in keys:
            if key["Status"] == "Active":
                iam.update_access_key(
                    UserName=user_name,
                    AccessKeyId=key["AccessKeyId"],
                    Status="Inactive"
                )
                actions_taken.append(
                    f"Disabled access key {key['AccessKeyId']} for {user_name}"
                )
    except Exception as e:
        print(f"Could not disable access keys: {e}")
        actions_taken.append(f"FAILED to disable keys: {str(e)}")
 
    # Step 2: Send SNS alert
    message = (f"GUARDDUTY IAM REMEDIATION\n\n"
               f"Finding: {finding_type}\n"
               f"Severity: {severity}\n"
               f"User: {user_name}\n"
               f"Account: {account_id}\n"
               f"Region: {region}\n\n"
               f"Actions Taken:\n" +
               "\n".join(f"  - {a}" for a in actions_taken) +
               f"\n\nKeys were DISABLED, not deleted (reversible).\n"
               f"Review CloudTrail for unauthorized API calls.")
 
    try:
        sns.publish(
            TopicArn=SNS_TOPIC,
            Subject=f"GuardDuty IAM Remediation: {user_name}",
            Message=message
        )
    except Exception as e:
        print(f"Could not send SNS: {e}")
 
    # Step 3: Log to DynamoDB
    try:
        table.put_item(Item={
            "finding_id": finding_id,
            "timestamp": datetime.utcnow().isoformat(),
            "finding_type": finding_type,
            "severity": str(severity),
            "resource_type": "IAM",
            "resource_id": user_name,
            "actions_taken": json.dumps(actions_taken),
            "account_id": account_id,
            "region": region
        })
    except Exception as e:
        print(f"Could not write audit record: {e}")
 
    print(f"REMEDIATION COMPLETE: {len(actions_taken)} actions taken")
    return {"statusCode": 200, "body": json.dumps(actions_taken)}
PYTHON
    filename = "iam_remediation.py"
  }
}

# ── IAM Role ────────────────────────────────────────────────
resource "aws_iam_role" "iam_remediation" {
  name = "guardduty-iam-remediation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "iam_remediation" {
  name = "iam-remediation-policy"
  role = aws_iam_role.iam_remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DisableKeys"
        Effect = "Allow"
        Action = [
          "iam:ListAccessKeys",
          "iam:UpdateAccessKey"
        ]
        Resource = "arn:aws:iam::*:user/*"
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.remediation_alerts.arn
      },
      {
        Sid      = "DynamoDBWrite"
        Effect   = "Allow"
        Action   = "dynamodb:PutItem"
        Resource = aws_dynamodb_table.remediation_audit.arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_lambda_function" "iam_remediation" {
  function_name    = "guardduty-iam-remediation"
  filename         = data.archive_file.iam_remediation.output_path
  source_code_hash = data.archive_file.iam_remediation.output_base64sha256
  handler          = "iam_remediation.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  role             = aws_iam_role.iam_remediation.arn

  environment {
    variables = {
      AUDIT_TABLE   = aws_dynamodb_table.remediation_audit.name
      SNS_TOPIC_ARN = aws_sns_topic.remediation_alerts.arn
    }
  }

  tags = { Name = "guardduty-iam-remediation" }
}

resource "aws_lambda_permission" "iam_eventbridge" {
  statement_id  = "AllowEventBridgeIAM"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.iam_remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_threats.arn
}

resource "aws_cloudwatch_log_group" "iam_remediation" {
  name              = "/aws/lambda/${aws_lambda_function.iam_remediation.function_name}"
  retention_in_days = 30
}
