# ═════════════════════════════════════════════════════════════
# S3 REMEDIATION LAMBDA
# When GuardDuty detects S3 public access:
#   1. Re-enables public access block on the bucket
#   2. Sends SNS alert
#   3. Logs to DynamoDB
# ═════════════════════════════════════════════════════════════

data "archive_file" "s3_remediation" {
  type        = "zip"
  output_path = "${path.module}/s3_remediation.zip"

  source {
    content  = <<-PYTHON
import boto3
import json
import os
from datetime import datetime
 
s3_client = boto3.client("s3")
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
 
    # Extract the bucket name from the finding
    resource = detail.get("resource", {})
    s3_bucket = resource.get("s3BucketDetails", [{}])
    bucket_name = None
    if s3_bucket and len(s3_bucket) > 0:
        bucket_name = s3_bucket[0].get("name", None)
 
    if not bucket_name:
        print(f"No bucket name found in finding {finding_id}")
        return {"statusCode": 400, "body": "No bucket name in finding"}
 
    print(f"REMEDIATION START: {finding_type} on {bucket_name}")
 
    actions_taken = []
 
    # Step 1: Re-enable public access block
    try:
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        )
        actions_taken.append(f"Public access block re-enabled on {bucket_name}")
    except Exception as e:
        print(f"Could not set public access block: {e}")
        actions_taken.append(f"FAILED to set public access block: {str(e)}")
 
    # Step 2: Send SNS alert
    message = (f"GUARDDUTY S3 REMEDIATION\n\n"
               f"Finding: {finding_type}\n"
               f"Severity: {severity}\n"
               f"Bucket: {bucket_name}\n"
               f"Account: {account_id}\n"
               f"Region: {region}\n\n"
               f"Actions Taken:\n" +
               "\n".join(f"  - {a}" for a in actions_taken) +
               f"\n\nReview CloudTrail for who made the bucket public.")
 
    try:
        sns.publish(
            TopicArn=SNS_TOPIC,
            Subject=f"GuardDuty S3 Remediation: {bucket_name}",
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
            "resource_type": "S3",
            "resource_id": bucket_name,
            "actions_taken": json.dumps(actions_taken),
            "account_id": account_id,
            "region": region
        })
    except Exception as e:
        print(f"Could not write audit record: {e}")
 
    print(f"REMEDIATION COMPLETE: {len(actions_taken)} actions taken")
    return {"statusCode": 200, "body": json.dumps(actions_taken)}
PYTHON
    filename = "s3_remediation.py"
  }
}

# ── IAM Role ────────────────────────────────────────────────
resource "aws_iam_role" "s3_remediation" {
  name = "guardduty-s3-remediation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "s3_remediation" {
  name = "s3-remediation-policy"
  role = aws_iam_role.s3_remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3PublicAccessBlock"
        Effect = "Allow"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:GetBucketPublicAccessBlock"
        ]
        Resource = "arn:aws:s3:::*"
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

resource "aws_lambda_function" "s3_remediation" {
  function_name    = "guardduty-s3-remediation"
  filename         = data.archive_file.s3_remediation.output_path
  source_code_hash = data.archive_file.s3_remediation.output_base64sha256
  handler          = "s3_remediation.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  role             = aws_iam_role.s3_remediation.arn

  environment {
    variables = {
      AUDIT_TABLE   = aws_dynamodb_table.remediation_audit.name
      SNS_TOPIC_ARN = aws_sns_topic.remediation_alerts.arn
    }
  }

  tags = { Name = "guardduty-s3-remediation" }
}

resource "aws_lambda_permission" "s3_eventbridge" {
  statement_id  = "AllowEventBridgeS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_threats.arn
}

resource "aws_cloudwatch_log_group" "s3_remediation" {
  name              = "/aws/lambda/${aws_lambda_function.s3_remediation.function_name}"
  retention_in_days = 30
}
