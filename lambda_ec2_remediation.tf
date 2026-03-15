# ═════════════════════════════════════════════════════════════
# EC2 REMEDIATION LAMBDA
# When GuardDuty detects EC2 compromise:
#   1. Creates a quarantine security group (no ingress/egress)
#   2. Swaps the instance to the quarantine SG
#   3. Takes EBS snapshots of all attached volumes
#   4. Tags the instance as compromised
#   5. Sends SNS alert with full details
#   6. Logs the action to DynamoDB
# ═════════════════════════════════════════════════════════════

data "archive_file" "ec2_remediation" {
  type        = "zip"
  output_path = "${path.module}/ec2_remediation.zip"

  source {
    content  = <<-PYTHON

import boto3
import json
import os
from datetime import datetime

ec2 = boto3.client("ec2")
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

    # Extract the instance ID from the finding
    resource = detail.get("resource", {})
    instance_detail = resource.get("instanceDetails", {})
    instance_id = instance_detail.get("instanceId", "unknown")

    print(f"REMEDIATION START: {finding_type} on {instance_id}")

    actions_taken = []

    # Step 1: Get the instance VPC
    vpc_id = None
    try:
        instance_info = ec2.describe_instances(
            InstanceIds=[instance_id]
        )["Reservations"][0]["Instances"][0]
        vpc_id = instance_info["VpcId"]
    except Exception as e:
        print(f"Could not describe instance: {e}")
        actions_taken.append(f"FAILED to describe instance: {str(e)}")

    # Step 2: Create quarantine security group
    quarantine_sg_id = None
    if vpc_id:
        try:
            sg_name = f"quarantine-{instance_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            sg = ec2.create_security_group(
                GroupName=sg_name,
                Description=f"Quarantine SG for {instance_id} - {finding_type}",
                VpcId=vpc_id
            )
            quarantine_sg_id = sg["GroupId"]

            # Revoke the default egress rule so NO traffic can leave
            ec2.revoke_security_group_egress(
                GroupId=quarantine_sg_id,
                IpPermissions=[{
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }]
            )
            actions_taken.append(f"Created quarantine SG: {quarantine_sg_id}")
        except Exception as e:
            print(f"Could not create quarantine SG: {e}")
            actions_taken.append(f"FAILED to create quarantine SG: {str(e)}")

    # Step 3: Swap instance to quarantine SG
    if quarantine_sg_id:
        try:
            ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[quarantine_sg_id]
            )
            actions_taken.append("Instance moved to quarantine SG")
        except Exception as e:
            print(f"Could not modify instance SG: {e}")
            actions_taken.append(f"FAILED to quarantine instance: {str(e)}")

    # Step 4: Snapshot all attached EBS volumes
    if vpc_id:
        try:
            volumes = ec2.describe_volumes(
                Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
            )["Volumes"]
            for vol in volumes:
                snap = ec2.create_snapshot(
                    VolumeId=vol["VolumeId"],
                    Description=f"Forensic snapshot - {finding_type} - {instance_id}",
                    TagSpecifications=[{
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": "Purpose", "Value": "forensic-capture"},
                            {"Key": "FindingType", "Value": finding_type},
                            {"Key": "InstanceId", "Value": instance_id},
                            {"Key": "FindingId", "Value": finding_id}
                        ]
                    }]
                )
                actions_taken.append(f"Snapshot created: {snap['SnapshotId']} for volume {vol['VolumeId']}")
        except Exception as e:
            print(f"Could not create snapshots: {e}")
            actions_taken.append(f"FAILED to create snapshots: {str(e)}")

    # Step 5: Tag the instance
    if vpc_id:
        try:
            ec2.create_tags(
                Resources=[instance_id],
                Tags=[
                    {"Key": "SecurityStatus", "Value": "COMPROMISED"},
                    {"Key": "QuarantinedAt", "Value": datetime.utcnow().isoformat()},
                    {"Key": "FindingType", "Value": finding_type},
                    {"Key": "QuarantineSG", "Value": quarantine_sg_id or "FAILED"}
                ]
            )
            actions_taken.append("Instance tagged as COMPROMISED")
        except Exception as e:
            print(f"Could not tag instance: {e}")
            actions_taken.append(f"FAILED to tag instance: {str(e)}")

    # Step 6: Send SNS alert (ALWAYS runs)
    message = (f"GUARDDUTY EC2 REMEDIATION\n\n"
               f"Finding: {finding_type}\n"
               f"Severity: {severity}\n"
               f"Instance: {instance_id}\n"
               f"Account: {account_id}\n"
               f"Region: {region}\n\n"
               f"Actions Taken:\n" +
               "\n".join(f"  - {a}" for a in actions_taken) +
               f"\n\nReview CloudTrail for full activity timeline.")

    try:
        sns.publish(
            TopicArn=SNS_TOPIC,
            Subject=f"GuardDuty EC2 Remediation: {instance_id}",
            Message=message
        )
    except Exception as e:
        print(f"Could not send SNS: {e}")

    # Step 7: Log to DynamoDB (ALWAYS runs)
    try:
        table.put_item(Item={
            "finding_id": finding_id,
            "timestamp": datetime.utcnow().isoformat(),
            "finding_type": finding_type,
            "severity": str(severity),
            "resource_type": "EC2",
            "resource_id": instance_id,
            "actions_taken": json.dumps(actions_taken),
            "account_id": account_id,
            "region": region
        })
    except Exception as e:
        print(f"Could not write audit record: {e}")

    print(f"REMEDIATION COMPLETE: {len(actions_taken)} actions taken")
    return {"statusCode": 200, "body": json.dumps(actions_taken)}

PYTHON
    filename = "ec2_remediation.py"
  }
}

# ── IAM Role ────────────────────────────────────────────────
resource "aws_iam_role" "ec2_remediation" {
  name = "guardduty-ec2-remediation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "ec2_remediation" {
  name = "ec2-remediation-policy"
  role = aws_iam_role.ec2_remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2Quarantine"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:CreateSecurityGroup",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:ModifyInstanceAttribute",
          "ec2:CreateTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "ForensicSnapshots"
        Effect = "Allow"
        Action = [
          "ec2:DescribeVolumes",
          "ec2:CreateSnapshot",
          "ec2:DescribeSnapshots"
        ]
        Resource = "*"
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

# ── Lambda Function ─────────────────────────────────────────
resource "aws_lambda_function" "ec2_remediation" {
  function_name    = "guardduty-ec2-remediation"
  filename         = data.archive_file.ec2_remediation.output_path
  source_code_hash = data.archive_file.ec2_remediation.output_base64sha256
  handler          = "ec2_remediation.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60
  role             = aws_iam_role.ec2_remediation.arn

  environment {
    variables = {
      AUDIT_TABLE   = aws_dynamodb_table.remediation_audit.name
      SNS_TOPIC_ARN = aws_sns_topic.remediation_alerts.arn
    }
  }

  tags = { Name = "guardduty-ec2-remediation" }
}

# ── Permission: EventBridge -> Lambda ──────────────────────
resource "aws_lambda_permission" "ec2_eventbridge" {
  statement_id  = "AllowEventBridgeEC2"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ec2_remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ec2_threats.arn
}

# ── CloudWatch Log Group ──────────────────────────────────
resource "aws_cloudwatch_log_group" "ec2_remediation" {
  name              = "/aws/lambda/${aws_lambda_function.ec2_remediation.function_name}"
  retention_in_days = 30
}
