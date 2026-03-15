# ═════════════════════════════════════════════════════════════
# DYNAMODB TABLE: Remediation Audit Log
# Every automated action is recorded here. This is separate
# from CloudTrail for defense in depth — if an attacker
# tampers with CloudTrail, this record still exists.
# ═════════════════════════════════════════════════════════════

resource "aws_dynamodb_table" "remediation_audit" {
  name         = "guardduty-remediation-audit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"
  range_key    = "timestamp"

  attribute {
    name = "finding_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Name    = "guardduty-remediation-audit"
    Purpose = "security-audit-trail"
  }
}
