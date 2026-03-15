# ═════════════════════════════════════════════════════════════
# SIMULATE REAL FINDINGS
# This Terraform creates sacrificial resources that will
# generate actual GuardDuty findings (not sample ones).
#
# Deploy separately: cd testing && terraform init && terraform apply
# Destroy after testing: terraform destroy -auto-approve
# ═════════════════════════════════════════════════════════════

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = "us-east-1"
  profile = "guardduty-lab"
}

# ── Sacrificial S3 Bucket (will be made public, then auto-fixed) ──
resource "aws_s3_bucket" "test_bucket" {
  bucket_prefix = "guardduty-test-"
  force_destroy = true
  tags          = { Name = "guardduty-test-bucket", Purpose = "testing" }
}

# Start with public access blocked
resource "aws_s3_bucket_public_access_block" "test_bucket" {
  bucket                  = aws_s3_bucket.test_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# To trigger the finding, run this after deploy:
# aws s3api delete-public-access-block \
#   --bucket $(terraform output -raw test_bucket_name) \
#   --profile guardduty-lab
# GuardDuty will detect this and Lambda will re-enable the block.

output "test_bucket_name" {
  value = aws_s3_bucket.test_bucket.id
}
