variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI profile name (SSO profile from Identity Center)"
  type        = string
}

variable "alert_email" {
  description = "Email address for security alerts. Receives SNS notifications on every remediation."
  type        = string
}
