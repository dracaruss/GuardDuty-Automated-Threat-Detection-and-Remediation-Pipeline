# GuardDuty Threat Detection and Automated Remediation
 
## Overview
A complete threat detection and automated response system using AWS GuardDuty.
When GuardDuty detects a threat, EventBridge routes the finding to Lambda
functions that automatically remediate, alert the security team via SNS,
and log the action to DynamoDB for audit.
 
## Architecture
GuardDuty Finding -> EventBridge Rule -> Lambda Remediation -> SNS + DynamoDB
 
## Remediation Scenarios
| Threat | GuardDuty Finding | Automated Response |
|--------|-------------------|-------------------|
| Crypto mining on EC2 | CryptoCurrency:EC2/BitcoinTool.B!DNS | Quarantine SG, EBS snapshot, tag |
| S3 bucket made public | Policy:S3/BucketBlockPublicAccessDisabled | Re-enable public access block |
| Compromised IAM creds | UnauthorizedAccess:IAMUser/MaliciousIPCaller | Disable access keys |
 
## Prerequisites
- AWS account with Identity Center SSO configured
- Terraform >= 1.0
- AWS CLI with SSO profile
 
## Deployment
```bash
aws sso login --profile guardduty-lab
terraform init
terraform plan
terraform apply
```
 
## Testing
```bash
# Generate sample findings to trigger the pipeline
cd testing/
chmod +x generate-sample-findings.sh
./generate-sample-findings.sh
```
 
## Validate
```bash
# Check DynamoDB for audit records
aws dynamodb scan --table-name guardduty-remediation-audit --profile guardduty-lab
 
# Check CloudWatch dashboard
echo $(terraform output -raw dashboard_url)
```
 
## Cleanup
```bash
terraform destroy -auto-approve
```
 
## Design Decisions
- One Lambda per finding category for single-responsibility and independent scaling
- SNS notification sent from inside the Lambda (not a separate EventBridge target)
  so the email includes what was remediated, not just what was detected
- DynamoDB audit table separate from CloudTrail for defense in depth
- Quarantine SG blocks all traffic but preserves the instance for forensics
- GuardDuty sample findings used for safe, repeatable testing
 
## Interview Talking Points
- 'I built automated remediation that responds to GuardDuty findings in seconds
  without human intervention. EC2 instances get quarantined, public S3 buckets
  get locked down, and compromised IAM keys get disabled automatically.'
- 'The Lambda sends an SNS alert after remediation so the security team knows
  both what happened and what was done about it.'
- 'I tested with both GuardDuty sample findings for pipeline validation and
  simulated real attacks for end-to-end verification.'
 
## What I Would Add in Enterprise
- Step Functions for multi-step remediation workflows
- Security Hub integration to aggregate findings
- Cross-account GuardDuty with delegated administrator
- WAF auto-blocking for repeated malicious IPs
