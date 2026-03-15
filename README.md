# GuardDuty Threat Detection and Automated Remediation
 
## Overview
> [!IMPORTANT]
> Overview
> This project builds a complete threat detection and automated response system using AWS GuardDuty.  
>
> When GuardDuty detects a threat, EventBridge routes the finding to Lambda functions that automatically remediate the issue, send an SNS alert to the security team, and log the action to a DynamoDB audit table. A CloudWatch dashboard provides real-time visibility into all findings and remediation actions.  
>
> This follows the Provision, Break, Detect, Respond lifecycle. You Terraform the infrastructure, intentionally create security issues, GuardDuty detects them, and Lambda auto-remediates before a human needs to intervene.

 
## Architecture
GuardDuty Finding → EventBridge → Lambda → SNS Email to Security Team + DynamoDB Audit Record + CloudWatch
<img width="2016" height="2134" alt="Image" src="https://github.com/user-attachments/assets/90e65b4d-dd8e-4b8f-b4d9-081c09760bc7" />

## Remediation Scenarios
| Threat                | GuardDuty Finding                            | Automated Response                     |
|-----------------------|----------------------------------------------|----------------------------------------|
| Crypto mining on EC2  | CryptoCurrency:EC2/BitcoinTool.B!DNS         | Quarantine SG, EBS snapshot, tag       |
| S3 bucket made public | Policy:S3/BucketBlockPublicAccessDisabled    | Re-enable public access block          |
| Compromised IAM creds | UnauthorizedAccess:IAMUser/MaliciousIPCaller | Disable access keys                    |
 
## Deployment
```bash
aws sso login --profile guardduty-lab
terraform init
terraform plan
terraform apply
```
On the plan I got an error because I already had GuardDuty running in my account:
<img width="1164" height="246" alt="Image" src="https://github.com/user-attachments/assets/bb7fee20-57ff-4c12-a62a-96de5ac262fd" />

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
