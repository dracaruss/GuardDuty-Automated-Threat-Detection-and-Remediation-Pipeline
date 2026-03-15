#!/bin/bash
# ═════════════════════════════════════════════════════════════
# Generate GuardDuty sample findings to test the pipeline.
# Run this after terraform apply.
# ═════════════════════════════════════════════════════════════
 
set -e
 
PROFILE="guardduty-lab"
DETECTOR_ID=$(cd .. && terraform output -raw guardduty_detector_id)
 
echo "Detector ID: $DETECTOR_ID"
echo "Generating sample findings..."
 
aws guardduty create-sample-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-types \
    "CryptoCurrency:EC2/BitcoinTool.B!DNS" \
    "Backdoor:EC2/DenialOfService.Tcp" \
    "Policy:S3/BucketBlockPublicAccessDisabled" \
    "UnauthorizedAccess:S3/MaliciousIPCaller.Custom" \
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller" \
    "CredentialAccess:IAMUser/AnomalousBehavior" \
  --profile "$PROFILE"
 
echo ""
echo "Sample findings generated. Check:"
echo "  1. GuardDuty console for new findings"
echo "  2. Email inbox for SNS remediation alerts"
echo "  3. DynamoDB table for audit records:"
echo "     aws dynamodb scan --table-name guardduty-remediation-audit --profile $PROFILE"
echo "  4. CloudWatch dashboard:"
echo "     $(cd .. && terraform output -raw dashboard_url)"
