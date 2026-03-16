# GuardDuty Threat Detection and Automated Remediation
This project builds a complete threat detection and automated response system using AWS GuardDuty.
## Overview
> [!IMPORTANT]
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
$ aws sso login --profile guardduty-lab
$ terraform init
$ terraform plan
$ terraform apply
```
On the plan I got an error because I already had GuardDuty running in my account:
<img width="1164" height="246" alt="Image" src="https://github.com/user-attachments/assets/bb7fee20-57ff-4c12-a62a-96de5ac262fd" />

I just had to import it into the Terraform state. First I needed to get the details from the CLI:
<img width="710" height="135" alt="Image" src="https://github.com/user-attachments/assets/1d5f184c-afdd-4772-9c8d-27aaa545b010" />

Then import it into Terraform for it to be tracked and managed:
<img width="1087" height="384" alt="Image" src="https://github.com/user-attachments/assets/cbe12700-bd8c-4f7a-829b-eb0846d8d09b" />

And lastly re-run **Terraform apply**:
<img width="1048" height="340" alt="Image" src="https://github.com/user-attachments/assets/9cc03109-ba27-466c-ad9b-2a6cf41db24e" />

## Testing
After everything is configured and running in AWS, it's time to run the first script.  
This script is setup to trigger the GuardDuty function that similates threats, to test that it's working correctly.
```bash
# Generate sample findings to trigger the pipeline
cd testing/
chmod +x generate-sample-findings.sh
./generate-sample-findings.sh
```
<img width="1282" height="233" alt="Image" src="https://github.com/user-attachments/assets/08f283fd-7b58-4afa-86db-cbfecebd6132" />

##

I got the first email from the pipeline, which was regarding the IAM issue
<img width="1195" height="483" alt="Image" src="https://github.com/user-attachments/assets/feb26526-4b6f-4c80-bd24-15a469537c0f" />

##

The pipeline is now validated to be working perfectly. Here's what happened:  
- The sample finding used a fake username "GeneratedFindingUserName" which doesn't exist in your account.
- So the Lambda triggered correctly, tried to disable the keys, couldn't find the user (because it's fake), logged the failure, and still sent the SNS email with the full details.  
> [!IMPORTANT]
> **That proves the entire chain works:**    
> GuardDuty finding → EventBridge matched the **UnauthorizedAccess:IAMUser/** prefix → IAM Lambda triggered → attempted remediation → SNS email delivered.
> 
> The *"FAILED to disable keys"* is expected behavior with sample findings. If this were a real finding with a real username, it would have successfully disabled the keys.  

##

The next 2 emails were regarding the S3 "incidents":  
<img width="1182" height="412" alt="Image" src="https://github.com/user-attachments/assets/f4038665-67d7-4402-971d-b2287bd5cf92" />

> [!NOTE]
> As seen in the email, "example-bucket1" is a fake bucket name that GuardDuty generates in its sample findings.
> It's not a real bucket in the AWS account, so the Lambda can't modify it. The bucket has to actually exist in your account for that permission to work.

##

Same with the second S3 email:
<img width="1177" height="415" alt="Image" src="https://github.com/user-attachments/assets/25832e0c-95ec-4471-a02c-75a5a4933d2c" />

##

> [!WARNING]
> But I realize no more emails came in. There were 6 alerts, so why just 3 emails? Hmm. When I checked the logs I saw:  
```Bash
$ aws logs tail /aws/lambda/guardduty-ec2-remediation --since 30m --profile guardduty-lab
```
<img width="1526" height="355" alt="Image" src="https://github.com/user-attachments/assets/95ad1c1e-f17a-4a0b-906f-1be251997acd" />

##

> [!WARNING]
> Checking the logs showed only 3 items.. hmm:
```
$ aws dynamodb scan --table-name guardduty-remediation-audit
```
<img width="732" height="402" alt="Image" src="https://github.com/user-attachments/assets/e65dbbbc-053c-4d12-9a1c-c08240680b4b" />

##

> [!WARNING]
> I see the issue. This return statement is exiting the entire Lambda function immediately. So when *describe_instances* failed on the fake instance ID, the 500 code hits and breaks the lambda execution:
```Bash
pythonreturn {"statusCode": 500, "body": str(e)}
```
<img width="625" height="205" alt="Image" src="https://github.com/user-attachments/assets/d3a090f3-3ca4-4d69-a5b9-82d34417e40c" />

> [!NOTE]
> And that was it, function over. Everything below that line (quarantine, snapshot, tag, SNS, DynamoDB) never executed. The Lambda reported back to AWS "I'm done" and shut down.

##

I had to change the *lambda_ec2_remediation.tf* file to not error out with the 500 and shut off the script:
<img width="825" height="227" alt="Image" src="https://github.com/user-attachments/assets/5f0cddcf-57ce-4b75-b854-8b991297b331" />

> [!NOTE]
> The fix replaces that hard exit with a soft failure: log what went wrong, skip the steps that depend on having a real instance, but keep going until SNS and DynamoDB are done. The function always reaches the bottom now.

##

Now when I re run the script I get 8 findings now (5 new):
<img width="749" height="360" alt="Image" src="https://github.com/user-attachments/assets/324c2f8c-bdfc-4fa0-854b-0ec4085e1eb1" />

##

And I get the 5 emails:
<img width="1065" height="277" alt="Image" src="https://github.com/user-attachments/assets/a71c437c-e133-4877-9503-1ddb4619cb8a" />

##

The second IAM finding CredentialAccess:IAMUser/AnomalousBehavior gets merged with UnauthorizedAccess:IAMUser/MaliciousIPCaller because they both reference the same fake user GeneratedFindingUserName arriving at the same time.
> [!NOTE]
> 2 EC2 records (CryptoCurrency + Backdoor) ✓ New — the fix worked
> 4 S3 records (2 finding types × 2 runs each) ✓
> 2 IAM records (same finding, 2 runs) ✓
> 
> All three Lambdas are firing, notifying, and logging. The EC2 Lambda now completes the full cycle instead of dying at the early return. The pipeline is fully operational.
> 5 out of 6 with one deduplicated by GuardDuty is expected behavior, not a bug. In a real incident every finding would have unique resource IDs and timestamps, so deduplication wouldn't apply.

##

## Lastly to Test the Remediation Pipeline with a Real Event
First I create the test bucket and the access block resources:
<img width="767" height="447" alt="Image" src="https://github.com/user-attachments/assets/164b43f0-5255-4ffa-87d3-32ad91c4fa1f" />

##

Next I remove public access block to trigger GuardDuty and the pipeline:
```Bash
$ aws s3api delete-public-access-block \
  --bucket $(terraform output -raw test_bucket_name) \
  --profile guardduty-lab
```

##

Checking for the successful removal of the blocks shows no blocks are now on:
```
$ aws s3api get-public-access-block --bucket guardduty-test-20260315221759506200000001 --profile guardduty-lab
```
<img width="863" height="176" alt="Image" src="https://github.com/user-attachments/assets/c516d1e9-b501-4bc7-b258-ec185428278c" />

##

And correctly the email arrives, showing the pipeline had re-enabled the public access block:
<img width="855" height="341" alt="Image" src="https://github.com/user-attachments/assets/11cf4ef9-f0c3-4042-832e-f15406bf2bef" />

##

Now when I check for the public block, I can see it's there re-enabled by the pipeline:
<img width="1136" height="195" alt="Image" src="https://github.com/user-attachments/assets/0873d626-eb6a-4553-8f9f-fc40a24dcffe" />
 
## Ok Everything Works, Just to Cleanup
```Bash
terraform destroy -auto-approve
```
<img width="693" height="190" alt="Image" src="https://github.com/user-attachments/assets/e09a0e0e-e882-4f29-9aba-37f8e85fe185" />


## Design Decisions
- One Lambda per finding category for single-responsibility and independent scaling
- SNS notification sent from inside the Lambda (not a separate EventBridge target)
  so the email includes what was remediated, not just what was detected
- DynamoDB audit table separate from CloudTrail for defense in depth
- Quarantine SG blocks all traffic but preserves the instance for forensics
- GuardDuty sample findings used for safe, repeatable testing
 
 
## What I Would Add in Enterprise
- Step Functions for multi-step remediation workflows
- Security Hub integration to aggregate findings
- Cross-account GuardDuty with delegated administrator
- WAF auto-blocking for repeated malicious IPs

##

> [!CAUTION]
>  ***Mission Accomplished.***
