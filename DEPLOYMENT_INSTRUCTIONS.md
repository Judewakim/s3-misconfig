# WakimWorks S3 Compliance Scanner - Deployment Guide

## Overview
This CloudFormation template deploys a complete S3 security and compliance scanner with automatic remediation for HIPAA, PCI DSS, and GLBA standards.

## Prerequisites
- AWS CLI configured with admin credentials
- AWS account with Config service enabled
- Unique S3 bucket name for auditing

## Quick Deploy

### Option 1: AWS CLI
```bash
aws cloudformation deploy \
    --stack-name WakimWorksComplianceScanner \
    --template-file wakimworks-compliance-scanner.yaml \
    --region us-east-1 \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameter-overrides \
        ComplianceStandards="HIPAA,PCI,GLBA" \
        AuditingBucketName="wakimworks-audit-YOUR_ACCOUNT_ID"
```

### Option 2: AWS Console
1. Go to CloudFormation console
2. Click "Create stack" → "With new resources"
3. Upload `wakimworks-compliance-scanner.yaml`
4. Fill parameters:
   - **ComplianceStandards**: Select standards (e.g., `HIPAA,PCI,GLBA`)
   - **AuditingBucketName**: Enter unique bucket name
5. Check "I acknowledge that AWS CloudFormation might create IAM resources"
6. Click "Create stack"

## Post-Deployment Steps

### 1. Start Config Recorder
```bash
aws configservice start-configuration-recorder \
    --configuration-recorder-name wakimworks-config-recorder \
    --region us-east-1
```

### 2. Verify Deployment
```bash
# Check Config status
aws configservice describe-configuration-recorder-status --region us-east-1

# Check Lambda function
aws lambda get-function --function-name wakimworks-s3-remediation --region us-east-1

# List Config rules
aws configservice describe-config-rules --region us-east-1
```

### 3. Test Remediation
```bash
# Create non-compliant test bucket
TEST_BUCKET="test-noncompliant-$(date +%s)"
aws s3 mb s3://$TEST_BUCKET --region us-east-1

# Disable public access block (makes it non-compliant)
aws s3api put-public-access-block \
    --bucket $TEST_BUCKET \
    --public-access-block-configuration \
        BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false

# Wait 5-10 minutes for Config to detect and remediate

# Verify remediation
aws s3api get-public-access-block --bucket $TEST_BUCKET
# Should show all blocks enabled
```

## What Gets Deployed

### Infrastructure
- **KMS Key**: Customer-managed encryption key
- **S3 Auditing Bucket**: Encrypted bucket for Config/CloudTrail logs
- **CloudTrail**: Multi-region trail logging S3 data events
- **Config Recorder**: Monitors S3 buckets only
- **Lambda Function**: Automatic remediation engine

### Config Rules (HIPAA Example)
- s3-bucket-public-read-prohibited
- s3-bucket-public-write-prohibited
- s3-account-level-public-access-blocks-periodic
- s3-bucket-server-side-encryption-enabled
- s3-bucket-ssl-requests-only
- s3-bucket-versioning-enabled
- s3-bucket-logging-enabled

### Remediations
All rules automatically remediate non-compliant S3 buckets:
- Block public access
- Enable encryption (AES256)
- Enforce SSL/TLS
- Enable versioning
- Enable logging
- Set private ACLs

## Monitoring

### Check Lambda Logs
```bash
aws logs tail /aws/lambda/wakimworks-s3-remediation --follow --region us-east-1
```

### Check Config Compliance
```bash
aws configservice describe-compliance-by-config-rule --region us-east-1
```

### Check Audit Logs
```bash
# List Config snapshots
aws s3 ls s3://wakimworks-audit-YOUR_ACCOUNT_ID/AWSLogs/

# List CloudTrail logs
aws s3 ls s3://wakimworks-audit-YOUR_ACCOUNT_ID/AWSLogs/YOUR_ACCOUNT_ID/CloudTrail/
```

## Cost Estimate

| Service | Cost |
|---------|------|
| AWS Config | $2/rule/month × 7 rules = $14/month |
| CloudTrail (S3 data events) | $0.10/100k events (~$5/month) |
| Lambda | $0.20/1M requests (~$0.50/month) |
| S3 Storage | $0.023/GB (~$1/month) |
| KMS | $1/month |
| **Total** | **~$21.50/month** |

## Troubleshooting

### Config Not Detecting Violations
```bash
# Manually trigger evaluation
aws configservice start-config-rules-evaluation \
    --config-rule-names s3-bucket-public-read-prohibited \
    --region us-east-1
```

### Lambda Not Triggering
```bash
# Check Lambda permissions
aws lambda get-policy --function-name wakimworks-s3-remediation --region us-east-1

# Check SNS subscription
aws sns list-subscriptions --region us-east-1
```

### Permission Errors
- Ensure IAM role `WakimWorksRemediationLambdaRole` has S3 permissions
- Check KMS key policy allows Config and CloudTrail

## Cleanup

```bash
# Delete stack
aws cloudformation delete-stack --stack-name WakimWorksComplianceScanner --region us-east-1

# Wait for deletion
aws cloudformation wait stack-delete-complete --stack-name WakimWorksComplianceScanner --region us-east-1

# Manually delete auditing bucket (CloudFormation won't delete non-empty buckets)
aws s3 rb s3://wakimworks-audit-YOUR_ACCOUNT_ID --force
```

## Support

For issues or questions:
- Email: judewakim@wakimworks.com
- GitHub: https://github.com/judewakim/s3-misconfig

## License
MIT License
