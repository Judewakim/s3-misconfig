#!/bin/bash

# AWS CLI install 

# `aws configure`

echo "You are logged in as:" aws sts get-caller-identity

echo "Deploying CloudFormation stack..."
echo "This may take a few minutes..."
aws cloudformation deploy --stack-name WakimWorksComplianceScanner --template-file wakimworks-compliance-scanner.yaml --region us-east-1 --capabilities CAPABILITY_NAMED_IAM  --parameter-overrides AuditingBucketName="wakimworks-compliance-scanner-audit-logs"

echo "Deploying dashboard..."
aws cp .\dashboard\index.html s3://wakimworks-compliance-scanner-audit-logs-dashboard --region us-east-1
aws cp .\dashboard\error.html s3://wakimworks-compliance-scanner-audit-logs-dashboard --region us-east-1
aws cp .\logo.png s3://wakimworks-compliance-scanner-audit-logs-dashboard --region us-east-1

echo "Deployment complete!"


