# PDF Report Generation - Deployment Guide

## Overview
This guide covers deploying the PDF report generation feature that creates downloadable HIPAA compliance reports.

## Prerequisites
- AWS CLI configured
- Docker installed (for building Lambda layer with WeasyPrint)
- Existing compliance scanner stack deployed

## Step 1: Build WeasyPrint Lambda Layer

WeasyPrint requires system libraries that aren't available in Lambda by default. We need to create a Lambda layer.

### Option A: Use Pre-built Layer (Recommended)
```powershell
# Download pre-built WeasyPrint layer from AWS Serverless Application Repository
# Layer ARN: arn:aws:lambda:us-east-1:764866452798:layer:weasyprint:1
```

### Option B: Build Custom Layer
```powershell
# Create layer directory
mkdir lambda-layer
cd lambda-layer

# Create Dockerfile
@"
FROM public.ecr.aws/lambda/python:3.12

RUN yum install -y \
    cairo \
    pango \
    gdk-pixbuf2 \
    libffi \
    && yum clean all

RUN pip install --target /opt/python weasyprint==60.2 boto3==1.34.0

CMD ["echo", "Layer built successfully"]
"@ | Out-File -FilePath Dockerfile -Encoding ASCII

# Build layer
docker build -t weasyprint-layer .
docker run --rm -v ${PWD}:/output weasyprint-layer sh -c "cd /opt && zip -r /output/weasyprint-layer.zip ."

# Upload to S3
aws s3 cp weasyprint-layer.zip s3://YOUR-BUCKET/lambda-layers/

# Create Lambda layer
aws lambda publish-layer-version `
    --layer-name weasyprint-layer `
    --description "WeasyPrint for PDF generation" `
    --content S3Bucket=YOUR-BUCKET,S3Key=lambda-layers/weasyprint-layer.zip `
    --compatible-runtimes python3.12 `
    --region us-east-1
```

## Step 2: Update CloudFormation Template

The template has been updated with:
- `ReportGeneratorRole` - IAM role for Lambda
- `ReportGeneratorLambda` - PDF generation function
- `ReportAPI` - HTTP API Gateway
- `ReportAPIEndpoint` - Output with API URL

## Step 3: Package Lambda Function

```powershell
cd lambda

# Create deployment package
Compress-Archive -Path report_generator.py -DestinationPath report_generator.zip

# Upload to S3 (if needed for large packages)
aws s3 cp report_generator.zip s3://YOUR-BUCKET/lambda-functions/
```

## Step 4: Update Stack

```powershell
# Update CloudFormation stack
aws cloudformation update-stack `
    --stack-name wakimworks-compliance-scanner `
    --template-body file://wakimworks-compliance-scanner.yaml `
    --capabilities CAPABILITY_NAMED_IAM `
    --region us-east-1

# Wait for completion
aws cloudformation wait stack-update-complete `
    --stack-name wakimworks-compliance-scanner `
    --region us-east-1
```

## Step 5: Add WeasyPrint Layer to Lambda

```powershell
# Get Lambda function name
$FUNCTION_NAME = "wakimworks-report-generator"

# Add layer (use your layer ARN)
aws lambda update-function-configuration `
    --function-name $FUNCTION_NAME `
    --layers arn:aws:lambda:us-east-1:764866452798:layer:weasyprint:1 `
    --region us-east-1
```

## Step 6: Update Lambda Function Code

```powershell
# Update function code with full implementation
aws lambda update-function-code `
    --function-name wakimworks-report-generator `
    --zip-file fileb://lambda/report_generator.zip `
    --region us-east-1
```

## Step 7: Get API Endpoint

```powershell
# Get API endpoint from stack outputs
aws cloudformation describe-stacks `
    --stack-name wakimworks-compliance-scanner `
    --query "Stacks[0].Outputs[?OutputKey=='ReportAPIEndpoint'].OutputValue" `
    --output text `
    --region us-east-1
```

## Step 8: Update Dashboard

```powershell
# Update index.html with API endpoint
$API_ENDPOINT = aws cloudformation describe-stacks `
    --stack-name wakimworks-compliance-scanner `
    --query "Stacks[0].Outputs[?OutputKey=='ReportAPIEndpoint'].OutputValue" `
    --output text `
    --region us-east-1

# Replace placeholder in index.html
(Get-Content dashboard/index.html) -replace 'REPLACE_WITH_API_ENDPOINT', $API_ENDPOINT | Set-Content dashboard/index.html

# Upload updated dashboard
$DASHBOARD_BUCKET = "wakimworks-compliance-scanner-audit-logs-dashboard"
aws s3 cp dashboard/index.html s3://$DASHBOARD_BUCKET/index.html
```

## Step 9: Test Report Generation

```powershell
# Test Lambda function directly
aws lambda invoke `
    --function-name wakimworks-report-generator `
    --payload '{}' `
    response.json `
    --region us-east-1

# Check response
Get-Content response.json | ConvertFrom-Json
```

## Step 10: Test from Dashboard

1. Open dashboard URL
2. Navigate to "Technical Config Controls" tab
3. Click "📄 Generate PDF Report" button
4. Wait for generation (5-10 seconds)
5. PDF should download automatically

## Troubleshooting

### Lambda Timeout
If report generation times out:
```powershell
aws lambda update-function-configuration `
    --function-name wakimworks-report-generator `
    --timeout 120 `
    --region us-east-1
```

### Memory Issues
If Lambda runs out of memory:
```powershell
aws lambda update-function-configuration `
    --function-name wakimworks-report-generator `
    --memory-size 1024 `
    --region us-east-1
```

### CORS Errors
Verify API Gateway CORS configuration:
```powershell
aws apigatewayv2 get-api `
    --api-id YOUR-API-ID `
    --region us-east-1
```

### Missing Compliance Events
Check S3 bucket for events:
```powershell
aws s3 ls s3://wakimworks-compliance-scanner-audit-logs/compliance-events/
```

## Cost Estimate

- Lambda invocations: $0.20 per 1M requests
- Lambda duration: $0.0000166667 per GB-second
- API Gateway: $1.00 per million requests
- S3 storage (PDFs): $0.023 per GB

**Estimated monthly cost for 100 reports: ~$0.50**

## Security Considerations

1. **Pre-signed URLs**: Reports use 5-minute expiring URLs
2. **S3 Encryption**: PDFs stored with AES-256 encryption
3. **IAM Permissions**: Lambda has minimal S3 read/write access
4. **API Gateway**: No authentication (add Cognito/API keys for production)

## Next Steps

1. Add date range filtering to reports
2. Implement scheduled report generation (weekly/monthly)
3. Add email delivery via SES
4. Customize report branding with company logo
5. Add authentication to API Gateway
