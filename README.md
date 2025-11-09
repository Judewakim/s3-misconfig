Start editing…WAKIMWORKS S3 SECURITY SCANNER
### OVERVIEW
The WakimWorks S3 Security Scanner is a serverless AWS solution designed to automatically detect and remediate security misconfigurations in Amazon S3 buckets across AWS accounts.
This current release is the free version (v1.0), designed to demonstrate secure scanning, cross-account role assumption, and email reporting.
The scanner identifies issues such as public bucket access, missing encryption, unlogged access patterns, and improper versioning.
It can operate in two modes:

Scan only (audit/report mode)

Scan and auto-remediate (attempts to fix issues automatically)

All scans are executed using secure, cross-account STS role assumption and results are delivered via SES email with inline reporting and branding.

ARCHITECTURE OVERVIEW
SELLER ACCOUNT

Hosts the scanning Lambda function, DynamoDB metadata, SES email sender, and EventBridge daily scheduler.

Handles all cross-account assume-role logic and email generation.

Receives scan requests from client accounts through SQS.

Uses CloudFormation Custom Resource triggers for initial setup.

CLIENT ACCOUNT

Deploys a lightweight CloudFormation template (S3ScannerClient).

Creates an IAM role that grants controlled S3 read access to the seller account using a secure ExternalId (to prevent confused deputy attacks).

Triggers a scan upon stack creation and daily thereafter.


KEY COMPONENTS

Lambda Function (S3SecurityScannerFunction)
Performs S3 configuration scans and sends email notifications.

SES Email Notification
Sends HTML scan reports with severity ranking and remediation commands.

CloudFormation Custom Resource
Automatically triggers the initial scan upon client stack deployment.

EventBridge (DailyScanRule)
Triggers recurring daily scans at 10 PM EDT.

SQS (S3ScannerRegistrationQueue)
Manages asynchronous communication between client and seller accounts.


CLIENT PERSPECTIVE
WHAT IT DOES

Automatically scans all S3 buckets in the client account (except those excluded).

Detects risky configurations and optionally remediates them.

Sends an email summary report to the client, including findings, recommended actions, and auto-remediation results.

DEPLOYMENT STEPS

Prerequisites:

AWS CLI configured (optionally)

An active AWS account with CloudFormation permissions

Deploy the client template via CLI:
Example:
aws cloudformation deploy --stack-name WakimWorksS3ScannerLauncher--template-file WakimWorks-S3Scanner-Launcher.yaml --region us-east-1 --capabilities CAPABILITY_NAMED_IAM --parameter-overrides UserEmail=[YOUR_EMAIL] ExcludeBuckets=[BUCKETS_YOU_WANT_EXCLUDED] InvocationMode=[scanning_only OR scanning_and_autoremediation]Deploy the client template via console:
Example:Go to AWS CloudFormation service &gt; Create stack &gt; Choose an existing template &gt; Upload a template file &gt; Upload the WakimWorks-S3Scanner-Launcher.yaml &gt; Enter 'WakimWorksS3ScannerLauncher' as the stack name &gt; add any buckets you would like to exclude, select the invocation mode (scan only or scan and autoremediate), and enter the email where you would like to receive scan results &gt; accept the AWS acknowledgement &gt; Submit
Upon stack creation, a scan will start automatically.

Results will be emailed to the UserEmail address.

Daily scans will continue via EventBridge.

USER EXPECTATIONS

Email will arrive from scanner@wakimworks.com (check spam if not visible).

Scans will identify risky buckets and suggest best-practice changes.


SECURITY CONSIDERATIONS
IAM

S3SecurityScannerLambdaRole (seller): Grants DynamoDB, STS, SES, and SQS permissions.

S3SecurityScannerClientRole (client): Grants least-privilege S3 read access and uses an STS ExternalId for protection.

SQS

Restricts message sending to the client account only.

STS ExternalId

Uniquely generated for each client deployment to prevent unauthorized access.

DATA HANDLING

No persistent customer data is stored by the seller account beyond minimal scan metadata.

All logs are handled within AWS CloudWatch and automatically rotated.


SCAN COVERAGE
The scanner checks for:

Public bucket access

Public object access via ACL or policy

Missing default encryption (SSE-S3 or SSE-KMS)

Insecure cross-account bucket policies

Logging disabled or missing access logs

Versioning and MFA Delete disabled

Unencrypted object uploads *(future feature)*

Lifecycle misconfiguration *(future feature)*


INTERNATIONAL SECURITY AND COMPLIANCE MAPPING
Each scan finding corresponds to major international standards for data protection and cloud storage:

ISO/IEC 27017: Cloud Security Controls for S3 Access Policies

ISO/IEC 27018: Personal Data Protection in Cloud Storage

CIS AWS Foundations Benchmark: S3.1, S3.2, S3.3 (public access and encryption controls)

NIST SP 800-53 Rev. 5: AC-3, SC-13, SC-28, AU-9 (access control, encryption, auditing)

GDPR Article 32: Security of Processing (data confidentiality and integrity)


COST MODEL
This **free** version incurs only the AWS costs associated with:

Lambda execution (usually &lt; $0.01 per scan)

SES outbound email (first 62,000 emails/month free)

SQS and EventBridge (pennies per month)

CloudFormation and IAM (no additional charge)

No part of the scanner itself requires a paid WakimWorks license in this version.

TROUBLESHOOTING
If CloudFormation stack gets stuck:

Ensure your Lambda sends SUCCESS responses for Create, Update, and Delete custom resource events.

Check CloudWatch logs in the seller account for “RequestType” messages.

If email not received:
Check spam folder or valid email format during stack deployment.


FUTURE RELEASES AND FEATURES
Planned for future paid or enterprise versions:

Advanced reporting dashboard

Automated compliance mapping reports (PDF and CSV exports)

Multi-region scanning orchestration

S3 malware/object scanning integration

Integration with AWS Security Hub and GuardDuty

Organization-wide deployment through AWS Control Tower

Customer-managed encryption and key policy audits

Custom branding for partner deployments


SUPPORT AND CONTACT
For assistance, feature requests, or bug reports:
Email: judewakim@wakimworks.com
Website: https://www.wakimworks.com
GitHub: https://github.com/judewakim/s3-misconfig

### LICENSE
MIT License.
Use, modify, and distribute freely with attribution.