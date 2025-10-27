# **WakimWorks S3 Scanner — Marketplace Launch Instructions**

The **WakimWorks S3 Scanner** automatically scans your S3 buckets for security misconfigurations and sends daily reports via email. This deployment uses a CloudFormation template that:

1. Creates the IAM role required for deployment.
2. Launches a lightweight EC2 instance from the Marketplace AMI.
3. Passes your chosen parameters to the scanner’s internal CloudFormation stack.
4. Terminates the EC2 instance automatically after deployment.

---

## **Step 1: Prepare Your Parameters**

Before launching, decide on these three parameters:

| Parameter Name | Description                                        | Example                                           |
| -------------- | -------------------------------------------------- | ------------------------------------------------- |
| ExcludeBuckets | Comma-separated S3 bucket names to skip from scans | `bucket1,bucket2`                                 |
| InnovationMode | Enable auto-remediation features                   | `scanning_only` or `scanning_and_autoremediation` |
| UserEmail      | Email address to receive daily scan results        | `you@example.com`                                 |

---

## **Step 2: Launch the CloudFormation Stack**

1. Go to the **AWS CloudFormation Console**.
2. Click **Create Stack → With new resources (standard)**.
3. Under **Specify template**, choose **Upload a template file** and upload the file:
   `WakimWorks-S3Scanner-Launcher.yaml` (the template provided).
4. Click **Next**.
5. Enter the **stack name**, e.g., `WakimWorksS3Scanner`.
6. Fill in the **parameters** from Step 1.
7. Click **Next**, then **Next** again (skip tags and advanced options).
8. Check the acknowledgment box for IAM resources:

   > “I acknowledge that AWS CloudFormation might create IAM resources.”
9. Click **Create stack**.

> CloudFormation will now:
>
> * Create the IAM role `S3ScannerLauncherRole`
> * Launch the EC2 instance from the Marketplace AMI
> * Pass your parameters (`ExcludeBuckets`, `InnovationMode`, `UserEmail`) to the AMI user-data
> * Automatically terminate the EC2 instance after deployment

---

## **Step 3: Two-Stack Flow (Important)**

After deployment, users will **see two CloudFormation stacks** in their account:

| Stack Name                    | Purpose                                  | Visibility |
| ----------------------------- | ---------------------------------------- | ---------- |
| `WakimWorksS3ScannerLauncher` | Creates IAM role + launches EC2 AMI      | Visible    |
| `S3ScannerDeployment`         | Creates Lambda, SNS, SES, etc. (scanner) | Visible    |

**Key Points:**

* The **first stack** (`WakimWorksS3ScannerLauncher`) is a **bootstrapper**. It creates the IAM role and launches the EC2 instance. Once the EC2 instance completes deployment, it self-terminates.
* The **second stack** (`S3ScannerDeployment`) is the **active scanner**. It contains the Lambda functions, SNS topic, SES configuration, and any other resources used for daily S3 scanning.
* Users should **not worry** about seeing two stacks — this is expected and by design. The launcher stack is temporary; the main scanner stack is where ongoing resources live.

---

## **Step 4: Monitor Deployment**

1. Open the **CloudFormation Console**.
2. Watch both stacks:

   * `WakimWorksS3ScannerLauncher` → Should show `CREATE_COMPLETE` (EC2 may be `TERMINATED` shortly after)
   * `S3ScannerDeployment` → Shows `CREATE_IN_PROGRESS` and then `CREATE_COMPLETE`
3. Confirm that daily scan emails are delivered to the **UserEmail** you provided.

---

## **Step 5: Confirm and Customize**

* You can **view the resources** in the `S3ScannerDeployment` stack for Lambda, SNS, SES, and any IAM roles/policies it created.
* To modify parameters (like excluded buckets or InnovationMode) later, update the **main scanner stack** (`S3ScannerDeployment`) directly — no need to touch the launcher stack.

---

## **Step 6: Costs and Termination**

* The EC2 instance from the launcher stack **terminates automatically** after deployment.
* Ongoing costs are only for resources created by the **main scanner stack**:

  * Lambda functions
  * SNS topics
  * SES emails
* No server management is required.

---

## **Step 7: Optional Troubleshooting**

* Check `/var/log/scanner-deploy.log` on the EC2 instance (if needed) or CloudWatch logs if logging is enabled.
* Ensure the IAM role was created successfully and the Marketplace AMI ID in the template matches the AMI being launched.

---

✅ **Done!**
