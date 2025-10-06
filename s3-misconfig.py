# Import necessary libraries
import profile
import boto3
import json
import os
from datetime import datetime
from botocore.exceptions import ClientError

# Initialize AWS clients (e.g., S3 client)
s3_client = boto3.client('s3')

# Main Lambda handler function
def lambda_handler(event, context):
    # Determine event source: CloudFormation Custom Resource or EventBridge
    if 'RequestType' in event and event['RequestType'] == 'Create':
        event_data = json.loads(event['ResourceProperties']['ScanConfig'])
    else:
        event_data = event
    
    # Parse input event for configuration and flags
    config = event_data.get('config', {})  # e.g., {'exclude_buckets': ['logs-bucket']}
    remediate = event_data.get('remediate', False)  # Flag to enable remediation
    dry_run = event_data.get('dry_run', True)  # Default to dry run for safety
    email = event_data.get('email', None)  # Email from parameters

    # Initialize result structure
    results = {
        'summary': {'total_buckets': 0, 'high_risk': 0},
        'buckets': []
    }

    # Call function to scan all buckets and collect risks
    bucket_risks = scan_buckets(s3_client, config)

    # Update summary with total and high-risk counts
    results['summary']['total_buckets'] = len(bucket_risks)
    results['summary']['high_risk'] = sum(1 for b in bucket_risks if b.get('severity') == 'high')

    # Append detailed bucket risks to results
    results['buckets'] = bucket_risks

    # If remediation is requested, apply fixes (with safety checks)
    if remediate and not dry_run:
        fixes_applied = remediate_risks(s3_client, bucket_risks, config)
        # Update results with remediation outcomes
        results['fixes'] = fixes_applied

    # Email notification logic - send results via SES
    if email:
        send_email_notification(email, results, remediate)

    # Return JSON response with status and body
    if 'RequestType' in event:
        return {'Status': 'SUCCESS', 'Data': {'message': 'Scan completed', 'results': results}}
    return {'statusCode': 200, 'body': json.dumps(results)}

# Function to scan all S3 buckets for misconfigurations
def scan_buckets(s3_client, config):
    """
    Scan all S3 buckets in an AWS account for misconfigurations.

    Args:
        s3_client: A boto3 S3 client
        config: Dictionary that may contain an 'exclude_buckets' key with a list of bucket names to skip

    Returns:
        List of dictionaries containing bucket name, risks, severity, and skipped flags
    """
    # Initialize list to hold all bucket risk assessments
    risks = []

    print("Starting S3 bucket misconfiguration scan...")

    # Helper function to determine severity ranking for comparison
    def severity_rank(severity):
        return {'none': 0, 'low': 1, 'medium': 2, 'high': 3}.get(severity, 0)

    # Fetch list of all buckets in the account with direct call (no pagination needed)
    bucket_list = []
    try:
        response = s3_client.list_buckets()
        bucket_list.extend(response['Buckets'])
    except ClientError as e:
        print(f"Error listing buckets: {e}")
        return []

    print(f"Found {len(bucket_list)} buckets to scan")

    # Loop through each bucket
    for bucket in bucket_list:
        bucket_name = bucket['Name']
        print(f"Scanning bucket: {bucket_name}")

        # Skip buckets listed in config exclusions
        if bucket_name in config.get('exclude_buckets', []):
            print(f"Skipping excluded bucket: {bucket_name}")
            risks.append({'name': bucket_name, 'risks': [], 'skipped': True, 'severity': 'none'})
            continue

        # Initialize bucket-specific risk list and severity
        bucket_risks = []
        severity = 'none'

        # Check 1: Public Access Block Configuration
        # Retrieve and check if PublicAccessBlock is disabled
        try:
            public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
            pab_config = public_access_block['PublicAccessBlockConfiguration']

            # Check if any setting is False (disabled)
            disabled_settings = []
            for setting, value in pab_config.items():
                if not value:
                    disabled_settings.append(setting)

            if disabled_settings:
                bucket_risks.append({
                    'type': 'PublicAccessBlockDisabled',
                    'details': f"Disabled settings: {', '.join(disabled_settings)}"
                })
                severity = 'high' if severity_rank('high') > severity_rank(severity) else severity
                print(f"  - PublicAccessBlock disabled for {bucket_name}: {disabled_settings}")
        except ClientError as e:
            print(f"  - Error checking PublicAccessBlock for {bucket_name}: {e}")

        # Check 2: Public ACLs
        # Retrieve ACL and check for public grants
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            public_grants = []
            for grant in acl['Grants']:
                grantee = grant.get('Grantee', {})
                if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                    public_grants.append(grant)

            if public_grants:
                bucket_risks.append({
                    'type': 'PublicACL',
                    'details': f"Found {len(public_grants)} public grants"
                })
                severity = 'high' if severity_rank('high') > severity_rank(severity) else severity
                print(f"  - Public ACL found for {bucket_name}")
        except ClientError as e:
            print(f"  - Error checking ACL for {bucket_name}: {e}")

        # Check 3: Wildcard in Bucket Policy
        # Retrieve and parse bucket policy for wildcard principals
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_json = json.loads(policy['Policy'])
            wildcard_statements = []

            for statement in policy_json.get('Statement', []):
                principal = statement.get('Principal')
                actions = statement.get('Action', [])

                # Handle both string and list actions
                if isinstance(actions, str):
                    actions = [actions]

                # Check for wildcard principal and s3:* action
                if principal == '*' or any('s3:*' in action for action in actions):
                    wildcard_statements.append(statement)

            if wildcard_statements:
                bucket_risks.append({
                    'type': 'WildcardPolicy',
                    'details': f"Found {len(wildcard_statements)} statement(s) with wildcard principal and/or wildcard action"
                })
                severity = 'medium' if severity_rank('medium') > severity_rank(severity) else severity
                print(f"  - Wildcard policy found for {bucket_name}")
        except ClientError as e:
            # Check if no bucket policy exists
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                bucket_risks.append({
                    'type': 'NoPolicy',
                    'details': 'No bucket policy configured'
                })
                severity = 'medium' if severity_rank('medium') > severity_rank(severity) else severity
                print(f"  - No bucket policy configured for {bucket_name}")
            else:
                print(f"  - Error checking bucket policy for {bucket_name}: {e}")

        # Check 4: Encryption Status
        # Check if default encryption is enabled
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            # If we get here, encryption exists - check if it's properly configured
        except ClientError as e:
            # NoSuchEncryption error means no encryption is configured
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                bucket_risks.append({
                    'type': 'NoEncryption',
                    'details': 'Default encryption not configured'
                })
                severity = 'medium' if severity_rank('medium') > severity_rank(severity) else severity
                print(f"  - No encryption configured for {bucket_name}")
            else:
                print(f"  - Error checking encryption for {bucket_name}: {e}")

        # Add bucket results to the risks list
        risks.append({
            'name': bucket_name,
            'risks': bucket_risks,
            'severity': severity,
            'skipped': False
        })

        print(f"  Completed scan for {bucket_name}, severity: {severity}, risks: {len(bucket_risks)}")

    print(f"Scan completed. Processed {len(risks)} buckets")
    # Return the list of risks
    return risks

# Function to remediate identified risks safely
def remediate_risks(s3_client, risks, config):
    # Initialize list to track applied or skipped fixes
    fixes = []

    # Loop through buckets with high or medium severity (skip low/none or skipped buckets)
    for bucket in [r for r in risks if r['severity'] in ['high', 'medium'] and not r.get('skipped')]:
        bucket_name = bucket['name']
        print(f"Starting remediation for bucket: {bucket_name}")

        # Loop through each risk in the bucket
        # NOTE: Processing order matters - PublicACL should be handled before PublicAccessBlockDisabled
        # to ensure proper ACL cleanup before enabling blocks that would prevent ACL changes
        for risk in bucket['risks']:
            risk_type = risk['type']
            details = risk['details']

            # Remediation 1: Remove Public ACLs if present (with safety check) - PRIORITY FIRST
            if risk_type == 'PublicACL':
                try:
                    # Safety check: List objects and check for public ACLs
                    objects = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=100)
                    has_public_objects = False

                    # Check each object for public ACL grants using get_object_acl
                    if 'Contents' in objects:
                        for obj in objects['Contents']:
                            try:
                                obj_acl = s3_client.get_object_acl(Bucket=bucket_name, Key=obj['Key'])
                                for grant in obj_acl.get('Grants', []):
                                    grantee = grant.get('Grantee', {})
                                    if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                                        has_public_objects = True
                                        break
                                if has_public_objects:
                                    break
                            except ClientError:
                                # Skip if can't check object ACL
                                continue

                    if has_public_objects:
                        fixes.append({'bucket': bucket_name, 'action': 'removed_public_acl', 'status': 'skipped', 'reason': 'Objects with public ACLs detected - manual review required'})
                        print(f"Skipped removing Public ACL for {bucket_name} due to public objects")
                    else:
                        # Apply fix: Set bucket ACL to private
                        s3_client.put_bucket_acl(Bucket=bucket_name, ACL='private')
                        fixes.append({'bucket': bucket_name, 'action': 'removed_public_acl', 'status': 'success'})
                        print(f"- Removed Public ACL for {bucket_name}")
                except ClientError as e:
                    fixes.append({'bucket': bucket_name, 'action': 'removed_public_acl', 'status': 'failed', 'reason': str(e)})
                    print(f"Error removing Public ACL for {bucket_name}: {str(e)}")

            # Remediation 2: Enable Public Access Block if disabled - AFTER ACL cleanup
            elif risk_type == 'PublicAccessBlockDisabled':
                try:
                    # Apply fix: Set all blocks to True
                    s3_client.put_public_access_block(
                        Bucket=bucket_name,
                        PublicAccessBlockConfiguration={
                            'BlockPublicAcls': True,
                            'IgnorePublicAcls': True,
                            'BlockPublicPolicy': True,
                            'RestrictPublicBuckets': True
                        }
                    )
                    fixes.append({'bucket': bucket_name, 'action': 'enabled_public_access_block', 'status': 'success'})
                    print(f"- Enabled Public Access Block for {bucket_name}")
                except ClientError as e:
                    fixes.append({'bucket': bucket_name, 'action': 'enabled_public_access_block', 'status': 'failed', 'reason': str(e)})
                    print(f"Error enabling Public Access Block for {bucket_name}: {str(e)}")

            # Remediation 3: Fix Wildcard Policy (simple cases only)
            elif risk_type == 'WildcardPolicy':
                try:
                    # Retrieve current policy
                    policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                    policy_json = json.loads(policy['Policy'])
                    statements = policy_json.get('Statement', [])

                    # Remove wildcard statements (e.g., Principal == '*')
                    updated_statements = [stmt for stmt in statements if stmt.get('Principal') != '*']  # Refine for complex principals

                    # If changes made and not complex, apply
                    if len(updated_statements) < len(statements):
                        new_policy = json.dumps({'Version': policy_json['Version'], 'Statement': updated_statements})
                        s3_client.put_bucket_policy(Bucket=bucket_name, Policy=new_policy)
                        fixes.append({'bucket': bucket_name, 'action': 'removed_wildcard_policy', 'status': 'success'})
                        print(f"- Removed wildcard policy for {bucket_name}")
                    else:
                        fixes.append({'bucket': bucket_name, 'action': 'removed_wildcard_policy', 'status': 'skipped', 'reason': 'no changes or complex policy'})
                        print(f"Skipped wildcard policy remediation for {bucket_name}: no changes or complex")
                except ClientError as e:
                    fixes.append({'bucket': bucket_name, 'action': 'removed_wildcard_policy', 'status': 'failed', 'reason': str(e)})
                    print(f"Error fixing wildcard policy for {bucket_name}: {str(e)}")

            # Remediation 4: Enable Default Encryption if missing
            elif risk_type == 'NoEncryption':
                try:
                    # Apply fix: Enable SSE-S3 (AES256)
                    s3_client.put_bucket_encryption(
                        Bucket=bucket_name,
                        ServerSideEncryptionConfiguration={
                            'Rules': [{
                                'ApplyServerSideEncryptionByDefault': {
                                    'SSEAlgorithm': 'AES256'
                                }
                            }]
                        }
                    )
                    fixes.append({'bucket': bucket_name, 'action': 'enabled_encryption', 'status': 'success'})
                    print(f"- Enabled encryption for {bucket_name}")
                except ClientError as e:
                    fixes.append({'bucket': bucket_name, 'action': 'enabled_encryption', 'status': 'failed', 'reason': str(e)})
                    print(f"Error enabling encryption for {bucket_name}: {str(e)}")

        print(f"Completed remediation for bucket: {bucket_name}")

    # Return the fixes list for inclusion in the Lambda response
    return fixes

# Function to send email notification with scan results
def send_email_notification(email, results, remediate):
    """
    Send email notification with scan results using SES

    Args:
        email: Recipient email address
        results: Scan results dictionary
        remediate: Boolean indicating if remediation was performed
    """
    # Initialize SES client
    ses_client = boto3.client('ses')

    try:
        # Determine mode and build subject
        if remediate:
            # Count fixes by status
            fixes = results.get('fixes', [])
            fixed_count = len([f for f in fixes if f['status'] == 'success'])
            needs_help_count = len([f for f in fixes if f['status'] in ['skipped', 'failed']])

            # Add remaining high risk after fixes
            remaining_high_risk = results['summary']['high_risk']
            total_needs_help = needs_help_count + remaining_high_risk

            if total_needs_help > 0:
                subject = f"S3 Scan: {fixed_count} issues fixed, {total_needs_help} needs your help"
            else:
                subject = f"S3 Scan: {fixed_count} issues fixed, All Clean"
        else:
            # Scan only mode
            high_risk_count = results['summary']['high_risk']
            if high_risk_count > 0:
                subject = f"S3 Scan: {high_risk_count} issues found"
            else:
                subject = "S3 Scan: All Clean"

        # Build HTML email body
        html_body = build_html_email_body(results, remediate)

        # Send email using SES
        ses_client.send_email(
            Source='scanner@wakimworks.com',
            Destination={'ToAddresses': [email]},
            Message={
                'Subject': {'Data': subject},
                'Body': {'Html': {'Data': html_body}}
            }
        )

        print(f"Email notification sent successfully to {email}")

    except ClientError as e:
        print(f"Error sending email notification: {e}")
        # Continue execution - don't crash on email failure

# Function to build HTML email body
def build_html_email_body(results, remediate):
    """
    Build HTML email body with scan results

    Args:
        results: Scan results dictionary
        remediate: Boolean indicating if remediation was performed

    Returns:
        HTML string for email body
    """
    # Get scan details
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    region = os.environ.get('AWS_REGION', 'Unknown')
    total_buckets = results['summary']['total_buckets']

    # Start building HTML
    html = f"""
    <html>
    <head>
        <style>
            table {{border-collapse: collapse; width: 100%;}}
            th, td {{border: 1px solid #ddd; padding: 8px; text-align: left;}}
            th {{background-color: #f2f2f2;}}
            .high {{color: #ff0000; font-weight: bold;}}
            .medium {{color: #ff8800; font-weight: bold;}}
            .low {{color: #0088ff;}}
            .none {{color: #008800;}}
            h1, h2 {{color: #333;}}
        </style>
    </head>
    <body>
        <h1>Scan Details</h1>
        <p><strong>Timestamp:</strong> {timestamp}</p>
        <p><strong>Region:</strong> {region}</p>
        <p><strong>Total Buckets Scanned:</strong> {total_buckets}</p>
    """

    # Add remediation section if applicable
    if remediate and 'fixes' in results:
        html += """
        <h2>Remediations</h2>
        <table>
            <tr><th>Bucket</th><th>Action</th><th>Status</th><th>Reason</th></tr>
        """

        for fix in results['fixes']:
            status_class = 'high' if fix['status'] == 'failed' else ('medium' if fix['status'] == 'skipped' else 'none')
            reason = fix.get('reason', 'N/A')
            html += f"""
            <tr>
                <td>{fix['bucket']}</td>
                <td>{fix['action'].replace('_', ' ').title()}</td>
                <td class="{status_class}">{fix['status'].title()}</td>
                <td>{reason}</td>
            </tr>
            """

        html += "</table>"

    # Group findings by severity
    findings_by_severity = {'high': [], 'medium': [], 'low': [], 'none': []}

    for bucket in results['buckets']:
        if not bucket.get('skipped', False):
            for risk in bucket['risks']:
                # Determine severity for this specific risk
                if risk['type'] in ['PublicAccessBlockDisabled', 'PublicACL']:
                    severity = 'high'
                elif risk['type'] in ['WildcardPolicy', 'NoPolicy', 'NoEncryption']:
                    severity = 'medium'
                else:
                    severity = 'low'

                # Generate risk explanation and fix command
                risk_explanation, fix_command = get_risk_details(risk['type'], bucket['name'])

                findings_by_severity[severity].append({
                    'bucket': bucket['name'],
                    'issue': risk['type'],
                    'risk': risk_explanation,
                    'fix': fix_command
                })

    # Add findings section
    html += "<h2>Findings</h2>"

    for severity in ['high', 'medium', 'low', 'none']:
        if findings_by_severity[severity]:
            html += f"""
            <h3 class="{severity}">{severity.title()} Risk Issues</h3>
            <table>
                <tr><th>Severity</th><th>Bucket</th><th>Issue</th><th>Risk</th><th>Fix</th></tr>
            """

            for finding in findings_by_severity[severity]:
                html += f"""
                <tr>
                    <td class="{severity}">{severity.upper()}</td>
                    <td>{finding['bucket']}</td>
                    <td>{finding['issue']}</td>
                    <td>{finding['risk']}</td>
                    <td><code>{finding['fix']}</code></td>
                </tr>
                """

            html += "</table>"

    html += """
    </body>
    </html>
    """

    return html

# Function to get risk details
def get_risk_details(risk_type, bucket_name):
    """
    Get plain English explanation and CLI fix command for each risk type

    Args:
        risk_type: Type of risk identified
        bucket_name: Name of the affected bucket

    Returns:
        Tuple of (risk_explanation, fix_command)
    """
    risk_details = {
        'PublicAccessBlockDisabled': (
            'Public Access Block settings are disabled, allowing potential public access to your data—high exposure risk',
            f'aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
        ),
        'PublicACL': (
            'Public ACL allows anyone to read your data—high exposure risk',
            f'aws s3api put-bucket-acl --bucket {bucket_name} --acl private'
        ),
        'WildcardPolicy': (
            'Bucket policy contains wildcard permissions that may allow unintended public access—medium risk',
            f'aws s3api delete-bucket-policy --bucket {bucket_name} # Review and update policy'
        ),
        'NoPolicy': (
            'No bucket policy configured—medium risk of uncontrolled access',
            f'aws s3api put-bucket-policy --bucket {bucket_name} --policy file://restrictive-policy.json'
        ),
        'NoEncryption': (
            'Default encryption not configured—medium risk of data exposure',
            f'aws s3api put-bucket-encryption --bucket {bucket_name} --server-side-encryption-configuration \'{{"Rules": [{{"ApplyServerSideEncryptionByDefault": {{"SSEAlgorithm": "AES256"}}}}]}}\''
        )
    }

    return risk_details.get(risk_type, ('Unknown risk type', 'Manual review required'))

# Optional: Add error handling or logging functions if needed
# def log_error(error_message):
#     print(error_message)  # Logs to CloudWatch