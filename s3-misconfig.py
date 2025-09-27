#needs to be in lambda_function.zip and zip needs to be uploaded to s3://judewakim-s3-misconfig/code

# Import necessary libraries
import profile
import boto3
import json
from botocore.exceptions import ClientError

# Initialize AWS clients (e.g., S3 client)
s3_client = boto3.client('s3')

# Main Lambda handler function
def lambda_handler(event, context):
    # Parse input event for configuration and flags
    config = event.get('config', {})  # e.g., {'exclude_buckets': ['logs-bucket']}
    remediate = event.get('remediate', False)  # Flag to enable remediation
    dry_run = event.get('dry_run', True)  # Default to dry run for safety

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

    # Return JSON response with status and body
    return {
        'statusCode': 200,
        'body': json.dumps(results)
    }

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

    # Fetch list of all buckets in the account with pagination support
    bucket_list = []
    paginator = s3_client.get_paginator('list_buckets')

    try:
        for page in paginator.paginate():
            bucket_list.extend(page['Buckets'])
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

        print(f"  - Completed scan for {bucket_name}, severity: {severity}, risks: {len(bucket_risks)}")

    print(f"Scan completed. Processed {len(risks)} buckets")
    # Return the list of risks
    return risks

# Function to remediate identified risks
def remediate_risks(s3_client, risks, config):
    # Initialize list to track applied fixes
    fixes = []

    # Loop through buckets with high or medium severity risks
    for bucket in [r for r in risks if r['severity'] in ['high', 'medium'] and not r.get('skipped')]:
        bucket_name = bucket['name']
        for risk in bucket['risks']:
            # Remediation 1: Enable Public Access Block
            if risk['type'] == 'PublicAccessBlockDisabled':
                s3_client.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    }
                )
                fixes.append({'bucket': bucket_name, 'action': 'enabled_public_access_block'})

            # Remediation 2: Remove Public ACLs (with safety check)
            if risk['type'] == 'PublicACL':
                # Check for objects with public ACLs before changing
                objects = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=100)
                if not any(obj.get('ACL') for obj in objects.get('Contents', [])):
                    s3_client.put_bucket_acl(Bucket=bucket_name, ACL='private')
                    fixes.append({'bucket': bucket_name, 'action': 'removed_public_acl'})
                else:
                    fixes.append({'bucket': bucket_name, 'action': 'skipped_public_acl_due_to_objects', 'reason': 'public_object_acls_detected'})

            # Remediation 3: Fix Wildcard Policy (simple case only)
            if risk['type'] == 'WildcardPolicy':
                try:
                    policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                    policy_json = json.loads(policy['Policy'])
                    updated_statements = [s for s in policy_json['Statement'] if s.get('Principal') != '*']
                    if len(updated_statements) < len(policy_json['Statement']):
                        s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps({'Statement': updated_statements}))
                        fixes.append({'bucket': bucket_name, 'action': 'removed_wildcard_policy'})
                    else:
                        fixes.append({'bucket': bucket_name, 'action': 'skipped_wildcard_policy', 'reason': 'complex_policy_detected'})
                except ClientError:
                    fixes.append({'bucket': bucket_name, 'action': 'skipped_wildcard_policy', 'reason': 'policy_access_denied'})

            # Remediation 4: Enable Encryption
            if risk['type'] == 'NoEncryption':
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
                fixes.append({'bucket': bucket_name, 'action': 'enabled_encryption'})

    # Return list of applied fixes
    return fixes

# Optional: Add error handling or logging functions if needed
# def log_error(error_message):
#     print(error_message)  # Logs to CloudWatch
