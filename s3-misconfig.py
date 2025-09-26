#needs to be in lambda_function.zip and zip needs to be uploaded to s3://judewakim-s3-misconfig/code

# Import necessary libraries
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
    # Initialize list to hold all bucket risk assessments
    risks = []

    # Fetch list of all buckets in the account
    bucket_list = s3_client.list_buckets()

    # Loop through each bucket
    for bucket in bucket_list['Buckets']:
        bucket_name = bucket['Name']

        # Skip buckets listed in config exclusions
        if bucket_name in config.get('exclude_buckets', []):
            risks.append({'name': bucket_name, 'risks': [], 'skipped': True, 'severity': 'none'})
            continue

        # Initialize bucket-specific risk list and severity
        bucket_risks = []
        severity = 'low'

        # Check 1: Public Access Block Configuration
        # Retrieve and check if PublicAccessBlock is disabled
        public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
        if not all(public_access_block['PublicAccessBlockConfiguration'].values()):
            bucket_risks.append({'type': 'PublicAccessBlockDisabled', 'details': public_access_block['PublicAccessBlockConfiguration']})
            severity = max(severity, 'high')

        # Check 2: Public ACLs
        # Retrieve ACL and check for public grants
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            public_grants = [g for g in acl['Grants'] if g['Grantee'].get('Type') == 'Group' and 'AllUsers' in g['Grantee'].get('URI', '')]
            if public_grants:
                bucket_risks.append({'type': 'PublicACL', 'details': public_grants})
                severity = max(severity, 'high')
        except ClientError:
            # Log error and skip (e.g., no permission)
            pass

        # Check 3: Wildcard in Bucket Policy
        # Retrieve and parse bucket policy for wildcard principals
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_json = json.loads(policy['Policy'])
            for statement in policy_json.get('Statement', []):
                if statement.get('Principal') == '*' and 's3:GetObject' in statement.get('Action', []):
                    bucket_risks.append({'type': 'WildcardPolicy', 'details': statement})
                    severity = max(severity, 'medium')
        except ClientError:
            # No policy or access denied, skip
            pass

        # Check 4: Encryption Status
        # Check if default encryption is enabled
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            if not encryption['ServerSideEncryptionConfiguration'][0]['Rules'][0].get('ApplyServerSideEncryptionByDefault'):
                bucket_risks.append({'type': 'NoEncryption', 'details': 'Default encryption not enabled'})
                severity = max(severity, 'medium')
        except ClientError:
            # No encryption or access denied, skip
            pass

        # Add bucket results to the risks list
        risks.append({'name': bucket_name, 'risks': bucket_risks, 'severity': severity})

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