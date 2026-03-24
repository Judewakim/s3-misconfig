import boto3
import botocore.exceptions

def assume_client_role(account_id, external_id):
    """
    Assume a cross-account role in the customer account.
    Returns a boto3.Session object using the temporary creds.
    """
    role_arn = f"arn:aws:iam::{account_id}:role/s3-misconfig-scanner"
    sts = boto3.client("sts")
    resp = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"s3-scan-{account_id}",
        ExternalId=external_id,
        DurationSeconds=900,
    )

    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )

def save_to_dynamodb(findings):
    """
    Placeholder for central persistence; currently prints.
    Replace with DynamoDB PutItem / batch write.
    """
    print("save_to_dynamodb:", findings)

def run_s3_scan(session):
    """
    Refactored from s3-misconfig.py scan code.
    """
    s3 = session.client("s3")
    findings = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except botocore.exceptions.ClientError as e:
        print("list_buckets failed:", e)
        return

    for b in buckets:
        bucket_name = b.get("Name")
        if not bucket_name:
            continue

        bucket_finding = {"bucket": bucket_name, "issues": []}

        # ACL check
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            grants = acl.get("Grants", [])
            for g in grants:
                grantee = g.get("Grantee", {})
                uri = grantee.get("URI", "")
                if uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"):
                    bucket_finding["issues"].append("public-acl")
                    break
        except Exception as e:
            bucket_finding["issues"].append(f"acl-error:{e}")

        # Policy check
        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            # minimal policy parse, emulate s3-misconfig.py
            statement = policy.get("Policy")
            # in original code line ~99 they may serialize; we just note presence
            bucket_finding["issues"].append("has-policy")
        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            if code != "NoSuchBucketPolicy":
                bucket_finding["issues"].append(f"policy-error:{code}")

        if bucket_finding["issues"]:
            findings.append(bucket_finding)

    # replaced local csv write with DynamoDB placeholder
    save_to_dynamodb(findings)

if __name__ == "__main__":
    client_accounts = [
        "111111111111",
        "222222222222",
    ]
    for account_id in client_accounts:
        print(f"Scanning client account {account_id}")
        assumed_session = assume_client_role(account_id, external_id="provider-external-id")
        run_s3_scan(assumed_session)