"""
seed_test_data.py

Creates the S3Sentry DynamoDB table (with the SK-index GSI) and inserts one
dummy tenant so the orchestrator can be verified immediately.

Usage:
    python seed_test_data.py

Prerequisites:
    - AWS credentials in env / ~/.aws/credentials with permission to create
      DynamoDB tables and write items.
    - pip install boto3

The script is idempotent: if the table already exists it skips creation and
goes straight to upserting the dummy tenant item.
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

TABLE_NAME = "S3Sentry"
REGION = "us-east-1"

DUMMY_TENANT = {
    # Single-table keys
    "PK":         "ACC#123456789012",
    "SK":         "METADATA",
    # Explicit AccountId attribute (preferred over PK parsing)
    "AccountId":  "123456789012",
    # Replace with a real role ARN when running against a live account.
    "RoleArn":    "arn:aws:iam::123456789012:role/S3SentryCrossAccountRole",
    "ExternalId": "test-external-id-abc123",
    "Email":      "tenant-owner@example.com",
    "Status":     "ACTIVE",
}


def create_table(dynamodb):
    print(f"Creating table '{TABLE_NAME}'...")
    try:
        table = dynamodb.create_table(
            TableName=TABLE_NAME,
            # Base table keys
            KeySchema=[
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "PK", "AttributeType": "S"},
                {"AttributeName": "SK", "AttributeType": "S"},
            ],
            # SK-index GSI — used by get_all_active_tenants() in orchestrator.py
            # to query all items where SK = 'METADATA' in O(tenants) cost.
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "SK-index",
                    "KeySchema": [
                        {"AttributeName": "SK", "KeyType": "HASH"},
                        {"AttributeName": "PK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 5,
                        "WriteCapacityUnits": 5,
                    },
                }
            ],
            BillingMode="PROVISIONED",
            ProvisionedThroughput={
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 5,
            },
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"]["Message"]
        if code == "ResourceInUseException":
            print(f"Table '{TABLE_NAME}' already exists (ResourceInUseException). Skipping creation.")
            return dynamodb.Table(TABLE_NAME)
        elif code == "AccessDeniedException":
            print(f"Permission denied creating table '{TABLE_NAME}': {message}")
            raise
        else:
            print(f"Unexpected error creating table (code={code}): {message}")
            raise

    print("Waiting for table to become ACTIVE...")
    table.meta.client.get_waiter("table_exists").wait(TableName=TABLE_NAME)
    print(f"Table '{TABLE_NAME}' is now ACTIVE.")
    return table


def get_or_create_table(dynamodb):
    try:
        table = dynamodb.Table(TABLE_NAME)
        table.load()  # raises ResourceNotFoundException if absent
        print(f"Table '{TABLE_NAME}' already exists — skipping creation.")
        return table
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return create_table(dynamodb)
        code = e.response["Error"]["Code"]
        message = e.response["Error"]["Message"]
        print(f"Error checking for table (code={code}): {message}")
        raise


def seed_tenant(table):
    print(f"Upserting dummy tenant (AccountId={DUMMY_TENANT['AccountId']})...")
    table.put_item(Item=DUMMY_TENANT)
    print("Done. Dummy tenant written:")
    for k, v in DUMMY_TENANT.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    try:
        # --- Credential debug block ---
        session = boto3.Session(region_name=REGION)

        print(f"AWS Profile : {session.profile_name or '(default)'}")
        print(f"AWS Region  : {session.region_name}")

        creds = session.get_credentials()
        if creds is None:
            print("AWS Credentials: NONE FOUND — no credentials could be resolved.")
        else:
            resolved = creds.get_frozen_credentials()
            key = resolved.access_key or ""
            masked = f"{key[:4]}...{key[-4:]}" if len(key) >= 8 else "(too short to mask)"
            print(f"AWS Access Key: {masked}")
        print()
        # --- End debug block ---

        try:
            dynamodb = session.resource("dynamodb")
            table = get_or_create_table(dynamodb)
        except NoCredentialsError:
            print(
                "ERROR: No AWS credentials found.\n"
                "\n"
                "To fix this, do one of the following:\n"
                "  1. Run 'aws configure' to set up a credentials profile.\n"
                "  2. Set environment variables:\n"
                "       set AWS_ACCESS_KEY_ID=your-key\n"
                "       set AWS_SECRET_ACCESS_KEY=your-secret\n"
                "       set AWS_SESSION_TOKEN=your-token  (if using temporary creds)\n"
                "  3. If using a named profile, run:\n"
                "       set AWS_PROFILE=your-profile-name\n"
            )
            raise

        seed_tenant(table)
        print(
            "\nVerification: run the orchestrator now and you should see:\n"
            "  Found 1 active tenant(s).\n"
            f"  [{DUMMY_TENANT['AccountId']}] Assuming role {DUMMY_TENANT['RoleArn']}...\n"
            "\nNote: the assume-role call will fail unless the dummy ARN is replaced\n"
            "with a real role that trusts your provider account.\n"
        )
    except Exception as e:
        import traceback
        print("\n--- ERROR ---")
        traceback.print_exc()
        print("-------------")
    finally:
        input("\nPress Enter to exit...")
