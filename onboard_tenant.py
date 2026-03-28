"""
onboard_tenant.py  —  Phase 2 Handshake, Step 2

Finalises the tenant registration by writing their METADATA item to the
S3Sentry DynamoDB table. This is what makes the tenant visible to the
orchestrator on the next scan cycle.

Usage:
    python onboard_tenant.py

Prerequisites:
    - .pending_tenant file must exist (created by generate_launch_url.py)
    - Customer must have deployed client_onboarding.yaml and shared the Outputs
    - AWS credentials configured (run 'aws configure' or set env vars)
"""

import json
import boto3
from pathlib import Path
from botocore.exceptions import ClientError, NoCredentialsError

PENDING_FILE   = ".pending_tenant"
DYNAMODB_TABLE = "S3Sentry"
REGION         = "us-east-1"


def load_pending_tenant():
    """Read the ExternalId saved by generate_launch_url.py."""
    p = Path(PENDING_FILE)
    if not p.exists():
        raise FileNotFoundError(
            f"'{PENDING_FILE}' not found.\n"
            "Run generate_launch_url.py first to generate an ExternalId."
        )
    data = json.loads(p.read_text())
    external_id = data.get("ExternalId")
    if not external_id:
        raise ValueError(f"'ExternalId' key missing from {PENDING_FILE}.")
    return external_id


def extract_account_id(role_arn):
    """
    Parse AccountId out of the role ARN.
    Example: arn:aws:iam::123456789012:role/S3SentryCrossAccountRole
                                ^^^^^^^^^^^^
    """
    parts = role_arn.strip().split(":")
    if len(parts) < 5 or not parts[4].isdigit():
        raise ValueError(
            f"Could not parse AccountId from RoleArn: '{role_arn}'\n"
            "Expected format: arn:aws:iam::<AccountId>:role/<RoleName>"
        )
    return parts[4]


def write_metadata_to_dynamodb(account_id, role_arn, external_id, email, session):
    """Write the tenant METADATA item to the S3Sentry single table."""
    table = session.resource("dynamodb", region_name=REGION).Table(DYNAMODB_TABLE)
    item = {
        "PK":         f"ACC#{account_id}",
        "SK":         "METADATA",
        "AccountId":  account_id,
        "RoleArn":    role_arn,
        "ExternalId": external_id,
        "Email":      email,
        "Status":     "ACTIVE",
    }
    table.put_item(Item=item)
    return item


def prompt(label, example=None):
    """Prompt the user for input with an optional example hint."""
    hint = f"  (e.g. {example})" if example else ""
    value = input(f"\n  {label}{hint}\n  > ").strip()
    if not value:
        raise ValueError(f"{label} cannot be empty.")
    return value


if __name__ == "__main__":
    try:
        print("=" * 70)
        print("S3 Sentry — New Tenant Onboarding: Step 2 of 2")
        print("=" * 70)

        # Step 1 — load ExternalId from local file.
        print(f"\nReading ExternalId from '{PENDING_FILE}'...")
        external_id = load_pending_tenant()
        print(f"  ExternalId: {external_id}")

        # Step 2 — collect CloudFormation Outputs from the customer.
        print("\nPaste the values from the customer's CloudFormation Outputs tab:")
        role_arn = prompt(
            "RoleArn",
            "arn:aws:iam::123456789012:role/S3SentryCrossAccountRole"
        )
        email = prompt(
            "Customer Email",
            "owner@example.com"
        )

        # Step 3 — derive AccountId from the RoleArn.
        account_id = extract_account_id(role_arn)
        print(f"\n  Parsed AccountId: {account_id}")

        # Step 4 — write to DynamoDB using local credentials.
        print(f"\nWriting METADATA item to DynamoDB table '{DYNAMODB_TABLE}'...")
        session = boto3.Session()
        try:
            item = write_metadata_to_dynamodb(
                account_id, role_arn, external_id, email, session
            )
        except NoCredentialsError:
            print(
                "\nERROR: No AWS credentials found.\n"
                "  Run 'aws configure' or set:\n"
                "    AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN"
            )
            raise
        except ClientError as e:
            print(
                f"\nAWS Error: {e.response['Error']['Code']}: "
                f"{e.response['Error']['Message']}"
            )
            raise

        # Step 5 — confirm.
        print("\n  Item written successfully:")
        for k, v in item.items():
            print(f"    {k}: {v}")

        print()
        print("=" * 70)
        print("Tenant onboarding complete.")
        print()
        print("  This account will be included in the next orchestrator scan cycle.")
        print("  To trigger a scan now, run:")
        print("    python run_orchestrator.bat")
        print()
        print(f"  Cleaning up '{PENDING_FILE}'...")
        Path(PENDING_FILE).unlink(missing_ok=True)
        print("  Done.")
        print("=" * 70)

    except (FileNotFoundError, ValueError) as e:
        print(f"\nERROR: {e}")
    except Exception:
        import traceback
        print("\n--- UNEXPECTED ERROR ---")
        traceback.print_exc()
        print("------------------------")
    finally:
        input("\nPress Enter to close...")
