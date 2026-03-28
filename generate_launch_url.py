"""
generate_launch_url.py  —  Phase 2 Handshake, Step 1

Generates a unique ExternalId for a new tenant and constructs the AWS
CloudFormation Quick-Create console URL to send to the customer.

Usage:
    python generate_launch_url.py

Output:
    - Prints the Quick-Create URL to paste into the browser or send to the customer
    - Saves the ExternalId to .pending_tenant so onboard_tenant.py can read it
"""

import json
import uuid
from urllib.parse import urlencode
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PROVIDER_ACCOUNT_ID = "390488375643"
STACK_NAME          = "S3SentrySetup"
REGION              = "us-east-1"
PENDING_FILE        = ".pending_tenant"

# The template must be uploaded to a public S3 bucket or accessible URL before
# sharing with the customer. Replace this placeholder with the real S3 URL once
# you have uploaded client_onboarding.yaml.
#
# To upload:
#   aws s3 cp client_onboarding.yaml s3://<your-bucket>/s3sentry/client_onboarding.yaml --acl public-read
# Then set TEMPLATE_URL to the public HTTPS URL of that object.
TEMPLATE_URL = "https://s3.amazonaws.com/<your-bucket>/s3sentry/client_onboarding.yaml"


def generate_launch_url():
    # Generate a cryptographically random ExternalId for this tenant.
    external_id = str(uuid.uuid4())

    # Build the CloudFormation Quick-Create URL.
    # param_* keys map to CloudFormation Parameter names in the template.
    params = {
        "templateURL":            TEMPLATE_URL,
        "stackName":              STACK_NAME,
        "param_ProviderAccountId": PROVIDER_ACCOUNT_ID,
        "param_ExternalId":       external_id,
    }
    base_url = f"https://console.aws.amazon.com/cloudformation/home?region={REGION}#/stacks/quickcreate"
    launch_url = f"{base_url}?{urlencode(params)}"

    # Save the ExternalId locally so onboard_tenant.py can complete the handshake.
    pending = {"ExternalId": external_id}
    Path(PENDING_FILE).write_text(json.dumps(pending, indent=2))

    # Print instructions for each step.
    print("=" * 70)
    print("S3 Sentry — New Tenant Onboarding: Step 1 of 2")
    print("=" * 70)
    print()
    print(f"  ExternalId (saved to {PENDING_FILE}):")
    print(f"    {external_id}")
    print()
    print("  BEFORE sharing the URL:")
    print(f"    Upload client_onboarding.yaml to a public S3 bucket and update")
    print(f"    TEMPLATE_URL in this script. Current value:")
    print(f"    {TEMPLATE_URL}")
    print()
    print("  Quick-Create URL — send this to the customer:")
    print()
    print(f"    {launch_url}")
    print()
    print("  The customer will:")
    print("    1. Click the URL (must be logged into their AWS console)")
    print("    2. Review and deploy the S3SentrySetup CloudFormation stack")
    print("    3. Copy the three values from the Outputs tab:")
    print("         - RoleArn")
    print("         - ExternalId  (confirm it matches above)")
    print("         - AWSAccountId")
    print()
    print("  Once the customer shares those values, run:")
    print("    python onboard_tenant.py")
    print()
    print("=" * 70)

    return external_id, launch_url


if __name__ == "__main__":
    try:
        generate_launch_url()
    except Exception:
        import traceback
        print("\n--- ERROR ---")
        traceback.print_exc()
        print("-------------")
    finally:
        input("\nPress Enter to close...")
