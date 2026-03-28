import atexit
atexit.register(lambda: input("\nScan cycle finished. Press Enter to close..."))

# ---------------------------------------------------------------------------
# Python version guard — Prowler 3.x requires Python 3.9–3.11.
# ---------------------------------------------------------------------------
import sys
if sys.version_info >= (3, 12):
    print(
        f"ERROR: This script requires Python 3.9–3.11.\n"
        f"       Currently running: Python {sys.version}\n"
        f"       Interpreter:       {sys.executable}\n\n"
        f"  Fix: run via run_orchestrator.bat, which activates the .venv\n"
        f"       created with 'py -3.11 -m venv .venv'."
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Pydantic v1 compatibility shim — must run before any Prowler import.
# Prowler 3.x uses Pydantic v1 APIs (class Config, validators, etc.) which
# are broken under Pydantic v2. If v2 is installed, redirect sys.modules so
# every subsequent `import pydantic` (including inside Prowler) resolves to
# the bundled v1 compatibility layer instead of the v2 API.
# ---------------------------------------------------------------------------
import sys
import pydantic
print(f"DEBUG: Using Pydantic version {pydantic.VERSION}")
if pydantic.VERSION.startswith("2"):
    from pydantic import v1 as pydantic_v1
    sys.modules["pydantic"] = pydantic_v1

import os
from datetime import datetime, timezone

import boto3
import botocore.exceptions
from boto3.dynamodb.conditions import Key
from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.lib.check.check import execute as prowler_execute
from prowler.lib.check.check import import_check

# ---------------------------------------------------------------------------
# S3 checks to run and their NIST CSF v1.1 control mappings
# ---------------------------------------------------------------------------

S3_CHECKS = [
    "s3_bucket_public_access",
    "s3_bucket_acl_prohibited",
    "s3_bucket_policy_no_allow_mixed_and_public_access",
    "s3_bucket_default_encryption",
    "s3_bucket_versioning_enabled",
    "s3_bucket_server_access_logging_enabled",
    "s3_bucket_no_public_access",
    "s3_bucket_secure_transport_policy",
    "s3_bucket_object_lock",
]

NIST_CSF_MAPPING = {
    "s3_bucket_public_access":                           ["PR.AC-3", "PR.DS-3", "DE.CM-7"],
    "s3_bucket_acl_prohibited":                          ["PR.AC-3", "PR.DS-1"],
    "s3_bucket_policy_no_allow_mixed_and_public_access": ["PR.AC-3", "PR.DS-5"],
    "s3_bucket_default_encryption":                      ["PR.DS-1", "PR.DS-2"],
    "s3_bucket_versioning_enabled":                      ["PR.IP-4", "RC.RP-1"],
    "s3_bucket_server_access_logging_enabled":           ["DE.CM-7", "DE.AE-3", "RS.AN-1"],
    "s3_bucket_no_public_access":                        ["PR.AC-3", "PR.DS-5"],
    "s3_bucket_secure_transport_policy":                 ["PR.DS-2", "PR.PT-4"],
    "s3_bucket_object_lock":                             ["PR.IP-4", "PR.DS-1"],
}

# Single-table name for both tenant metadata and scan findings.
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "S3Sentry")


def get_all_active_tenants():
    """
    Query the SK-index GSI for all items where SK = 'METADATA'.
    This returns only tenant metadata rows — O(number of tenants) cost —
    regardless of how many findings exist in the table.

    AccountId is read from the explicit 'AccountId' attribute first.
    If absent, it falls back to parsing 'ACC#<id>' from the PK.
    Items missing RoleArn, ExternalId, or a resolvable AccountId are
    logged and skipped.
    """
    session = boto3.Session()
    table = session.resource("dynamodb").Table(DYNAMODB_TABLE)
    tenants = []
    kwargs = {
        "IndexName": "SK-index",
        "KeyConditionExpression": Key("SK").eq("METADATA"),
    }

    while True:
        response = table.query(**kwargs)
        for item in response.get("Items", []):
            pk         = item.get("PK", "")
            role_arn   = item.get("RoleArn")
            ext_id     = item.get("ExternalId")

            # Prefer the explicit AccountId attribute; fall back to PK parsing.
            account_id = item.get("AccountId")
            if not account_id:
                account_id = pk.replace("ACC#", "") if pk.startswith("ACC#") else None

            if not role_arn or not ext_id or not account_id:
                print(f"[WARN] Malformed tenant metadata (PK={pk!r}) — "
                      f"missing RoleArn={role_arn!r}, ExternalId={ext_id!r}, "
                      f"AccountId={account_id!r}. Skipping.")
                continue

            tenants.append({
                "AccountId":  account_id,
                "RoleArn":    role_arn,
                "ExternalId": ext_id,
                "Email":      item.get("Email"),   # carried forward for Phase 3 SES
            })

        last = response.get("LastEvaluatedKey")
        if not last:
            break
        kwargs["ExclusiveStartKey"] = last

    print(f"Found {len(tenants)} active tenant(s).")
    return tenants


def assume_client_role(role_arn, external_id):
    """
    Assume a cross-account role using the RoleArn stored in the tenant's
    metadata item. The account_id is extracted from the ARN itself so
    this function has no dependency on the caller's data model.
    Returns a boto3.Session with the temporary credentials.
    """
    account_id = role_arn.split(":")[4]
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


def _enrich_finding(finding, account_id):
    """
    Convert a Prowler Check_Report_AWS to a plain dict aligned with the
    blueprint's single-table key schema:
      PK = ACC#<AccountID>
      SK = SCAN#<CheckID>#<ResourceID>

    Tags every finding with AccountID for multi-tenant isolation.
    Adds ComplianceMapping (NIST CSF v1.1) on FAIL findings only.
    """
    check_id = finding.check_metadata.checkID
    item = {
        "PK":             f"ACC#{account_id}",
        "SK":             f"SCAN#{check_id}#{finding.resource_id}",
        "AccountID":      account_id,
        "CheckID":        check_id,
        "CheckTitle":     finding.check_metadata.checkTitle,
        "Status":         finding.status,
        "StatusExtended": finding.status_extended,
        "ResourceID":     finding.resource_id,
        "ResourceARN":    getattr(finding, "resource_arn", None),
        "Region":         getattr(finding, "region", None),
        "Severity":       finding.check_metadata.severity,
        "ScannedAt":      datetime.now(timezone.utc).isoformat(),
    }
    if finding.status == "FAIL":
        item["ComplianceMapping"] = {
            "NIST-CSF-1.1": NIST_CSF_MAPPING.get(check_id, [])
        }
    return item


def save_to_dynamodb(findings):
    """
    Persist enriched Prowler findings to the single DynamoDB table.
    Uses batch_writer for efficiency. No-ops if there are no findings.
    """
    if not findings:
        return
    table = boto3.resource("dynamodb").Table(DYNAMODB_TABLE)
    with table.batch_writer() as batch:
        for item in findings:
            batch.put_item(Item=item)
    print(f"Saved {len(findings)} finding(s) to '{DYNAMODB_TABLE}'.")


def run_s3_scan(assumed_session):
    """
    Run Prowler S3 checks using the cross-account session.
    Prowler is initialised with the assumed session so no additional
    role assumption occurs. Each check runs independently; an Access
    Denied or other error on a single check is logged and skipped so
    the rest of the account scan continues.

    Note: current_audit_info is a contextvars.ContextVar — safe for
    sequential multi-account loops. Use copy_context() if parallelising.
    """
    sts = assumed_session.client("sts")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    partition = identity["Arn"].split(":")[1]

    audit_info = AWS_Audit_Info(
        session_config=None,
        original_session=assumed_session,
        audit_session=assumed_session,
        audited_account=account_id,
        audited_account_arn=f"arn:{partition}:iam::{account_id}:root",
        audited_partition=partition,
        audited_identity_arn=identity["Arn"],
        audited_user_id=identity["UserId"],
        audited_regions=None,
        organizations_metadata=None,
        audit_resources=[],
    )
    current_audit_info.set(audit_info)

    enriched = []
    for check_name in S3_CHECKS:
        module_path = (
            f"prowler.providers.aws.services.s3.{check_name}.{check_name}"
        )
        try:
            check_module = import_check(module_path)
        except Exception as e:
            print(f"[{account_id}] Could not import check '{check_name}': {e}")
            continue

        try:
            check_instance = check_module()
            raw_findings = prowler_execute(check_instance, audit_info)
        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            print(
                f"[{account_id}] Check '{check_name}' skipped — "
                f"AWS error {code}: {e.response['Error']['Message']}"
            )
            continue
        except Exception as e:
            print(f"[{account_id}] Check '{check_name}' failed unexpectedly: {e}")
            continue

        for finding in raw_findings:
            enriched.append(_enrich_finding(finding, account_id))

    save_to_dynamodb(enriched)


if __name__ == "__main__":
    try:
        tenants = get_all_active_tenants()
        if not tenants:
            print("No active tenants found. Exiting.")
            raise SystemExit(0)

        for tenant in tenants:
            account_id = tenant["AccountId"]
            role_arn   = tenant["RoleArn"]

            # Skip placeholder tenants inserted by seed_test_data.py.
            if "123456789012" in role_arn:
                print(f"[INFO] Skipping dummy tenant scan as this is a placeholder.")
                continue

            try:
                print(f"[{account_id}] Assuming role {role_arn}...")
                assumed_session = assume_client_role(role_arn, tenant["ExternalId"])
            except botocore.exceptions.NoCredentialsError:
                print(
                    f"[{account_id}] Role assumption failed — NoCredentialsError: "
                    f"No AWS credentials found in the environment. "
                    f"Run 'aws configure' or set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY. "
                    f"Skipping tenant."
                )
                continue
            except botocore.exceptions.ClientError as e:
                print(
                    f"[{account_id}] Role assumption failed — "
                    f"{e.response['Error']['Code']}: {e.response['Error']['Message']}. "
                    f"Skipping tenant."
                )
                continue
            except Exception as e:
                print(f"[{account_id}] Unexpected error during role assumption: {e}. Skipping tenant.")
                continue

            try:
                print(f"[{account_id}] Starting scan...")
                run_s3_scan(assumed_session)
                print(f"[{account_id}] Scan complete.")
            except Exception as e:
                print(f"[{account_id}] Scan failed unexpectedly: {e}. Continuing to next tenant.")
                continue

    except SystemExit:
        raise
    except Exception:
        import traceback
        print("\n--- UNHANDLED ERROR ---")
        traceback.print_exc()
        print("-----------------------")
