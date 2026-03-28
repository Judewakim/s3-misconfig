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
# Prowler version (informational only — no Python API import needed).
# ---------------------------------------------------------------------------
try:
    from importlib.metadata import version as _pkg_version
    print(f"Prowler Version: {_pkg_version('prowler')}")
except Exception:
    print("Prowler Version: unknown")

import glob
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

import boto3
import botocore.exceptions
from boto3.dynamodb.conditions import Key

# Prowler executable lives in the same Scripts/ directory as this Python interpreter.
_PROWLER_EXE = pathlib.Path(sys.executable).parent / (
    "prowler.exe" if sys.platform == "win32" else "prowler"
)
if not _PROWLER_EXE.exists():
    # Some installs create a plain 'prowler' script even on Windows
    _PROWLER_EXE = pathlib.Path(sys.executable).parent / "prowler"
print(f"Prowler executable : {_PROWLER_EXE}")

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
    Convert a Prowler CLI JSON finding (dict) to the blueprint's
    single-table key schema:
      PK = ACC#<AccountID>
      SK = SCAN#<CheckID>#<ResourceID>

    Tags every finding with AccountID for multi-tenant isolation.
    Adds ComplianceMapping (NIST CSF v1.1) on FAIL findings only.
    """
    check_id    = finding.get("CheckID", "")
    resource_id = finding.get("ResourceId", "")
    status      = finding.get("Status", "")
    item = {
        "PK":             f"ACC#{account_id}",
        "SK":             f"SCAN#{check_id}#{resource_id}",
        "AccountID":      account_id,
        "CheckID":        check_id,
        "CheckTitle":     finding.get("CheckTitle", ""),
        "Status":         status,
        "StatusExtended": finding.get("StatusExtended", ""),
        "ResourceID":     resource_id,
        "ResourceARN":    finding.get("ResourceArn"),
        "Region":         finding.get("Region"),
        "Severity":       finding.get("Severity", ""),
        "ScannedAt":      datetime.now(timezone.utc).isoformat(),
    }
    if status == "FAIL":
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
    Run Prowler S3 checks via the CLI subprocess using the temporary credentials
    from the cross-account AssumeRole call.

    Strategy:
    - Inject assumed-role credentials as env vars so Prowler authenticates as
      the tenant's cross-account role — no AWS_Audit_Info constructor needed.
    - Write JSON output to a temp directory, parse it, enrich, and store to DynamoDB.
    - Temp directory is always cleaned up, even on error.

    Prowler exit codes:
      0 = all checks passed
      3 = one or more FAIL findings (normal operation — not an error)
      other = unexpected failure
    """
    sts = assumed_session.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    frozen = assumed_session.get_credentials().get_frozen_credentials()

    # Pass assumed-role credentials to Prowler via environment variables.
    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"]     = frozen.access_key
    env["AWS_SECRET_ACCESS_KEY"] = frozen.secret_key
    env["AWS_SESSION_TOKEN"]     = frozen.token
    # Remove any profile that might override the explicit credentials.
    env.pop("AWS_PROFILE", None)
    env.pop("AWS_DEFAULT_PROFILE", None)

    output_dir = tempfile.mkdtemp(prefix="s3sentry-")
    try:
        cmd = [
            str(_PROWLER_EXE),
            "aws",
            "--checks", *S3_CHECKS,
            "--no-banner",
            "--quiet",
            "--output-modes", "json",
            "--output-directory", output_dir,
        ]
        env["PYTHONUNBUFFERED"]  = "1"
        env["PYTHONIOENCODING"] = "utf-8"

        print(f"[{account_id}] Running Prowler CLI for {len(S3_CHECKS)} checks...")
        result = subprocess.run(cmd, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")

        json_files = glob.glob(os.path.join(output_dir, "*.json"))

        # Exit codes: 0 = all pass, 3 = FAIL findings present, 1 = Prowler internal
        # warning (e.g. progress bar encoding issue on Windows). Treat any of these
        # as recoverable as long as Prowler produced a JSON output file.
        fatal = result.returncode not in (0, 1, 3) or not json_files
        if result.returncode not in (0, 3):
            print(f"[{account_id}] Prowler exited with code {result.returncode} — checking for output...")
        if fatal:
            print(f"[{account_id}] Prowler failed fatally (code {result.returncode}, no JSON output).")
            if result.stdout.strip():
                print(f"[{account_id}] STDOUT:\n{result.stdout[-2000:]}")
            if result.stderr.strip():
                print(f"[{account_id}] STDERR:\n{result.stderr[-2000:]}")
            return
        if not json_files:
            print(f"[{account_id}] No JSON output file produced.")
            if result.stderr.strip():
                print(f"[{account_id}] STDERR:\n{result.stderr[-2000:]}")
            return

        json_path = json_files[0]
        if os.path.getsize(json_path) == 0:
            print(f"[{account_id}] JSON output file is empty — no findings to store.")
            return

        with open(json_path, encoding="utf-8") as fh:
            raw_findings = json.load(fh)

        print(f"[{account_id}] Prowler returned {len(raw_findings)} finding(s).")
        if not raw_findings:
            print(f"[{account_id}] No findings (account may have no S3 buckets). Nothing to store.")
            return
        enriched = [_enrich_finding(f, account_id) for f in raw_findings]
        save_to_dynamodb(enriched)

    finally:
        shutil.rmtree(output_dir, ignore_errors=True)


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
