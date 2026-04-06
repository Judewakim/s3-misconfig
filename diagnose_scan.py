#!/usr/bin/env python3
"""
diagnose_scan.py -- Prowler S3 diagnostic tool

Runs OUTSIDE the Lambda directly from your local .venv.
Assumes the cross-account role (same way the Orchestrator does) and then:
  1. Lists every S3 check ID available in Prowler v3.16.17
  2. Runs ALL S3 checks (no --checks filter) against the target account
     so you can see exactly what Prowler detects vs. what our S3_CHECKS list requests

Usage (from project root, with .venv active):
  python diagnose_scan.py <client_account_id>

Prerequisites:
  - AWS credentials in environment (or ~/.aws) with access to the provider account
  - .venv active (prowler must be on PATH)
  - The tenant must exist in DynamoDB

Example:
  .venv\\Scripts\\activate
  python diagnose_scan.py 123456789012
"""

import glob
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

import boto3

# ---------------------------------------------------------------------------
REGION     = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
TABLE_NAME = os.environ.get("DYNAMODB_TABLE", "S3Sentry")

# These are the check IDs currently in lambda_handler.py S3_CHECKS.
# The diagnostic will tell us which ones are valid in Prowler v3.16.17.
CURRENT_S3_CHECKS = [
    "s3_bucket_public_access_block",
    "s3_bucket_acl_prohibited",
    "s3_bucket_policy_no_allow_mixed_and_public_access",
    "s3_bucket_default_encryption",
    "s3_bucket_versioning_enabled",
    "s3_bucket_server_access_logging_enabled",
    "s3_bucket_secure_transport_policy",
    "s3_bucket_object_lock",
]
# ---------------------------------------------------------------------------


def _prowler_exe() -> str:
    return str(pathlib.Path(sys.executable).parent / "prowler")


def _assume_role(tenant: dict) -> dict:
    sts   = boto3.client("sts", region_name=REGION)
    resp  = sts.assume_role(
        RoleArn=tenant["RoleArn"],
        RoleSessionName="s3sentry-diagnose",
        ExternalId=tenant["ExternalId"],
        DurationSeconds=900,
    )
    return resp["Credentials"]


def _build_env(creds: dict) -> dict:
    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"]        = creds["AccessKeyId"]
    env["AWS_SECRET_ACCESS_KEY"]    = creds["SecretAccessKey"]
    env["AWS_SESSION_TOKEN"]        = creds["SessionToken"]
    env["PROWLER_OUTPUT_DIRECTORY"] = tempfile.gettempdir()
    # Prevent alive_progress Unicode characters from crashing on Windows cp1252
    env["PYTHONUTF8"]               = "1"
    env["PYTHONIOENCODING"]         = "utf-8"
    env.pop("AWS_PROFILE", None)
    env.pop("AWS_DEFAULT_PROFILE", None)
    return env


def step_list_checks(env: dict) -> list[str]:
    """Return every S3 check ID available in this Prowler installation."""
    print("\n" + "=" * 60)
    print("STEP 1 — Available S3 check IDs in Prowler v3.16.17")
    print("=" * 60)

    result = subprocess.run(
        [_prowler_exe(), "--list-checks", "--service", "s3"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
    )

    # Prowler --list-checks outputs lines like:
    #   [s3_bucket_name] - Description text
    # Extract the check ID from inside the brackets.
    available = []
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("[s3_") and "]" in stripped:
            check_id = stripped[1:stripped.index("]")]
            available.append(check_id)
            print(f"  {check_id}")

    if result.stderr.strip():
        print(f"\nSTDERR from --list-checks:\n{result.stderr[:1000]}")

    if not available:
        print("  (no s3_ checks found — stdout below)")
        print(result.stdout[:2000])

    # Cross-reference against our current list
    print(f"\n--- Cross-reference with current S3_CHECKS ---")
    for check in CURRENT_S3_CHECKS:
        status = "OK " if check in available else "MISSING from Prowler"
        print(f"  [{status:25}]  {check}")

    return available


def step_run_all_checks(account_id: str, env: dict) -> None:
    """Run every S3 check (no --checks filter) and print a full findings report."""
    print("\n" + "=" * 60)
    print("STEP 2 — Full S3 scan (ALL checks, no filter)")
    print(f"         Account: {account_id}")
    print("         This takes ~60-90 seconds...")
    print("=" * 60)

    output_dir = tempfile.mkdtemp(prefix="s3sentry-diag-")
    try:
        result = subprocess.run(
            [
                _prowler_exe(), "aws",
                "--service", "s3",
                "--no-banner",
                "--quiet",
                "--output-modes", "json",
                "--output-directory", output_dir,
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
        )

        print(f"\nProwler exit code: {result.returncode}")

        if result.stderr.strip():
            print(f"\n--- Prowler STDERR (check here for unknown-check warnings) ---")
            print(result.stderr[:3000])

        json_files = glob.glob(os.path.join(output_dir, "*.json"))
        if not json_files:
            print("\nERROR: Prowler produced no JSON output.")
            if result.stdout.strip():
                print("STDOUT:", result.stdout[:1000])
            return

        with open(json_files[0], encoding="utf-8") as fh:
            findings = json.load(fh)

        fail_findings = [f for f in findings if f.get("Status") == "FAIL"]
        pass_findings = [f for f in findings if f.get("Status") == "PASS"]

        print(f"\nTotal findings : {len(findings)}")
        print(f"FAIL           : {len(fail_findings)}")
        print(f"PASS           : {len(pass_findings)}")

        print("\n--- FAIL findings ---")
        for f in sorted(fail_findings, key=lambda x: (x.get("CheckID",""), x.get("ResourceId",""))):
            print(
                f"  [{f.get('Severity','?').upper():8}]  "
                f"{f.get('CheckID',''):50}  "
                f"{f.get('ResourceId','')}"
            )

        print("\n--- Check IDs that returned at least one result (PASS or FAIL) ---")
        all_check_ids = sorted(set(f.get("CheckID","") for f in findings))
        for cid in all_check_ids:
            fail_count = sum(1 for f in findings if f.get("CheckID") == cid and f.get("Status") == "FAIL")
            pass_count = sum(1 for f in findings if f.get("CheckID") == cid and f.get("Status") == "PASS")
            print(f"  {cid:50}  FAIL={fail_count}  PASS={pass_count}")

        # Highlight any public-access-related check IDs
        print("\n--- Public access related check IDs ---")
        pub_checks = [cid for cid in all_check_ids if "public" in cid.lower() or "access" in cid.lower()]
        if pub_checks:
            for cid in pub_checks:
                fail_count = sum(1 for f in findings if f.get("CheckID") == cid and f.get("Status") == "FAIL")
                print(f"  {cid:50}  FAIL={fail_count}")
        else:
            print("  (none found — Block Public Access checks may not have run)")

    finally:
        shutil.rmtree(output_dir, ignore_errors=True)


def step_targeted_check(account_id: str, check_id: str, env: dict) -> None:
    """Run a single check and dump the raw JSON — useful for iterating on specific IDs."""
    print("\n" + "=" * 60)
    print(f"STEP 3 — Targeted run: {check_id}")
    print("=" * 60)

    output_dir = tempfile.mkdtemp(prefix="s3sentry-targeted-")
    try:
        result = subprocess.run(
            [
                _prowler_exe(), "aws",
                "--checks", check_id,
                "--no-banner",
                "--quiet",
                "--output-modes", "json",
                "--output-directory", output_dir,
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
        )

        print(f"Exit code: {result.returncode}")
        if result.stderr.strip():
            print(f"STDERR: {result.stderr[:1000]}")

        json_files = glob.glob(os.path.join(output_dir, "*.json"))
        if not json_files:
            print("No JSON output produced.")
            return

        with open(json_files[0], encoding="utf-8") as fh:
            findings = json.load(fh)

        print(f"Findings returned: {len(findings)}")
        for f in findings:
            print(f"  Status={f.get('Status')}  Resource={f.get('ResourceId')}  Msg={f.get('StatusExtended','')[:100]}")

    finally:
        shutil.rmtree(output_dir, ignore_errors=True)


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    account_id = sys.argv[1].strip()

    # Look up tenant
    print(f"Looking up tenant {account_id} in DynamoDB table '{TABLE_NAME}'...")
    table  = boto3.resource("dynamodb", region_name=REGION).Table(TABLE_NAME)
    result = table.get_item(Key={"PK": f"ACC#{account_id}", "SK": "METADATA"})
    tenant = result.get("Item")
    if not tenant:
        print(f"ERROR: Tenant {account_id} not found. Check the account ID and TABLE_NAME.")
        sys.exit(1)
    print(f"  Role : {tenant['RoleArn']}")
    print(f"  Email: {tenant.get('Email', 'n/a')}")

    print(f"Assuming cross-account role...")
    creds = _assume_role(tenant)
    env   = _build_env(creds)
    print(f"  OK.")

    # Step 1: list available check IDs and cross-reference our current list
    available = step_list_checks(env)

    # Step 2: run all S3 checks with no filter
    step_run_all_checks(account_id, env)

    # Step 3: run the specific public access check we care about
    step_targeted_check(account_id, "s3_bucket_public_access_block", env)


if __name__ == "__main__":
    main()
