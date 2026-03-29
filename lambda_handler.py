"""
lambda_handler.py — S3 Sentry Orchestrator (Lambda entry point)

Derived from orchestrator.py with all Windows/local-dev code removed:
  - No atexit / input() blocking calls
  - No Python version guard (Lambda base image is 3.11)
  - No sys.platform check (_PROWLER_EXE is always the Linux path)
  - No run_orchestrator.bat references

New additions:
  - handler(event, context)   — Lambda entry point
  - _publish_summary(results) — SNS scan-complete notification
  - Timeout guard using context.get_remaining_time_in_millis()
"""

import glob
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

import boto3
import botocore.exceptions
from boto3.dynamodb.conditions import Key

# ---------------------------------------------------------------------------
# Prowler executable — in the Lambda container, pip installs scripts to the
# same directory as the Python interpreter (/var/lang/bin/).
# ---------------------------------------------------------------------------
_PROWLER_EXE = pathlib.Path(sys.executable).parent / "prowler"

# ---------------------------------------------------------------------------
# Runtime configuration — all values injected via Lambda environment variables.
# ---------------------------------------------------------------------------
DYNAMODB_TABLE   = os.environ.get("DYNAMODB_TABLE", "S3Sentry")
SNS_TOPIC_ARN    = os.environ.get("SNS_TOPIC_ARN")          # optional
TIMEOUT_BUFFER_MS = 180_000  # stop tenant loop if < 3 minutes remain

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


# ---------------------------------------------------------------------------
# Tenant discovery
# ---------------------------------------------------------------------------

def get_all_active_tenants():
    """
    Query the SK-index GSI for all items where SK = 'METADATA'.
    Returns only tenant metadata rows — O(number of tenants) DynamoDB cost
    regardless of how many findings exist in the table.
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
                "Email":      item.get("Email"),
            })

        last = response.get("LastEvaluatedKey")
        if not last:
            break
        kwargs["ExclusiveStartKey"] = last

    print(f"Found {len(tenants)} active tenant(s).")
    return tenants


# ---------------------------------------------------------------------------
# Cross-account role assumption
# ---------------------------------------------------------------------------

def assume_client_role(role_arn, external_id):
    """
    Assume the tenant's cross-account role using sts:AssumeRole with ExternalId.
    Returns a boto3.Session authenticated as the tenant's role.
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


# ---------------------------------------------------------------------------
# Finding enrichment and persistence
# ---------------------------------------------------------------------------

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
    Persist enriched findings to the single DynamoDB table via batch_writer.
    No-ops on an empty list.
    """
    if not findings:
        return
    table = boto3.resource("dynamodb").Table(DYNAMODB_TABLE)
    with table.batch_writer() as batch:
        for item in findings:
            batch.put_item(Item=item)
    print(f"Saved {len(findings)} finding(s) to '{DYNAMODB_TABLE}'.")


# ---------------------------------------------------------------------------
# Prowler CLI scan
# ---------------------------------------------------------------------------

def run_s3_scan(assumed_session):
    """
    Run Prowler S3 checks via CLI subprocess using the temporary credentials
    from the cross-account AssumeRole call.

    Credentials are injected as AWS_* environment variables — no Prowler
    Python API initialization needed.

    Prowler exit codes:
      0 = all checks passed
      3 = FAIL findings present (normal — not an error)
      1 = internal warning (e.g. progress bar encoding) — recoverable if JSON exists
    """
    sts = assumed_session.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    frozen = assumed_session.get_credentials().get_frozen_credentials()

    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"]     = frozen.access_key
    env["AWS_SECRET_ACCESS_KEY"] = frozen.secret_key
    env["AWS_SESSION_TOKEN"]     = frozen.token
    env["PYTHONUNBUFFERED"]      = "1"
    env["PYTHONIOENCODING"]      = "utf-8"
    # Prevent any ambient profile from overriding the explicit credentials.
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
        print(f"[{account_id}] Running Prowler CLI for {len(S3_CHECKS)} checks...")
        result = subprocess.run(
            cmd, env=env, capture_output=True,
            text=True, encoding="utf-8", errors="replace",
        )

        json_files = glob.glob(os.path.join(output_dir, "*.json"))

        # Exit codes 0, 1, 3 are all recoverable as long as a JSON file was produced.
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

        json_path = json_files[0]
        if os.path.getsize(json_path) == 0:
            print(f"[{account_id}] JSON output file is empty — no findings to store.")
            return

        with open(json_path, encoding="utf-8") as fh:
            raw_findings = json.load(fh)

        print(f"[{account_id}] Prowler returned {len(raw_findings)} finding(s).")

        fail_findings = [f for f in raw_findings if f.get("Status") == "FAIL"]

        if raw_findings:
            enriched = [_enrich_finding(f, account_id) for f in raw_findings]
            save_to_dynamodb(enriched)
        else:
            print(f"[{account_id}] No findings (account may have no S3 buckets). Nothing to store.")

        # Build the summary dict that the handler will pass to _publish_summary.
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in fail_findings:
            key = f.get("Severity", "").lower()
            if key in sev:
                sev[key] += 1

        return {
            "account_id":        account_id,
            "total_findings":    len(raw_findings),
            "fail_count":        len(fail_findings),
            "buckets_affected":  len({f.get("ResourceId", "") for f in fail_findings}),
            "severity_breakdown": sev,
            "fail_findings":     fail_findings,   # raw dicts — JSON-dumped in SNS body
        }

    finally:
        shutil.rmtree(output_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# SNS summary notification
# ---------------------------------------------------------------------------

def _publish_summary(account_id, scan_summary):
    """
    Publish a per-tenant scan summary to SNS if SNS_TOPIC_ARN is configured.
    No-ops silently when the env var is absent (scan-only mode).

    Subject format : ⚠️ S3Sentry Alert: {fail_count} Findings for acc#{account_id}
    Body           : human-readable severity breakdown + JSON finding details
    """
    if not SNS_TOPIC_ARN:
        return

    fail_count       = scan_summary["fail_count"]
    buckets_affected = scan_summary["buckets_affected"]
    sev              = scan_summary["severity_breakdown"]
    fail_findings    = scan_summary["fail_findings"]

    subject = f"\u26a0\ufe0f S3Sentry Alert: {fail_count} Findings for acc#{account_id}"

    body = (
        f"The daily scan is complete. "
        f"We found {fail_count} FAIL findings across {buckets_affected} bucket(s).\n"
        f"\n"
        f"Severity Breakdown:\n"
        f"  Critical : {sev['critical']}\n"
        f"  High     : {sev['high']}\n"
        f"  Medium   : {sev['medium']}\n"
        f"  Low      : {sev['low']}\n"
        f"\n"
        f"--- Finding Details (JSON) ---\n"
        f"{json.dumps(fail_findings, indent=2, default=str)}\n"
    )

    boto3.client("sns").publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=body,
    )
    print(f"[{account_id}] SNS alert published: {fail_count} FAIL finding(s).")


# ---------------------------------------------------------------------------
# Lambda entry point
# ---------------------------------------------------------------------------

def handler(event, context):
    """
    Lambda entry point — triggered by EventBridge on a schedule (or manually).

    Reads all active tenants from DynamoDB, runs a Prowler scan for each,
    and publishes a summary to SNS when complete.

    Timeout guard: stops the tenant loop if fewer than 3 minutes remain in
    the Lambda execution window, preventing a hard kill mid-scan.
    """
    print(f"S3 Sentry scan cycle starting. Prowler executable: {_PROWLER_EXE}")

    tenants = get_all_active_tenants()
    if not tenants:
        print("No active tenants found. Exiting.")
        return {"statusCode": 200, "tenantsScanned": 0}

    results = []
    for tenant in tenants:
        # Timeout guard — bail out gracefully before Lambda hard-terminates.
        if context.get_remaining_time_in_millis() < TIMEOUT_BUFFER_MS:
            remaining = len(tenants) - len(results)
            print(
                f"[TIMEOUT WARNING] < 3 minutes remaining in Lambda window. "
                f"Stopping tenant loop. Scanned: {len(results)}, Skipped: {remaining}."
            )
            break

        account_id = tenant["AccountId"]
        role_arn   = tenant["RoleArn"]

        if "123456789012" in role_arn:
            print(f"[INFO] Skipping dummy tenant (placeholder account).")
            continue

        try:
            print(f"[{account_id}] Assuming role {role_arn}...")
            assumed_session = assume_client_role(role_arn, tenant["ExternalId"])
        except botocore.exceptions.ClientError as e:
            msg = f"{e.response['Error']['Code']}: {e.response['Error']['Message']}"
            print(f"[{account_id}] Role assumption failed — {msg}. Skipping.")
            results.append({"accountId": account_id, "status": "ERROR", "error": msg})
            continue
        except Exception as e:
            print(f"[{account_id}] Unexpected error during role assumption: {e}. Skipping.")
            results.append({"accountId": account_id, "status": "ERROR", "error": str(e)})
            continue

        try:
            print(f"[{account_id}] Starting scan...")
            scan_summary = run_s3_scan(assumed_session)
            print(f"[{account_id}] Scan complete.")

            if scan_summary:
                _publish_summary(account_id, scan_summary)
                results.append({
                    "accountId":      account_id,
                    "status":         "SUCCESS",
                    "totalFindings":  scan_summary["total_findings"],
                    "failCount":      scan_summary["fail_count"],
                    "bucketsAffected": scan_summary["buckets_affected"],
                    "severityBreakdown": scan_summary["severity_breakdown"],
                })
            else:
                # run_s3_scan returned None — Prowler failed fatally (logged inside)
                results.append({"accountId": account_id, "status": "ERROR",
                                 "error": "Prowler produced no output. See CloudWatch logs."})

        except Exception as e:
            print(f"[{account_id}] Scan failed unexpectedly: {e}.")
            results.append({"accountId": account_id, "status": "ERROR", "error": str(e)})

    return {
        "statusCode":    200,
        "tenantsScanned": len(results),
        "results":        results,
    }
