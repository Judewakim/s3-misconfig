"""
lambda_handler.py — S3 Sentry Orchestrator (Lambda entry point)

Derived from orchestrator.py with all Windows/local-dev code removed.

Phase 3 additions:
  - handler(event, context)       — Lambda entry point
  - _publish_summary()            — SNS fallback notification
  - Timeout guard

Phase 4 Sprint 1 additions:
  - increment_scan_sequence()     — atomic DynamoDB counter per tenant
  - _build_action_url()           — HMAC-signed action button URL
  - _send_dashboard_email()       — SES HTML dashboard email (replaces SNS)
"""

import glob
import html
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

import token_utils

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
DYNAMODB_TABLE    = os.environ.get("DYNAMODB_TABLE", "S3Sentry")
SNS_TOPIC_ARN     = os.environ.get("SNS_TOPIC_ARN")           # optional fallback
SES_FROM_ADDRESS  = os.environ.get("SES_FROM_ADDRESS", "")
HMAC_KEY_PATH     = os.environ.get("HMAC_KEY_PATH", "/s3sentry/hmac_signing_key")
RESPONDER_URL     = os.environ.get("RESPONDER_URL", "").rstrip("/")
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
# Scan sequence — Phase 4 freshness tracking
# ---------------------------------------------------------------------------

def increment_scan_sequence(account_id):
    """
    Atomically increment the ScanSequence counter on the tenant METADATA item.

    Uses DynamoDB ADD, which initialises the attribute to 0 if absent, then
    increments — so the very first call returns 1.

    All HMAC tokens generated in a scan cycle embed this sequence number.
    The Responder validates that the token sequence matches the tenant's
    current sequence, preventing action on findings from a superseded scan.

    Returns the new (post-increment) sequence as an int.
    """
    table = boto3.resource("dynamodb").Table(DYNAMODB_TABLE)
    resp = table.update_item(
        Key={"PK": f"ACC#{account_id}", "SK": "METADATA"},
        UpdateExpression="ADD ScanSequence :one",
        ExpressionAttributeValues={":one": 1},
        ReturnValues="UPDATED_NEW",
    )
    return int(resp["Attributes"]["ScanSequence"])


# ---------------------------------------------------------------------------
# Action URL builder — Phase 4 HMAC tokens
# ---------------------------------------------------------------------------

def _build_action_url(check_id, resource_id, action, account_id,
                      recipient_email, scan_sequence, signing_key,
                      duration_hours=24):
    """
    Generate a signed HMAC token for one finding action and return the full
    Responder URL with the token as a query parameter.

    recipient_email is embedded in the token payload so Sprint 2's Responder
    can pass it as SourceIdentity when assuming the cross-account role, making
    the specific email address visible in the client's CloudTrail logs.
    """
    payload = {
        "account_id":      account_id,
        "check_id":        check_id,
        "resource_id":     resource_id,
        "action":          action,
        "recipient_email": recipient_email,
        "scan_sequence":   scan_sequence,
    }
    token = token_utils.generate_action_token(payload, signing_key, duration_hours)
    return f"{RESPONDER_URL}?token={token}"


# ---------------------------------------------------------------------------
# SES HTML dashboard email — Phase 4 Sprint 1
# ---------------------------------------------------------------------------

_SEV_COLOR = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#2563eb",
}


def _send_dashboard_email(account_id, scan_summary, recipient_email,
                          scan_sequence, signing_key):
    """
    Build and send the per-tenant SES HTML dashboard email.

    Falls back to _publish_summary (SNS) if SES prerequisites are absent
    (SES_FROM_ADDRESS, RESPONDER_URL, or recipient_email not set).

    Email sections:
      1. Header + scan metadata (account, date, sequence)
      2. Risk banner (derived from highest severity present)
      3. Severity breakdown (Critical / High / Medium / Low counts)
      4. Findings table (per-finding: bucket, severity, issue, NIST, buttons)
      5. Footer (expiry notice)
    """
    if not SES_FROM_ADDRESS or not RESPONDER_URL or not recipient_email:
        print(f"[{account_id}] SES prerequisites missing "
              f"(FROM={bool(SES_FROM_ADDRESS)}, URL={bool(RESPONDER_URL)}, "
              f"EMAIL={bool(recipient_email)}) — falling back to SNS.")
        _publish_summary(account_id, scan_summary)
        return

    fail_count       = scan_summary["fail_count"]
    buckets_affected = scan_summary["buckets_affected"]
    sev              = scan_summary["severity_breakdown"]
    fail_findings    = scan_summary["fail_findings"]
    scan_date        = datetime.now(timezone.utc).strftime("%B %d, %Y")

    # Risk level derived from highest severity present
    if sev["critical"] > 0:
        risk_level, risk_color, risk_icon = "CRITICAL RISK", "#dc2626", "&#128308;"
    elif sev["high"] > 0:
        risk_level, risk_color, risk_icon = "HIGH RISK",     "#ea580c", "&#129001;"
    elif sev["medium"] > 0:
        risk_level, risk_color, risk_icon = "MEDIUM RISK",   "#d97706", "&#128993;"
    elif sev["low"] > 0:
        risk_level, risk_color, risk_icon = "LOW RISK",      "#2563eb", "&#128309;"
    else:
        risk_level, risk_color, risk_icon = "CLEAN",         "#16a34a", "&#9989;"

    # Build one table row per FAIL finding
    finding_rows = []
    for f in fail_findings:
        check_id    = f.get("CheckID", "")
        resource_id = html.escape(f.get("ResourceId", ""))
        severity    = f.get("Severity", "unknown").upper()
        issue       = html.escape(f.get("CheckTitle") or f.get("StatusExtended") or check_id)
        sev_color   = _SEV_COLOR.get(severity.lower(), "#666666")
        nist        = NIST_CSF_MAPPING.get(check_id, [])
        nist_label  = html.escape(nist[0] if nist else "—")

        fix_url    = _build_action_url(check_id, resource_id, "FIX",
                                       account_id, recipient_email,
                                       scan_sequence, signing_key, 24)
        ignore_url = _build_action_url(check_id, resource_id, "IGNORE",
                                       account_id, recipient_email,
                                       scan_sequence, signing_key, 24)

        finding_rows.append(
            f'<tr style="border-bottom:1px solid #f0f0f0;">'
            f'<td style="padding:10px 16px;font-size:13px;color:#1e293b;font-family:monospace;">{resource_id}</td>'
            f'<td style="padding:10px 16px;font-size:12px;font-weight:bold;color:{sev_color};">{severity}</td>'
            f'<td style="padding:10px 16px;font-size:13px;color:#475569;">{issue}</td>'
            f'<td style="padding:10px 16px;font-size:12px;color:#94a3b8;">{nist_label}</td>'
            f'<td style="padding:10px 16px;white-space:nowrap;">'
            f'<a href="{fix_url}" style="display:inline-block;padding:6px 14px;background:#16a34a;'
            f'color:#ffffff;text-decoration:none;border-radius:4px;font-size:12px;'
            f'font-weight:bold;margin-right:6px;">Fix Now</a>'
            f'<a href="{ignore_url}" style="display:inline-block;padding:6px 14px;'
            f'background:#e2e8f0;color:#475569;text-decoration:none;border-radius:4px;'
            f'font-size:12px;">Ignore</a>'
            f'</td></tr>'
        )

    findings_html = "\n".join(finding_rows) if finding_rows else (
        '<tr><td colspan="5" style="padding:24px;text-align:center;'
        'color:#16a34a;font-size:14px;">&#9989; No FAIL findings. Account is clean.</td></tr>'
    )

    safe_account   = html.escape(account_id)
    safe_recipient = html.escape(recipient_email)

    html_body = f"""<!DOCTYPE html>
<html lang="en">
<body style="margin:0;padding:20px;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif;">
<table width="640" cellpadding="0" cellspacing="0"
       style="margin:0 auto;background:#ffffff;border-radius:8px;
              overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.08);">

  <!-- Header -->
  <tr>
    <td colspan="5" bgcolor="#1e293b" style="padding:24px 32px;">
      <span style="color:#ffffff;font-size:20px;font-weight:bold;">
        &#128274; S3 Sentry Security Dashboard
      </span>
    </td>
  </tr>

  <!-- Scan metadata -->
  <tr>
    <td colspan="5" bgcolor="#f8fafc"
        style="padding:12px 32px;border-bottom:1px solid #e2e8f0;">
      <span style="color:#64748b;font-size:12px;">
        Account: <strong>{safe_account}</strong> &nbsp;|&nbsp;
        Scan Date: <strong>{scan_date}</strong> &nbsp;|&nbsp;
        Sequence: <strong>#{scan_sequence}</strong>
      </span>
    </td>
  </tr>

  <!-- Risk banner -->
  <tr>
    <td colspan="5" bgcolor="{risk_color}" style="padding:20px 32px;">
      <span style="color:#ffffff;font-size:22px;font-weight:bold;">
        {risk_icon}&nbsp; {risk_level}
      </span><br>
      <span style="color:rgba(255,255,255,0.88);font-size:14px;
                   margin-top:4px;display:block;">
        {fail_count} finding(s) across {buckets_affected} bucket(s)
      </span>
    </td>
  </tr>

  <!-- Severity breakdown -->
  <tr>
    <td colspan="5" style="padding:20px 32px;border-bottom:1px solid #e2e8f0;">
      <span style="font-size:11px;font-weight:bold;color:#94a3b8;
                   text-transform:uppercase;letter-spacing:1px;">
        Severity Breakdown
      </span>
      <table style="margin-top:12px;border-collapse:collapse;">
        <tr>
          <td style="padding:8px 24px 8px 0;text-align:center;">
            <span style="display:block;font-size:28px;font-weight:bold;
                         color:#dc2626;">{sev['critical']}</span>
            <span style="font-size:11px;color:#94a3b8;
                         text-transform:uppercase;">Critical</span>
          </td>
          <td style="padding:8px 24px;text-align:center;
                     border-left:1px solid #f1f5f9;">
            <span style="display:block;font-size:28px;font-weight:bold;
                         color:#ea580c;">{sev['high']}</span>
            <span style="font-size:11px;color:#94a3b8;
                         text-transform:uppercase;">High</span>
          </td>
          <td style="padding:8px 24px;text-align:center;
                     border-left:1px solid #f1f5f9;">
            <span style="display:block;font-size:28px;font-weight:bold;
                         color:#d97706;">{sev['medium']}</span>
            <span style="font-size:11px;color:#94a3b8;
                         text-transform:uppercase;">Medium</span>
          </td>
          <td style="padding:8px 24px;text-align:center;
                     border-left:1px solid #f1f5f9;">
            <span style="display:block;font-size:28px;font-weight:bold;
                         color:#2563eb;">{sev['low']}</span>
            <span style="font-size:11px;color:#94a3b8;
                         text-transform:uppercase;">Low</span>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- Findings table — column headers -->
  <tr bgcolor="#f8fafc">
    <td style="padding:10px 16px;font-size:11px;font-weight:bold;color:#64748b;
               text-transform:uppercase;border-bottom:2px solid #e2e8f0;">Bucket</td>
    <td style="padding:10px 16px;font-size:11px;font-weight:bold;color:#64748b;
               text-transform:uppercase;border-bottom:2px solid #e2e8f0;">Severity</td>
    <td style="padding:10px 16px;font-size:11px;font-weight:bold;color:#64748b;
               text-transform:uppercase;border-bottom:2px solid #e2e8f0;">Issue</td>
    <td style="padding:10px 16px;font-size:11px;font-weight:bold;color:#64748b;
               text-transform:uppercase;border-bottom:2px solid #e2e8f0;">NIST CSF</td>
    <td style="padding:10px 16px;font-size:11px;font-weight:bold;color:#64748b;
               text-transform:uppercase;border-bottom:2px solid #e2e8f0;">Action</td>
  </tr>

  <!-- Findings rows -->
  {findings_html}

  <!-- Footer -->
  <tr>
    <td colspan="5" bgcolor="#f8fafc"
        style="padding:20px 32px;border-top:1px solid #e2e8f0;">
      <span style="font-size:12px;color:#94a3b8;line-height:1.6;">
        Action links expire in 24 hours. Sent to {safe_recipient}.<br>
        S3 Sentry scans your account daily. Next scan: tomorrow at 02:00 UTC.
      </span>
    </td>
  </tr>

</table>
</body>
</html>"""

    plain_text = (
        f"S3 Sentry Security Dashboard\n"
        f"Account: {account_id} | Scan Date: {scan_date} | Sequence: #{scan_sequence}\n\n"
        f"Risk Level : {risk_level}\n"
        f"Findings   : {fail_count} across {buckets_affected} bucket(s)\n\n"
        f"Severity Breakdown:\n"
        f"  Critical : {sev['critical']}\n"
        f"  High     : {sev['high']}\n"
        f"  Medium   : {sev['medium']}\n"
        f"  Low      : {sev['low']}\n\n"
        f"Findings:\n" +
        "\n".join(
            f"  [{f.get('Severity','').upper()}] {f.get('ResourceId','')} — "
            f"{f.get('CheckTitle') or f.get('CheckID','')}"
            for f in fail_findings
        ) +
        "\n\nTo act on findings, open this email in an HTML-capable client.\n"
        "Action links expire in 24 hours.\n"
    )

    boto3.client("ses").send_email(
        Source=SES_FROM_ADDRESS,
        Destination={"ToAddresses": [recipient_email]},
        Message={
            "Subject": {
                "Data": f"\u26a0\ufe0f S3 Sentry: {fail_count} finding(s) in "
                        f"acc#{account_id} \u2014 Action Required"
            },
            "Body": {
                "Html": {"Data": html_body},
                "Text": {"Data": plain_text},
            },
        },
    )
    print(f"[{account_id}] SES dashboard email sent to {recipient_email} "
          f"(seq #{scan_sequence}, {fail_count} finding(s)).")


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
            # Increment sequence BEFORE scan so all tokens in this email cycle
            # share the same number. A re-run invalidates every prior email's tokens.
            scan_sequence = increment_scan_sequence(account_id)
            print(f"[{account_id}] ScanSequence incremented to {scan_sequence}.")

            print(f"[{account_id}] Starting scan...")
            scan_summary = run_s3_scan(assumed_session)
            print(f"[{account_id}] Scan complete.")

            if scan_summary:
                signing_key = token_utils.get_signing_key(HMAC_KEY_PATH)
                _send_dashboard_email(
                    account_id, scan_summary,
                    recipient_email=tenant.get("Email"),
                    scan_sequence=scan_sequence,
                    signing_key=signing_key,
                )
                results.append({
                    "accountId":         account_id,
                    "status":            "SUCCESS",
                    "totalFindings":     scan_summary["total_findings"],
                    "failCount":         scan_summary["fail_count"],
                    "bucketsAffected":   scan_summary["buckets_affected"],
                    "severityBreakdown": scan_summary["severity_breakdown"],
                    "scanSequence":      scan_sequence,
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
