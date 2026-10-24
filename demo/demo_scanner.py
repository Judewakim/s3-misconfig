"""
demo_scanner.py — runs ONE read-only Prowler scan for a live-demo session.

Invoked asynchronously by demo_api.py with {"sessionKey": "SESSION#<sha256>"}.
Reuses the production scan engine (lambda_handler.run_prowler) but:
  - assumes the visitor's read-only S3SentryDemoReadOnlyRole
  - stores results only on the session item (24h TTL), never under ACC#
  - sends no email and never joins the daily schedule
"""

import json
import os
import time

import boto3
import botocore.exceptions

from lambda_handler import NIST_CSF_MAPPING, is_bucket_finding, run_prowler, summarize

TABLE_NAME     = os.environ.get("DEMO_TABLE", "S3SentryDemo")
DEMO_ROLE_NAME = os.environ.get("DEMO_ROLE_NAME", "S3SentryDemoReadOnlyRole")
MAX_FINDINGS   = 500   # keeps the session item well under DynamoDB's 400 KB limit

_table = boto3.resource("dynamodb").Table(TABLE_NAME)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _finish(pk, status, **attrs):
    names  = {"#s": "Status"}
    values = {":s": status, ":now": int(time.time())}
    sets   = ["#s = :s", "ScanFinishedAt = :now"]
    for i, (k, v) in enumerate(attrs.items()):
        names[f"#a{i}"], values[f":v{i}"] = k, v
        sets.append(f"#a{i} = :v{i}")
    _table.update_item(Key={"PK": pk, "SK": "META"},
                       UpdateExpression="SET " + ", ".join(sets),
                       ExpressionAttributeNames=names, ExpressionAttributeValues=values)


def compact(raw_findings):
    """Only the fields the demo page renders, worst first."""
    rows = [{
        "check":    f.get("CheckID", ""),
        "title":    f.get("CheckTitle", ""),
        "status":   f.get("Status", ""),
        "severity": (f.get("Severity") or "").lower(),
        "resource": f.get("ResourceId", ""),
        "detail":   (f.get("StatusExtended") or "")[:300],
        "nist":     NIST_CSF_MAPPING.get(f.get("CheckID", ""), []),
    } for f in raw_findings]
    rows.sort(key=lambda r: (r["status"] != "FAIL", _SEVERITY_ORDER.get(r["severity"], 9), r["resource"]))
    return rows[:MAX_FINDINGS]


def handler(event, context):
    pk = event.get("sessionKey", "")
    item = _table.get_item(Key={"PK": pk, "SK": "META"}).get("Item")
    if not item or item.get("Status") != "SCANNING":
        print(f"[demo] {pk[:20]}… not in SCANNING state; nothing to do.")
        return

    account_id = item["AccountId"]
    role_arn   = f"arn:aws:iam::{account_id}:role/{DEMO_ROLE_NAME}"
    try:
        creds = boto3.client("sts").assume_role(
            RoleArn=role_arn, RoleSessionName="s3sentry-demo-scan",
            ExternalId=item["ExternalId"], DurationSeconds=900,
        )["Credentials"]
        session = boto3.Session(aws_access_key_id=creds["AccessKeyId"],
                                aws_secret_access_key=creds["SecretAccessKey"],
                                aws_session_token=creds["SessionToken"])
        scanned = run_prowler(session)
    except botocore.exceptions.ClientError as e:
        print(f"[demo] assume/scan failed: {e.response['Error']['Code']}")
        _finish(pk, "ERROR", Error="S3 Sentry lost access to the demo role. Is the stack still deployed?")
        return
    except Exception as e:
        print(f"[demo] unexpected: {type(e).__name__}: {e}")
        _finish(pk, "ERROR", Error="The scan failed unexpectedly. Please try again later.")
        return

    if scanned is None:
        _finish(pk, "ERROR", Error="The scanner produced no output. Please try again later.")
        return

    _, raw = scanned
    summary = summarize(raw)
    result = {
        "accountId":        account_id,
        "scannedAt":        int(time.time()),
        "checksRun":        len({f.get("CheckID") for f in raw}),
        "bucketsScanned":   len({f.get("ResourceId") for f in raw if is_bucket_finding(f)}),
        "totalFindings":    summary["total_findings"],
        "failCount":        summary["fail_count"],
        "bucketsAffected":  summary["buckets_affected"],
        "accountFailCount": summary["account_fail_count"],
        "severity":         summary["severity_breakdown"],
        "findings":         compact(raw),
        "truncated":        len(raw) > MAX_FINDINGS,
    }
    _finish(pk, "DONE", Result=json.dumps(result, default=str))
    print(f"[demo] scan done: {summary['fail_count']} FAIL / {summary['total_findings']} total.")
