"""
demo_api.py — S3 Sentry public LIVE DEMO API (Lambda Function URL)

Lets a portfolio visitor scan their OWN AWS account, read-only, once.

Flow
----
  POST /sessions          -> new session: one-time ExternalId + CloudFormation
                             quick-create link for demo_onboarding.yaml
  POST /sessions/scan     -> {sessionId, accountId}: verifies the visitor's role
                             is deployed (AssumeRole with the session ExternalId),
                             then queues ONE async scan
  POST /sessions/status   -> {sessionId}: PENDING | SCANNING | DONE | ERROR (+ results)

Security model
--------------
- Session ID is a 256-bit bearer secret. Only its SHA-256 is stored, so a table
  read never yields a usable session. It travels in the request body, never the
  URL, so it does not land in access logs or browser history.
- Each session gets its own 256-bit ExternalId. The visitor's role trusts only
  this account's two demo roles AND that ExternalId (Confused Deputy defence).
- The demo role is read-only bucket *configuration* (demo_onboarding.yaml).
  Demo sessions live in a separate table, never join the daily schedule, never
  get email, and expire after 24h via DynamoDB TTL.
- Cost/abuse caps: per-IP session limit, global daily scan cap, one scan per
  session, plus reserved concurrency on both Lambdas (see demo_infrastructure.yaml).
"""

import hashlib
import json
import os
import re
import secrets
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

import boto3
import botocore.exceptions

TABLE_NAME            = os.environ.get("DEMO_TABLE", "S3SentryDemo")
SCANNER_FUNCTION      = os.environ.get("SCANNER_FUNCTION", "S3SentryDemoScanner")
TEMPLATE_URL          = os.environ.get("DEMO_TEMPLATE_URL", "")
DEMO_ROLE_NAME        = os.environ.get("DEMO_ROLE_NAME", "S3SentryDemoReadOnlyRole")
REGION                = os.environ.get("AWS_REGION", "us-east-1")
MAX_SESSIONS_PER_IP   = int(os.environ.get("MAX_SESSIONS_PER_IP_PER_DAY", "5"))
MAX_SCANS_PER_DAY     = int(os.environ.get("MAX_SCANS_PER_DAY", "50"))
MAX_VERIFY_ATTEMPTS   = int(os.environ.get("MAX_VERIFY_ATTEMPTS", "20"))
SESSION_TTL_SECONDS   = 24 * 3600
STACK_NAME            = "S3SentryLiveDemo"

_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_SESSION_RE = re.compile(r"^[A-Za-z0-9_-]{40,64}$")

_ddb    = boto3.resource("dynamodb")
_table  = _ddb.Table(TABLE_NAME)
_sts    = boto3.client("sts")
_lambda = boto3.client("lambda")
_PROVIDER_ACCOUNT = None


# ── helpers ──────────────────────────────────────────────────────────────────

class ApiError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def _json(status, body):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
        "body": json.dumps(body),
    }


def _hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _today():
    return datetime.now(timezone.utc).strftime("%Y%m%d")


def _provider_account():
    global _PROVIDER_ACCOUNT
    if _PROVIDER_ACCOUNT is None:
        _PROVIDER_ACCOUNT = _sts.get_caller_identity()["Account"]
    return _PROVIDER_ACCOUNT


def _bump_counter(pk, limit, error_code, message):
    """Atomically increment a daily counter; reject once it reaches `limit`."""
    try:
        _table.update_item(
            Key={"PK": pk, "SK": "COUNT"},
            UpdateExpression="ADD #c :one SET #t = if_not_exists(#t, :ttl)",
            ConditionExpression="attribute_not_exists(#c) OR #c < :limit",
            ExpressionAttributeNames={"#c": "Count", "#t": "ttl"},
            ExpressionAttributeValues={
                ":one": 1, ":limit": limit, ":ttl": int(time.time()) + 2 * 86400,
            },
        )
    except _ddb.meta.client.exceptions.ConditionalCheckFailedException:
        raise ApiError(429, error_code, message)


def _parse_body(event):
    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        import base64
        raw = base64.b64decode(raw).decode("utf-8")
    if len(raw) > 2048:
        raise ApiError(413, "BODY_TOO_LARGE", "Request body too large.")
    try:
        body = json.loads(raw)
    except ValueError:
        raise ApiError(400, "BAD_JSON", "Body must be JSON.")
    if not isinstance(body, dict):
        raise ApiError(400, "BAD_JSON", "Body must be a JSON object.")
    return body


def _load_session(body):
    session_id = str(body.get("sessionId", ""))
    if not _SESSION_RE.match(session_id):
        raise ApiError(400, "BAD_SESSION", "Missing or malformed sessionId.")
    item = _table.get_item(Key={"PK": f"SESSION#{_hash(session_id)}", "SK": "META"}).get("Item")
    if not item or int(item.get("ttl", 0)) < time.time():
        raise ApiError(404, "SESSION_NOT_FOUND", "Session not found or expired. Start a new one.")
    return item


# ── routes ───────────────────────────────────────────────────────────────────

def create_session(event):
    ip = event.get("requestContext", {}).get("http", {}).get("sourceIp", "unknown")
    _bump_counter(
        f"RATE#IP#{_hash(ip)}#{_today()}", MAX_SESSIONS_PER_IP,
        "RATE_LIMITED", "Too many demo sessions from your network today. Try again tomorrow.",
    )

    session_id  = secrets.token_urlsafe(32)   # 43 chars, 256 bits
    external_id = secrets.token_urlsafe(32)
    now         = int(time.time())

    _table.put_item(
        Item={
            "PK": f"SESSION#{_hash(session_id)}",
            "SK": "META",
            "ExternalId": external_id,
            "Status": "PENDING",
            "VerifyAttempts": 0,
            "CreatedAt": now,
            "ttl": now + SESSION_TTL_SECONDS,
        },
        ConditionExpression="attribute_not_exists(PK)",
    )

    launch_url = (
        f"https://console.aws.amazon.com/cloudformation/home?region={REGION}#/stacks/quickcreate?"
        + urlencode({
            "templateURL": TEMPLATE_URL,
            "stackName": STACK_NAME,
            "param_ProviderAccountId": _provider_account(),
            "param_ExternalId": external_id,
        })
    )
    return _json(201, {
        "sessionId": session_id,
        "launchUrl": launch_url,
        "stackName": STACK_NAME,
        "expiresAt": now + SESSION_TTL_SECONDS,
    })


def start_scan(event):
    body = _parse_body(event)
    item = _load_session(body)
    account_id = str(body.get("accountId", "")).replace("-", "").strip()
    if not _ACCOUNT_RE.match(account_id):
        raise ApiError(400, "BAD_ACCOUNT", "Enter your 12-digit AWS account ID.")
    if item["Status"] != "PENDING":
        return _json(200, {"status": item["Status"]})
    if int(item.get("VerifyAttempts", 0)) >= MAX_VERIFY_ATTEMPTS:
        raise ApiError(429, "TOO_MANY_ATTEMPTS", "Too many attempts for this session. Start a new one.")

    pk = item["PK"]
    _table.update_item(Key={"PK": pk, "SK": "META"},
                       UpdateExpression="ADD VerifyAttempts :one",
                       ExpressionAttributeValues={":one": 1})

    # Prove the visitor deployed the role with THIS session's ExternalId.
    role_arn = f"arn:aws:iam::{account_id}:role/{DEMO_ROLE_NAME}"
    try:
        _sts.assume_role(RoleArn=role_arn, RoleSessionName="s3sentry-demo-verify",
                         ExternalId=item["ExternalId"], DurationSeconds=900)
    except botocore.exceptions.ClientError:
        raise ApiError(409, "ROLE_NOT_READY",
                       "Can't reach the demo role yet. Make sure the stack shows "
                       "CREATE_COMPLETE in that account, then try again.")

    _bump_counter(f"RATE#GLOBAL#SCANS#{_today()}", MAX_SCANS_PER_DAY,
                  "DAILY_CAP", "The live demo hit today's scan limit. Try the sample scan, or come back tomorrow.")

    try:
        _table.update_item(
            Key={"PK": pk, "SK": "META"},
            UpdateExpression="SET #s = :scanning, AccountId = :acct, ScanStartedAt = :now",
            ConditionExpression="#s = :pending",
            ExpressionAttributeNames={"#s": "Status"},
            ExpressionAttributeValues={":scanning": "SCANNING", ":pending": "PENDING",
                                       ":acct": account_id, ":now": int(time.time())},
        )
    except _ddb.meta.client.exceptions.ConditionalCheckFailedException:
        return _json(200, {"status": "SCANNING"})   # a parallel request won the race

    _lambda.invoke(FunctionName=SCANNER_FUNCTION, InvocationType="Event",
                   Payload=json.dumps({"sessionKey": pk}).encode())
    return _json(202, {"status": "SCANNING"})


def get_status(event):
    item = _load_session(_parse_body(event))
    out = {"status": item["Status"], "expiresAt": int(item["ttl"])}
    if item["Status"] == "DONE":
        out["result"] = json.loads(item.get("Result", "{}"))
    if item["Status"] == "ERROR":
        out["error"] = item.get("Error", "The scan failed.")
    return _json(200, out)


ROUTES = {
    ("POST", "/sessions"):        create_session,
    ("POST", "/sessions/scan"):   start_scan,
    ("POST", "/sessions/status"): get_status,
}


def handler(event, context):
    http   = event.get("requestContext", {}).get("http", {})
    method = http.get("method", "GET").upper()
    path   = (event.get("rawPath") or "/").rstrip("/") or "/"
    route  = ROUTES.get((method, path))
    if not route:
        return _json(404, {"error": "NOT_FOUND"})
    try:
        return route(event)
    except ApiError as e:
        return _json(e.status, {"error": e.code, "message": e.message})
    except Exception as e:  # never leak internals to the browser
        print(f"[ERROR] {type(e).__name__}: {e}")
        return _json(500, {"error": "INTERNAL", "message": "Something went wrong. Try again."})
