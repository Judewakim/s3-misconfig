"""
S3 Sentry — Responder Lambda
Handles customer-facing FIX / IGNORE / ROLLBACK actions delivered via
HMAC-signed links embedded in the SES dashboard email.

Entry point: handler(event, context)
Routes:
  GET  /?token=<token>  → render Safety Summary confirmation page
  POST /                → 4-layer gatekeeper → dispatcher → audit log
"""

import base64
import json
import logging
import os
from datetime import datetime, timezone
from urllib.parse import parse_qs

import boto3
from boto3.dynamodb.conditions import Attr

from token_utils import (
    TokenError,
    TokenExpiredError,
    TokenSequenceError,
    TokenSignatureError,
    get_signing_key,
    validate_action_token,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── Environment ───────────────────────────────────────────────────────────────
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "S3Sentry")
HMAC_KEY_PATH  = os.environ.get("HMAC_KEY_PATH", "/s3sentry/hmac_signing_key")
S3_VAULT_BUCKET = os.environ["S3_VAULT_BUCKET"]
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"

# ── Shared AWS resources ──────────────────────────────────────────────────────
_dynamodb    = boto3.resource("dynamodb")
_table       = _dynamodb.Table(DYNAMODB_TABLE)
_sts         = boto3.client("sts")
_provider_s3 = boto3.client("s3")

# ── Safety Summary copy ───────────────────────────────────────────────────────
SAFETY_SUMMARIES: dict = {
    "s3_bucket_level_public_access_block": {
        "title": "Enable S3 Public Access Block",
        "action_description": (
            "This will enable the S3 Block Public Access setting on this bucket, "
            "immediately cutting off all public internet access. Any existing public "
            "URLs pointing to this bucket will stop working."
        ),
        "severity": "CRITICAL",
        "severity_color": "#d32f2f",
    },
    "s3_bucket_default_encryption": {
        "title": "Enable Default Bucket Encryption",
        "action_description": (
            "This will configure AES-256 server-side encryption as the default for all "
            "new objects written to this bucket. Existing unencrypted objects are NOT "
            "retroactively encrypted."
        ),
        "severity": "HIGH",
        "severity_color": "#e65100",
    },
}

# ── HTML helpers ──────────────────────────────────────────────────────────────

_PAGE_CSS = """
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #f0f2f5;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; padding: 24px;
  }
  .card {
    background: #fff; border-radius: 12px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.10);
    max-width: 520px; width: 100%; overflow: hidden;
  }
  .card-header {
    background: #1a1a2e; padding: 20px 28px;
    display: flex; align-items: center; justify-content: space-between;
  }
  .brand { color: #fff; font-size: 18px; font-weight: 700; letter-spacing: 0.5px; }
  .brand span { color: #4fc3f7; }
  .badge {
    padding: 4px 12px; border-radius: 20px; font-size: 12px;
    font-weight: 700; color: #fff; text-transform: uppercase; letter-spacing: 1px;
  }
  .card-body { padding: 28px; }
  .resource-info { margin-bottom: 20px; }
  .resource-info h2 { font-size: 16px; color: #333; margin-bottom: 8px; }
  .label { font-size: 13px; color: #888; margin-bottom: 2px; }
  .value { font-size: 15px; font-weight: 600; color: #1a1a2e; font-family: monospace; }
  .safety-box {
    background: #fff8e1; border-left: 4px solid #ffa000;
    border-radius: 6px; padding: 16px 18px; margin: 20px 0;
  }
  .safety-title {
    font-size: 13px; font-weight: 700; color: #e65100;
    text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px;
  }
  .safety-box p { font-size: 14px; color: #555; line-height: 1.6; }
  .actions { display: flex; gap: 12px; margin-top: 24px; }
  .btn {
    flex: 1; padding: 12px; border: none; border-radius: 8px;
    font-size: 15px; font-weight: 600; cursor: pointer; transition: opacity 0.2s;
  }
  .btn:hover { opacity: 0.88; }
  .btn-cancel { background: #e0e0e0; color: #333; }
  .btn-confirm { color: #fff; }
  .center { text-align: center; }
  .icon { font-size: 48px; margin-bottom: 16px; }
  .msg { color: #555; font-size: 15px; line-height: 1.6; }
"""


def _page(body_html: str, title: str = "S3 Sentry") -> str:
    return (
        f"<!DOCTYPE html><html lang='en'><head>"
        f"<meta charset='UTF-8'>"
        f"<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
        f"<title>{title}</title>"
        f"<style>{_PAGE_CSS}</style>"
        f"</head><body>{body_html}</body></html>"
    )


def render_confirmation_page(
    token: str, check_id: str, resource_id: str, account_id: str, action: str
) -> str:
    summary = SAFETY_SUMMARIES.get(check_id)
    if not summary:
        return render_error_page(f"Unsupported security check: <code>{check_id}</code>", 422)

    badge_color   = summary["severity_color"]
    severity      = summary["severity"]
    confirm_color = "#d32f2f" if severity == "CRITICAL" else "#e65100" if severity == "HIGH" else "#1976d2"

    body = f"""
<div class="card">
  <div class="card-header">
    <div class="brand">S3 <span>Sentry</span></div>
    <div class="badge" style="background:{badge_color}">{severity}</div>
  </div>
  <div class="card-body">
    <div class="resource-info">
      <h2>Security Action Request</h2>
      <div class="label">Bucket</div>
      <div class="value">{resource_id}</div>
      <div class="label" style="margin-top:8px">Account</div>
      <div class="value">{account_id}</div>
    </div>
    <div class="safety-box">
      <div class="safety-title">What will happen</div>
      <p>{summary["action_description"]}</p>
    </div>
    <form method="POST">
      <input type="hidden" name="token" value="{token}">
      <div class="actions">
        <button type="button" class="btn btn-cancel" onclick="window.close()">Cancel</button>
        <button type="submit" class="btn btn-confirm" style="background:{confirm_color}">
          Confirm {action}
        </button>
      </div>
    </form>
  </div>
</div>"""
    return _page(body, title="Confirm Security Action — S3 Sentry")


def render_success_page(action: str, resource_id: str) -> str:
    dry_label = " (Dry Run — no real changes made)" if DRY_RUN else ""
    body = f"""
<div class="card">
  <div class="card-header"><div class="brand">S3 <span>Sentry</span></div></div>
  <div class="card-body center">
    <div class="icon">&#x2705;</div>
    <div class="msg">
      <strong>{action} completed{dry_label}</strong><br><br>
      The action has been applied to <code>{resource_id}</code>.<br>
      A full audit record has been saved.
    </div>
  </div>
</div>"""
    return _page(body, title="Action Complete — S3 Sentry")


def render_error_page(message: str, code: int = 400) -> str:
    body = f"""
<div class="card">
  <div class="card-header">
    <div class="brand">S3 <span>Sentry</span></div>
    <div class="badge" style="background:#555">ERROR {code}</div>
  </div>
  <div class="card-body center">
    <div class="icon">&#x1F512;</div>
    <div class="msg">{message}</div>
  </div>
</div>"""
    return _page(body, title="Error — S3 Sentry")


def http_response(status: int, html: str) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": html,
    }


# ── Token peek (no signature check — GET rendering only) ─────────────────────

def _peek_payload(token: str) -> dict | None:
    """Decode the payload portion of the token without verifying the signature.
    Used only to extract display fields for the confirmation page (GET).
    All security validation happens at POST time via validate_action_token."""
    try:
        payload_b64 = token.split(".")[0]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return None


# ── Tenant & cross-account helpers ───────────────────────────────────────────

def _get_tenant(account_id: str) -> dict | None:
    resp = _table.get_item(Key={"PK": f"ACC#{account_id}", "SK": "METADATA"})
    return resp.get("Item")


def _assume_cross_account(role_arn: str, external_id: str, account_id: str) -> boto3.Session:
    creds = _sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"s3sentry-remediate-{account_id}",
        ExternalId=external_id,
        DurationSeconds=900,
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


# ── S3 Vault ──────────────────────────────────────────────────────────────────

def _write_vault_snapshot(
    account_id: str, check_id: str, resource_id: str, state: dict
) -> str:
    ts  = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    key = f"{account_id}/{ts}/{resource_id}/{check_id}.json"
    _provider_s3.put_object(
        Bucket=S3_VAULT_BUCKET,
        Key=key,
        Body=json.dumps(state, default=str),
        ContentType="application/json",
        ServerSideEncryption="AES256",
    )
    logger.info("Vault snapshot written: s3://%s/%s", S3_VAULT_BUCKET, key)
    return key


# ── Audit logging ─────────────────────────────────────────────────────────────

def _write_audit_item(
    account_id: str,
    check_id: str,
    resource_id: str,
    action: str,
    source_identity: str,
    before_state: dict,
    after_state: dict,
    vault_key: str,
    jti: str,
    scan_sequence: int,
) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    _table.put_item(Item={
        "PK": f"ACC#{account_id}",
        "SK": f"REMEDIATION#{ts}#{check_id}#{resource_id}",
        "Action": action,
        "CheckID": check_id,
        "ResourceID": resource_id,
        "SourceIdentity": source_identity,
        "Before": json.dumps(before_state, default=str),
        "After": json.dumps(after_state, default=str),
        "VaultKey": vault_key,   # Sprint 4 ROLLBACK reads this key
        "RemediatedAt": ts,
        "TokenJTI": jti,
        "DryRun": DRY_RUN,
        "ScanSequence": scan_sequence,
    })
    logger.info(
        "Audit item written: ACC#%s / REMEDIATION#%s#%s#%s",
        account_id, ts, check_id, resource_id,
    )


def _write_suppress_item(
    account_id: str, check_id: str, resource_id: str, source_identity: str, jti: str
) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    _table.put_item(Item={
        "PK": f"ACC#{account_id}",
        "SK": f"SUPPRESS#{check_id}#{resource_id}",
        "SuppressedAt": ts,
        "SourceIdentity": source_identity,
        "TokenJTI": jti,
    })
    logger.info("Suppress item written: ACC#%s / SUPPRESS#%s#%s", account_id, check_id, resource_id)


# ── Handlers ──────────────────────────────────────────────────────────────────

class PublicAccessHandler:
    def read_current_config(self, s3_client, bucket_name: str) -> dict:
        try:
            return s3_client.get_public_access_block(
                Bucket=bucket_name
            )["PublicAccessBlockConfiguration"]
        except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
            return {}  # All four flags default to False when no config exists

    def apply_fix(self, s3_client, bucket_name: str) -> dict:
        config = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
        if DRY_RUN:
            logger.info("[DRY_RUN] put_public_access_block(Bucket=%s, config=%s)", bucket_name, config)
        else:
            s3_client.put_public_access_block(Bucket=bucket_name, PublicAccessBlockConfiguration=config)
        return config

    def apply_rollback(self, s3_client, bucket_name: str, before_state: dict) -> dict:
        if DRY_RUN:
            logger.info(
                "[DRY_RUN] rollback put_public_access_block(Bucket=%s, before=%s)", bucket_name, before_state
            )
        else:
            if before_state:
                s3_client.put_public_access_block(
                    Bucket=bucket_name, PublicAccessBlockConfiguration=before_state
                )
            else:
                s3_client.delete_public_access_block(Bucket=bucket_name)
        return before_state


class EncryptionHandler:
    def read_current_config(self, s3_client, bucket_name: str) -> dict:
        try:
            return s3_client.get_bucket_encryption(
                Bucket=bucket_name
            )["ServerSideEncryptionConfiguration"]
        except s3_client.exceptions.ClientError as exc:
            if exc.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                return {}
            raise

    def apply_fix(self, s3_client, bucket_name: str) -> dict:
        config = {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
        if DRY_RUN:
            logger.info("[DRY_RUN] put_bucket_encryption(Bucket=%s, config=%s)", bucket_name, config)
        else:
            s3_client.put_bucket_encryption(
                Bucket=bucket_name, ServerSideEncryptionConfiguration=config
            )
        return config

    def apply_rollback(self, s3_client, bucket_name: str, before_state: dict) -> dict:
        if DRY_RUN:
            logger.info(
                "[DRY_RUN] rollback put_bucket_encryption(Bucket=%s, before=%s)", bucket_name, before_state
            )
        else:
            if before_state:
                s3_client.put_bucket_encryption(
                    Bucket=bucket_name, ServerSideEncryptionConfiguration=before_state
                )
            else:
                s3_client.delete_bucket_encryption(Bucket=bucket_name)
        return before_state


HANDLERS: dict = {
    "s3_bucket_level_public_access_block": PublicAccessHandler,
    "s3_bucket_default_encryption": EncryptionHandler,
}


# ── POST /confirm — 4-layer gatekeeper + dispatcher ──────────────────────────

def handle_post(token: str) -> dict:
    # ── Layer 1 & 2: Cryptographic + Freshness Gate ───────────────────────────
    signing_key = get_signing_key(HMAC_KEY_PATH)

    peek = _peek_payload(token)
    if not peek:
        return http_response(400, render_error_page("Malformed token.", 400))

    account_id = peek.get("account_id", "")
    tenant = _get_tenant(account_id)
    if not tenant:
        return http_response(400, render_error_page("Unknown tenant account.", 400))

    current_scan_sequence = int(tenant.get("ScanSequence", 0))

    try:
        payload = validate_action_token(token, signing_key, current_scan_sequence)
    except TokenSignatureError:
        return http_response(
            400,
            render_error_page(
                "Invalid token signature. This link may have been tampered with.", 400
            ),
        )
    except TokenExpiredError:
        return http_response(
            410,
            render_error_page(
                "This action link has expired. Please check your latest scan email for a fresh link.",
                410,
            ),
        )
    except TokenSequenceError:
        return http_response(
            409,
            render_error_page(
                "This link is no longer valid — a newer scan has completed. "
                "Please use the link in your most recent email.",
                409,
            ),
        )
    except TokenError as exc:
        return http_response(400, render_error_page(f"Token error: {exc}", 400))

    jti           = payload["jti"]
    check_id      = payload["check_id"]
    resource_id   = payload["resource_id"]
    action        = payload["action"]
    source_identity = payload["recipient_email"]
    scan_sequence = int(payload["scan_sequence"])

    # ── Layer 3: Idempotency Gate ─────────────────────────────────────────────
    # Atomic conditional write prevents replay without a TOCTOU race.
    try:
        _table.put_item(
            Item={
                "PK": f"TOKEN#{jti}",
                "SK": "USED",
                "UsedAt": datetime.now(timezone.utc).isoformat(),
                "AccountId": account_id,
                "ttl": int(payload["exp"]) + 86400,  # TTL: 24h after token expiry
            },
            ConditionExpression=Attr("PK").not_exists(),
        )
    except _dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        return http_response(
            409,
            render_error_page(
                "This action has already been completed. Each link is single-use.", 409
            ),
        )

    # ── Route by action ───────────────────────────────────────────────────────
    HandlerClass = HANDLERS.get(check_id)
    if not HandlerClass:
        return http_response(422, render_error_page(f"Unsupported check: <code>{check_id}</code>", 422))

    if action == "IGNORE":
        _write_suppress_item(account_id, check_id, resource_id, source_identity, jti)
        return http_response(200, render_success_page("IGNORE", resource_id))

    # ── FIX / ROLLBACK: Layer 4 — Safety Snapshot ────────────────────────────
    cross_session = _assume_cross_account(tenant["RoleArn"], tenant["ExternalId"], account_id)
    cross_s3      = cross_session.client("s3")
    h             = HandlerClass()

    before_state = h.read_current_config(cross_s3, resource_id)
    vault_key    = _write_vault_snapshot(account_id, check_id, resource_id, before_state)

    if action == "FIX":
        after_state = h.apply_fix(cross_s3, resource_id)
    elif action == "ROLLBACK":
        after_state = h.apply_rollback(cross_s3, resource_id, before_state)
    else:
        return http_response(400, render_error_page(f"Unknown action: {action}", 400))

    _write_audit_item(
        account_id=account_id,
        check_id=check_id,
        resource_id=resource_id,
        action=action,
        source_identity=source_identity,
        before_state=before_state,
        after_state=after_state,
        vault_key=vault_key,
        jti=jti,
        scan_sequence=scan_sequence,
    )

    return http_response(200, render_success_page(action, resource_id))


# ── Lambda entry point ────────────────────────────────────────────────────────

def handler(event: dict, context) -> dict:  # noqa: ANN001
    method = (
        event.get("requestContext", {})
             .get("http", {})
             .get("method", "GET")
             .upper()
    )

    if method == "GET":
        params    = event.get("queryStringParameters") or {}
        token     = params.get("token", "").strip()
        if not token:
            return http_response(400, render_error_page("Missing token parameter.", 400))

        peek = _peek_payload(token)
        if not peek:
            return http_response(400, render_error_page("Malformed token.", 400))

        return http_response(
            200,
            render_confirmation_page(
                token=token,
                check_id=peek.get("check_id", ""),
                resource_id=peek.get("resource_id", ""),
                account_id=peek.get("account_id", ""),
                action=peek.get("action", "FIX"),
            ),
        )

    if method == "POST":
        raw_body = event.get("body") or ""
        if event.get("isBase64Encoded"):
            raw_body = base64.b64decode(raw_body).decode("utf-8")

        params = {k: v[0] for k, v in parse_qs(raw_body).items()}
        token  = params.get("token", "").strip()
        if not token:
            return http_response(400, render_error_page("Missing token in request body.", 400))

        return handle_post(token)

    return http_response(405, render_error_page("Method not allowed.", 405))
