"""
token_utils.py — HMAC-SHA256 action token system for S3 Sentry

Token format
------------
  <base64url(payload_json)>.<base64url(hmac_sha256_signature)>

The signature covers the entire base64url-encoded payload string.
This prevents any modification of the payload fields (including expiry)
without invalidating the signature.

Payload fields
--------------
  jti            : str   — UUID, single-use nonce (checked in DynamoDB by Responder)
  account_id     : str   — tenant AWS account ID
  check_id       : str   — Prowler check identifier
  resource_id    : str   — S3 bucket name
  action         : str   — "FIX" | "IGNORE" | "ROLLBACK"
  recipient_email: str   — email of the user who received this token
                           (embedded now, used in Sprint 2 as STS SourceIdentity
                            so the client's CloudTrail shows the specific actor)
  scan_sequence  : int   — monotonic counter from tenant METADATA in DynamoDB;
                           Responder rejects tokens from superseded scans
  iat            : int   — issued-at unix timestamp
  exp            : int   — expiry unix timestamp (iat + duration_hours * 3600)

Design decisions
----------------
- Uses stdlib only: hmac, hashlib, base64, json, time, uuid, boto3.
  No itsdangerous, PyJWT, or other signing libraries needed.
- Signature comparison uses hmac.compare_digest to prevent timing oracle attacks.
- SSM key is cached at module level for the lifetime of a Lambda invocation,
  eliminating repeated network calls across multiple token generations in one scan.
- Payload is JSON-serialised with sorted keys and no extra whitespace so the
  encoded string is deterministic across Python versions and platforms.
"""

import base64
import hashlib
import hmac
import json
import time
import uuid

import boto3

# ---------------------------------------------------------------------------
# Module-level SSM key cache
# Populated once per Lambda cold start; avoids repeated SSM calls per tenant.
# ---------------------------------------------------------------------------
_KEY_CACHE: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Custom exceptions
# Callers (Responder Lambda) must distinguish failure modes to return the
# correct HTTP response and log the right audit event.
# ---------------------------------------------------------------------------

class TokenError(Exception):
    """Base class for all token validation failures."""

class TokenSignatureError(TokenError):
    """
    Signature does not match the payload.
    Indicates tampering or use of a wrong/rotated key.
    HTTP response: 400 Bad Request.
    """

class TokenExpiredError(TokenError):
    """
    Token has passed its exp timestamp.
    HTTP response: 410 Gone — "This link has expired."
    """

class TokenSequenceError(TokenError):
    """
    Token's scan_sequence is older than the tenant's current scan_sequence.
    A newer scan has run since this email was sent.
    HTTP response: 409 Conflict — "This scan is outdated."
    Message is user-facing; embed it directly in the Responder HTML response.
    """


# ---------------------------------------------------------------------------
# Internal base64url helpers
# RFC 4648 §5: URL-safe alphabet, no padding — safe to embed in query strings
# and href attributes without percent-encoding.
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    # Restore stripped padding before decoding.
    remainder = len(s) % 4
    if remainder:
        s += "=" * (4 - remainder)
    return base64.urlsafe_b64decode(s)


# ---------------------------------------------------------------------------
# SSM key retrieval
# ---------------------------------------------------------------------------

def get_signing_key(ssm_path: str = "/s3sentry/hmac_signing_key") -> str:
    """
    Fetch the HMAC signing secret from SSM Parameter Store with decryption.

    The key is cached at module level so repeated calls within a single
    Lambda invocation (one key fetch per tenant scan cycle) cost zero
    additional network round-trips after the first.

    Args:
        ssm_path: SSM parameter name. Defaults to /s3sentry/hmac_signing_key.

    Returns:
        The plaintext secret string.

    Raises:
        botocore.exceptions.ClientError if the parameter does not exist
        or the Lambda's execution role lacks ssm:GetParameter permission.
    """
    if ssm_path not in _KEY_CACHE:
        ssm = boto3.client("ssm")
        resp = ssm.get_parameter(Name=ssm_path, WithDecryption=True)
        _KEY_CACHE[ssm_path] = resp["Parameter"]["Value"]
    return _KEY_CACHE[ssm_path]


# ---------------------------------------------------------------------------
# Token generation
# ---------------------------------------------------------------------------

def generate_action_token(
    payload: dict,
    secret: str,
    duration_hours: int = 24,
) -> str:
    """
    Sign a payload dict and return a URL-safe token string.

    The function augments the caller-supplied payload with three fields:
      jti  — UUID, used by the Responder as a single-use nonce in DynamoDB
      iat  — issued-at unix timestamp
      exp  — expiry unix timestamp

    Expected payload fields (caller must supply):
      account_id      : str
      check_id        : str
      resource_id     : str
      action          : "FIX" | "IGNORE" | "ROLLBACK"
      recipient_email : str   — SourceIdentity for Sprint 2 CloudTrail attribution
      scan_sequence   : int   — from tenant METADATA in DynamoDB

    Args:
        payload:        Dict of action metadata (see above).
        secret:         HMAC signing key (from get_signing_key()).
        duration_hours: Token lifetime. Use 24 for FIX/IGNORE, 48 for ROLLBACK.

    Returns:
        URL-safe token string: "<payload_b64>.<signature_b64>"
    """
    now = int(time.time())

    signed_payload = {
        **payload,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + int(duration_hours) * 3600,
    }

    # Deterministic serialisation: sorted keys, no whitespace.
    payload_json = json.dumps(signed_payload, separators=(",", ":"), sort_keys=True)
    payload_b64  = _b64url_encode(payload_json.encode("utf-8"))

    # HMAC-SHA256: sign the encoded payload string (not the raw JSON) so the
    # encoding is part of the authenticated data.
    signature = hmac.new(
        secret.encode("utf-8"),
        payload_b64.encode("ascii"),
        digestmod=hashlib.sha256,
    ).digest()
    signature_b64 = _b64url_encode(signature)

    return f"{payload_b64}.{signature_b64}"


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------

def validate_action_token(
    token: str,
    secret: str,
    current_scan_sequence: int,
) -> dict:
    """
    Validate a token and return its decoded payload.

    Validation order is intentional:
      1. Signature first — never decode an untrusted payload
      2. Expiry second — signed but expired tokens are a normal UX case
      3. Scan sequence last — signed, fresh but superseded is an edge case

    This ordering means:
      - Tampered tokens always get TokenSignatureError (no information leak)
      - Expired tokens get a user-friendly message
      - Stale-scan tokens get a clear "check your latest email" message

    Args:
        token:                 Token string from the action button URL.
        secret:                HMAC signing key (from get_signing_key()).
        current_scan_sequence: Latest ScanSequence for this tenant from DynamoDB.
                               Fetched by the Responder Lambda before calling this.

    Returns:
        Decoded payload dict on success.

    Raises:
        TokenSignatureError  — token is malformed or signature does not match
        TokenExpiredError    — token has passed its exp timestamp
        TokenSequenceError   — token belongs to a superseded scan
    """
    # --- Parse ---
    try:
        payload_b64, signature_b64 = token.rsplit(".", 1)
    except ValueError:
        raise TokenSignatureError("Malformed token: missing '.' separator.")

    # --- Step 1: Signature verification (ALWAYS before decoding payload) ---
    expected_sig = hmac.new(
        secret.encode("utf-8"),
        payload_b64.encode("ascii"),
        digestmod=hashlib.sha256,
    ).digest()

    try:
        received_sig = _b64url_decode(signature_b64)
    except Exception:
        raise TokenSignatureError("Malformed token: signature segment could not be decoded.")

    # compare_digest is constant-time — prevents timing oracle attacks.
    if not hmac.compare_digest(expected_sig, received_sig):
        raise TokenSignatureError("Token signature is invalid.")

    # --- Decode payload (safe now that signature is verified) ---
    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception:
        raise TokenSignatureError("Token payload could not be decoded after signature verification.")

    # --- Step 2: Expiry check ---
    now = int(time.time())
    if now > payload.get("exp", 0):
        raise TokenExpiredError(
            "This action link has expired. Links are valid for 24 hours (48 hours for Rollback). "
            "Please wait for your next scheduled scan email."
        )

    # --- Step 3: Scan sequence freshness check ---
    token_sequence = payload.get("scan_sequence", -1)
    if token_sequence != current_scan_sequence:
        raise TokenSequenceError(
            "This scan is outdated. A newer security scan has been completed since this email "
            "was sent. Please use the dashboard from today's email for the most accurate "
            "security state."
        )

    return payload
