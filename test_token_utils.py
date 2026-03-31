"""
test_token_utils.py — Local verification for token_utils.py

Run from the project root (no AWS credentials needed):
  python test_token_utils.py

Tests:
  1. Happy path          — valid token validates successfully
  2. URL safety          — token contains no characters that break email hrefs
  3. Signature tamper    — modified token raises TokenSignatureError
  4. Expired token       — past-expiry token raises TokenExpiredError
  5. Stale sequence      — old scan_sequence raises TokenSequenceError
  6. Determinism         — same payload produces different tokens (jti is random)
  7. Field integrity     — decoded payload contains all expected fields
"""

import sys
import time
import unittest.mock

import token_utils
from token_utils import (
    TokenExpiredError,
    TokenSequenceError,
    TokenSignatureError,
    generate_action_token,
    validate_action_token,
)

# ---------------------------------------------------------------------------
# Test configuration — no AWS, no SSM
# ---------------------------------------------------------------------------
SECRET = "deadbeefcafe1234deadbeefcafe1234deadbeefcafe1234deadbeefcafe1234"
CURRENT_SEQUENCE = 7

SAMPLE_PAYLOAD = {
    "account_id":      "928459458650",
    "check_id":        "s3_bucket_default_encryption",
    "resource_id":     "my-prod-bucket",
    "action":          "FIX",
    "recipient_email": "lawyer@firm.com",
    "scan_sequence":   CURRENT_SEQUENCE,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
PASS = "\033[92m PASS\033[0m"
FAIL = "\033[91m FAIL\033[0m"

def check(name: str, passed: bool, detail: str = ""):
    status = PASS if passed else FAIL
    line = f"  [{status}] {name}"
    if detail:
        line += f"\n         {detail}"
    print(line)
    return passed


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_happy_path():
    token = generate_action_token(SAMPLE_PAYLOAD, SECRET, duration_hours=24)
    payload = validate_action_token(token, SECRET, CURRENT_SEQUENCE)

    ok = (
        payload["account_id"]      == SAMPLE_PAYLOAD["account_id"]
        and payload["check_id"]    == SAMPLE_PAYLOAD["check_id"]
        and payload["resource_id"] == SAMPLE_PAYLOAD["resource_id"]
        and payload["action"]      == SAMPLE_PAYLOAD["action"]
        and payload["recipient_email"] == SAMPLE_PAYLOAD["recipient_email"]
        and payload["scan_sequence"]   == SAMPLE_PAYLOAD["scan_sequence"]
    )
    return check("Happy path — valid token validates successfully", ok)


def test_url_safety():
    token = generate_action_token(SAMPLE_PAYLOAD, SECRET, duration_hours=24)
    url   = f"https://example.lambda-url.us-east-1.on.aws/?token={token}"
    bad_chars = set(token) & {"+", "/", "=", " ", "\n"}
    ok = len(bad_chars) == 0
    return check(
        "URL safety — token has no characters that break email hrefs",
        ok,
        detail=f"token={token[:60]}..." if ok else f"bad chars found: {bad_chars}",
    )


def test_field_integrity():
    token   = generate_action_token(SAMPLE_PAYLOAD, SECRET, duration_hours=24)
    payload = validate_action_token(token, SECRET, CURRENT_SEQUENCE)
    required = {"jti", "iat", "exp", "account_id", "check_id",
                "resource_id", "action", "recipient_email", "scan_sequence"}
    missing = required - set(payload.keys())
    ok = len(missing) == 0
    return check(
        "Field integrity — payload contains all required fields",
        ok,
        detail=f"missing: {missing}" if missing else f"jti={payload['jti']}, exp={payload['exp']}",
    )


def test_determinism():
    # Same payload → different tokens (jti randomises each call)
    t1 = generate_action_token(SAMPLE_PAYLOAD, SECRET)
    t2 = generate_action_token(SAMPLE_PAYLOAD, SECRET)
    ok = t1 != t2
    return check("Determinism — same payload produces unique tokens (jti)", ok)


def test_signature_tamper():
    token = generate_action_token(SAMPLE_PAYLOAD, SECRET)
    # Flip the last character of the signature segment
    payload_b64, sig_b64 = token.rsplit(".", 1)
    bad_char = "A" if sig_b64[-1] != "A" else "B"
    tampered = f"{payload_b64}.{sig_b64[:-1]}{bad_char}"
    try:
        validate_action_token(tampered, SECRET, CURRENT_SEQUENCE)
        return check("Signature tamper — raises TokenSignatureError", False,
                     detail="ERROR: no exception raised")
    except TokenSignatureError as e:
        return check("Signature tamper — raises TokenSignatureError", True,
                     detail=str(e))
    except Exception as e:
        return check("Signature tamper — raises TokenSignatureError", False,
                     detail=f"Wrong exception: {type(e).__name__}: {e}")


def test_payload_tamper():
    # Modify the payload segment but leave the original signature
    token = generate_action_token(SAMPLE_PAYLOAD, SECRET)
    payload_b64, sig_b64 = token.rsplit(".", 1)
    # Corrupt a byte in the middle of the payload
    mid = len(payload_b64) // 2
    corrupted_b64 = payload_b64[:mid] + ("A" if payload_b64[mid] != "A" else "B") + payload_b64[mid+1:]
    tampered = f"{corrupted_b64}.{sig_b64}"
    try:
        validate_action_token(tampered, SECRET, CURRENT_SEQUENCE)
        return check("Payload tamper — raises TokenSignatureError", False,
                     detail="ERROR: no exception raised")
    except TokenSignatureError as e:
        return check("Payload tamper — raises TokenSignatureError", True,
                     detail=str(e))
    except Exception as e:
        return check("Payload tamper — raises TokenSignatureError", False,
                     detail=f"Wrong exception: {type(e).__name__}: {e}")


def test_expired_token():
    # Generate token as if it was issued 25 hours ago
    past = int(time.time()) - (25 * 3600)
    with unittest.mock.patch("token_utils.time") as mock_time:
        mock_time.time.return_value = past
        mock_time.uuid4 = token_utils.uuid.uuid4  # keep uuid working
        expired_token = generate_action_token(SAMPLE_PAYLOAD, SECRET, duration_hours=24)

    try:
        validate_action_token(expired_token, SECRET, CURRENT_SEQUENCE)
        return check("Expired token — raises TokenExpiredError", False,
                     detail="ERROR: no exception raised")
    except TokenExpiredError as e:
        return check("Expired token — raises TokenExpiredError", True,
                     detail=str(e))
    except Exception as e:
        return check("Expired token — raises TokenExpiredError", False,
                     detail=f"Wrong exception: {type(e).__name__}: {e}")


def test_rollback_duration():
    # ROLLBACK tokens should survive 48 hours, not expire at 24
    past = int(time.time()) - (30 * 3600)  # 30 hours ago — stale for 24h, valid for 48h
    with unittest.mock.patch("token_utils.time") as mock_time:
        mock_time.time.return_value = past
        mock_time.uuid4 = token_utils.uuid.uuid4
        rollback_token = generate_action_token(
            {**SAMPLE_PAYLOAD, "action": "ROLLBACK"},
            SECRET,
            duration_hours=48,
        )

    try:
        payload = validate_action_token(rollback_token, SECRET, CURRENT_SEQUENCE)
        ok = payload["action"] == "ROLLBACK"
        return check("Rollback duration — 48h token valid at 30h mark", ok)
    except TokenExpiredError as e:
        return check("Rollback duration — 48h token valid at 30h mark", False,
                     detail=f"Incorrectly expired: {e}")
    except Exception as e:
        return check("Rollback duration — 48h token valid at 30h mark", False,
                     detail=f"Unexpected error: {type(e).__name__}: {e}")


def test_stale_sequence():
    # Token has scan_sequence=5 but current is 7
    stale_payload = {**SAMPLE_PAYLOAD, "scan_sequence": 5}
    token = generate_action_token(stale_payload, SECRET)
    try:
        validate_action_token(token, SECRET, current_scan_sequence=7)
        return check("Stale sequence — raises TokenSequenceError", False,
                     detail="ERROR: no exception raised")
    except TokenSequenceError as e:
        return check("Stale sequence — raises TokenSequenceError", True,
                     detail=str(e))
    except Exception as e:
        return check("Stale sequence — raises TokenSequenceError", False,
                     detail=f"Wrong exception: {type(e).__name__}: {e}")


def test_future_sequence():
    # Token has scan_sequence=99 (future) — also rejected
    future_payload = {**SAMPLE_PAYLOAD, "scan_sequence": 99}
    token = generate_action_token(future_payload, SECRET)
    try:
        validate_action_token(token, SECRET, current_scan_sequence=7)
        return check("Future sequence — raises TokenSequenceError", False,
                     detail="ERROR: no exception raised")
    except TokenSequenceError as e:
        return check("Future sequence — raises TokenSequenceError", True,
                     detail=str(e))
    except Exception as e:
        return check("Future sequence — raises TokenSequenceError", False,
                     detail=f"Wrong exception: {type(e).__name__}: {e}")


def test_wrong_secret():
    token = generate_action_token(SAMPLE_PAYLOAD, SECRET)
    try:
        validate_action_token(token, "completely_different_secret", CURRENT_SEQUENCE)
        return check("Wrong secret — raises TokenSignatureError", False,
                     detail="ERROR: no exception raised")
    except TokenSignatureError as e:
        return check("Wrong secret — raises TokenSignatureError", True,
                     detail=str(e))
    except Exception as e:
        return check("Wrong secret — raises TokenSignatureError", False,
                     detail=f"Wrong exception: {type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("\nS3 Sentry — token_utils.py verification\n")

    tests = [
        test_happy_path,
        test_url_safety,
        test_field_integrity,
        test_determinism,
        test_signature_tamper,
        test_payload_tamper,
        test_expired_token,
        test_rollback_duration,
        test_stale_sequence,
        test_future_sequence,
        test_wrong_secret,
    ]

    results = [t() for t in tests]
    passed  = sum(results)
    total   = len(results)

    print(f"\n{passed}/{total} tests passed.")
    if passed < total:
        print("Fix the failures above before proceeding to lambda_handler.py updates.")
        input("\nPress Enter to close...")
        sys.exit(1)
    else:
        print("All checks green. token_utils.py is ready.")
        input("\nPress Enter to close...")
        sys.exit(0)
