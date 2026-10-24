"""Scan email: ignored findings stay out, Fix only for fixable checks, log link present."""
import os
from unittest import mock

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
import lambda_handler as lh
import token_utils

F = [
    {"CheckID": "s3_bucket_level_public_access_block", "ResourceId": "b1", "ResourceArn": "arn:aws:s3:::b1",
     "Severity": "high", "Status": "FAIL", "CheckTitle": "PAB"},
    {"CheckID": "s3_bucket_object_lock", "ResourceId": "b1", "ResourceArn": "arn:aws:s3:::b1",
     "Severity": "low", "Status": "FAIL", "CheckTitle": "Lock"},
    {"CheckID": "s3_bucket_default_encryption", "ResourceId": "b2", "ResourceArn": "arn:aws:s3:::b2",
     "Severity": "medium", "Status": "FAIL", "CheckTitle": "Enc"},
]


def summary():
    return {"account_id": "111122223333", **lh.summarize(F)}


def test_apply_suppressions_recounts():
    s = lh.apply_suppressions(summary(), {("s3_bucket_default_encryption", "b2")})
    assert s["fail_count"] == 2 and s["ignored_count"] == 1
    assert s["buckets_affected"] == 1 and s["severity_breakdown"]["medium"] == 0


def test_email_links(monkeypatch):
    monkeypatch.setattr(lh, "SES_FROM_ADDRESS", "scanner@example.com")
    monkeypatch.setattr(lh, "RESPONDER_URL", "https://resp.example")
    sent = {}
    fake = mock.Mock()
    fake.send_email.side_effect = lambda **kw: sent.update(kw)
    with mock.patch("boto3.client", return_value=fake):
        s = lh.apply_suppressions(summary(), {("s3_bucket_default_encryption", "b2")})
        lh._send_dashboard_email("111122223333", s, "owner@example.com", 7, "k")
    body = sent["Message"]["Body"]["Html"]["Data"]
    assert body.count("Review fix") == 1          # PAB only; Object Lock is manual
    assert "Manual fix" in body
    assert "Enc" not in body                       # ignored finding not shown
    assert "1 ignored finding not shown" in body
    assert "View your action log" in body
    tok = body.split("https://resp.example?token=")[-1].split('"')[0]
    p = token_utils.validate_action_token(tok, "k", 0, check_sequence=False)
    assert p["action"] == "LOG"


def test_read_only_tenant_gets_no_fix_buttons(monkeypatch):
    monkeypatch.setattr(lh, "SES_FROM_ADDRESS", "scanner@example.com")
    monkeypatch.setattr(lh, "RESPONDER_URL", "https://resp.example")
    sent = {}
    fake = mock.Mock()
    fake.send_email.side_effect = lambda **kw: sent.update(kw)
    with mock.patch("boto3.client", return_value=fake):
        lh._send_dashboard_email("111122223333", lh.apply_suppressions(summary(), set()),
                                 "owner@example.com", 7, "k", remediation_enabled=False)
    body = sent["Message"]["Body"]["Html"]["Data"]
    assert "Review fix" not in body and body.count("Manual fix") == 3
