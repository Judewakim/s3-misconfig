"""End-to-end Responder tests on moto: GET warning page -> POST fix -> undo -> log."""
import importlib
import json
import os
import re
from urllib.parse import quote, unquote

import boto3
import pytest
from moto import mock_aws

os.environ.update({
    "AWS_DEFAULT_REGION": "us-east-1", "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing", "S3_VAULT_BUCKET": "s3sentry-vault-test",
    "DYNAMODB_TABLE": "S3Sentry",
})

ACCT = "123456789012"   # moto's default account, so assumed-role calls hit the same S3
BUCKET = "customer-data"
KEY = "test-signing-key"


def _env(dry):
    os.environ["DRY_RUN"] = "true" if dry else "false"


@pytest.fixture(params=[False])
def live(request):
    _env(request.param)
    with mock_aws():
        ddb = boto3.client("dynamodb")
        ddb.create_table(TableName="S3Sentry", BillingMode="PAY_PER_REQUEST",
                         AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"},
                                               {"AttributeName": "SK", "AttributeType": "S"}],
                         KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"},
                                    {"AttributeName": "SK", "KeyType": "RANGE"}])
        boto3.client("ssm").put_parameter(Name="/s3sentry/hmac_signing_key", Value=KEY, Type="SecureString")
        iam = boto3.client("iam")
        role = iam.create_role(RoleName="S3SentryCrossAccountRole", AssumeRolePolicyDocument="{}")["Role"]["Arn"]
        boto3.resource("dynamodb").Table("S3Sentry").put_item(Item={
            "PK": f"ACC#{ACCT}", "SK": "METADATA", "RoleArn": role, "ExternalId": "ext-123",
            "ScanSequence": 3, "Email": "owner@example.com"})
        s3 = boto3.client("s3")
        s3.create_bucket(Bucket="s3sentry-vault-test")
        s3.create_bucket(Bucket=BUCKET)
        s3.delete_public_access_block(Bucket=BUCKET)
        import token_utils
        token_utils._KEY_CACHE.clear()
        import responder
        importlib.reload(responder)
        yield responder, s3


def tok(action, check="s3_bucket_level_public_access_block", seq=3, **extra):
    import token_utils
    p = {"account_id": ACCT, "check_id": check, "resource_id": BUCKET, "action": action,
         "recipient_email": "owner@example.com", "scan_sequence": seq, **extra}
    return token_utils.generate_action_token(p, KEY, 24)


def get(responder, token, **q):
    params = {"token": token, **q}
    return responder.handler({"requestContext": {"http": {"method": "GET"}},
                              "queryStringParameters": params}, None)


def post(responder, token):
    return responder.handler({"requestContext": {"http": {"method": "POST"}},
                              "body": "token=" + quote(token)}, None)


def links(body):
    return [unquote(m) for m in re.findall(r"href='\?token=([^'&]+)", body)]


def test_get_shows_live_before_after_and_undo(live):
    responder, s3 = live
    r = get(responder, tok("FIX"))
    assert r["statusCode"] == 200
    assert '&quot;configured&quot;: false' in r["body"] and "What can break" in r["body"]
    assert "Undo link that works for 48 hours" in r["body"]
    assert "frame-ancestors 'none'" in r["headers"]["Content-Security-Policy"]


def test_forged_link_is_rejected_before_reading_anything(live):
    responder, _ = live
    t = tok("FIX")
    forged = t[:-4] + ("AAAA" if not t.endswith("AAAA") else "BBBB")
    assert get(responder, forged)["statusCode"] == 400


def test_stale_fix_link_rejected_but_rollback_survives_new_scan(live):
    responder, _ = live
    assert get(responder, tok("FIX", seq=2))["statusCode"] == 409


def test_fix_then_undo_then_log(live):
    responder, s3 = live
    t = tok("FIX")
    r = post(responder, t)
    assert r["statusCode"] == 200 and "applied and verified" in r["body"]
    cfg = s3.get_public_access_block(Bucket=BUCKET)["PublicAccessBlockConfiguration"]
    assert all(cfg.values())

    # same link can't be replayed
    assert post(responder, t)["statusCode"] == 409

    undo, log = links(r["body"])
    # a newer scan runs before the owner clicks Undo: must still work
    boto3.resource("dynamodb").Table("S3Sentry").update_item(
        Key={"PK": f"ACC#{ACCT}", "SK": "METADATA"}, UpdateExpression="SET ScanSequence = :s",
        ExpressionAttributeValues={":s": 4})
    g = get(responder, undo)
    assert g["statusCode"] == 200 and "Undo:" in g["body"]
    u = post(responder, undo)
    assert u["statusCode"] == 200 and "restored and verified" in u["body"]
    with pytest.raises(s3.exceptions.ClientError):
        s3.get_public_access_block(Bucket=BUCKET)          # back to "not configured"

    # second undo is refused
    assert post(responder, undo)["statusCode"] == 409

    j = get(responder, log, format="json")
    rows = json.loads(j["body"])
    assert [x["Action"] for x in rows] == ["ROLLBACK", "FIX"]
    assert rows[1]["Before"] == {"configured": False}
    c = get(responder, log, format="csv")
    assert c["headers"]["Content-Type"].startswith("text/csv") and "ROLLBACK" in c["body"]
    assert get(responder, log)["statusCode"] == 200
    # the log link can't be POSTed to make changes
    assert post(responder, log)["statusCode"] == 400


def test_tampered_snapshot_blocks_undo(live):
    responder, s3 = live
    r = post(responder, tok("FIX"))
    undo = links(r["body"])[0]
    key = s3.list_objects_v2(Bucket="s3sentry-vault-test")["Contents"][0]["Key"]
    s3.put_object(Bucket="s3sentry-vault-test", Key=key, Body=b'{"state":{"configured":false},"evil":1}')
    u = post(responder, undo)
    assert u["statusCode"] == 500 and "integrity" in u["body"]


def test_versioning_partial_undo_is_disclosed(live):
    responder, s3 = live
    t = tok("FIX", check="s3_bucket_object_versioning")
    g = get(responder, t)
    assert "Partly." in g["body"] and "suspend" in g["body"]
    r = post(responder, t)
    undo = links(r["body"])[0]
    assert "Partial undo" in get(responder, undo)["body"]
    post(responder, undo)
    assert s3.get_bucket_versioning(Bucket=BUCKET)["Status"] == "Suspended"


def test_unfixable_check_is_refused(live):
    responder, _ = live
    assert get(responder, tok("FIX", check="s3_bucket_object_lock"))["statusCode"] == 422


def test_ignore_and_unignore(live):
    responder, _ = live
    r = post(responder, tok("IGNORE"))
    table = boto3.resource("dynamodb").Table("S3Sentry")
    key = {"PK": f"ACC#{ACCT}", "SK": f"SUPPRESS#s3_bucket_level_public_access_block#{BUCKET}"}
    assert table.get_item(Key=key).get("Item")
    post(responder, links(r["body"])[0])
    assert not table.get_item(Key=key).get("Item")


def test_already_compliant_bucket_changes_nothing(live):
    responder, s3 = live
    s3.put_public_access_block(Bucket=BUCKET, PublicAccessBlockConfiguration={
        k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")})
    assert "Nothing to change" in get(responder, tok("FIX"))["body"] or \
           "already has the right settings" in get(responder, tok("FIX"))["body"]


def test_csv_neutralises_formulas():
    import responder
    assert responder._csv_cell("=HYPERLINK(1)") == "'=HYPERLINK(1)"
    assert responder._csv_cell("ok") == "ok"


def test_dry_run_changes_nothing():
    _env(True)
    with mock_aws():
        ddb = boto3.client("dynamodb")
        ddb.create_table(TableName="S3Sentry", BillingMode="PAY_PER_REQUEST",
                         AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"},
                                               {"AttributeName": "SK", "AttributeType": "S"}],
                         KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"},
                                    {"AttributeName": "SK", "KeyType": "RANGE"}])
        boto3.client("ssm").put_parameter(Name="/s3sentry/hmac_signing_key", Value=KEY, Type="SecureString")
        role = boto3.client("iam").create_role(RoleName="S3SentryCrossAccountRole", AssumeRolePolicyDocument="{}")["Role"]["Arn"]
        boto3.resource("dynamodb").Table("S3Sentry").put_item(Item={
            "PK": f"ACC#{ACCT}", "SK": "METADATA", "RoleArn": role, "ExternalId": "ext-123", "ScanSequence": 3})
        s3 = boto3.client("s3")
        s3.create_bucket(Bucket="s3sentry-vault-test"); s3.create_bucket(Bucket=BUCKET)
        s3.delete_public_access_block(Bucket=BUCKET)
        import token_utils; token_utils._KEY_CACHE.clear()
        import responder; importlib.reload(responder)
        r = post(responder, tok("FIX"))
        assert "practice mode" in r["body"]
        with pytest.raises(s3.exceptions.ClientError):
            s3.get_public_access_block(Bucket=BUCKET)       # untouched
    _env(False)


# ── Regression tests for the security review findings ─────────────────────────

def _flip_dry_run(responder, value):
    responder.DRY_RUN = value


def test_practice_undo_refused_once_live(live):
    """Finding 1: a practice-run Undo link must not make a real change later."""
    responder, s3 = live
    _flip_dry_run(responder, True)
    r = post(responder, tok("FIX"))
    undo = links(r["body"])[0]
    s3.put_public_access_block(Bucket=BUCKET, PublicAccessBlockConfiguration={
        k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")})
    _flip_dry_run(responder, False)
    u = post(responder, undo)
    assert u["statusCode"] == 409 and "practice run" in u["body"]
    assert all(s3.get_public_access_block(Bucket=BUCKET)["PublicAccessBlockConfiguration"].values())


def test_undo_after_later_change_needs_confirmation(live):
    """Finding 2: undo warns and refuses to overwrite later changes silently."""
    responder, s3 = live
    r = post(responder, tok("FIX"))
    undo = links(r["body"])[0]
    s3.put_public_access_block(Bucket=BUCKET, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": False, "RestrictPublicBuckets": True})
    g = get(responder, undo)
    assert "Settings changed since the fix" in g["body"] and "confirm_drift" in g["body"]
    assert post(responder, undo)["statusCode"] == 409            # no confirmation
    # link was not spent by the refused attempt; confirming works
    ok = responder.handler({"requestContext": {"http": {"method": "POST"}},
                            "body": "token=" + quote(undo) + "&confirm_drift=1"}, None)
    assert ok["statusCode"] == 200 and "restored and verified" in ok["body"]


def test_audit_failure_after_change_does_not_claim_nothing_changed(live, monkeypatch):
    """Finding 3: a PENDING record exists before the change, and the error page is honest."""
    responder, s3 = live
    calls = {"n": 0}
    real = responder.audit_update
    def boom(*a, **k):
        calls["n"] += 1
        raise RuntimeError("dynamo down")
    monkeypatch.setattr(responder, "audit_update", boom)
    r = post(responder, tok("FIX"))
    assert calls["n"] == 1 and r["statusCode"] == 200        # change applied, page still honest
    items = boto3.resource("dynamodb").Table("S3Sentry").scan()["Items"]
    assert any(i.get("Status") == "PENDING" and i.get("VaultKey") for i in items)


def test_failed_undo_offers_retry(live, monkeypatch):
    """Finding 5: a failed restore releases the claim and issues a fresh link."""
    responder, s3 = live
    r = post(responder, tok("FIX"))
    undo = links(r["body"])[0]
    h = responder.remediation.for_check("s3_bucket_level_public_access_block")
    monkeypatch.setattr(type(h), "restore", lambda self, *a: (_ for _ in ()).throw(RuntimeError("x")))
    u = post(responder, undo)
    assert "Try the undo again" in u["body"]
    monkeypatch.undo()
    retry = links(u["body"])[0]
    assert "restored and verified" in post(responder, retry)["body"]


def test_read_only_tenant_cannot_fix(live):
    """Finding 6: read-only customers get a clear refusal, not a scary failure."""
    responder, _ = live
    boto3.resource("dynamodb").Table("S3Sentry").update_item(
        Key={"PK": f"ACC#{ACCT}", "SK": "METADATA"}, UpdateExpression="SET RemediationEnabled = :f",
        ExpressionAttributeValues={":f": False})
    r = post(responder, tok("FIX"))
    assert r["statusCode"] == 403 and "read-only" in r["body"]


def test_source_identity_sanitised():
    """Finding 4: odd characters in the email can't break role assumption."""
    import responder
    assert responder._source_identity("o'brien@example.com") == "obrien@example.com"
    assert responder._source_identity("a") is None
    assert len(responder._source_identity("x" * 100)) == 64


# ── Second review round ───────────────────────────────────────────────────────

def test_unrecorded_fix_offers_no_dead_undo_link(live, monkeypatch):
    """A: if the result can't be recorded, don't hand out an Undo link that 404s."""
    responder, _ = live
    monkeypatch.setattr(responder, "audit_update", lambda *a, **k: (_ for _ in ()).throw(RuntimeError()))
    r = post(responder, tok("FIX"))
    assert "not fully recorded" in r["body"] and not links(r["body"])


def test_stuck_claim_expires(live):
    """B: a claim left by a crash can be taken over after 15 minutes."""
    responder, _ = live
    r = post(responder, tok("FIX"))
    undo = links(r["body"])[0]
    table = boto3.resource("dynamodb").Table("S3Sentry")
    fix = [i for i in table.scan()["Items"] if i.get("Action") == "FIX"][0]
    table.update_item(Key={"PK": fix["PK"], "SK": fix["SK"]}, UpdateExpression="SET RollbackClaim = :t",
                      ExpressionAttributeValues={":t": "2000-01-01T00:00:00+00:00"})
    assert "restored and verified" in post(responder, undo)["body"]


def test_drift_and_partial_notes_both_shown(live):
    """C: partial-undo note must not erase the drift warning."""
    responder, s3 = live
    r = post(responder, tok("FIX", check="s3_bucket_object_versioning"))
    undo = links(r["body"])[0]
    s3.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Suspended"})
    body = get(responder, undo)["body"]
    assert "Settings changed since the fix" in body and "Partial undo" in body


def test_undo_window_enforced(live):
    """D: past RollbackUntil, undo is refused even with a fresh link."""
    responder, _ = live
    r = post(responder, tok("FIX"))
    undo = links(r["body"])[0]
    table = boto3.resource("dynamodb").Table("S3Sentry")
    fix = [i for i in table.scan()["Items"] if i.get("Action") == "FIX"][0]
    table.update_item(Key={"PK": fix["PK"], "SK": fix["SK"]}, UpdateExpression="SET RollbackUntil = :t",
                      ExpressionAttributeValues={":t": "2000-01-01T00:00:00+00:00"})
    assert post(responder, undo)["statusCode"] == 410


def test_used_link_rejected_before_touching_customer_account(live, monkeypatch):
    """E: a spent undo link must not cause cross-account reads."""
    responder, _ = live
    r = post(responder, tok("FIX"))
    undo = links(r["body"])[0]
    post(responder, undo)
    called = []
    monkeypatch.setattr(responder, "_customer_s3", lambda *a: called.append(1))
    assert post(responder, undo)["statusCode"] == 409 and not called
