"""Tests for the live-demo API and scanner. Run: python -m pytest -q tests/"""

import importlib
import json
import os
import sys
from unittest import mock

import boto3
import botocore.exceptions
import pytest
from moto import mock_aws

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "demo")]

os.environ.update({
    "AWS_DEFAULT_REGION": "us-east-1", "AWS_REGION": "us-east-1",
    "AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
    "DEMO_TABLE": "S3SentryDemo", "DEMO_TEMPLATE_BUCKET": "s3sentry-demo-templates-test",
    "MAX_SESSIONS_PER_IP_PER_DAY": "2", "MAX_SCANS_PER_DAY": "1",
})


@pytest.fixture
def api():
    with mock_aws():
        boto3.client("dynamodb").create_table(
            TableName="S3SentryDemo", BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"},
                                  {"AttributeName": "SK", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"},
                       {"AttributeName": "SK", "KeyType": "RANGE"}])
        import demo_api
        importlib.reload(demo_api)
        demo_api._lambda = mock.Mock()
        yield demo_api


def call(api, path, body=None, ip="203.0.113.7"):
    ev = {"rawPath": path, "requestContext": {"http": {"method": "POST", "sourceIp": ip}},
          "body": json.dumps(body or {})}
    r = api.handler(ev, None)
    return r["statusCode"], json.loads(r["body"])


def test_session_creates_launch_url_and_hides_raw_session_id(api):
    code, body = call(api, "/sessions")
    assert code == 201
    assert "quickcreate" in body["launchUrl"] and "param_ExternalId" in body["launchUrl"]
    assert "X-Amz-Signature" in body["launchUrl"]          # presigned, bucket stays private
    assert "s3sentry-demo-templates-test.s3" in body["launchUrl"]
    items = api._table.scan()["Items"]
    sessions = [i for i in items if i["PK"].startswith("SESSION#")]
    assert len(sessions) == 1
    assert body["sessionId"] not in json.dumps(items, default=str)   # only the hash is stored
    assert len(sessions[0]["ExternalId"]) >= 43                     # 256-bit


def test_per_ip_rate_limit(api):
    assert call(api, "/sessions")[0] == 201
    assert call(api, "/sessions")[0] == 201
    code, body = call(api, "/sessions")
    assert code == 429 and body["error"] == "RATE_LIMITED"
    assert call(api, "/sessions", ip="198.51.100.9")[0] == 201      # other IPs unaffected


def test_rejects_bad_input(api):
    assert call(api, "/sessions/scan", {"sessionId": "x"})[1]["error"] == "BAD_SESSION"
    sid = call(api, "/sessions")[1]["sessionId"]
    assert call(api, "/sessions/scan", {"sessionId": sid, "accountId": "12345"})[1]["error"] == "BAD_ACCOUNT"
    assert call(api, "/sessions/status", {"sessionId": "A" * 43})[0] == 404
    assert call(api, "/nope")[0] == 404


def test_role_not_ready_keeps_session_pending(api):
    sid = call(api, "/sessions")[1]["sessionId"]
    err = botocore.exceptions.ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, "AssumeRole")
    with mock.patch.object(api._sts, "assume_role", side_effect=err):
        code, body = call(api, "/sessions/scan", {"sessionId": sid, "accountId": "111122223333"})
    assert code == 409 and body["error"] == "ROLE_NOT_READY"
    assert call(api, "/sessions/status", {"sessionId": sid})[1]["status"] == "PENDING"
    api._lambda.invoke.assert_not_called()


def test_scan_queues_once_and_enforces_daily_cap(api):
    sid = call(api, "/sessions")[1]["sessionId"]
    with mock.patch.object(api._sts, "assume_role") as ar:
        code, body = call(api, "/sessions/scan", {"sessionId": sid, "accountId": "1111-2222-3333"})
        assert code == 202 and body["status"] == "SCANNING"
        assert ar.call_args.kwargs["RoleArn"] == "arn:aws:iam::111122223333:role/S3SentryDemoReadOnlyRole"
        # same session again: no second scan
        assert call(api, "/sessions/scan", {"sessionId": sid, "accountId": "111122223333"})[0] == 200
        assert api._lambda.invoke.call_count == 1
        # new session, but the global daily cap (1) is used up
        sid2 = call(api, "/sessions", ip="198.51.100.9")[1]["sessionId"]
        code, body = call(api, "/sessions/scan", {"sessionId": sid2, "accountId": "444455556666"})
        assert code == 429 and body["error"] == "DAILY_CAP"


def test_scanner_writes_compact_results(api):
    sid = call(api, "/sessions")[1]["sessionId"]
    with mock.patch.object(api._sts, "assume_role"):
        call(api, "/sessions/scan", {"sessionId": sid, "accountId": "111122223333"})
    pk = json.loads(api._lambda.invoke.call_args.kwargs["Payload"])["sessionKey"]

    fake = [
        {"CheckID": "s3_bucket_public_access", "CheckTitle": "Public bucket", "Status": "FAIL",
         "Severity": "critical", "ResourceId": "b1", "ResourceArn": "arn:aws:s3:::b1", "StatusExtended": "x"},
        {"CheckID": "s3_bucket_default_encryption", "CheckTitle": "Enc", "Status": "PASS",
         "Severity": "medium", "ResourceId": "b2", "ResourceArn": "arn:aws:s3:::b2", "StatusExtended": "y"},
    ]
    import demo_scanner
    importlib.reload(demo_scanner)
    with mock.patch.object(demo_scanner, "run_prowler", return_value=("111122223333", fake)):
        demo_scanner.handler({"sessionKey": pk}, None)

    code, body = call(api, "/sessions/status", {"sessionId": sid})
    assert body["status"] == "DONE"
    res = body["result"]
    assert res["failCount"] == 1 and res["severity"]["critical"] == 1 and res["bucketsScanned"] == 2
    assert res["findings"][0]["status"] == "FAIL"
    assert res["findings"][0]["nist"]


def test_scanner_reports_lost_access(api):
    sid = call(api, "/sessions")[1]["sessionId"]
    with mock.patch.object(api._sts, "assume_role"):
        call(api, "/sessions/scan", {"sessionId": sid, "accountId": "111122223333"})
    pk = json.loads(api._lambda.invoke.call_args.kwargs["Payload"])["sessionKey"]
    import demo_scanner
    importlib.reload(demo_scanner)
    err = botocore.exceptions.ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, "AssumeRole")
    with mock.patch("boto3.client") as bc:
        bc.return_value.assume_role.side_effect = err
        demo_scanner.handler({"sessionKey": pk}, None)
    body = call(api, "/sessions/status", {"sessionId": sid})[1]
    assert body["status"] == "ERROR" and "stack" in body["error"]


def test_launch_link_refresh(api):
    sid = call(api, "/sessions")[1]["sessionId"]
    code, body = call(api, "/sessions/launch", {"sessionId": sid})
    assert code == 200 and "X-Amz-Signature" in body["launchUrl"]
    with mock.patch.object(api._sts, "assume_role"):
        call(api, "/sessions/scan", {"sessionId": sid, "accountId": "111122223333"})
    assert call(api, "/sessions/launch", {"sessionId": sid})[0] == 409
