"""Each remediation against moto's S3: plan -> apply -> verify -> restore -> verify."""
import os
import boto3
import pytest
from moto import mock_aws

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from remediation import FULL, PARTIAL, REGISTRY, RemediationError, for_check


@pytest.fixture
def s3():
    with mock_aws():
        c = boto3.client("s3")
        c.create_bucket(Bucket="bucket-one")
        yield c


def roundtrip(r, s3, check):
    before = r.read(s3, "bucket-one")
    plan = r.plan(before, check)
    assert plan.changes_needed
    r.apply(s3, "bucket-one", plan.after)
    r.verify(s3, "bucket-one", plan.after)
    r.restore(s3, "bucket-one", before)
    r.verify(s3, "bucket-one", r.restorable_state(before))
    return before, plan


def test_registry_covers_expected_checks():
    assert set(REGISTRY) == {
        "s3_bucket_level_public_access_block", "s3_bucket_public_access",
        "s3_bucket_default_encryption", "s3_bucket_object_versioning"}
    assert for_check("s3_bucket_object_lock") is None   # guidance only
    assert for_check("s3_bucket_no_mfa_delete") is None


def test_public_access_block_from_nothing(s3):
    s3.delete_public_access_block(Bucket="bucket-one")
    r = for_check("s3_bucket_level_public_access_block")
    before, plan = roundtrip(r, s3, "s3_bucket_level_public_access_block")
    assert before == {"configured": False}
    assert plan.undo == FULL and plan.warnings


def test_public_access_block_partial_settings_restored_exactly(s3):
    s3.put_public_access_block(Bucket="bucket-one", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": False,
        "BlockPublicPolicy": False, "RestrictPublicBuckets": True})
    r = for_check("s3_bucket_public_access")
    before, _ = roundtrip(r, s3, "s3_bucket_public_access")
    assert r.read(s3, "bucket-one") == before


def test_encryption_from_nothing_and_back(s3):
    s3.delete_bucket_encryption(Bucket="bucket-one")
    r = for_check("s3_bucket_default_encryption")
    before, _ = roundtrip(r, s3, "s3_bucket_default_encryption")
    assert before == {"configured": False}


def test_encryption_does_not_downgrade_kms(s3):
    s3.put_bucket_encryption(Bucket="bucket-one", ServerSideEncryptionConfiguration={"Rules": [
        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]})
    r = for_check("s3_bucket_default_encryption")
    plan = r.plan(r.read(s3, "bucket-one"), "s3_bucket_default_encryption")
    assert not plan.changes_needed


def test_versioning_never_enabled_is_partial_undo(s3):
    r = for_check("s3_bucket_object_versioning")
    before = r.read(s3, "bucket-one")
    assert before == {"Status": "Never enabled"}
    plan = r.plan(before, "s3_bucket_object_versioning")
    assert plan.undo == PARTIAL and "suspend" in plan.undo_note
    r.apply(s3, "bucket-one", plan.after); r.verify(s3, "bucket-one", plan.after)
    r.restore(s3, "bucket-one", before)
    assert r.read(s3, "bucket-one") == {"Status": "Suspended"}
    r.verify(s3, "bucket-one", r.restorable_state(before))


def test_versioning_suspended_is_full_undo(s3):
    s3.put_bucket_versioning(Bucket="bucket-one", VersioningConfiguration={"Status": "Suspended"})
    r = for_check("s3_bucket_object_versioning")
    _, plan = roundtrip(r, s3, "s3_bucket_object_versioning")
    assert plan.undo == FULL


def test_verify_catches_a_change_that_did_not_take(s3):
    r = for_check("s3_bucket_default_encryption")
    with pytest.raises(RemediationError):
        r.verify(s3, "bucket-one", {"configured": True, "Rules": [
            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]})
