"""Concrete remediations. Each one is registered in remediation/__init__.py."""

from __future__ import annotations

from botocore.exceptions import ClientError

from .base import FULL, PARTIAL, Remediation

_PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _code(err: ClientError) -> str:
    return err.response.get("Error", {}).get("Code", "")


class BucketPublicAccessBlock(Remediation):
    """Turn on all four bucket-level Block Public Access settings.

    Also the fix for 'bucket is publicly accessible': with all four on, ACL and
    policy grants to the public stop working."""

    check_ids = ("s3_bucket_level_public_access_block", "s3_bucket_public_access")
    title = "Turn on Block Public Access for this bucket"
    action = "Turns on all four Block Public Access settings for this bucket."
    warnings = (
        "Anything that reads this bucket over a public URL stops working, "
        "including static websites served straight from S3.",
        "Public ACL and bucket-policy grants are ignored while this is on.",
    )

    def read(self, s3, bucket):
        try:
            cfg = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        except ClientError as e:
            if _code(e) == "NoSuchPublicAccessBlockConfiguration":
                return {"configured": False}
            raise
        return {"configured": True, **{k: bool(cfg.get(k, False)) for k in _PAB_KEYS}}

    def desired(self, state):
        return {"configured": True, **{k: True for k in _PAB_KEYS}}

    def apply(self, s3, bucket, desired):
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={k: desired[k] for k in _PAB_KEYS},
        )

    def restore(self, s3, bucket, snapshot):
        if snapshot.get("configured"):
            s3.put_public_access_block(
                Bucket=bucket,
                PublicAccessBlockConfiguration={k: snapshot[k] for k in _PAB_KEYS},
            )
        else:
            s3.delete_public_access_block(Bucket=bucket)


class DefaultEncryption(Remediation):
    """Set SSE-S3 (AES-256) as the bucket's default encryption."""

    check_ids = ("s3_bucket_default_encryption",)
    title = "Turn on default encryption"
    action = "Sets AES-256 (SSE-S3) as the default encryption for new objects."
    warnings = (
        "Only new uploads are encrypted. Existing objects stay as they are "
        "until they are copied or rewritten.",
    )

    def read(self, s3, bucket):
        try:
            cfg = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]
        except ClientError as e:
            if _code(e) == "ServerSideEncryptionConfigurationNotFoundError":
                return {"configured": False}
            raise
        return {"configured": True, "Rules": cfg.get("Rules", [])}

    def desired(self, state):
        # Already encrypted (e.g. with KMS): leave it alone rather than downgrade.
        if state.get("configured") and state.get("Rules"):
            return state
        return {"configured": True,
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}

    def matches(self, actual, expected):
        def algos(s):
            return sorted(
                (r.get("ApplyServerSideEncryptionByDefault") or {}).get("SSEAlgorithm", "")
                for r in s.get("Rules", [])
            ) if s.get("configured") else []
        return actual.get("configured") == expected.get("configured") and algos(actual) == algos(expected)

    def apply(self, s3, bucket, desired):
        s3.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={"Rules": desired["Rules"]},
        )

    # Since Jan 2023 AWS encrypts every bucket with SSE-S3 and DeleteBucketEncryption
    # resets to SSE-S3 rather than "none". So "not configured" can only be
    # restored as SSE-S3, which is what this fix sets anyway.
    _SSE_S3 = {"configured": True,
               "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}

    def undo_for(self, state):
        if not state.get("configured"):
            return PARTIAL, ("AWS now encrypts every bucket by default, so undo can't remove "
                             "encryption; it leaves the AWS default (SSE-S3).")
        return FULL, ""

    def restorable_state(self, snapshot):
        return snapshot if snapshot.get("configured") else self._SSE_S3

    def restore(self, s3, bucket, snapshot):
        target = self.restorable_state(snapshot)
        s3.put_bucket_encryption(Bucket=bucket,
                                 ServerSideEncryptionConfiguration={"Rules": target["Rules"]})


class Versioning(Remediation):
    """Turn on versioning. AWS never lets a versioned bucket go back to
    'never versioned', only to 'suspended', so undo can be partial."""

    check_ids = ("s3_bucket_object_versioning",)
    title = "Turn on versioning"
    action = "Turns on versioning so overwritten or deleted objects can be recovered."
    warnings = (
        "Every overwrite and delete keeps the old version, so storage use grows "
        "until a lifecycle rule expires old versions.",
    )
    cost_note = "Old versions are billed as normal S3 storage."

    def read(self, s3, bucket):
        status = s3.get_bucket_versioning(Bucket=bucket).get("Status")
        return {"Status": status or "Never enabled"}

    def desired(self, state):
        return {"Status": "Enabled"}

    def undo_for(self, state):
        if state.get("Status") == "Never enabled":
            return PARTIAL, ("Undo can only suspend versioning. AWS never lets a bucket "
                             "go back to 'never versioned', and versions kept while it "
                             "was on stay until you delete them.")
        return FULL, ""

    def restorable_state(self, snapshot):
        if snapshot.get("Status") == "Never enabled":
            return {"Status": "Suspended"}
        return snapshot

    def apply(self, s3, bucket, desired):
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": desired["Status"]})

    def restore(self, s3, bucket, snapshot):
        target = self.restorable_state(snapshot)["Status"]
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": target})
