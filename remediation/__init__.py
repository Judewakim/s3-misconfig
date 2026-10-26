"""Registry of checks S3 Sentry can fix. A check not listed here is guidance-only."""

from .base import FULL, NONE, PARTIAL, Plan, Remediation, RemediationError, canonical
from .handlers import BucketPublicAccessBlock, DefaultEncryption, Versioning

_ALL = (BucketPublicAccessBlock(), DefaultEncryption(), Versioning())

REGISTRY: dict = {cid: r for r in _ALL for cid in r.check_ids}


def for_check(check_id: str):
    """The Remediation for a Prowler check ID, or None if it's guidance-only."""
    return REGISTRY.get(check_id)


__all__ = ["REGISTRY", "for_check", "Plan", "Remediation", "RemediationError",
           "canonical", "FULL", "PARTIAL", "NONE"]
