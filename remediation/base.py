"""
Remediation framework.

Every fixable check is one Remediation subclass. The Responder never calls the
S3 API directly; it goes through this interface so each fix is read, planned,
applied, verified and (where AWS allows) undone the same way:

    state  = r.read(s3, bucket)          # current settings, JSON-serialisable
    plan   = r.plan(state)               # what will change, what can break, undo level
    r.apply(s3, bucket, plan.after)      # make the change
    r.verify(s3, bucket, plan.after)     # re-read and confirm it took
    r.restore(s3, bucket, state)         # put the snapshot back (undo)
    r.verify(s3, bucket, r.restorable_state(state))

Undo levels
-----------
FULL     restoring the snapshot returns the bucket to exactly how it was.
PARTIAL  AWS allows only part of the way back (e.g. versioning can be suspended,
         never removed). `plan.undo_note` says what can't be undone.
NONE     AWS can't reverse it at all. These checks are guidance-only and are not
         registered here, so the Responder can never apply them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

FULL, PARTIAL, NONE = "full", "partial", "none"


class RemediationError(Exception):
    """A fix or restore could not be applied or did not verify."""


@dataclass
class Plan:
    check_id: str
    title: str
    before: dict
    after: dict
    changes_needed: bool
    undo: str                       # FULL | PARTIAL | NONE
    undo_note: str = ""
    warnings: list = field(default_factory=list)
    cost_note: str = ""

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id, "title": self.title,
            "before": self.before, "after": self.after,
            "changes_needed": self.changes_needed, "undo": self.undo,
            "undo_note": self.undo_note, "warnings": list(self.warnings),
            "cost_note": self.cost_note,
        }


def canonical(state: dict) -> str:
    """Deterministic JSON so snapshots can be checksummed and compared."""
    return json.dumps(state, sort_keys=True, separators=(",", ":"), default=str)


class Remediation:
    check_ids: tuple = ()           # Prowler check IDs this fixes
    title: str = ""
    action: str = ""                # one sentence, shown before the change
    warnings: tuple = ()            # what can break
    cost_note: str = ""

    # --- to implement -------------------------------------------------------
    def read(self, s3, bucket: str) -> dict:
        raise NotImplementedError

    def desired(self, state: dict) -> dict:
        raise NotImplementedError

    def apply(self, s3, bucket: str, desired: dict) -> None:
        raise NotImplementedError

    def restore(self, s3, bucket: str, snapshot: dict) -> None:
        raise NotImplementedError

    # --- overridable defaults ----------------------------------------------
    def undo_for(self, state: dict) -> tuple[str, str]:
        """(undo level, note) for undoing a fix applied on top of `state`."""
        return FULL, ""

    def restorable_state(self, snapshot: dict) -> dict:
        """The state a restore actually produces (differs from the snapshot
        only for PARTIAL undo)."""
        return snapshot

    def matches(self, actual: dict, expected: dict) -> bool:
        return canonical(actual) == canonical(expected)

    # --- shared behaviour ---------------------------------------------------
    def plan(self, state: dict, check_id: str) -> Plan:
        after = self.desired(state)
        undo, note = self.undo_for(state)
        return Plan(
            check_id=check_id, title=self.title, before=state, after=after,
            changes_needed=not self.matches(state, after), undo=undo,
            undo_note=note, warnings=list(self.warnings), cost_note=self.cost_note,
        )

    def verify(self, s3, bucket: str, expected: dict) -> dict:
        actual = self.read(s3, bucket)
        if not self.matches(actual, expected):
            raise RemediationError(
                f"{self.title}: bucket settings did not match after the change "
                f"(expected {canonical(expected)}, found {canonical(actual)})."
            )
        return actual
