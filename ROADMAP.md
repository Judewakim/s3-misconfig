# Roadmap: from portfolio demo to paid product

S3 Sentry is a working scanner with a public read-only demo. It is **not** ready to sell. This is what has to be true before anyone pays.

## Where it stands (Oct 2026)

| Area | Status |
|---|---|
| Daily multi-tenant scanning (14 Prowler S3 checks, NIST CSF mapping) | Working |
| Cross-account access (ExternalId + PrincipalArn trust) | Working |
| Public read-only live demo (`demo/`, `web/`) | Working |
| Signed Fix / Ignore links (HMAC, single-use, 24 h, scan-sequence bound) | Working; signature now also checked before the confirmation page reads anything |
| Remediation framework (read / plan / apply / verify / restore per check) | Working (`remediation/`) |
| Fixes | Built for 4 checks (bucket Block Public Access, public bucket, default encryption, versioning); `DRY_RUN` on by default |
| Pre-change warning | Working: live before/after, what can break, cost, and whether it can be undone |
| Rollback | Working: checksummed vault snapshot read back before the fix, signed 48 h Undo link, restore from snapshot, verified, logged; survives new scans |
| Ignore | Working: emails skip ignored findings, show how many were hidden, and offer Stop ignoring |
| Action log | Working: every fix, undo, ignore and practice run; CSV and JSON download via a signed 7-day link in each email |
| Signup, billing, self-serve onboarding | Missing (onboarding is two local scripts) |

## Must-haves before charging

Items 1–4 are done (Oct 2026). What's left is item 5 (more checks) and item 6 (the product itself).

### 1. Every action logged and downloadable
- Every Fix, Ignore and Rollback writes an audit record: who (email in the signed link, also passed as STS `SourceIdentity` so it shows in the customer's CloudTrail), what, when, before and after config, and the vault key.
- Dry-run results are logged the same way, marked as dry runs.
- A customer page lists the log and downloads it as CSV and JSON.

### 2. Ignore that sticks
- Scans and emails skip findings with a `SUPPRESS#` record, and the dashboard lists ignored findings so they can be un-ignored.

### 3. Warn before changing anything
The confirmation page must show, for that exact bucket:
- the current setting and the setting after the fix, side by side;
- what can break (for example, "public website URLs stop working", "apps using ACLs lose access", "HTTP clients are blocked");
- cost impact if any (KMS requests, extra versions, log storage);
- **whether the change can be undone**, using the per-check table below. If undo is partial or impossible, say so in plain words before the button.

### 4. Rollback that is proven to work
- Snapshot the full relevant config to the vault **before** the fix (already done).
- Verify the snapshot can be restored *before* applying the fix: read it back, check it parses and that the restore call is valid for this check. If not, the warning says rollback isn't available and the default action changes to "Ignore".
- Rollback restores **from the vault snapshot**, re-reads the bucket to confirm it matches, and logs the result.
- Rollback links are offered for 48 h after a fix.

### 5. Per-check remediation plan

| Check | Fix | Undo | Notes for the warning |
|---|---|---|---|
| Bucket-level Block Public Access | Built | Full | Public URLs stop working |
| Account-level Block Public Access | To build | Full | Affects every bucket in the account |
| Bucket publicly accessible | Via Block Public Access | Full | |
| ACL allows public listing | To build | Full | Reset ACL to private |
| ACL allows public writes | To build | Full | Reset ACL to private |
| Policy allows public writes | Guidance only | n/a | Policy edits need human review |
| ACLs disabled (owner enforced) | To build | Full | Apps relying on ACLs lose access |
| Default encryption | Built | Full | Existing objects not re-encrypted |
| KMS encryption | To build | Full | Customer picks a key; KMS cost |
| Versioning | Built | Partial | Can only be suspended, never removed |
| Object Lock | Guidance only | None | Can't be disabled once on |
| MFA Delete | Not possible | n/a | Root user only |
| Server access logging | To build | Full | Needs a log bucket; storage cost |
| Require HTTPS policy | To build | Full | Must merge with existing policy; blocks HTTP |

This table must be on the pricing page so customers know what isn't automated before they pay.

### 6. Product basics
- Signup with email verification; self-serve CloudFormation onboarding (reuse the demo's presigned quick-create flow).
- Stripe checkout and plan limits (accounts, scan frequency).
- Customer dashboard: latest findings, history, log download.
- Terms, privacy policy, and a clear statement of what the cross-account role can do.
- Turn `DRY_RUN` off per customer only after they opt in.

## Scope, stated plainly

Covers S3 bucket and account-level S3 configuration only. Not included yet: object contents (sensitive data discovery), IAM, other AWS services, runtime threat detection, other clouds, and formal compliance attestations (HIPAA, PCI DSS, SOC 2).

**Is 14 checks enough?** For an S3 configuration scanner it covers the core risks: public exposure, encryption, recoverability and logging. Notable S3 gaps to add later: lifecycle rules, replication, event notifications, access-point Block Public Access, and cross-account access in bucket policies.
