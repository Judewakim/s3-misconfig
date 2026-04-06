# Phase 4: Interactive SOAR Platform — Technical Blueprint

> **Status:** Sprint 2 Complete — Responder Lambda deployed and verified
> **Depends on:** Phase 3 complete (Lambda + ECR + EventBridge + SNS verified ✓)
> **Paradigm:** Moving from passive SNS alerting to an interactive security operations platform.
> Customers receive an HTML dashboard email, click action buttons, and approve automated fixes.

---

## Infrastructure Sprint — COMPLETE ✓

All provider-side infrastructure for Phase 4 is deployed and verified.

| Component | Status | Notes |
|-----------|--------|-------|
| `S3SentryResponder` Lambda | Deployed | Image-type, `responder.handler` CMD, env vars at birth |
| Responder Function URL | Live | Managed by `deploy.ps1` (not CFN — see scar below) |
| HMAC signing key | Seeded | SSM `/s3sentry/hmac_signing_key` as SecureString |
| `RESPONDER_URL` env var | Wired | Injected into `S3SentryOrchestrator` |
| `deploy.ps1` | Complete | One-click full deployment; see Sprint 2 scars below |
| End-to-end scan | Verified | Findings confirmed; correct Prowler check IDs now in place |

### Infrastructure Scars (do not repeat)

**Docker manifest list / "media type not supported"**
Docker BuildKit pushes an OCI Image Index (manifest list) by default, even for single-platform builds. Lambda rejects this. ECR shows two digests — the real `amd64` layer and an "unknown" manifest wrapper.
Fix (in `deploy.ps1`): `docker buildx build --platform linux/amd64 --provenance=false --load`

**AWS::Lambda::Url ghost resource**
CloudFormation's `AWS::Lambda::Url` resource consistently reported success and returned a URL string in stack outputs, but the URL was never attached to the Lambda function (console showed nothing; requests returned `403 Forbidden`). Persisted across multiple stack delete/recreates.
Fix: Removed `AWS::Lambda::Url` and `AWS::Lambda::Permission` from CFN entirely. `deploy.ps1` creates the URL via `aws lambda create-function-url-config` and the permission via `aws lambda add-permission`. URL is read back via `get-function-url-config` and injected into the Orchestrator.

**SSM SecureString conflict**
CloudFormation cannot create `SecureString` parameters. Including `HMACSigningKey` as a CFN resource caused it to overwrite the real SecureString key with a plain `String "CHANGE_ME"` on every deploy.
Fix: Removed `HMACSigningKey` from CFN. `deploy.ps1` Step 1 owns the SSM parameter lifecycle.

**Cross-account trust policy role ID vs ARN**
After deleting and recreating the provider stack, `S3SentryOrchestratorRole` was assigned a new internal role ID (`AROA...`). The client account's trust policy stored the old role ID (not the ARN), so every `sts:AssumeRole` call returned `AccessDenied`.
Fix: Updated the trust policy in account `928459458650` to use the ARN `arn:aws:iam::390488375643:role/S3SentryOrchestratorRole` instead of the orphaned role ID. **If the provider stack is ever deleted and recreated, this trust policy must be updated again.**

**PowerShell + AWS CLI JSON quoting (Windows)**
- `Set-Content -Encoding UTF8` writes a UTF-8 BOM. AWS CLI JSON parser rejects BOM-prefixed files with "Invalid JSON received".
- `file:///C:\path` is invalid in AWS CLI. The correct format is `file://C:/path` (two slashes, forward slashes).
Fix (in `deploy.ps1`): `[System.IO.File]::WriteAllText` with `UTF8Encoding($false)` + `"file://" + $path.Replace("\", "/")`.

---

## System Architecture

```
EventBridge (daily cron)
       │
       ▼
S3SentryOrchestrator Lambda (container, Prowler)
  ├── Pulls tenant list from DynamoDB
  ├── For each tenant:
  │     ├── STS AssumeRole (ExternalId)
  │     ├── Prowler CLI scan (14 S3 checks — verified in Prowler v3.16.17)
  │     ├── Writes findings → DynamoDB
  │     └── [PHASE 4] Sends SES HTML dashboard email with signed action tokens
  └── Returns scan summary

Customer clicks action button in email
       │
       ▼
S3SentryResponder Lambda (Function URL, public)
  ├── Validates HMAC token (expiry + single-use nonce)
  ├── GET /action?token=...  → renders confirmation popup
  └── POST /confirm          → executes FIX / IGNORE / ROLLBACK
        ├── Safety Engine: snapshots current config to S3 Vault
        ├── Applies fix via cross-account assumed session
        └── Writes REMEDIATION# audit item to DynamoDB
```

---

## Sprint Overview

| Sprint | Deliverable | New Files | Status |
|--------|-------------|-----------|--------|
| Infra | Provider infrastructure, deploy.ps1 | `deploy.ps1` | ✓ Complete |
| 1 | HMAC token system + SES HTML email | `token_utils.py` | ✓ Complete |
| 2 | Responder Lambda (FIX / IGNORE / ROLLBACK) | `responder.py` | ⚠ Blocked — see below |
| 3 | Confidence Engine (0–100 score per finding) | `confidence.py` | Next |
| 4 | Rollback + Yesterday's Activity section | — | Planned |
| 5 | Suppression system | `suppressor.py` | Planned |

---

## Sprint 1 — HMAC Token System + SES HTML Email ✓ COMPLETE

**Delivered:**
- `token_utils.py` — HMAC-SHA256 token generation/validation, SSM key retrieval with module-level cache, `TokenSignatureError` / `TokenExpiredError` / `TokenSequenceError` exceptions, 11/11 tests passing locally
- `lambda_handler.py` — `increment_scan_sequence()` (atomic DynamoDB `ADD`), `_build_action_url()`, `_send_dashboard_email()` (SES HTML with severity breakdown + per-finding Fix Now / Ignore buttons), SNS fallback when SES prerequisites absent
- `Dockerfile` — added `COPY token_utils.py` so it's available in the Lambda container
- `deploy.ps1` — added `aws lambda update-function-code` step after image push (CFN alone doesn't update Lambda when `:latest` tag doesn't change)
- `provider_infrastructure.yaml` — added `dynamodb:UpdateItem` to `S3SentryOrchestratorRole` (required by `increment_scan_sequence`)

**Verified:** `scanSequence: 1` confirmed in Lambda response. 12 findings across 3 buckets processed.

**Scar:** `dynamodb:UpdateItem` was missing from the Orchestrator IAM policy — `increment_scan_sequence` uses `update_item` with `ADD`, which is a separate action from `PutItem`. Always audit DynamoDB permissions when adding new write patterns.

---

## Sprint 1 — HMAC Token System + SES HTML Email (archive)

### token_utils.py

Generates and validates single-use signed tokens embedded in email action buttons.

**Token format:** `base64url(payload_json).<base64url(hmac_sha256_signature)>`

**Payload fields:**
```json
{
  "account_id": "928459458650",
  "check_id":   "s3_bucket_public_access",
  "resource_id": "my-prod-bucket",
  "action":     "FIX",
  "exp":        1234567890
}
```

**Expiry:** 24h for FIX/IGNORE, 48h for ROLLBACK.

**Single-use enforcement:** On first use, write `PK=TOKEN#<token_id>, SK=USED` to DynamoDB. Reject if item already exists.

**Key source:** `aws ssm get-parameter --name /s3sentry/hmac_signing_key --with-decryption`

### SES HTML Email (lambda_handler.py update)

Replace `_publish_summary()` SNS plain-text with `_send_dashboard_email()` SES HTML.

**Email sections:**
1. **Risk Summary** — overall risk level derived from highest severity finding
2. **Severity Breakdown** — Critical / High / Medium / Low counts with color coding
3. **Findings Table** — per-finding rows with Bucket, Risk, Issue, NIST Control
4. **Action Buttons** — per-finding: `[Fix Now]` / `[Ignore]` links (HMAC-signed URLs pointing to Responder Function URL)

**New env vars used:** `SES_FROM_ADDRESS`, `HMAC_KEY_PATH`, `RESPONDER_URL`

**IAM already in place:** `S3SentrySES` policy on `S3SentryOrchestratorRole` grants `ses:SendEmail`.

**SES prerequisite:** Verify `scanner@wakimworks.com` in SES before Sprint 1 deploy.

---

## Sprint 2 — Responder Lambda ✓ COMPLETE

**Delivered:**
- `responder.py` — full Responder Lambda with 4-Layer Gatekeeper + Safety Engine + HTML confirmation UI
- `deploy.ps1` — updated with Zip→Image migration, Function URL probe-first creation, `wait function-updated` race fix, env vars injected at function birth, S3 Vault bucket creation (Step 2b)
- Correct Prowler v3.16.17 check IDs (`s3_bucket_level_public_access_block`) wired into HANDLERS and SAFETY_SUMMARIES

**4-Layer Gatekeeper (POST):**
1. Cryptographic — HMAC-SHA256 signature validation via `token_utils.validate_action_token`
2. Freshness — `exp` checked + `scan_sequence` monotonicity via `TokenSequenceError`
3. Idempotency — DynamoDB conditional `PutItem` on `TOKEN#<jti>` (`ConditionExpression=Attr("PK").not_exists()`)
4. Safety Snapshot — before-state written to S3 Vault before any write

**Routes:**
- `GET /?token=<token>` → Safety Summary HTML confirmation page (title, action description, severity)
- `POST /` → token re-validation → nonce consumed → dispatch to handler → audit log

**Supported check IDs for FIX:**
- `s3_bucket_level_public_access_block` → `PutPublicAccessBlock` (all 4 flags = True)
- `s3_bucket_default_encryption` → `PutBucketEncryption` (SSE-S3 / AES256)

**DRY_RUN env var:** When `DRY_RUN=true` (default), logs intent but makes no AWS write calls.

### Sprint 2 Scars (do not repeat)

**Zip→Image migration on Responder**: `S3SentryResponder` was initially created as Zip-type placeholder. Calling `update-function-code --image-uri` on a Zip function raises `InvalidParameterValueException`. Fix in `deploy.ps1`: detect package type, preserve IAM role ARN, delete function, recreate as Image with env vars in the same create call.

**ResourceNotFoundException on get-function-url-config after Zip→Image migration**: Deleting and recreating the function also destroys the Function URL. Fix: probe-first pattern — `aws lambda get-function-url-config 2>&1`, check `$LASTEXITCODE`, create only if missing.

**KeyError: S3_VAULT_BUCKET**: Recreating the function without env vars left the Responder missing `S3_VAULT_BUCKET`. Fix: (1) derive bucket name as `s3sentry-vault-<AccountId>` (account-scoped for S3 global uniqueness), (2) add Step 2b vault bucket creation to `deploy.ps1`, (3) inject all env vars in the `$createJson` at create time.

**ResourceConflictException on Orchestrator**: `update-function-code` is async. Immediately calling `update-function-configuration` hit a race. Fix: `aws lambda wait function-updated` after every code update.

**Prowler silently skips unknown check IDs**: All 8 original `S3_CHECKS` entries were wrong — Prowler v3.16.17 uses different IDs with no warning on unknown names. Detected via `diagnose_scan.py --list-checks`. The correct bucket-level Block Public Access check is `s3_bucket_level_public_access_block`, not `s3_bucket_public_access_block`. Full corrected list is now in `lambda_handler.py`.

**CFN `PackageType` is immutable**: CloudFormation cannot change a Lambda's `PackageType` (Zip→Image) in-place. With a hardcoded `FunctionName`, resource replacement also fails (name conflict). Fix: removed `ResponderFunction` from the CFN template entirely — it is now fully managed by `deploy.ps1` Steps 6–7. `ResponderRole`, `ResponderLogGroup`, and vault IAM policy remain CFN-managed.

**CFN `UPDATE_ROLLBACK_FAILED`**: When CFN failed to update `ResponderFunction` (Zip→Image), the rollback also failed (CFN tried to restore it to Zip but the actual function is Image-type). Stack was stuck and rejected all new deploys. Fix: `aws cloudformation continue-update-rollback --resources-to-skip ResponderFunction`. `deploy.ps1` now auto-detects this state and runs the recovery command before attempting a deploy.

**`S3SentryResponderRole` missing `s3:PutObject` on vault bucket**: The `VaultBucketName` CFN parameter defaulted to `"s3sentry-vault"` but the actual bucket is `"s3sentry-vault-390488375643"`. Fix: pass `VaultBucketName=$S3_VAULT_BUCKET` in `--parameter-overrides` in `deploy.ps1` Step 6.

### Current Blocker — Sprint 2 not yet fully verified

**Error:** Pressing the Fix button on the confirmation page returns:
```json
{"Message":"Forbidden. For troubleshooting Function URL authorization issues, see: https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html"}
```
**What this means:** The Lambda Function URL is returning a 403. The POST request from the browser is being rejected before it reaches `responder.py`. The Function URL has `AuthType=NONE` and a public invoke permission (`AllowPublicURL` statement), so this is likely one of:
1. The `AllowPublicURL` permission statement is missing or attached to the wrong function version/alias after the latest recreation.
2. A CORS preflight (OPTIONS) is being rejected — the CORS config only allows GET and POST, not OPTIONS.
3. The `add-permission` call in `deploy.ps1` used statement ID `AllowPublicURL` on first creation and `AllowPublicFunctionUrl` on subsequent runs — a duplicate or missing statement may exist.

**To resume:** Check the Function URL's resource-based policy:
```
aws lambda get-policy --function-name S3SentryResponder --region us-east-1
```
Confirm a statement with `lambda:InvokeFunctionUrl`, `Principal: "*"`, and `FunctionUrlAuthType: NONE` exists. If missing, add it manually or re-run `deploy.ps1` (the `add-permission` step in Step 8 is idempotent-safe).

---

## Sprint 3 — Confidence Engine

### confidence.py

Assigns a 0–100 confidence score to each finding. Controls the email UI:
- Score ≥ 70 → `[Fix Now]` button (direct action)
- Score < 70 → `[View Recommendation]` link (informational)

**Baseline scores per check:**
| Check ID | Baseline |
|----------|----------|
| `s3_bucket_level_public_access_block` | 95 |
| `s3_bucket_public_access` | 98 |
| `s3_bucket_default_encryption` | 85 |
| `s3_bucket_object_versioning` | 70 |
| `s3_bucket_server_access_logging_enabled` | 65 |
| `s3_bucket_secure_transport_policy` | 80 |

**Dynamic modifiers:** +5 if finding appeared in previous scan (persistent), −10 if bucket name contains `log` or `backup` (conservative treatment).

---

## Sprint 4 — Rollback + Yesterday's Activity

**Yesterday's Activity** section added to the SES email: queries `REMEDIATION#` items from DynamoDB for the past 24h and renders a summary table (what was fixed, when, by whom).

**Rollback flow:** Responder reads `Before` JSON from S3 Vault (`s3sentry-vault/<AccountId>/<timestamp>/<check_id>/<resource>.json`) and calls the inverse AWS API to restore the prior configuration.

---

## Sprint 5 — Suppression System

### suppressor.py

When a customer clicks `[Ignore]`:
- Writes `PK=ACC#<AccountId>`, `SK=SUPPRESS#<CheckID>#<ResourceId>` to DynamoDB
- `lambda_handler.py` filters suppressed findings before generating tokens or counting FAIL findings

Suppressions are permanent until manually deleted. No expiry in MVP.

---

## DynamoDB Schema — Phase 4 Additions

| PK | SK | Purpose |
|----|----|---------|
| `ACC#<AccountId>` | `REMEDIATION#<ts>#<CheckID>#<ResourceId>` | Audit trail — before/after state, result |
| `ACC#<AccountId>` | `SUPPRESS#<CheckID>#<ResourceId>` | Suppression record |
| `TOKEN#<token_id>` | `USED` | Single-use nonce enforcement |

No new GSIs needed. All queries use PK + SK `begins_with`.

---

## IAM Status

All Phase 4 IAM permissions are already deployed:

| Permission | Role | Status |
|-----------|------|--------|
| `ses:SendEmail`, `ses:SendRawEmail` | OrchestratorRole | ✓ Deployed |
| `ssm:GetParameter` on `/s3sentry/*` | OrchestratorRole + ResponderRole | ✓ Deployed |
| `sts:AssumeRole` on `*/S3SentryCrossAccountRole` | ResponderRole | ✓ Deployed |
| `dynamodb:GetItem/PutItem/Query` | ResponderRole | ✓ Deployed |
| `s3:GetObject/PutObject` on vault bucket | ResponderRole | ✓ Deployed |
| `s3:PutBucketPublicAccessBlock`, `PutEncryptionConfiguration`, etc. | S3SentryCrossAccountRole (client) | ✓ Deployed (Phase 2) |

---

## File Manifest

| File | Action | Sprint |
|------|--------|--------|
| `deploy.ps1` | Created | Infra ✓ |
| `token_utils.py` | Create | 1 |
| `lambda_handler.py` | Modify (`_send_dashboard_email`, token generation) | 1 |
| `responder.py` | Create | 2 |
| `confidence.py` | Create | 3 |
| `suppressor.py` | Create | 5 |
| `provider_infrastructure.yaml` | Complete | Infra ✓ |
