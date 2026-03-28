# S3 Sentry — Engineering Journal

> A living record of the technical decisions, scars, and breakthroughs behind
> building a multi-tenant AWS S3 security scanner from scratch.
> Intended as source material for Medium and Dev.to articles.

---

## The Blueprint Phase — Designing Before Building

### The Pivot
The project started as a single-account Boto3 script (`s3-misconfig.py`) that
manually checked S3 bucket configurations one API call at a time. The pivot came
when we asked: *what if this served hundreds of customers?* A bespoke Boto3
loop doesn't scale, doesn't map to compliance frameworks, and can't be
maintained as AWS releases new S3 features.

The answer was to adopt **Prowler** — an open-source AWS security scanner with
pre-built checks already mapped to NIST, CIS, HIPAA, and SOC2 — as the scanning
engine, and to design around a **Central Brain** architecture: all logic lives in
a single Provider account; client accounts expose exactly one IAM role and
nothing else. Zero logic deployed to the customer.

### The Scar
The hardest design constraint to accept was the **confused deputy problem**.
A naive cross-account architecture trusts any caller from the provider account.
If an attacker tricks the orchestrator into making an `sts:AssumeRole` call on
their behalf, the customer's account is compromised. The fix — `sts:ExternalId`
— is an AWS best practice that almost no SMB SaaS product implements correctly.
Every tenant gets a UUID generated *by S3 Sentry before the customer deploys
anything*, locked into their CloudFormation trust policy. Without that token, the
role cannot be assumed — even by someone inside the provider account.

### The 'Aha!' Moment
The architecture crystallized when we mapped the DynamoDB single-table design to
the scan lifecycle:
- `PK=ACC#<AccountId>` + `SK=METADATA` → tenant onboarding record
- `PK=ACC#<AccountId>` + `SK=SCAN#<CheckID>#<ResourceID>` → individual finding

A GSI on `SK` (`SK-index`) means tenant discovery costs O(n tenants) regardless
of how many millions of findings exist in the table. That's the insight that made
multi-tenancy feel real rather than theoretical.

### The Best Practice
**Single-Table Design with a GSI inverted index.** Rather than a findings table
and a tenants table (two round-trips, two IAM policies, two billing dimensions),
everything lives in one `S3Sentry` table. The GSI lets the orchestrator discover
all active tenants with a single `query` call. NIST CSF v1.1 control IDs are
stored as a `ComplianceMapping` attribute on every `FAIL` finding at write time —
no post-processing required for compliance reporting.

---

## Phase 1 — The Scanning Engine

### The Pivot
The original `run_s3_scan` function iterated through S3 buckets using raw Boto3
calls: `s3.get_bucket_encryption()`, `s3.get_bucket_versioning()`, and so on.
This worked for one account but had three fatal problems at scale: (1) each new
S3 check required new Boto3 code and new IAM permissions research; (2) there was
no compliance framework mapping; (3) there was no concept of tenants — the
account was hardcoded.

The pivot: replace manual Boto3 loops with **Prowler's programmatic Python API**
(v3.16.17), and replace the hardcoded account with a **DynamoDB-driven tenant
loop** — the orchestrator wakes up, queries the `SK-index` GSI for all
`SK=METADATA` records, and runs a scan for each one.

### The Scar
**The Python version wall.** The system Python on the development machine was
3.14 (installed via the Windows Store). Prowler 3.x depends on Pydantic v1, and
Pydantic v1 uses internal CPython type-inference APIs that were silently broken
in 3.12+. The error:

```
pydantic.errors.ConfigError: unable to infer type for attribute "Compliance"
```

appeared even after manually reinstalling Pydantic v1. The fix required three
layers of defense:

1. A dedicated Python 3.11 virtual environment (`py -3.11 -m venv .venv`)
2. A `run_orchestrator.bat` launcher that activates `.venv` before running the
   script — so double-clicking the `.py` file is impossible
3. A Python version guard at the very top of `orchestrator.py`:
   ```python
   if sys.version_info >= (3, 12):
       sys.exit(1)
   ```

**The terminal that vanished.** Before the version guard existed, the script
crashed during imports — before any `try/finally` block could keep the window
open. The fix was `atexit.register()` as the literal first line of the file,
before every import. `atexit` fires on any interpreter exit, including import
failures. That single line turned invisible crashes into readable error messages.

### The 'Aha!' Moment
The first time the orchestrator queried DynamoDB, found a tenant record, assumed
the cross-account role via `sts:AssumeRole` with `ExternalId`, and received valid
temporary credentials — that was the moment the architecture proved itself. A
single Python process, running in Account A, was now authenticated as a role in
Account B. The IAM handshake worked.

### The Best Practice
**Explicit `boto3.Session()` everywhere.** Relying on ambient credentials
(environment variables, `~/.aws/credentials`) is fine for local dev but creates
invisible failures in multi-account code. Every function that needs AWS access
receives a `boto3.Session` object explicitly constructed with the assumed-role
credentials. This makes the credential chain auditable, testable, and correct
when multiple tenants are scanned in sequence.

---

## Phase 2 — Client Infrastructure and the Handshake

### The Pivot
**Three pivots, all forced by reality:**

**Pivot 1 — Trust policy principal.** The `client_onboarding.yaml` CloudFormation
template was designed to trust a specific role ARN:
`arn:aws:iam::390488375643:role/S3SentryOrchestratorRole`. CloudFormation
rejected it with `CREATE_FAILED: Invalid principal in policy` because that role
doesn't exist yet (it's a Phase 3 deliverable). The temporary fix: use the
account root (`arn:aws:iam::390488375643:root`) with a `TODO` comment to tighten
it in Phase 3. The `sts:ExternalId` condition still provides the confused deputy
protection in the interim.

**Pivot 2 — Remediation gating.** The original design had an `EnableRemediation`
CloudFormation parameter (a boolean) that conditionally attached a write policy
to the role. This was removed in favor of deploying *both* audit and remediation
permissions from day one. The business reason: "one-click fix" emails (Phase 4)
require the write permissions to already exist. Asking customers to update a
CloudFormation stack before they can use a feature kills conversion.

**Pivot 3 — Prowler Python API → CLI subprocess.** The most consequential pivot
of the project. After the `AWS_Audit_Info` constructor fights (see below), we
abandoned the Prowler Python API entirely and switched to running Prowler as a
subprocess, injecting the assumed-role credentials as `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` environment variables.

### The Scar
**The `AWS_Audit_Info` constructor saga.** Prowler 3.16.17 has no official
programmatic API documentation. The constructor signature had to be discovered
through error messages alone, across multiple sessions:

- **Round 1:** 11-argument constructor (copied from an older Prowler example):
  `original_session`, `audit_session`, etc. — all wrong.
- **Round 2:** Switched to 5 arguments (`profile`, `profile_region`,
  `credentials`, `mfa_enabled`, `assumed_role_info`) — correct for 3.16.17.
- **Round 3:** `'NoneType' object is not callable` — `AWS_Credentials` was found
  but `AWS_Assumed_Role` was `None`. The import loop stopped at the first module
  that had `AWS_Audit_Info` without continuing to search for the credential
  helper classes.
- **Round 4:** We wrote `inspect_prowler.py` — a diagnostic script using
  `inspect.getmembers()` and `pkgutil.walk_packages()` to list every class in
  every submodule of `prowler.providers.aws.lib.audit_info.*`. The scanner
  revealed that the class is named **`AWS_Assume_Role`** (present tense, no
  `_Info` suffix) — not `AWS_Assumed_Role` and not `AWS_Assumed_Role_Info`.
- **Round 5:** Correct class name, but: `missing 1 required positional argument:
  'role_session_name'`. Added `role_session_name="S3SentryScanSession"`.

At this point, rather than continue probing an undocumented internal API, we
switched to the subprocess strategy.

**The `UnicodeEncodeError` on Windows.** Once the subprocess approach worked,
Prowler's `alive_progress` library tried to render Unicode progress bar
characters to the Windows console:
```
UnicodeEncodeError: 'charmap' codec can't encode character '\u2588'
```
The fix: two environment variables injected into the subprocess:
```python
env["PYTHONIOENCODING"] = "utf-8"
env["PYTHONUNBUFFERED"] = "1"
```
Plus `--quiet` and `--no-banner` CLI flags, which suppress the progress bar
entirely. `encoding="utf-8", errors="replace"` on the `subprocess.run` call
ensures our own process handles any residual non-UTF-8 output gracefully.

### The 'Aha!' Moment
The two-script onboarding handshake clicking into place:

1. **`generate_launch_url.py`** generates a UUID `ExternalId`, saves it to
   `.pending_tenant`, and prints a CloudFormation Quick-Create URL with the
   `ExternalId` pre-filled as a parameter. The customer clicks the link, deploys
   the stack in their account, and copies three values from the Outputs tab.

2. **`onboard_tenant.py`** reads the `ExternalId` from `.pending_tenant`, prompts
   for the customer's `RoleArn` and email, parses the `AccountId` from the ARN
   (`arn.split(":")[4]`), and writes a single DynamoDB `METADATA` item.

The orchestrator then picks up that item on its next run, assumes the role with
the stored `ExternalId`, and runs the scan. The entire lifecycle — from UUID
generation to findings in DynamoDB — flows without manual credential sharing or
AWS console intervention.

### The Best Practice
**Subprocess credential injection over programmatic API initialization.** Passing
temporary credentials as `AWS_*` environment variables to a subprocess is a
well-established pattern (used by AWS CodeBuild, GitHub Actions OIDC, and AWS
CLI role chaining). It is:

- **Version-agnostic:** The orchestrator doesn't care which internal classes
  Prowler uses to initialize its session. The subprocess sees standard AWS SDK
  credential resolution.
- **Auditable:** Every scan runs as a named, time-boxed assumed-role session
  (`DurationSeconds=900`). CloudTrail in the client account logs every API call
  made by that session under the role name.
- **Isolated:** `os.environ.copy()` plus `env.pop("AWS_PROFILE", None)` ensures
  the subprocess inherits no ambient credentials that could bleed across tenants.
- **Safe:** Temp dir for JSON output is created with `tempfile.mkdtemp()` and
  always deleted in a `finally` block — no scan artifacts persist on disk.

The `sts:ExternalId` condition on the trust policy means that even if the
orchestrator's AWS credentials were compromised, an attacker could not assume any
customer's role without also possessing the per-tenant UUID — a secret that never
appears in logs, CloudFormation events (`NoEcho: true`), or source code.

---

*Last updated: Phase 2 complete — cross-account scan verified end-to-end.*
*Next: Phase 3 — Step Function orchestration (Scan → Store → Email → PAUSE).*
