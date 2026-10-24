# S3 Sentry: The Autonomous Data Security Officer

S3 Sentry is a high-fidelity, multi-tenant security orchestration platform designed to provide continuous oversight of AWS S3 storage environments. It acts as an automated "Data Security Officer," ensuring that organizational data remains private, encrypted, and compliant without manual intervention.

**Try it:** [live demo](https://wakimworks.com/judewakim/s3-sentry/). Run a sample scan in your browser, or scan your own AWS account with a read-only role you can delete afterwards.

------
### The Mission

In the modern cloud era, a single misconfigured S3 bucket can lead to catastrophic data exposure. S3 Sentry bridges the gap between complex AWS IAM policies and actionable security intelligence by providing a "zero-friction" onboarding experience and automated remediation scanning.

------
### Core Architecture

S3 Sentry utilizes a Cross-Account Trust Handshake to scan client environments securely.

  - <b>The Handshake</b>: Uses a unique ExternalID protocol to prevent "Confused Deputy" attacks.

  - <b>The Engine</b>: Powered by an orchestrated Prowler CLI integration for industry-standard security checks.

  - <b>The Single-Table Design</b>: Leverages Amazon DynamoDB to manage thousands of tenants and millions of findings within a high-performance, scalable schema.

------
### Key Features

  - <b>Automated Client Onboarding</b>: Deployable CloudFormation templates that establish secure, least-privilege IAM roles in under 60 seconds.

  - <b>Multi-Tenant Orchestration</b>: A central engine that iterates through onboarded accounts and performs deep-scan security audits.

  - <b>Security Intelligence</b>: Covers 9 critical S3 security vectors, including:

    - Public Access Block verification.

    - Server-Side Encryption (SSE) enforcement.

    - Bucket Versioning & MFA Delete status.

    - Object Ownership & Policy auditing.

  - <b>Cloud-Native Execution</b>: Fully containerized AWS Lambda deployment with zero on-premises infrastructure.

  - <b>Real-Time Alerting</b>: Severity-categorized SNS notifications delivered after every scan cycle.

------
### Phase 3: Cloud-Native Orchestration

Phase 3 migrated S3 Sentry from a local Python script into a fully managed, serverless
architecture running 24/7 without any on-premises infrastructure.

#### Architecture

```
EventBridge (cron)
       │  daily at 02:00 UTC
       ▼
AWS Lambda (Container Image)
  ├── Pulls tenant list from DynamoDB
  ├── For each tenant:
  │     ├── STS AssumeRole (with ExternalId)
  │     ├── Prowler CLI scan (subprocess, 9 S3 checks)
  │     ├── Writes findings → DynamoDB
  │     └── Publishes severity alert → SNS
  └── Returns scan summary to CloudWatch Logs
```

#### Container Image

The orchestrator runs as a Docker container image stored in Amazon ECR and executed
by Lambda. The image is built for `linux/amd64` to match Lambda's x86_64 execution
environment.

```
public.ecr.aws/lambda/python:3.11
  └── prowler==3.16.17 (Prowler CLI)
  └── lambda_handler.py (entry point)
```

Key environment constraints solved in the image:
- `ENV HOME=/tmp` — Prowler writes `~/.prowler/` cache on startup; Lambda's filesystem
  is read-only outside `/tmp`.
- `ENV PROWLER_OUTPUT_DIRECTORY=/tmp` — Prowler JSON scan output redirected to the
  writable volume.

#### Security Milestone: Least-Privilege Trust

The client role trusts the provider account only when **both** conditions hold:

```yaml
Principal:
  AWS: arn:aws:iam::<PROVIDER_ACCOUNT_ID>:root
Condition:
  StringEquals:
    sts:ExternalId: <per-tenant secret>
  ArnEquals:
    aws:PrincipalArn:
      - arn:aws:iam::<PROVIDER_ACCOUNT_ID>:role/S3SentryOrchestratorRole
      - arn:aws:iam::<PROVIDER_ACCOUNT_ID>:role/S3SentryResponderRole
```

Putting the role ARNs directly in `Principal` looks tighter, but IAM stores them as the
role's internal ID. Recreating the provider stack changes that ID and silently breaks
every tenant's trust policy (this happened in Phase 4). A `PrincipalArn` condition
gives the same least-privilege result and survives role recreation.

The Lambda execution role (`S3SentryOrchestratorRole`) is scoped to the minimum
permissions required: DynamoDB query/write on the `S3Sentry` table, STS AssumeRole
scoped to `*/S3SentryCrossAccountRole`, SNS publish, and ECR image pull.

#### Infrastructure as Code

All provider-account resources are deployed via a single CloudFormation stack
(`provider_infrastructure.yaml`):

| Resource | Name |
|----------|------|
| ECR Repository | `s3sentry-orchestrator` |
| IAM Role | `S3SentryOrchestratorRole` |
| SNS Topic | `S3SentryScanAlerts` |
| Lambda Function | `S3SentryOrchestrator` |
| EventBridge Rule | `S3SentryDailyScan` |

#### SNS Alert Format

After each tenant scan, a severity-breakdown email is published to the SNS topic:

```
Subject: ⚠️ S3Sentry Alert: 4 Findings for acc#111122223333

The daily scan is complete. We found 4 FAIL findings across 2 bucket(s).

Severity Breakdown:
  Critical : 0
  High     : 2
  Medium   : 2
  Low      : 0

--- Finding Details (JSON) ---
[...]
```

------
### Tech Stack

  - Language: Python 3.11

  - Cloud: AWS (IAM, STS, S3, DynamoDB, Lambda, ECR, EventBridge, SNS, CloudFormation)

  - Security Engine: Prowler v3.16.17

  - Database: DynamoDB (Single-Table Design with GSI)

  - Container: Docker (`linux/amd64`, AWS Lambda base image)

  - IaC: AWS CloudFormation

------
### Development & Testing

  To run a manual scan cycle locally (Phase 2 runner — requires `.venv` with Python 3.11):

  ```
  .\run_orchestrator.bat
  ```

  To invoke the Lambda function directly:

  ```
  aws lambda invoke --function-name S3SentryOrchestrator \
    --payload '{}' response.json && cat response.json
  ```

------
### Phase 4: Interactive SOAR Platform (In Progress)

Phase 4 transforms S3 Sentry from a passive alerting system into an interactive
security operations platform. Customers receive a rich HTML dashboard email and
can approve automated fixes with a single click.

#### Target Architecture

```
S3SentryOrchestrator Lambda
  └── Sends SES HTML email per tenant
        └── Per-finding action buttons (HMAC-signed URLs)
                    │
                    ▼ Customer clicks "Fix Now"
        S3SentryResponder Lambda (Function URL)
          ├── Validates HMAC token (expiry + single-use nonce)
          ├── Snapshots current config → S3 Vault (safety engine)
          ├── Applies fix via cross-account assumed session
          └── Writes audit trail → DynamoDB (REMEDIATION# items)
```

#### Phase 4 Infrastructure — Complete ✓

| Component | Detail |
|-----------|--------|
| `S3SentryResponder` Lambda | Deployed, Function URL live |
| HMAC signing key | Seeded in SSM (`/s3sentry/hmac_signing_key`) |
| `deploy.ps1` | One-click deployment script (ECR + Docker + CFN + URL wiring) |
| End-to-end scan | Verified — 12 findings across 3 buckets |

#### Deployment

All provider infrastructure is deployed via a single script from the project root:

```powershell
.\deploy.ps1
```

The script handles ECR repo creation, Docker image build (single-arch `linux/amd64`),
ECR push, CloudFormation stack deploy, Function URL creation, and RESPONDER_URL wiring
into the Orchestrator Lambda — in the correct order with no manual steps.

#### Roadmap

  [x] Phase 1: Core Scan Engine & Local Simulation.

  [x] Phase 2: Multi-Tenant Handshake & Cross-Account Orchestration.

  [x] Phase 3: AWS Lambda Migration & Real-time SNS Notifications.

  [~] Phase 4: Interactive SOAR Platform (Infrastructure complete — code sprints in progress).

  [x] Phase 4 Sprint 1: HMAC Token System + SES HTML Dashboard Email.

  [~] Phase 4 Sprint 2: Responder Lambda (FIX / IGNORE working in dry-run; ROLLBACK not finished, see below).

  [x] Public live demo: read-only, isolated, rate-limited (`demo/`, `web/`).

  [ ] Phase 4 Sprint 3: Confidence Engine (per-finding action scoring).

  [ ] Phase 4 Sprints 4-5: Rollback, Yesterday's Activity, Suppression System.

#### Known limitations

- **Rollback is not finished.** `responder.py` currently snapshots the *current*
  config at rollback time instead of loading the pre-fix snapshot from the vault,
  so a rollback is a no-op. Remediation ships with `DRY_RUN=true` until this is fixed.
- One-click fixes cover two checks today (bucket Block Public Access, default encryption).

------
### Repository layout

| Path | What it is |
|---|---|
| `lambda_handler.py` | Scheduled multi-tenant scanner (container Lambda) |
| `responder.py`, `token_utils.py` | Signed Fix/Ignore links and the remediation handler |
| `client_onboarding.yaml` | The one IAM role a customer deploys |
| `provider_infrastructure.yaml`, `deploy.ps1` | Provider-account infrastructure and deploy script |
| `demo/` | Isolated public live demo (API, scanner, templates, deploy notes) |
| `web/` | Static demo page for the portfolio |
| `tests/` | `python -m pytest -q tests/` |
| `orchestrator.py`, `run_orchestrator.bat` | Local runner used in Phases 1–2 |

The earlier v1 scanner (SES + HIPAA compliance stack) is preserved at the git tag `legacy-v1-scanner`.

------
### SUPPORT AND CONTACT

For assistance, feature requests, or bug reports: <br>
📧 Email: [judewakim@wakimworks.com](judewakim@wakimworks.com) <br>
🌐 Website: [https://www.wakimworks.com](https://www.wakimworks.com) <br>
💻 GitHub: [https://github.com/judewakim/s3-misconfig](https://github.com/judewakim/s3-misconfig)

------
### 📜 LICENSE

MIT License.
Use, modify, and distribute freely with attribution.
