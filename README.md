# S3 Sentry: The Autonomous Data Security Officer

S3 Sentry is a high-fidelity, multi-tenant security orchestration platform designed to provide continuous oversight of AWS S3 storage environments. It acts as an automated "Data Security Officer," ensuring that organizational data remains private, encrypted, and compliant without manual intervention.

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

------
### Tech Stack

  - Language: Python 3.11

  - Cloud: AWS (IAM, S3, DynamoDB, CloudFormation, STS)

  - Security Engine: Prowler v3.16.17

  - Database: DynamoDB (Single-Table Design)

------
### Development & Testing

  To run a manual scan cycle of all onboarded tenants:

  1. Ensure Provider credentials are active in your environment.

  2. Run the orchestrator:

    `.\run_orchestrator.bat`

### Roadmap

  [x] Phase 1: Core Scan Engine & Local Simulation.

  [x] Phase 2: Multi-Tenant Handshake & Cross-Account Orchestration.

  [ ] Phase 3: AWS Lambda Migration & Real-time SNS Notifications.

  [ ] Phase 4: Automated Remediation ("The Fix Button").

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
