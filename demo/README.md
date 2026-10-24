# Live demo: deploy and verify

The live demo lets a visitor scan **their own** AWS account, read-only, once. It is fully separate from paying tenants: its own table, its own roles, no email, data deleted after 24 hours.

## Cost and abuse ceiling

| Guard | Setting |
|---|---|
| Scans per day (all visitors) | `MaxScansPerDay`, default 50 |
| Demo links per IP per day | `MaxSessionsPerIpPerDay`, default 5 |
| Parallel scans | Reserved concurrency 2 |
| Parallel API calls | Reserved concurrency 5 |
| Failed scan retries | 0 |
| Data retention | 24 h (DynamoDB TTL) |

At about 1–2 min per scan at 1 GB, a full day at the cap is roughly 50 × $0.002 ≈ **$0.10**. That's an estimate; confirm it in Cost Explorer after a week.

> Reserved concurrency needs the account's Lambda concurrency limit to be above 17 (7 reserved + 10 unreserved minimum). Brand-new accounts sometimes start at 10. Check with `aws lambda get-account-settings`.

## Deploy (staging first)

1. **Rebuild and push the image.** `deploy.ps1` already does this; the Dockerfile now includes `demo_api.py` and `demo_scanner.py`.
2. **Create the demo stack** with the image URI from step 1:
   ```
   aws cloudformation deploy --stack-name s3sentry-demo \
     --template-file demo/demo_infrastructure.yaml \
     --capabilities CAPABILITY_NAMED_IAM \
     --parameter-overrides ImageUri=<acct>.dkr.ecr.us-east-1.amazonaws.com/s3sentry-repo:latest \
       AllowedOrigin=https://wakimworks.com StagingOrigin=<your staging origin>
   ```
3. **Upload the visitor template** to the bucket named in the stack output `TemplateBucket`. The bucket stays private (account-level Block Public Access can stay on); the API gives each visitor a presigned link that's valid for 1 hour.
   ```
   aws s3 cp demo/demo_onboarding.yaml s3://<TemplateBucket>/demo_onboarding.yaml
   ```
4. **Point the page at the API.** Put the `DemoApiUrl` output into `web/config.js` (`apiUrl`).
5. **Publish `web/`** to the staging path first, then `wakimworks.com/judewakim/s3-sentry/` after you've tested it.
   In CloudFront, add response headers `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`, because those can't be set from a meta tag.

## Staging test checklist

- [ ] Sample scan runs; findings and "Preview the fix" open and close.
- [ ] Live: create link → CloudFormation opens with both parameters filled.
- [ ] Wrong account ID → "Can't reach the demo role yet".
- [ ] Right account ID → results in 1–3 min, and they match the AWS console.
- [ ] CloudWatch log for `S3SentryDemoScanner` has **no** `AccessDenied` in Prowler STDERR. If it does, add the missing `s3:Get*` action to `demo_onboarding.yaml` (the permission list is not yet proven against a real scan).
- [ ] Delete the visitor stack → a new scan on that session returns the "lost access" error.
- [ ] 6th link from the same IP in a day → rate-limit message.

## Tests

```
pip install moto pytest boto3
python -m pytest -q tests/
```
