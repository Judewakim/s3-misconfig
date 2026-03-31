# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# S3 Sentry — Orchestrator Lambda Container Image
#
# Build:  docker build --platform linux/amd64 -t s3sentry-orchestrator .
# Test:   docker run --rm \
#           -e AWS_ACCESS_KEY_ID=... \
#           -e AWS_SECRET_ACCESS_KEY=... \
#           -e AWS_SESSION_TOKEN=... \
#           -e AWS_DEFAULT_REGION=us-east-1 \
#           s3sentry-orchestrator lambda_handler.handler
# ---------------------------------------------------------------------------

FROM --platform=linux/amd64 public.ecr.aws/lambda/python:3.11

# ---------------------------------------------------------------------------
# Prowler writes cache/config to $HOME (~/.prowler/) on startup.
# The Lambda filesystem is read-only outside /tmp.
# Redirect HOME and Prowler's default output directory to /tmp so the
# process never attempts a write outside the writable volume.
# ---------------------------------------------------------------------------
ENV HOME=/tmp
ENV PROWLER_OUTPUT_DIRECTORY=/tmp

# ---------------------------------------------------------------------------
# Install dependencies.
# prowler==3.16.17 — exact version verified in Phase 2 testing.
# boto3 is bundled in the Lambda runtime but pinning it avoids surprise
# version skew between the runtime layer and the container layer.
# --no-cache-dir keeps the image lean (ECR storage is billed by GB).
# ---------------------------------------------------------------------------
RUN pip install --no-cache-dir \
    prowler==3.16.17 \
    boto3

# ---------------------------------------------------------------------------
# Copy the Lambda handler into the Lambda task root (/var/task).
# ---------------------------------------------------------------------------
COPY lambda_handler.py ${LAMBDA_TASK_ROOT}/
COPY token_utils.py    ${LAMBDA_TASK_ROOT}/

# Lambda entry point — module=lambda_handler, function=handler
CMD ["lambda_handler.handler"]
