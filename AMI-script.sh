#!/bin/bash -xe
#=============================================================================
# WakimWorks S3 Security Scanner – AMI User Data (AL2023) - Fixed & Testable
# - Use on Amazon Linux 2023
# - Robust logging, error handling
# - Optional TEST_MODE for quick tests without EC2 tags
# - Deploys CloudFormation via --template-url
#=============================================================================

set -euxo pipefail

# --- Logging: append and send to console/syslog ---
exec > >(tee /var/log/user-data.log | logger -t user-data -s 2>/dev/console) 2>&1
echo "=== S3 Scanner AMI Bootstrap START: $(date -u) ==="

# --------- Configurable test mode (set to true to override tags for testing) ----------
TEST_MODE=false
TEST_USER_EMAIL="test@example.com"
TEST_INVOCATION_MODE="scanning_only"
TEST_EXCLUDE_BUCKETS=""

# --- Globals / Defaults ---
INSTANCE_METADATA_URL="http://169.254.169.254/latest/meta-data"
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s)
INSTANCE_ID=$(curl -fsSL -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id || true)
REGION=$(curl -fsSL -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region || true)

STACK_NAME="S3ScannerClient"
TEMPLATE_URL="https://s3.amazonaws.com/judewakim-s3-misconfig/code/client-template.yaml"

POLL_INTERVAL=10
MAX_WAIT_SECONDS=$((30 * 60))   # 30 minutes

# --- Helper: send CFN signal if available ---
send_cfn_signal() {
    local exit_code=$1
    local reason="$2"
    local url="$3"

    if [ -z "$url" ]; then
        echo "No CFN signal URL provided; skipping signal."
        return 0
    fi

    # prefer cfn-signal binary if present
    CFN_SIGNAL_BIN="$(command -v cfn-signal || true)"
    if [ -z "$CFN_SIGNAL_BIN" ]; then
        for p in /opt/aws/bin/cfn-signal /usr/local/bin/cfn-signal /usr/bin/cfn-signal; do
            if [ -x "$p" ]; then
                CFN_SIGNAL_BIN="$p"
                break
            fi
        done
    fi

    if [ -n "$CFN_SIGNAL_BIN" ] && [ -x "$CFN_SIGNAL_BIN" ]; then
        echo "Running cfn-signal ($CFN_SIGNAL_BIN) exit=$exit_code reason='$reason'"
        "$CFN_SIGNAL_BIN" --exit-code "$exit_code" --reason "$reason" "$url" || true
    else
        echo "cfn-signal not found; attempting HTTP fallback PUT to signal URL."
        # Minimal fallback; Marketplace prefers cfn-signal binary but this sometimes works.
        local status_str
        if [ "$exit_code" -eq 0 ]; then status_str="SUCCESS"; else status_str="FAILURE"; fi
        printf '{"Status":"%s","Reason":"%s"}' "$status_str" "$reason" | \
            curl -fsS --retry 3 --retry-delay 2 -X PUT -H "Content-Type: application/json" -d @- "$url" || echo "Fallback signal failed (nonfatal)."
    fi
}

# --- Error handler ---
error_handler() {
    local lineno=${1:-"unknown"}
    echo "ERROR: user-data failed at line $lineno"
    if [ -n "${CFN_SIGNAL_URL:-}" ]; then
        send_cfn_signal 1 "User data failed at line $lineno" "$CFN_SIGNAL_URL"
    fi

    echo "Skipping self termiantation (testing)"
    # # Attempt to terminate; if not allowed, shut down
    # if [ -n "$INSTANCE_ID" ] && command -v aws >/dev/null 2>&1; then
    #     echo "Attempting to terminate instance ${INSTANCE_ID} via API..."
    #     if aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "${REGION:-}" >/dev/null 2>&1; then
    #         echo "Instance termination requested."
    #     else
    #         echo "Terminate API call failed or not permitted; shutting down."
    #         # shutdown -h now || true
    #     fi
    # else
    #     echo "No aws CLI or instance id available; shutting down."
    #     # shutdown -h now || true
    # fi
    exit 1
}
trap 'error_handler $LINENO' ERR
trap 'echo "User-data received SIGTERM/SIGINT; exiting."; exit 1' INT TERM

# --- 1. Basic environment & dependencies ---
echo "Region: $REGION, InstanceId: $INSTANCE_ID"
echo "Installing essentials (dnf update + packages)..."
# Amazon Linux 2023 fix: avoid curl conflicts
dnf -y update -x curl -x curl-minimal
dnf -y install python3 python3-pip jq unzip

# Install AWS CLI v2 if not present or not v2
if ! command -v aws >/dev/null 2>&1 || ! aws --version 2>&1 | grep -q "aws-cli/2"; then
    echo "Installing AWS CLI v2..."
    TMPDIR=$(mktemp -d)
    pushd "$TMPDIR"
    curl -fsS "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip -q awscliv2.zip
    ./aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update || true
    popd
    rm -rf "$TMPDIR"
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq not installed!"
    error_handler ${LINENO}
fi

# try to make cfn-signal available via pip if not present
if ! command -v cfn-signal >/dev/null 2>&1; then
    echo "Attempting to install aws-cfn-bootstrap (may provide cfn-signal) via pip..."
    pip3 install --upgrade aws-cfn-bootstrap || echo "aws-cfn-bootstrap pip install failed; continuing."
fi

# --- 2. Get optional CFN signal URL ---
CFN_SIGNAL_URL=$(curl -fsS "${INSTANCE_METADATA_URL}/cfn-signal-url" 2>/dev/null || echo "")
if [ -z "$CFN_SIGNAL_URL" ]; then
    echo "No CFN_SIGNAL_URL metadata value found. Marketplace signaling will be skipped."
else
    echo "CFN_SIGNAL_URL found."
fi

# --- 3. Fetch EC2 tags (user inputs) ---
echo "Fetching EC2 instance tags..."
TAGS_JSON=$(aws ec2 describe-tags --filters "Name=resource-id,Values=${INSTANCE_ID}" --region "${REGION:-}" --output json 2>/dev/null || echo "{}")
echo "Raw tags: ${TAGS_JSON}"

USER_EMAIL=$(echo "$TAGS_JSON" | jq -r '.Tags[] | select(.Key=="UserEmail") | .Value' || true)
INVOCATION_MODE=$(echo "$TAGS_JSON" | jq -r '.Tags[] | select(.Key=="InvocationMode") | .Value' || true)
EXCLUDE_BUCKETS=$(echo "$TAGS_JSON" | jq -r '.Tags[] | select(.Key=="ExcludeBuckets") | .Value' || true)
SELF_TERMINATE_TAG=$(echo "$TAGS_JSON" | jq -r '.Tags[] | select(.Key=="SelfTerminate") | .Value' || true)

# Test-mode override (handy for local testing without tags)
if [ "${TEST_MODE}" = "true" ]; then
    echo "TEST_MODE=true -> using test parameters instead of tags."
    USER_EMAIL="${TEST_USER_EMAIL}"
    INVOCATION_MODE="${TEST_INVOCATION_MODE}"
    EXCLUDE_BUCKETS="${TEST_EXCLUDE_BUCKETS}"
    SELF_TERMINATE_TAG="false"
fi

# Provide defaults where necessary
: "${INVOCATION_MODE:=scanning_only}"
: "${EXCLUDE_BUCKETS:=""}"
: "${SELF_TERMINATE_TAG:="true"}"

# Validate required parameter
if [ -z "$USER_EMAIL" ] || [ "$USER_EMAIL" = "null" ]; then
    echo "ERROR: Required EC2 tag 'UserEmail' is missing or empty."
    error_handler ${LINENO}
fi

echo "UserEmail: $USER_EMAIL"
echo "InvocationMode: $INVOCATION_MODE"
echo "ExcludeBuckets: $EXCLUDE_BUCKETS"
echo "SelfTerminateTag: $SELF_TERMINATE_TAG"

# PARAM_OVERRIDES=(
#   "ParameterKey=UserEmail" "ParameterValue=${USER_EMAIL}"
#   "ParameterKey=InvocationMode" "ParameterValue=${INVOCATION_MODE}"
#   "ParameterKey=ExcludeBuckets" "ParameterValue=${EXCLUDE_BUCKETS}"
# )

# --- 5. Deploy CloudFormation using template-url ---
echo "Deploying CloudFormation stack: ${STACK_NAME} using template-url: ${TEMPLATE_URL}"

aws cloudformation create-stack \
    --stack-name "${STACK_NAME}" \
    --template-url "${TEMPLATE_URL}" \
    --parameters \
        ParameterKey=UserEmail,ParameterValue="${USER_EMAIL}" \
        ParameterKey=InvocationMode,ParameterValue="${INVOCATION_MODE}" \
        ParameterKey=ExcludeBuckets,ParameterValue="${EXCLUDE_BUCKETS}" \
    --capabilities CAPABILITY_NAMED_IAM CAPABILITY_IAM \
    --region "${REGION}"


# --- 6. Poll stack status with timeout ---
echo "Polling CloudFormation stack status (timeout ${MAX_WAIT_SECONDS}s)..."
start_ts=$(date +%s)
while true; do
    sleep "$POLL_INTERVAL"
    now_ts=$(date +%s)
    elapsed=$((now_ts - start_ts))

    STACK_STATUS=$(aws cloudformation describe-stacks \
        --stack-name "${STACK_NAME}" --region "${REGION:-}" \
        --query "Stacks[0].StackStatus" --output text 2>/dev/null || echo "UNKNOWN")

    echo "Stack status: ${STACK_STATUS} (elapsed ${elapsed}s)"

    case "${STACK_STATUS}" in
        CREATE_COMPLETE|UPDATE_COMPLETE)
            echo "Stack completed successfully: ${STACK_STATUS}"
            send_cfn_signal 0 "Deployment successful (stack ${STACK_STATUS})" "${CFN_SIGNAL_URL}"
            break
            ;;
        CREATE_IN_PROGRESS|UPDATE_IN_PROGRESS|ROLLBACK_IN_PROGRESS|UPDATE_COMPLETE_CLEANUP_IN_PROGRESS)
            # continue polling
            ;;
        CREATE_FAILED|ROLLBACK_COMPLETE|ROLLBACK_FAILED|DELETE_COMPLETE|DELETE_FAILED|UPDATE_ROLLBACK_FAILED|UPDATE_ROLLBACK_COMPLETE)
            echo "Stack reached failure state: ${STACK_STATUS}"
            send_cfn_signal 1 "Stack failed with status ${STACK_STATUS}" "${CFN_SIGNAL_URL}"
            error_handler ${LINENO}
            ;;
        UNKNOWN)
            echo "Stack status unknown; continuing to poll..."
            ;;
        *)
            echo "Unhandled stack status: ${STACK_STATUS}; continuing to poll..."
            ;;
    esac

    if [ "$elapsed" -ge "$MAX_WAIT_SECONDS" ]; then
        echo "ERROR: Timeout waiting for stack to reach a terminal state (waited ${elapsed}s)."
        send_cfn_signal 1 "Timeout waiting for stack - elapsed ${elapsed}s" "${CFN_SIGNAL_URL}"
        error_handler ${LINENO}
    fi
done

# --- 7. Final verification ---
FINAL_STATUS=$(aws cloudformation describe-stacks --stack-name "${STACK_NAME}" --region "${REGION:-}" --query "Stacks[0].StackStatus" --output text || echo "UNKNOWN")
echo "Final CloudFormation status: ${FINAL_STATUS}"

if [[ "${FINAL_STATUS}" != "CREATE_COMPLETE" && "${FINAL_STATUS}" != "UPDATE_COMPLETE" ]]; then
    echo "Non-success final status: ${FINAL_STATUS}"
    send_cfn_signal 1 "Final stack status ${FINAL_STATUS}" "${CFN_SIGNAL_URL}"
    error_handler ${LINENO}
fi

# --- 8. Artifact and optional termination ---
# Create an artifact file so you can detect success after boot
echo "Deployment successful at $(date -u)" > /tmp/s3scanner-bootstrap-complete
echo "Stack status: ${FINAL_STATUS}" >> /tmp/s3scanner-bootstrap-complete

echo "Bootstrap finished successfully. Checking self-termination setting..."

# If the stack was created successfully, self-terminate if the EC2 tag allows it
if [[ "${FINAL_STATUS}" == "CREATE_COMPLETE" || "${FINAL_STATUS}" == "UPDATE_COMPLETE" ]]; then
    if [[ "${SELF_TERMINATE_TAG,,}" == "true" || "${SELF_TERMINATE_TAG,,}" == "yes" || "${SELF_TERMINATE_TAG}" == "1" ]]; then
        echo "Stack completed successfully and SelfTerminate=true — terminating instance ${INSTANCE_ID}..."
        if [ -n "$INSTANCE_ID" ]; then
            aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "${REGION:-}" || shutdown -h now || true
        else
            echo "No instance ID found — performing shutdown instead."
            shutdown -h now || true
        fi
    else
        echo "SelfTerminate tag set to '${SELF_TERMINATE_TAG}', skipping termination."
    fi
else
    echo "Final stack status ${FINAL_STATUS} not successful — skipping termination."
fi

echo "=== S3 Scanner AMI Bootstrap END: $(date -u) ==="

