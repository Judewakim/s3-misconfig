# deploy.ps1 — S3 Sentry One-Click Deployment Script
#
# Run from the project root: .\deploy.ps1
#
# FIRST-TIME SETUP — if you see "running scripts is disabled", run this once
# in an elevated PowerShell window, then retry:
#   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
#
# What this script does (in order):
#   1. Seeds the HMAC signing key in SSM (skips if already set)
#   2. Creates the ECR repository if it doesn't exist
#   3. Logs Docker in to ECR
#   4. Builds the image with --provenance=false to prevent a manifest list
#      (without this, Docker BuildKit creates an OCI Image Index that Lambda
#       rejects with "media type not supported")
#   5. Tags and pushes the single-arch linux/amd64 image
#   6. Deploys the CloudFormation stack (create or update)
#   7. Reads the Responder URL from stack outputs and injects it into the
#      Orchestrator Lambda's environment variables

# NOTE: Do NOT use $ErrorActionPreference = "Stop" globally.
# PowerShell treats any stderr output from native commands (aws, docker) as a
# terminating error under Stop mode — including expected "not found" responses
# from aws ssm get-parameter and aws ecr describe-repositories.
# Instead, use explicit Assert-Success after each command that must succeed.

# ---------------------------------------------------------------------------
# Configuration — edit these values before first run
# ---------------------------------------------------------------------------
$ACCOUNT_ID       = "390488375643"
$REGION           = "us-east-1"
$ECR_REPO_NAME    = "s3sentry-repo"            # match the name you created in ECR
$STACK_NAME       = "s3sentry-provider"
$IMAGE_TAG        = "latest"
$DYNAMODB_TABLE   = "S3Sentry"
$SES_FROM_ADDRESS = "scanner@wakimworks.com"   # must be SES-verified before use
$HMAC_KEY_PATH    = "/s3sentry/hmac_signing_key"

# Derived — do not edit
$IMAGE_URI = "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO_NAME}:${IMAGE_TAG}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step([int]$n, [string]$msg) {
    Write-Host ""
    Write-Host "[$n/7] $msg" -ForegroundColor Cyan
}

function Assert-Success([string]$context) {
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERROR: $context failed (exit code $LASTEXITCODE)." -ForegroundColor Red
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Step 1: Seed HMAC signing key in SSM
#   CloudFormation creates it as a plain String placeholder "CHANGE_ME".
#   This step overwrites it with a real 32-byte hex secret as a SecureString.
#   Skipped if the key is already set to something other than the placeholder.
#
#   Uses 2>&1 to merge stderr into the captured output — prevents PowerShell
#   from throwing NativeCommandError when the parameter doesn't exist yet.
# ---------------------------------------------------------------------------
Write-Step 1 "Checking HMAC signing key in SSM..."
$existing = (aws ssm get-parameter --name $HMAC_KEY_PATH --query "Parameter.Value" --output text) 2>&1
$ssmFound = ($LASTEXITCODE -eq 0)

if (-not $ssmFound -or [string]::IsNullOrWhiteSpace($existing) -or $existing -eq "CHANGE_ME") {
    # Generate 32 cryptographically random bytes as a hex string
    $bytes  = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $newKey = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""

    $null = aws ssm put-parameter --name $HMAC_KEY_PATH --value $newKey --type SecureString --overwrite 2>&1
    Assert-Success "SSM put-parameter"
    Write-Host "  HMAC key seeded as SecureString." -ForegroundColor Green
} else {
    Write-Host "  HMAC key already set — skipping." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Step 2: Create ECR repository if it doesn't exist
#   The ECR repo is managed outside CloudFormation to avoid the bootstrap
#   paradox: the Lambda stack needs the image URI before the stack can create
#   the repo. Pre-creating it here breaks the chicken-and-egg problem.
#
#   Uses 2>&1 to suppress the expected "repository not found" stderr output.
# ---------------------------------------------------------------------------
Write-Step 2 "Ensuring ECR repository '$ECR_REPO_NAME' exists..."
$null = (aws ecr describe-repositories --repository-names $ECR_REPO_NAME --region $REGION) 2>&1
if ($LASTEXITCODE -ne 0) {
    $null = aws ecr create-repository `
        --repository-name $ECR_REPO_NAME `
        --region $REGION `
        --image-scanning-configuration scanOnPush=true 2>&1
    Assert-Success "ECR create-repository"
    Write-Host "  ECR repository created." -ForegroundColor Green
} else {
    Write-Host "  ECR repository already exists, skipping." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Step 3: Docker login to ECR
# ---------------------------------------------------------------------------
Write-Step 3 "Logging Docker in to ECR..."
$loginPassword = aws ecr get-login-password --region $REGION
Assert-Success "ECR get-login-password"
$loginPassword | docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
Assert-Success "Docker ECR login"

# ---------------------------------------------------------------------------
# Step 4: Build Docker image
#
#   --platform linux/amd64  Target Lambda's x86_64 execution environment.
#   --provenance=false       CRITICAL: Prevents Docker BuildKit from adding an
#                            OCI Image Index (manifest list) alongside the image.
#                            Without this, ECR shows two digests — the real
#                            amd64 layer AND a manifest list wrapper that appears
#                            as "unknown" architecture. Lambda cannot use a
#                            manifest list and throws:
#                              "image manifest media type not supported"
#   --load                   Load the result into the local Docker daemon so it
#                            can be tagged and pushed. Required when using
#                            buildx with --platform for a single target.
# ---------------------------------------------------------------------------
Write-Step 4 "Building Docker image (linux/amd64, single-arch manifest)..."
docker buildx build `
    --platform linux/amd64 `
    --provenance=false `
    --load `
    -t "s3sentry-orchestrator:${IMAGE_TAG}" `
    .
Assert-Success "Docker build"

# ---------------------------------------------------------------------------
# Step 5: Tag and push to ECR
# ---------------------------------------------------------------------------
Write-Step 5 "Tagging and pushing image to ECR..."
docker tag "s3sentry-orchestrator:${IMAGE_TAG}" $IMAGE_URI
Assert-Success "Docker tag"
docker push $IMAGE_URI
Assert-Success "Docker push"
Write-Host "  Pushed: $IMAGE_URI" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Step 6: Deploy CloudFormation stack (create or update)
#   --no-fail-on-empty-changeset allows re-running without error when the
#   template hasn't changed (e.g., re-running after an image-only update).
# ---------------------------------------------------------------------------
Write-Step 6 "Deploying CloudFormation stack '$STACK_NAME'..."
aws cloudformation deploy `
    --template-file provider_infrastructure.yaml `
    --stack-name $STACK_NAME `
    --region $REGION `
    --capabilities CAPABILITY_NAMED_IAM `
    --parameter-overrides `
        OrchestratorImageUri=$IMAGE_URI `
        DynamoDBTableName=$DYNAMODB_TABLE `
        SESFromAddress=$SES_FROM_ADDRESS `
    --no-fail-on-empty-changeset
Assert-Success "CloudFormation deploy"
Write-Host "  Stack deployed." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Step 7: Create Responder Function URL + wire it into the Orchestrator
#
#   AWS::Lambda::Url (CloudFormation) consistently creates a ghost resource —
#   CFN reports success and returns a URL, but the URL is never actually
#   attached to the Lambda function. Managing it via CLI is reliable.
#
#   create-function-url-config is idempotent-safe: if the URL already exists
#   (e.g. on a re-run or if it was created in the console), we catch the error
#   and proceed to read the existing URL.
# ---------------------------------------------------------------------------
Write-Step 7 "Creating Responder Function URL and wiring into Orchestrator..."

# Create the URL config (ignore error if it already exists)
$null = (aws lambda create-function-url-config `
    --function-name S3SentryResponder `
    --auth-type NONE `
    --cors "AllowOrigins=*,AllowMethods=GET POST,AllowHeaders=content-type" `
    --region $REGION) 2>&1
# exit code 1 = ResourceConflictException (already exists) — that is fine

# Ensure the public invocation permission exists (ignore error if already present)
$null = (aws lambda add-permission `
    --function-name S3SentryResponder `
    --statement-id AllowPublicFunctionUrl `
    --action lambda:InvokeFunctionUrl `
    --principal "*" `
    --function-url-auth-type NONE `
    --region $REGION) 2>&1
# exit code 1 = already exists — that is fine

# Read the real attached URL from the Lambda directly (not from CFN output)
$RESPONDER_URL = aws lambda get-function-url-config `
    --function-name S3SentryResponder `
    --region $REGION `
    --query "FunctionUrl" `
    --output text
Assert-Success "get-function-url-config"

if ([string]::IsNullOrWhiteSpace($RESPONDER_URL) -or $RESPONDER_URL -eq "None") {
    Write-Host "  ERROR: Could not read Responder URL after creation." -ForegroundColor Red
    exit 1
}
Write-Host "  Responder URL: $RESPONDER_URL" -ForegroundColor Green

# Inject RESPONDER_URL into the Orchestrator Lambda environment.
# Uses a temp file to avoid PowerShell JSON quoting issues with --environment.
#
# Two Windows-specific requirements:
#   1. Write WITHOUT BOM — Set-Content -Encoding UTF8 adds a BOM in PowerShell 5,
#      which the AWS CLI JSON parser rejects with "Invalid JSON received".
#      Fix: [System.IO.File]::WriteAllText with UTF8Encoding($false).
#   2. Forward slashes in file:// URI — AWS CLI cannot resolve file://C:\... paths.
#      Fix: replace backslashes and prepend file:///.
$envJson = aws lambda get-function-configuration `
    --function-name S3SentryOrchestrator `
    --region $REGION `
    --query "Environment.Variables" `
    --output json
Assert-Success "Lambda get-function-configuration"

# Convert PSCustomObject → plain hashtable so ConvertTo-Json serialises cleanly
$rawEnv = $envJson | ConvertFrom-Json
$envHash = @{}
$rawEnv.PSObject.Properties | ForEach-Object { $envHash[$_.Name] = $_.Value }
$envHash["RESPONDER_URL"] = $RESPONDER_URL

$json = @{ FunctionName = "S3SentryOrchestrator"; Environment = @{ Variables = $envHash } } `
    | ConvertTo-Json -Depth 5 -Compress

$tmpPath = [System.IO.Path]::GetTempPath() + "s3sentry-env.json"
[System.IO.File]::WriteAllText($tmpPath, $json, [System.Text.UTF8Encoding]::new($false))
$fileUri = "file://" + $tmpPath.Replace("\", "/")

aws lambda update-function-configuration --region $REGION --cli-input-json $fileUri | Out-Null
Assert-Success "Lambda update-function-configuration"

Remove-Item $tmpPath -ErrorAction SilentlyContinue
Write-Host "  RESPONDER_URL injected into S3SentryOrchestrator." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "Deployment complete." -ForegroundColor Green
Write-Host "  Orchestrator Lambda : S3SentryOrchestrator"
Write-Host "  Responder URL       : $RESPONDER_URL"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Subscribe an email to the SNS topic to receive scan alerts."
Write-Host "  2. Verify '$SES_FROM_ADDRESS' in SES before enabling HTML email."
Write-Host "  3. Test: aws lambda invoke --function-name S3SentryOrchestrator --payload '{}' out.json"
