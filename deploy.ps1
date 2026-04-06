# deploy.ps1 -- S3 Sentry One-Click Deployment Script
#
# Run from the project root: .\deploy.ps1
#
# FIRST-TIME SETUP -- if you see "running scripts is disabled", run this once
# in an elevated PowerShell window, then retry:
#   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
#
# What this script does (in order):
#   1. Seeds the HMAC signing key in SSM (skips if already set)
#   2. Creates the ECR repository and S3 Vault bucket if they don't exist
#   3. Logs Docker in to ECR
#   4. Builds the image with --provenance=false to prevent a manifest list
#      (without this, Docker BuildKit creates an OCI Image Index that Lambda
#       rejects with "media type not supported")
#   5. Tags and pushes the single-arch linux/amd64 image
#   6. Deploys the CloudFormation stack (IAM roles, DynamoDB, EventBridge, etc.)
#      S3SentryResponder is NOT in the CFN template -- PackageType is immutable
#      in CFN and the function is fully managed by this script instead.
#   7. Creates or updates both Lambda functions to the new image digest.
#      Handles three Responder states: not found (create), Zip (migrate), Image (update).
#   8. Creates the Responder Function URL if missing, then injects env vars.

# NOTE: Do NOT use $ErrorActionPreference = "Stop" globally.
# PowerShell treats any stderr output from native commands (aws, docker) as a
# terminating error under Stop mode -- including expected "not found" responses
# from aws ssm get-parameter and aws ecr describe-repositories.
# Instead, use explicit Assert-Success after each command that must succeed.

# ---------------------------------------------------------------------------
# Configuration -- edit these values before first run
# ---------------------------------------------------------------------------
$ACCOUNT_ID       = "390488375643"
$REGION           = "us-east-1"
$ECR_REPO_NAME    = "s3sentry-repo"            # match the name you created in ECR
$STACK_NAME       = "s3sentry-provider"
$IMAGE_TAG        = "latest"
$DYNAMODB_TABLE   = "S3Sentry"
$SES_FROM_ADDRESS = "scanner@wakimworks.com"   # must be SES-verified before use
$HMAC_KEY_PATH    = "/s3sentry/hmac_signing_key"
$S3_VAULT_BUCKET  = "s3sentry-vault-${ACCOUNT_ID}"  # account-scoped for global S3 uniqueness
$DRY_RUN          = "true"                     # set to "false" for live remediation

# Derived -- do not edit
$IMAGE_URI = "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO_NAME}:${IMAGE_TAG}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step([int]$n, [string]$msg) {
    Write-Host ""
    Write-Host "[$n/8] $msg" -ForegroundColor Cyan
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
#   Uses 2>&1 to merge stderr into the captured output -- prevents PowerShell
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
    Write-Host "  HMAC key already set -- skipping." -ForegroundColor Yellow
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
# Step 2b: Create S3 Vault bucket if it doesn't exist
#   The Responder Lambda writes Before-state snapshots here before any fix.
#   Bucket name includes the account ID to guarantee global S3 uniqueness.
#   Public access is blocked and versioning enabled so snapshots are never
#   accidentally exposed or silently overwritten.
# ---------------------------------------------------------------------------
Write-Host "  Ensuring S3 Vault bucket '$S3_VAULT_BUCKET' exists..."
$null = (aws s3api head-bucket --bucket $S3_VAULT_BUCKET --region $REGION) 2>&1
if ($LASTEXITCODE -ne 0) {
    aws s3api create-bucket --bucket $S3_VAULT_BUCKET --region $REGION | Out-Null
    Assert-Success "S3 create-bucket (vault)"

    aws s3api put-public-access-block `
        --bucket $S3_VAULT_BUCKET `
        --public-access-block-configuration `
            "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" | Out-Null
    Assert-Success "S3 vault public-access-block"

    aws s3api put-bucket-versioning `
        --bucket $S3_VAULT_BUCKET `
        --versioning-configuration Status=Enabled | Out-Null
    Assert-Success "S3 vault versioning"

    Write-Host "  S3 Vault bucket created with public-access block and versioning." -ForegroundColor Green
} else {
    Write-Host "  S3 Vault bucket already exists -- skipping." -ForegroundColor Yellow
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
#                            Without this, ECR shows two digests -- the real
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
# Step 6 (pre-check): Recover from UPDATE_ROLLBACK_FAILED
#   If a previous deploy failed AND the rollback also failed (typically because
#   CFN tried to restore ResponderFunction to Zip-type but the actual function
#   is Image-type), the stack gets stuck and rejects all new updates.
#   Fix: continue-update-rollback with --resources-to-skip so CFN abandons the
#   broken resource and returns to UPDATE_ROLLBACK_COMPLETE, from which a new
#   deploy can proceed normally.
# ---------------------------------------------------------------------------
$stackStatus = (aws cloudformation describe-stacks `
    --stack-name $STACK_NAME `
    --region $REGION `
    --query "Stacks[0].StackStatus" `
    --output text) 2>&1

if ($stackStatus -eq "UPDATE_ROLLBACK_FAILED") {
    Write-Host ""
    Write-Host "  Stack is in UPDATE_ROLLBACK_FAILED -- recovering..." -ForegroundColor Yellow
    aws cloudformation continue-update-rollback `
        --stack-name $STACK_NAME `
        --region $REGION `
        --resources-to-skip ResponderFunction | Out-Null
    Assert-Success "continue-update-rollback"
    Write-Host "  Waiting for rollback to complete..."
    aws cloudformation wait stack-rollback-complete --stack-name $STACK_NAME --region $REGION
    Assert-Success "wait stack-rollback-complete"
    Write-Host "  Stack recovered to UPDATE_ROLLBACK_COMPLETE." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Step 6: Deploy CloudFormation stack (create or update)
#   --no-fail-on-empty-changeset allows re-running without error when the
#   template hasn't changed (e.g., re-running after an image-only update).
#
#   S3SentryResponder is NOT in the CFN template. PackageType is an immutable
#   property in CloudFormation -- changing it requires resource replacement,
#   which fails when FunctionName is hardcoded (name conflict). The function
#   is fully managed by Step 7 below instead.
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
        VaultBucketName=$S3_VAULT_BUCKET `
    --no-fail-on-empty-changeset
Assert-Success "CloudFormation deploy"
Write-Host "  Stack deployed." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Step 7: Create or update Lambda functions to the newly pushed image digest
#   CFN only updates a Lambda when the ImageUri parameter changes. Since we
#   always push :latest, CFN sees no diff and skips the update.
#
#   Orchestrator: always Image-type, just update function code.
#
#   Responder: managed entirely outside CFN. Handles three states:
#     - Not found (CFN removed it, or first deploy): create as Image type.
#     - Zip (legacy placeholder): delete and recreate as Image type.
#     - Image: update function code to the new digest.
#
#   Environment variables are injected at create time so the function never
#   starts cold without them (avoids KeyError before Step 8 runs).
#   Step 8 re-injects them on every run to pick up config changes.
# ---------------------------------------------------------------------------
Write-Step 7 "Updating Lambda functions to new image digest..."

Write-Host "  Updating Orchestrator Lambda..."
aws lambda update-function-code `
    --function-name S3SentryOrchestrator `
    --region $REGION `
    --image-uri $IMAGE_URI | Out-Null
Assert-Success "Orchestrator Lambda update-function-code"
aws lambda wait function-updated --function-name S3SentryOrchestrator --region $REGION
Assert-Success "wait Orchestrator function-updated"
Write-Host "  Orchestrator Lambda updated." -ForegroundColor Green

Write-Host "  Checking Responder Lambda state..."
$responderConfig = (aws lambda get-function-configuration `
    --function-name S3SentryResponder `
    --region $REGION `
    --output json) 2>&1
$responderExists = ($LASTEXITCODE -eq 0)

# Shared helper: create Responder as Image type (used for both not-found and Zip migration)
function New-ResponderLambda([string]$roleArn) {
    $createJson = @{
        FunctionName = "S3SentryResponder"
        PackageType  = "Image"
        Code         = @{ ImageUri = $IMAGE_URI }
        ImageConfig  = @{ Command = @("responder.handler") }
        Role         = $roleArn
        Timeout      = 30
        MemorySize   = 256
        Environment  = @{
            Variables = @{
                DYNAMODB_TABLE  = $DYNAMODB_TABLE
                HMAC_KEY_PATH   = $HMAC_KEY_PATH
                S3_VAULT_BUCKET = $S3_VAULT_BUCKET
                DRY_RUN         = $DRY_RUN
            }
        }
    } | ConvertTo-Json -Depth 5 -Compress

    $tmpPath = [System.IO.Path]::GetTempPath() + "s3sentry-responder-create.json"
    [System.IO.File]::WriteAllText($tmpPath, $createJson, [System.Text.UTF8Encoding]::new($false))
    $fileUri = "file://" + $tmpPath.Replace("\", "/")

    aws lambda create-function --region $REGION --cli-input-json $fileUri | Out-Null
    Assert-Success "create Responder Lambda"
    Remove-Item $tmpPath -ErrorAction SilentlyContinue

    aws lambda wait function-active --function-name S3SentryResponder --region $REGION
    Assert-Success "wait Responder Lambda active"
}

if (-not $responderExists) {
    Write-Host "  Responder not found -- creating as Image type..." -ForegroundColor Yellow
    # Resolve the ResponderRole ARN from the CFN stack outputs/resources
    $responderRoleArn = aws cloudformation describe-stack-resource `
        --stack-name $STACK_NAME `
        --logical-resource-id ResponderRole `
        --region $REGION `
        --query "StackResourceDetail.PhysicalResourceId" `
        --output text
    Assert-Success "get ResponderRole ARN from stack"
    # Physical ID for IAM role is the role name; build the full ARN
    $responderRoleArn = "arn:aws:iam::${ACCOUNT_ID}:role/${responderRoleArn}"
    New-ResponderLambda $responderRoleArn
    Write-Host "  Responder Lambda created." -ForegroundColor Green
} else {
    $responderPackageType = ($responderConfig | ConvertFrom-Json).PackageType
    if ($responderPackageType -eq "Zip") {
        Write-Host "  Responder is Zip-based -- migrating to Image type..." -ForegroundColor Yellow
        $responderRoleArn = ($responderConfig | ConvertFrom-Json).Role
        aws lambda delete-function --function-name S3SentryResponder --region $REGION | Out-Null
        Assert-Success "delete Zip Responder Lambda"
        New-ResponderLambda $responderRoleArn
        Write-Host "  Responder Lambda migrated to Image type." -ForegroundColor Green
    } else {
        Write-Host "  Updating Responder Lambda to new image digest..."
        aws lambda update-function-code `
            --function-name S3SentryResponder `
            --region $REGION `
            --image-uri $IMAGE_URI | Out-Null
        Assert-Success "Responder Lambda update-function-code"
        aws lambda wait function-updated --function-name S3SentryResponder --region $REGION
        Assert-Success "wait Responder function-updated"
        Write-Host "  Responder Lambda updated." -ForegroundColor Green
    }
}

# ---------------------------------------------------------------------------
# Step 7: Wire Responder URL into Orchestrator + inject Responder env vars
#
#   Part A -- Responder Function URL
#   AWS::Lambda::Url (CloudFormation) consistently creates a ghost resource --
#   CFN reports success and returns a URL, but the URL is never actually
#   attached to the Lambda function. Managing it via CLI is reliable.
#
#   create-function-url-config is idempotent-safe: if the URL already exists
#   (e.g. on a re-run or if it was created in the console), we catch the error
#   and proceed to read the existing URL.
#
#   Part B -- Orchestrator env var: RESPONDER_URL
#   Uses a temp file to avoid PowerShell JSON quoting issues on Windows.
#
#   Part C -- Responder env vars: DYNAMODB_TABLE, HMAC_KEY_PATH,
#             S3_VAULT_BUCKET, DRY_RUN
#   These are required by responder.py and are not set by CloudFormation.
# ---------------------------------------------------------------------------
Write-Step 8 "Wiring Responder URL into Orchestrator and injecting Responder env vars..."

# --- Part A: Create / verify Responder Function URL ---
#
# Probe first: if get-function-url-config returns exit code 0 the URL exists
# and we skip creation. If it returns non-zero (ResourceNotFoundException after
# a Zip->Image migration, or first-time deploy) we create it and assert success
# so a real failure is never silently swallowed.

$RESPONDER_URL = (aws lambda get-function-url-config `
    --function-name S3SentryResponder `
    --region $REGION `
    --query "FunctionUrl" `
    --output text) 2>&1
$urlAlreadyExists = ($LASTEXITCODE -eq 0)

if (-not $urlAlreadyExists) {
    Write-Host "  Function URL not found -- creating..." -ForegroundColor Yellow

    # Use a temp file to pass CORS config as proper JSON arrays.
    # The --cors shorthand treats "GET POST" as one string, not two methods,
    # causing a ValidationException. The temp-file approach is the same
    # BOM-safe pattern used elsewhere in this script.
    $urlConfigJson = @{
        FunctionName = "S3SentryResponder"
        AuthType     = "NONE"
        Cors         = @{
            AllowOrigins = @("*")
            AllowMethods = @("GET", "POST")
            AllowHeaders = @("content-type")
        }
    } | ConvertTo-Json -Depth 5 -Compress

    $urlConfigTmpPath = [System.IO.Path]::GetTempPath() + "s3sentry-url-config.json"
    [System.IO.File]::WriteAllText($urlConfigTmpPath, $urlConfigJson, [System.Text.UTF8Encoding]::new($false))
    $urlConfigFileUri = "file://" + $urlConfigTmpPath.Replace("\", "/")

    aws lambda create-function-url-config --region $REGION --cli-input-json $urlConfigFileUri | Out-Null
    Assert-Success "create-function-url-config"
    Remove-Item $urlConfigTmpPath -ErrorAction SilentlyContinue

    # Add public invoke permission (required for AUTH_TYPE NONE browser access)
    aws lambda add-permission `
        --function-name S3SentryResponder `
        --statement-id AllowPublicURL `
        --action lambda:InvokeFunctionUrl `
        --principal "*" `
        --function-url-auth-type NONE `
        --region $REGION | Out-Null
    Assert-Success "add-permission AllowPublicURL"

    # Read the URL we just created
    $RESPONDER_URL = aws lambda get-function-url-config `
        --function-name S3SentryResponder `
        --region $REGION `
        --query "FunctionUrl" `
        --output text
    Assert-Success "get-function-url-config (after create)"
} else {
    Write-Host "  Function URL already exists -- skipping creation." -ForegroundColor Yellow

    # Ensure public invoke permission exists even if URL was pre-existing
    $null = (aws lambda add-permission `
        --function-name S3SentryResponder `
        --statement-id AllowPublicFunctionUrl `
        --action lambda:InvokeFunctionUrl `
        --principal "*" `
        --function-url-auth-type NONE `
        --region $REGION) 2>&1
    # exit code 1 = statement already exists -- that is fine
}

if ([string]::IsNullOrWhiteSpace($RESPONDER_URL) -or $RESPONDER_URL -eq "None") {
    Write-Host "  ERROR: Could not read Responder URL after creation." -ForegroundColor Red
    exit 1
}
Write-Host "  Responder URL: $RESPONDER_URL" -ForegroundColor Green

# --- Part B: Inject RESPONDER_URL into Orchestrator Lambda ---
#
# Two Windows-specific requirements:
#   1. Write WITHOUT BOM -- Set-Content -Encoding UTF8 adds a BOM in PowerShell 5,
#      which the AWS CLI JSON parser rejects with "Invalid JSON received".
#      Fix: [System.IO.File]::WriteAllText with UTF8Encoding($false).
#   2. Forward slashes in file:// URI -- AWS CLI cannot resolve file://C:\... paths.
#      Fix: replace backslashes and prepend file:///.
$orchEnvJson = aws lambda get-function-configuration `
    --function-name S3SentryOrchestrator `
    --region $REGION `
    --query "Environment.Variables" `
    --output json
Assert-Success "Lambda get-function-configuration (Orchestrator)"

# Convert PSCustomObject to plain hashtable so ConvertTo-Json serialises cleanly
$rawOrchEnv = $orchEnvJson | ConvertFrom-Json
$orchEnvHash = @{}
$rawOrchEnv.PSObject.Properties | ForEach-Object { $orchEnvHash[$_.Name] = $_.Value }
$orchEnvHash["RESPONDER_URL"] = $RESPONDER_URL

$orchJson = @{
    FunctionName = "S3SentryOrchestrator"
    Environment  = @{ Variables = $orchEnvHash }
} | ConvertTo-Json -Depth 5 -Compress

$orchTmpPath = [System.IO.Path]::GetTempPath() + "s3sentry-orch-env.json"
[System.IO.File]::WriteAllText($orchTmpPath, $orchJson, [System.Text.UTF8Encoding]::new($false))
$orchFileUri = "file://" + $orchTmpPath.Replace("\", "/")

aws lambda update-function-configuration --region $REGION --cli-input-json $orchFileUri | Out-Null
Assert-Success "Orchestrator Lambda update-function-configuration"
Remove-Item $orchTmpPath -ErrorAction SilentlyContinue
Write-Host "  RESPONDER_URL injected into S3SentryOrchestrator." -ForegroundColor Green

# --- Part C: Inject env vars into Responder Lambda ---
$responderJson = @{
    FunctionName = "S3SentryResponder"
    Environment  = @{
        Variables = @{
            DYNAMODB_TABLE  = $DYNAMODB_TABLE
            HMAC_KEY_PATH   = $HMAC_KEY_PATH
            S3_VAULT_BUCKET = $S3_VAULT_BUCKET
            DRY_RUN         = $DRY_RUN
        }
    }
} | ConvertTo-Json -Depth 5 -Compress

$responderTmpPath = [System.IO.Path]::GetTempPath() + "s3sentry-responder-env.json"
[System.IO.File]::WriteAllText($responderTmpPath, $responderJson, [System.Text.UTF8Encoding]::new($false))
$responderFileUri = "file://" + $responderTmpPath.Replace("\", "/")

aws lambda update-function-configuration --region $REGION --cli-input-json $responderFileUri | Out-Null
Assert-Success "Responder Lambda update-function-configuration"
Remove-Item $responderTmpPath -ErrorAction SilentlyContinue
Write-Host "  Environment variables injected into S3SentryResponder." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "Deployment complete." -ForegroundColor Green
Write-Host "  Orchestrator Lambda : S3SentryOrchestrator"
Write-Host "  Responder Lambda    : S3SentryResponder"
Write-Host "  Responder URL       : $RESPONDER_URL"
Write-Host "  DRY_RUN             : $DRY_RUN"
