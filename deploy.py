#!/usr/bin/env python3
import subprocess
import sys
import os
import shutil
import zipfile
import time
from pathlib import Path

def run_command(cmd, cwd=None, show_output=False, allow_failure=False):
    """Run shell command and handle errors"""
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        if result.stdout:
            print(f"Output: {result.stdout}")
        if not allow_failure:
            sys.exit(1)
    if show_output:
        print(result.stdout)
    return result.stdout.strip()

def build_lambda_package():
    """Build Lambda deployment package with Linux-compatible dependencies"""
    print("\n=== Packaging Lambda function ===")
    lambda_dir = Path("lambda")
    package_dir = lambda_dir / "package"
    zip_path = lambda_dir / "report_generator.zip"
    
    # Clean up
    if package_dir.exists():
        shutil.rmtree(package_dir)
    if zip_path.exists():
        zip_path.unlink()
    
    package_dir.mkdir(exist_ok=True)
    
    # Install dependencies for Linux
    print("Installing dependencies for Linux...")
    try:
        run_command([
            sys.executable, "-m", "pip", "install",
            "reportlab", "Pillow",
            "--platform", "manylinux2014_x86_64",
            "--only-binary=:all:",
            "--target", str(package_dir),
            "--python-version", "3.12",
            "--no-user"
        ], allow_failure=True)
    except Exception as e:
        print(f"Warning: Could not install platform-specific packages: {e}")
        print("Trying alternative installation method...")
        run_command([
            sys.executable, "-m", "pip", "install",
            "reportlab", "Pillow",
            "--target", str(package_dir),
            "--no-user"
        ])
    
    # Create zip
    print("Creating deployment package...")
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add dependencies
        for root, dirs, files in os.walk(package_dir):
            for file in files:
                file_path = Path(root) / file
                arcname = file_path.relative_to(package_dir)
                zipf.write(file_path, arcname)
        
        # Add Lambda functions
        zipf.write(lambda_dir / "report_generator.py", "report_generator.py")
        zipf.write(lambda_dir / "report_components.py", "report_components.py")
        zipf.write(lambda_dir / "report_styles.py", "report_styles.py")
        zipf.write(lambda_dir / "report_data.py", "report_data.py")
        
        # Add logo
        zipf.write("logo.png", "logo.png")
    
    print(f"Package created: {zip_path}")

def main():
    print("=" * 50)
    print("WakimWorks Compliance Scanner Deployment")
    print("=" * 50)
    
    # Verify AWS credentials
    print("\n=== Verifying AWS credentials ===")
    run_command(["aws", "sts", "get-caller-identity"], show_output=True)
    
    # Build Lambda package
    build_lambda_package()
    
    # Deploy CloudFormation stack
    print("\n\n=== Deploying CloudFormation stack ===")
    print("Starting deployment...")
    
    # Check if stack exists
    stack_exists = subprocess.run([
        "aws", "cloudformation", "describe-stacks",
        "--stack-name", "WakimWorksComplianceScanner",
        "--region", "us-east-1"
    ], capture_output=True).returncode == 0
    
    # Start deployment (non-blocking)
    if stack_exists:
        subprocess.run([
            "aws", "cloudformation", "update-stack",
            "--stack-name", "WakimWorksComplianceScanner",
            "--template-body", "file://wakimworks-compliance-scanner.yaml",
            "--region", "us-east-1",
            "--capabilities", "CAPABILITY_NAMED_IAM",
            "--parameters",
            "ParameterKey=AuditingBucketName,ParameterValue=wakimworks-compliance-scanner-audit-logs",
            "ParameterKey=EnableSecurityHubIntegration,ParameterValue=true"
        ], check=False)
    else:
        subprocess.run([
            "aws", "cloudformation", "create-stack",
            "--stack-name", "WakimWorksComplianceScanner",
            "--template-body", "file://wakimworks-compliance-scanner.yaml",
            "--region", "us-east-1",
            "--capabilities", "CAPABILITY_NAMED_IAM",
            "--parameters",
            "ParameterKey=AuditingBucketName,ParameterValue=wakimworks-compliance-scanner-audit-logs",
            "ParameterKey=EnableSecurityHubIntegration,ParameterValue=true"
        ], check=True)
    
    # Poll stack status
    print("Monitoring stack deployment...")
    print("This may take a few minutes...")
    while True:
        result = subprocess.run([
            "aws", "cloudformation", "describe-stacks",
            "--stack-name", "WakimWorksComplianceScanner",
            "--query", "Stacks[0].StackStatus",
            "--output", "text",
            "--region", "us-east-1"
        ], capture_output=True, text=True)
        
        status = result.stdout.strip()
        print(f"Status: {status}")
        
        if "COMPLETE" in status:
            print("Stack deployment successful!")
            break
        elif "FAILED" in status or "ROLLBACK" in status:
            print(f"\n❌ Stack deployment FAILED with status: {status}")
            print("\nFetching failure details...")
            run_command([
                "aws", "cloudformation", "describe-stack-events",
                "--stack-name", "WakimWorksComplianceScanner",
                "--query", "StackEvents[?ResourceStatus=='CREATE_FAILED' || ResourceStatus=='UPDATE_FAILED'].[LogicalResourceId,ResourceStatusReason]",
                "--output", "table",
                "--region", "us-east-1"
            ], show_output=True, allow_failure=True)
            sys.exit(1)
        
        time.sleep(10)
    
    # Update Lambda function
    print("\n\n=== Updating Lambda function ===")
    run_command([
        "aws", "lambda", "update-function-code",
        "--function-name", "wakimworks-report-generator",
        "--zip-file", "fileb://lambda/report_generator.zip",
        "--region", "us-east-1"
    ])
    
    print("Waiting for Lambda update to complete...")
    subprocess.run(["aws", "lambda", "wait", "function-updated",
                    "--function-name", "wakimworks-report-generator",
                    "--region", "us-east-1"], check=True)
    
    # Get API endpoint
    print("\n\n=== Deploying dashboard ===")
    api_url = run_command([
        "aws", "cloudformation", "describe-stacks",
        "--stack-name", "WakimWorksComplianceScanner",
        "--query", "Stacks[0].Outputs[?OutputKey=='ReportAPIEndpoint'].OutputValue",
        "--output", "text",
        "--region", "us-east-1"
    ])
    print(f"API Endpoint: {api_url}")
    
    # Update index.html with API endpoint
    print("Configuring dashboard with API endpoint...")
    print(f"API URL to inject: {api_url}")
    index_path = Path("dashboard/index.html")
    index_content = index_path.read_text(encoding='utf-8')
    
    if "REPLACE_WITH_API_ENDPOINT" not in index_content:
        print("WARNING: Placeholder 'REPLACE_WITH_API_ENDPOINT' not found in index.html!")
        print("Searching for existing API URL pattern...")
    
    # Replace the placeholder
    updated_content = index_content.replace("REPLACE_WITH_API_ENDPOINT", api_url)
    
    # Also replace any old hardcoded URLs (in case of re-deployment)
    if "execute-api" in index_content and api_url not in index_content:
        import re
        updated_content = re.sub(
            r'const REPORT_API_URL = [\'"]https://[^/]+\.execute-api\.[^/]+\.amazonaws\.com/[^\'"]+[\'"];',
            f'const REPORT_API_URL = \'{api_url}\';',
            updated_content
        )
    
    temp_index = Path("dashboard/index_configured.html")
    temp_index.write_text(updated_content, encoding='utf-8')
    
    # Verify replacement worked
    verify_content = temp_index.read_text(encoding='utf-8')
    if api_url in verify_content:
        print(f"✓ API endpoint successfully injected: {api_url}")
    else:
        print("✗ WARNING: API endpoint replacement failed!")
        print(f"Expected to find: {api_url}")
        print(f"In content preview: {verify_content[verify_content.find('REPORT_API_URL'):verify_content.find('REPORT_API_URL')+200]}")
    
    # Deploy dashboard files
    print("Uploading index.html...")
    run_command(["aws", "s3", "cp", str(temp_index),
                 "s3://wakimworks-compliance-scanner-audit-logs-dashboard/index.html",
                 "--content-type", "text/html",
                 "--region", "us-east-1"], show_output=True)
    print("Uploading error.html...")
    run_command(["aws", "s3", "cp", "dashboard/error.html",
                 "s3://wakimworks-compliance-scanner-audit-logs-dashboard/",
                 "--content-type", "text/html",
                 "--region", "us-east-1"], show_output=True)
    print("Uploading logo.png...")
    run_command(["aws", "s3", "cp", "logo.png",
                 "s3://wakimworks-compliance-scanner-audit-logs-dashboard/",
                 "--content-type", "image/png",
                 "--region", "us-east-1"], show_output=True)
    print("Dashboard files uploaded successfully!")
    
    # # Invalidate CloudFront cache
    # print("\nInvalidating CloudFront cache...")
    # cloudfront_id = run_command([
    #     "aws", "cloudformation", "describe-stacks",
    #     "--stack-name", "WakimWorksComplianceScanner",
    #     "--query", "Stacks[0].Outputs[?OutputKey=='DashboardURL'].OutputValue",
    #     "--output", "text",
    #     "--region", "us-east-1"
    # ]).split('.')[0].replace('https://', '')
    
    # try:
    #     run_command([
    #         "aws", "cloudfront", "create-invalidation",
    #         "--distribution-id", cloudfront_id,
    #         "--paths", "/*"
    #     ], allow_failure=True)
    #     print("CloudFront cache invalidated")
    # except:
    #     print("Could not invalidate CloudFront cache (may need to wait for propagation)")
    
    # Clean up temp file
    if temp_index.exists():
        temp_index.unlink()
    
    # Get CloudFront URL
    cloudfront_url = run_command([
        "aws", "cloudformation", "describe-stacks",
        "--stack-name", "WakimWorksComplianceScanner",
        "--query", "Stacks[0].Outputs[?OutputKey=='DashboardURL'].OutputValue",
        "--output", "text",
        "--region", "us-east-1"
    ])
    
    # Get Security Hub integration status
    sh_status = run_command([
        "aws", "cloudformation", "describe-stacks",
        "--stack-name", "WakimWorksComplianceScanner",
        "--query", "Stacks[0].Outputs[?OutputKey=='SecurityHubIntegrationStatus'].OutputValue",
        "--output", "text",
        "--region", "us-east-1"
    ])
    
    print("\n" + "=" * 50)
    print("Deployment Complete!")
    print("=" * 50)
    print(f"Dashboard URL: {cloudfront_url}")
    print(f"Report API URL: {api_url}")
    print(f"\nSecurity Hub Integration: {sh_status}")
    print("- Visit the Dashboard URL above")

    if sh_status == "Enabled":
        print("- Check Security Hub console for findings (after compliance event)")
    print("=" * 50)
    
    # Keep terminal open
    while True:
        user_input = input("\nType 'quit' or 'q' to exit: ").strip().lower()
        if user_input in ['quit', 'q']:
            break

if __name__ == "__main__":
    main()
