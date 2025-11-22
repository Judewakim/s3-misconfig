#!/usr/bin/env python3
import subprocess
import sys
import os
import shutil
import zipfile
from pathlib import Path

def run_command(cmd, cwd=None, show_output=False):
    """Run shell command and handle errors"""
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
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
    run_command([
        sys.executable, "-m", "pip", "install",
        "reportlab", "Pillow",
        "--platform", "manylinux2014_x86_64",
        "--only-binary=:all:",
        "--target", str(package_dir),
        "--python-version", "3.12"
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
        
        # Add Lambda function
        zipf.write(lambda_dir / "report_generator.py", "report_generator.py")
        
        # Add logo
        zipf.write("logo.png", "logo.png")
    
    print(f"Package created: {zip_path}")

def main():
    print("=" * 50)
    print("WakimWorks Compliance Scanner Deployment")
    print("=" * 50)
    
    # Verify AWS credentials
    print("\nVerifying AWS credentials...")
    run_command(["aws", "sts", "get-caller-identity"], show_output=True)
    
    # Build Lambda package
    build_lambda_package()
    
    # Deploy CloudFormation stack
    print("\n=== Deploying CloudFormation stack ===")
    print("This may take a few minutes...")
    run_command([
        "aws", "cloudformation", "deploy",
        "--stack-name", "WakimWorksComplianceScanner",
        "--template-file", "wakimworks-compliance-scanner.yaml",
        "--region", "us-east-1",
        "--capabilities", "CAPABILITY_NAMED_IAM",
        "--parameter-overrides", "AuditingBucketName=wakimworks-compliance-scanner-audit-logs"
    ])
    
    # Update Lambda function
    print("\n=== Updating Lambda function ===")
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
    print("\n=== Deploying dashboard ===")
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
    index_path = Path("dashboard/index.html")
    index_content = index_path.read_text()
    updated_content = index_content.replace("REPLACE_WITH_API_ENDPOINT", api_url)
    temp_index = Path("dashboard/index_configured.html")
    temp_index.write_text(updated_content)
    
    # Deploy dashboard files
    run_command(["aws", "s3", "cp", str(temp_index),
                 "s3://wakimworks-compliance-scanner-audit-logs-dashboard/index.html",
                 "--region", "us-east-1"])
    run_command(["aws", "s3", "cp", "dashboard/error.html",
                 "s3://wakimworks-compliance-scanner-audit-logs-dashboard/",
                 "--region", "us-east-1"])
    run_command(["aws", "s3", "cp", "logo.png",
                 "s3://wakimworks-compliance-scanner-audit-logs-dashboard/",
                 "--region", "us-east-1"])
    
    # Clean up temp file
    temp_index.unlink()
    
    # Get CloudFront URL
    cloudfront_url = run_command([
        "aws", "cloudformation", "describe-stacks",
        "--stack-name", "WakimWorksComplianceScanner",
        "--query", "Stacks[0].Outputs[?OutputKey=='DashboardURL'].OutputValue",
        "--output", "text",
        "--region", "us-east-1"
    ])
    
    print("\n" + "=" * 50)
    print("Deployment Complete!")
    print("=" * 50)
    print(f"Dashboard URL: {cloudfront_url}")
    # print(f"Report API URL: {api_url}")
    print("=" * 50)

if __name__ == "__main__":
    main()
