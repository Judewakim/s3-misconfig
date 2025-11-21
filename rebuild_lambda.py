#!/usr/bin/env python3
import sys
import shutil
import zipfile
from pathlib import Path
import subprocess

lambda_dir = Path("lambda")
package_dir = lambda_dir / "package"
zip_path = lambda_dir / "report_generator.zip"

print("Cleaning up old package...")
if package_dir.exists():
    shutil.rmtree(package_dir)
if zip_path.exists():
    zip_path.unlink()

package_dir.mkdir(exist_ok=True)

print("Installing dependencies for Linux...")
subprocess.run([
    sys.executable, "-m", "pip", "install",
    "reportlab", "Pillow",
    "--platform", "manylinux2014_x86_64",
    "--only-binary=:all:",
    "--target", str(package_dir),
    "--python-version", "3.12"
], check=True)

print("Creating deployment package...")
with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for root, dirs, files in package_dir.rglob("*"):
        if root.is_file():
            zipf.write(root, root.relative_to(package_dir))
    zipf.write(lambda_dir / "report_generator.py", "report_generator.py")
    zipf.write("logo.png", "logo.png")

print(f"✅ Package rebuilt: {zip_path}")
