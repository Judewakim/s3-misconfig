# fix_env.ps1
# Cleans out any conflicting Pydantic installation and reinstalls the
# exact versions compatible with Prowler 3.x.
# Run from the repo root: .\fix_env.ps1

Write-Host "Removing existing Pydantic installations..." -ForegroundColor Yellow
pip uninstall -y pydantic pydantic-core

Write-Host "`nInstalling compatible versions..." -ForegroundColor Yellow
pip install "pydantic>=1.10.0,<2.0.0" "prowler>=3.0,<4.0" boto3

Write-Host "`nInstalled versions:" -ForegroundColor Green
pip show pydantic | Select-String "Version"
pip show prowler  | Select-String "Version"
pip show boto3    | Select-String "Version"

Write-Host "`nDone. Run orchestrator.py to verify." -ForegroundColor Green
