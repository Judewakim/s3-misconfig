@echo off
REM Clean up old package
if exist package rmdir /s /q package
if exist report_generator.zip del report_generator.zip

REM Create package directory
mkdir package

REM Install dependencies for Linux (Lambda runtime)
pip install reportlab Pillow --platform manylinux2014_x86_64 --only-binary=:all: --target ./package --python-version 3.12

REM Create zip from package directory
cd package
7z a -tzip ../report_generator.zip *
cd ..

REM Add Lambda function code
7z a -tzip report_generator.zip report_generator.py

REM Add logo
7z a -tzip report_generator.zip ../logo.png

echo.
echo Package created: report_generator.zip
echo.
echo To deploy, run:
echo aws lambda update-function-code --function-name wakimworks-report-generator --zip-file fileb://report_generator.zip --region us-east-1
