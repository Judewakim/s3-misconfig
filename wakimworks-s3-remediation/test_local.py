#!/usr/bin/env python3
"""Local test script to verify Lambda function structure"""

import json
from lambda_function import lambda_handler, REMEDIATION_MAP

# Mock event from AWS Config
test_event = {
    'detail': {
        'configRuleName': 's3-bucket-public-read-prohibited',
        'resourceId': 'test-bucket-12345',
        'awsAccountId': '123456789012',
        'newEvaluationResult': {
            'complianceType': 'NON_COMPLIANT'
        }
    }
}

print("=== Lambda Function Structure Test ===\n")

# Test 1: Check REMEDIATION_MAP
print("[OK] REMEDIATION_MAP loaded with", len(REMEDIATION_MAP), "remediations:")
for rule_name in REMEDIATION_MAP.keys():
    print(f"  - {rule_name}")

# Test 2: Verify all modules are importable
print("\n[OK] All remediation modules imported successfully")

# Test 3: Check handler exists
print("\n[OK] lambda_handler function exists")

# Test 4: Simulate routing logic (without AWS calls)
rule_name = test_event['detail']['configRuleName']
if rule_name in REMEDIATION_MAP:
    print(f"\n[OK] Routing works: {rule_name} -> {REMEDIATION_MAP[rule_name].__name__}")
else:
    print(f"\n[FAIL] Routing failed: {rule_name} not found in REMEDIATION_MAP")

print("\n=== Structure Test Complete ===")
print("\nNote: This only tests structure. AWS API calls will fail without credentials.")
print("Deploy to AWS to test actual remediation functionality.")
