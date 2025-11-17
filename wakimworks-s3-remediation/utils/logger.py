import boto3
import json
import os
from datetime import datetime

TABLE_NAME = os.environ.get('DYNAMODB_TABLE', 'test-table')
LOGS_BUCKET = os.environ.get('S3_LOGS_BUCKET', 'test-bucket')

try:
    dynamodb = boto3.resource('dynamodb')
    s3 = boto3.client('s3')
except:
    dynamodb = None
    s3 = None

def log_remediation(account_id, resource_id, rule_name, result):
    if not dynamodb or not s3:
        print(f"[LOCAL TEST] Would log: {account_id}/{resource_id}/{rule_name}")
        return
    
    timestamp = datetime.utcnow().isoformat()
    
    # DynamoDB
    table = dynamodb.Table(TABLE_NAME)
    table.put_item(Item={
        'ClientAccountId': account_id,
        'Timestamp': timestamp,
        'ResourceId': resource_id,
        'RuleName': rule_name,
        'Result': json.dumps(result),
        'TTL': int(datetime.utcnow().timestamp()) + 7776000  # 90 days
    })
    
    # S3
    log_key = f'{account_id}/{resource_id}/{timestamp}.json'
    s3.put_object(
        Bucket=LOGS_BUCKET,
        Key=log_key,
        Body=json.dumps({
            'account_id': account_id,
            'resource_id': resource_id,
            'rule_name': rule_name,
            'result': result,
            'timestamp': timestamp
        })
    )
