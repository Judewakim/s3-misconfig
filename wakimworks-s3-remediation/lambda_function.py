import json
import os
from remediations import public_read, versioning, encryption_rest, encryption_transit, logging
from utils import logger

REMEDIATION_MAP = {
    's3-bucket-public-read-prohibited': public_read.remediate,
    's3-bucket-versioning-enabled': versioning.remediate,
    's3-bucket-server-side-encryption-enabled': encryption_rest.remediate,
    's3-bucket-ssl-requests-only': encryption_transit.remediate,
    's3-bucket-logging-enabled': logging.remediate
}

def lambda_handler(event, context):
    try:
        print(f"Received event: {json.dumps(event)}")
        
        # Parse SNS message
        if 'Records' in event and len(event['Records']) > 0:
            sns_message = json.loads(event['Records'][0]['Sns']['Message'])
        else:
            sns_message = event
        
        rule_name = sns_message['ConfigRuleName']
        resource_id = sns_message['ResourceId']
        account_id = sns_message['ClientAccountId']
        
        print(f"Processing {rule_name} for resource {resource_id} in account {account_id}")
        
        remediation_func = REMEDIATION_MAP.get(rule_name)
        if not remediation_func:
            return {'statusCode': 400, 'body': f'No remediation for rule: {rule_name}'}
        
        # Create event format for remediation functions
        remediation_event = {
            'detail': {
                'configRuleName': rule_name,
                'resourceId': resource_id,
                'awsAccountId': account_id
            }
        }
        
        result = remediation_func(remediation_event)
        logger.log_remediation(account_id, resource_id, rule_name, result)
        
        return {'statusCode': 200, 'body': json.dumps(result)}
    
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return {'statusCode': 500, 'body': str(e)}
