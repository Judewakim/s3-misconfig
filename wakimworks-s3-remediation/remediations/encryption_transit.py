import json
from utils.sts_helper import get_client_session

def remediate(event):
    bucket_name = event['detail']['resourceId']
    account_id = event['detail']['awsAccountId']
    
    session = get_client_session(account_id)
    s3 = session.client('s3')
    
    policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Sid': 'DenyInsecureTransport',
            'Effect': 'Deny',
            'Principal': '*',
            'Action': 's3:*',
            'Resource': [
                f'arn:aws:s3:::{bucket_name}',
                f'arn:aws:s3:::{bucket_name}/*'
            ],
            'Condition': {
                'Bool': {'aws:SecureTransport': 'false'}
            }
        }]
    }
    
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
    
    return {'status': 'success', 'action': 'Enforced SSL/TLS'}
