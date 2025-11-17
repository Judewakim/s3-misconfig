from utils.sts_helper import get_client_session

def remediate(event):
    bucket_name = event['detail']['resourceId']
    account_id = event['detail']['awsAccountId']
    
    session = get_client_session(account_id)
    s3 = session.client('s3')
    
    # Block public access
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
    
    return {'status': 'success', 'action': 'Blocked public access'}
