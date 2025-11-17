from utils.sts_helper import get_client_session

def remediate(event):
    bucket_name = event['detail']['resourceId']
    account_id = event['detail']['awsAccountId']
    
    session = get_client_session(account_id)
    s3 = session.client('s3')
    
    s3.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={'Status': 'Enabled'}
    )
    
    return {'status': 'success', 'action': 'Enabled versioning'}
