from utils.sts_helper import get_client_session

def remediate(event):
    bucket_name = event['detail']['resourceId']
    account_id = event['detail']['awsAccountId']
    
    session = get_client_session(account_id)
    s3 = session.client('s3')
    
    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            'Rules': [{
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'AES256'
                },
                'BucketKeyEnabled': True
            }]
        }
    )
    
    return {'status': 'success', 'action': 'Enabled AES256 encryption'}
