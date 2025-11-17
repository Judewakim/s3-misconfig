from utils.sts_helper import get_client_session

def remediate(event):
    bucket_name = event['detail']['resourceId']
    account_id = event['detail']['awsAccountId']
    
    session = get_client_session(account_id)
    s3 = session.client('s3')
    
    log_bucket = f'{bucket_name}-logs'
    
    # Create log bucket if it doesn't exist
    try:
        s3.head_bucket(Bucket=log_bucket)
    except:
        s3.create_bucket(Bucket=log_bucket)
        s3.put_public_access_block(
            Bucket=log_bucket,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
    
    # Enable logging
    s3.put_bucket_logging(
        Bucket=bucket_name,
        BucketLoggingStatus={
            'LoggingEnabled': {
                'TargetBucket': log_bucket,
                'TargetPrefix': f'{bucket_name}/'
            }
        }
    )
    
    return {'status': 'success', 'action': f'Enabled logging to {log_bucket}'}
