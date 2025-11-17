import boto3

def get_client_session(account_id):
    sts = boto3.client('sts')
    role_arn = f'arn:aws:iam::{account_id}:role/WakimWorksRemediationRole'
    
    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName='WakimWorksRemediation'
    )
    
    return boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )
