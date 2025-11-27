import boto3
from datetime import datetime

s3_client = boto3.client('s3')

def upload_pdf(pdf_bytes, bucket):
    timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    pdf_key = f'reports/compliance-report-{timestamp}.pdf'
    s3_client.put_object(Bucket=bucket, Key=pdf_key, Body=pdf_bytes, ContentType='application/pdf')
    return pdf_key

def generate_presigned_url(bucket, key, expiration=300):
    return s3_client.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket, 'Key': key},
        ExpiresIn=expiration
    )
