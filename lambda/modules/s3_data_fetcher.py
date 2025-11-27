import json
import boto3
from datetime import datetime, timedelta

s3_client = boto3.client('s3')

def fetch_compliance_events(bucket, days=30):
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    response = s3_client.list_objects_v2(Bucket=bucket, Prefix='compliance-events/')
    events = []
    for obj in response.get('Contents', []):
        if obj['LastModified'].replace(tzinfo=None) >= cutoff_date:
            event_obj = s3_client.get_object(Bucket=bucket, Key=obj['Key'])
            events.append(json.loads(event_obj['Body'].read()))
    return sorted(events, key=lambda x: x['timestamp'], reverse=True)

def fetch_latest_compliance_event(bucket):
    response = s3_client.list_objects_v2(Bucket=bucket, Prefix='compliance-events/', MaxKeys=1)
    if not response.get('Contents'):
        return {'events': [], 'timestamp': None}
    
    latest_obj = sorted(response['Contents'], key=lambda x: x['LastModified'], reverse=True)[0]
    event_obj = s3_client.get_object(Bucket=bucket, Key=latest_obj['Key'])
    event = json.loads(event_obj['Body'].read())
    
    return {
        'event': event,
        'timestamp': event['timestamp'],
        'scanTime': latest_obj['LastModified'].isoformat()
    }
