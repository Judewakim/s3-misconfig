import boto3
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def send(event, context, response_status, response_data, physical_resource_id=None, no_echo=False):
    response_url = event['ResponseURL']
    response_body = {
        'Status': response_status,
        'Reason': 'See the details in CloudWatch Log Stream: ' + context.log_stream_name,
        'PhysicalResourceId': physical_resource_id or context.log_stream_name,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'NoEcho': no_echo,
        'Data': response_data
    }
    json_response = json.dumps(response_body)
    logger.info(f"ResponseURL: {response_url}, ResponseBody: {json_response}")
    try:
        boto3.client('s3').put_object(
            Bucket=response_url.split('/')[2],
            Key='/'.join(response_url.split('/')[3:]),
            Body=json_response,
            ContentType='application/json'
        )
    except Exception as e:
        logger.error(f"Failed to send response: {e}")
        raise