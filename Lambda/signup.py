import json
from urllib.parse import parse_qs
import urllib.parse
import boto3
import logging
import os
import base64

log = logging.getLogger()
log.setLevel(logging.INFO)

def lambda_handler(event, context):
    log.info(event)
    log.info(event.get("body"))
    qs = parse_qs(event.get("body"))
    log.info(qs)
    uname = qs.get("uname")[0] 
    pwd = qs.get("password")[0]
    
    
    
    
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ['userTable'])

    log.info('key id:'+os.environ['keyid'])
    key = os.environ['keyid']
    client = boto3.client('kms')
    #Encrypt password
    response = client.encrypt(
    Plaintext=pwd,
    KeyId=key
    )
    log.info(response['CiphertextBlob'])
    #log.info(().decode('utf-8'))
    b64_pass = str(base64.b64encode(response['CiphertextBlob']),'utf-8')
    log.info(b64_pass)
   
    response = table.update_item(
        Key={
            'userid': uname
        },
        AttributeUpdates={
            'password': {
                'Value': b64_pass,
            }
            }
        )
    data = {}
    data['status'] = 'Signup Success'
    json_data = json.dumps(data)    
    return {
        'statusCode': 200,
        'body': json_data
    }
         

