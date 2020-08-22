import json
from urllib.parse import parse_qs
import urllib.parse
import boto3
import secrets
import logging
import os
import base64

log = logging.getLogger()
log.setLevel(logging.INFO)

def lambda_handler(event, context):
  
    log.info(event.get("body"))
    qs = parse_qs(event.get("body"))
  
    uname = qs.get("uname")[0] 
    pwd = qs.get("password")[0]
    
    dynamodb = boto3.resource('dynamodb')

    table = dynamodb.Table(os.environ['userTable'])
    response = table.get_item(Key={'userid': uname})
    json_str =  json.dumps( response['Item'])

    #using json.loads will turn your data into a python dictionary
    resp_dict = json.loads(json_str)
    dbpass = resp_dict.get("password")
    
    #Decrypt password
    log.info('key id:'+os.environ['keyid'])
    key = os.environ['keyid']
    client = boto3.client('kms')
   
    response = client.decrypt(
    CiphertextBlob=(base64.b64decode(dbpass)),
    KeyId=key
    )
    log.info("Decrypted value")
    decryptedPass = response['Plaintext'].decode('UTF-8')
    
    response = {}
   
    if decryptedPass == pwd : 
      token = secrets.token_hex(16)  
      response = table.update_item(
        Key={
            'userid': uname
        },
        AttributeUpdates={
            'token': {
                'Value': token,
            }
            }
        )
      
      return {
        'statusCode': 200,
        'headers':{
             'Set-Cookie':'tkn='+uname+'&'+token+';Secure;SameSite=None;HttpOnly;Domain=.amazonaws.com;Path=/',
             'Content-Type': 'text/html'
         },
        'body': '<html><head><script>window.location.href = \''+ os.environ['showFilesUrl']+'\' </script></head><body>Hello</body></html>'
      }
    else:
     response['status'] = 'Login Failed'
     return {
        'statusCode': 200,
        'body': json.dumps(response) 
      }
         


