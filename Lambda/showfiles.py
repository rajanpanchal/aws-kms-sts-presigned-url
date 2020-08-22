import json
import logging
import boto3
import os

log = logging.getLogger()
log.setLevel(logging.INFO)

#retuns login cookie information userid and unique token
def getLoginCookie(cookies):
    data ={}
    for x in cookies:
      keyValue = x.split('=')

      if keyValue[0].strip() =='tkn':
        cookieValue = keyValue[1]
        tknvalues = cookieValue.split('&')
        data['uid']=tknvalues[0]
        data['tkn']=tknvalues[1]
      else:
        cookieValue =''
      return data

#verifies unique token that is saved in database vs in request      
def verifyLogin(data):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ['userTable'])
    response = table.get_item(Key={'userid': data['uid']})
    json_str =  json.dumps( response['Item'])

    resp_dict = json.loads(json_str)
    token = resp_dict.get("token")
    return bool(token == data['tkn'])
    
def getSignedUrl(key,s3_client):
    KeyUrl = {}
    
    response = s3_client.generate_presigned_url('get_object',
                                                    Params={'Bucket': os.environ['filesBucket'],
                                                            'Key': key},
                                                    ExpiresIn=3600)
    KeyUrl[key] = response
    return KeyUrl
    

# Returns list of files from bucket using STS    
def getFilesList():
    sts_client = boto3.client('sts')

    # Call the assume_role method of the STSConnection object and pass the role
    # ARN and a role session name.
    assumed_role_object=sts_client.assume_role(
        RoleArn=os.environ['s3role'],
        RoleSessionName="AssumeRoleSession1"
    )
    
    # From the response that contains the assumed role, get the temporary 
    # credentials that can be used to make subsequent API calls
    credentials=assumed_role_object['Credentials']
    
    # Use the temporary credentials that AssumeRole returns to make a 
    # connection to Amazon S3  
    s3_resource=boto3.resource(
        's3',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
    )
    s3_client = boto3.client('s3',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])
    bucket = s3_resource.Bucket(os.environ['filesBucket'])
    files=[]
    for obj in bucket.objects.all():
        files.append(getSignedUrl(obj.key,s3_client))
    return files
    

def lambda_handler(event, context):
    headers = event.get("headers")
    cookies = headers['Cookie'].split(";")
    data = getLoginCookie(cookies)
    isVerified = verifyLogin(data)

    if(isVerified):
        response = getFilesList()
    
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin':os.environ['origin'],
            'Access-Control-Allow-Credentials': 'true'
        },
        'body': json.dumps(response)
    }

