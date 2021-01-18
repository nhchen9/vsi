import boto3
import json
import logging
import base64
import subprocess
import docker
import time
from botocore.exceptions import ClientError
from botocore.config import Config
from multiprocessing import Process
import re
KMS_KEY_ARN = 'arn:aws:kms:us-west-2:779619664536:key/d3a3ce82-5390-49d8-bd77-400ebbe77946'
BUCKET = 'enclave-testing-721f5e9d-2b0c-46b7-8128-411a764cb8de'
ENCLAVE_CID = '26'
def upload_file(key, text, bucket=BUCKET):
    session = boto3.session.Session(region_name='us-west-2')
    s3_client = session.client('s3')
    kms_client = session.client('kms')
    data = {'encrypted_data': text}
    serialized = json.dumps(data)
    try:
        response = s3_client.put_object(Bucket=bucket, Key=key, Body=bytes(serialized.encode('utf-8')))
    except ClientError as e:
        logging.error(e)
        return False
    return True

def get_s3_data(key, bucket=BUCKET):
    session = boto3.session.Session(region_name='us-west-2')
    s3_client = session.client('s3')
    kms_client = session.client('kms')
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        ciphertext = json.loads(response['Body'].read())['encrypted_data']
    except ClientError as e:
        #logging.error(e)
        return False
    return ciphertext
def run_instance(cid, data, command):
    #cid = 59
    #command = "AQICAHjDlQ35nIiO6k4cvEcJooGbQY3jNzV/jZYVN8q3cCqdMAH/kuDMzQ3ZvqvctGPXsoVrAAAAhTCBggYJKoZIhvcNAQcGoHUwcwIBADBuBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDI2CbKXhsN9uwyFfsAIBEIBBMnF0R+J+f6uK5tHLI8F6WMcKMqBsCt00G5c8s0Gnf2Fsu7dnJrbX/ykuBiqo/zXNuY2Qy2ZSHevyADbtNYsZmEE="
    docker_client = docker.from_env()
    container = docker_client.containers.run(image='kmstool-instance', network='host', command='/kmstool_instance --cid "{cid}" "{data}" "{command}"'.format(cid=cid, data=data, command=command), remove = True, stdout = False, stderr = True, detach=False)
    
    #print(container.logs(stdout=True, stderr=True))
    msg = re.findall('Message": "(.*?)" }\n', container)[0]
    return msg
if __name__ == '__main__':
    
    encrypted_commands = get_s3_data("encrypted_commands")
    cmd_list = encrypted_commands.split("\n")

    counter = 0
    s3_data_key = "encrypted_data"
    session = boto3.session.Session(region_name='us-west-2')
    kms_client = session.client('kms')

    plain_cmd_ref = open("cmd.txt","rt").read().split("\n")

    for cmd in cmd_list:

        encrypted_data = get_s3_data(s3_data_key)
        if not encrypted_data:
            encrypted_data = kms_client.encrypt(KeyId=KMS_KEY_ARN, Plaintext="{}")
            print(encrypted_data)
            encrypted_data = base64.b64encode(encrypted_data['CiphertextBlob']).decode()
        
        print(plain_cmd_ref[counter])
        counter += 1
        msg = run_instance(24, encrypted_data, cmd).replace("\\", "")
        if len(msg) > 1:
            print("Command {c}: Data update, Result: {res}".format(c = counter, res = msg))
            encrypted_data = msg #kms_client.encrypt(KeyId=KMS_KEY_ARN, Plaintext=msg)
            #print("DEMO PRINT DATA: %s\n", kms_client.decrypt(CiphertextBlob=encrypted_data))

            upload_file(s3_data_key, encrypted_data)
        else:
            print("Command {c}: Status Query, Result: {res}".format(c = counter, res = msg))
        #break
        
    """
    key = 'plaintext_commands'
    #decrypt_data(key)
    text = open("cmd.txt","rt").read()
    upload_file(key, text)

    encrypted_commands = []
    commands = text.split("\n")

    session = boto3.session.Session(region_name='us-west-2')
    kms_client = session.client('kms')

    for cmd in commands:
        if len(cmd) < 6:
            continue
        encrypted_data = kms_client.encrypt(KeyId=KMS_KEY_ARN, Plaintext=cmd)
        encrypted_commands.append(base64.b64encode(encrypted_data['CiphertextBlob']).decode())
    encrypted_commands_str = "\n".join(encrypted_commands)
    key = "encrypted_commands"
    upload_file(key, encrypted_commands_str)
    """