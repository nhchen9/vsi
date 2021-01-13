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
KMS_KEY_ARN = 'arn:aws:kms:us-west-1:779619664536:key/bd199a4c-b7d4-42a3-9b9e-816e9f4155e2'
BUCKET = 'enclave-testing-721f5e9d-2b0c-46b7-8128-411a764cb8de'
ENCLAVE_CID = '26'
def upload_file(key, text, bucket=BUCKET):
    session = boto3.session.Session(region_name='us-west-1')
    s3_client = session.client('s3')
    kms_client = session.client('kms')
    encrypted_data = kms_client.encrypt(KeyId=KMS_KEY_ARN, Plaintext=text)
    data = {'encrypted_data': base64.b64encode(encrypted_data['CiphertextBlob']).decode()}
    serialized = json.dumps(data)
    try:
        response = s3_client.put_object(Bucket=bucket, Key=key, Body=bytes(serialized.encode('utf-8')))
    except ClientError as e:
        logging.error(e)
        return False
    return True
def decrypt_data(key, bucket=BUCKET):
    session = boto3.session.Session(region_name='us-west-1')
    s3_client = session.client('s3')
    kms_client = session.client('kms')
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        ciphertext = json.loads(response['Body'].read())['encrypted_data']
    except ClientError as e:
        logging.error(e)
        return False
    docker_client = docker.from_env()
    # print(ciphertext)
    # print(ENCLAVE_CID)
    # start = time.time()
    # times = []
    # for i in range(10000):
        # elapsed = time.time() - start
        # print(i, elapsed)
        # times.append(elapsed)
        # start = time.time()
    container = docker_client.containers.run(image='kmstool-instance', network='host', command=f'/kmstool_instance --cid "{ENCLAVE_CID}" "{ciphertext}"', detach=True)
if __name__ == '__main__':
    key = 'test_key'
    decrypt_data(key)
    # text = 'Hello World!'
    # upload_file(key, text)