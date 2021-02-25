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
import numpy as np
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

def get_s3_plaintext(key, bucket=BUCKET):
    session = boto3.session.Session(region_name='us-west-2')
    s3_client = session.client('s3')
    kms_client = session.client('kms')
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        dat = response['Body'].read()
    except ClientError as e:
        #logging.error(e)
        return False
    return dat

def run_instance(cid, command, data, key):
    docker_client = docker.from_env()
    container = docker_client.containers.run(image='kmstool-instance', network='host', command='/kmstool_instance --cid "{cid}" "{command}" "{data}" "{key}"'.format(cid=cid, data=data, command=command, key=key).replace('"None"', ''), remove = True, stdout = False, stderr = True, detach=False)
    
    if len(re.findall('EncData": "(.*?)",', container)) > 0:
        encData = re.findall('EncData": "(.*?)",', container)[0].replace("\\", "")
        encKey = re.findall('KeyPackage": "(.*?)" }', container)[0].replace("\\", "")
        return encData, encKey, None
    else:
        msg = re.findall('Message": "(.*?)" }\n', container)[0].replace('\\', '')
        return None, None, msg

def num_to_id(i):
    uuid = str(i)
    return uuid
def make_data(users, hist_len):
    dat = {}
    for i in range(users):
        uuid = num_to_id(i)
        dat[uuid] = ''
        for j in range(hist_len):
            dat[uuid] += str(np.random.randint(2))

    return dat

if __name__ == '__main__':

    # Data and key are stored locally in encrypted format.
    LOCAL_DATA = "./data.txt"
    LOCAL_KEY = "./key.txt"
    cur_data = None
    cur_key = None

    #encrypted_commands = get_s3_data("encrypted_commands2")
    encrypted_commands = open("encrypted_commands.txt", "rt").read()
    cmd_list = encrypted_commands.split("\n")

    session = boto3.session.Session(region_name='us-west-2')
    kms_client = session.client('kms')

    #Local file with plaintext commands, for reference
    plain_cmd_ref = open("cmd.txt","rt").read().split("\n")
    for i in range(20):
        cmd = cmd_list[i]
        if i > 0:
            cur_data = open(LOCAL_DATA, "rt").read()
            cur_key = open(LOCAL_KEY, "rt").read()
        t0 = time.time()
        
        print(plain_cmd_ref[i])
        
        #hardcoded enclave cid to be 5... set with "--enclave-cid 5" or replace with actual cid
        encData, encKey, qResult = run_instance(5, cmd, cur_data, cur_key)
        if encData:
            #If data update, write new data and key files
            open(LOCAL_DATA, "wt").write(encData)
            open(LOCAL_KEY, "wt").write(encKey)
        else:
            #If status query, print result
            print(qResult)
