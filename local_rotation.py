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
import requests
import sys
import hashlib
import os
KMS_KEY_ARN = 'arn:aws:kms:us-west-2:269163721785:key/f12133ea-b6ac-4cff-89ad-8b1145b4a8bc'
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
	
def run_complete(cid, command, data, key, signature, value):
    if data == None:
      data = "None"
    if key == None:
      key = "None"
    docker_client = docker.from_env()
    container = docker_client.containers.run(image='kmstool-instance', network='host', command='/kmstool_instance --cid "{cid}" "{command}" "{data}" "{key}" "{sig}" "{value}"'.format(cid=cid, data=data, command=command, key=key, sig=signature, value=value), remove = True, stdout = False, stderr = True, detach=False)
    #print(cid, command, data, key, signature, value)
    #print(container)
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
def make_data(users, hisst_len):
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
		
        print("")        
        print(plain_cmd_ref[i])
        
        #hardcoded enclave cid to be 5... set with "--enclave-cid 5" or replace with actual cid
        #encData, encKey, qResult = run_instance(5, cmd, cur_data, cur_key)

        m = hashlib.sha256()
        if cur_data != None:
          m.update(cur_data)
        if cmd != None:
          m.update(cmd)
        m.update(b"1")
        inputHash = m.hexdigest()
        print("inputHash:"),
        print(inputHash)
        cert_file_path = "./user0_cert.pem"
        key_file_path = "./user0_privk.pem"
        cert = (cert_file_path, key_file_path)
        
        # for each run the assumption is that counter is initially zero, we cannot reset a counter once it has been incremented for monotonicity, however we can request a new counter from CCF using: curl https://168.62.188.41:8080/app/counter/reset -X POST --cacert networkcert.pem --cert user0_cert.pem --key user0_privk.pem -k -w "\n"
        # assign counter_id to response from the above curl request (new counter id)
        counter_id = str(6)
        headers = {'Content-Type': 'application/json'}
        data = {}
        data['id'] = counter_id
        data['hash'] = inputHash
        json_data = json.dumps(data)
        
        # temporary redirecting stderr around requests.post() due to console spam about server cert "verify=False", this is a open issue on CCF github concerning a mismatch in alternative domain name of node certificates and network certificate overall
        null_fds = [os.open(os.devnull, os.O_RDWR) for x in xrange(2)]
        save = os.dup(1), os.dup(2)
        os.dup2(null_fds[0], 1)
        os.dup2(null_fds[1], 2)     
        
        r = requests.post('https://168.62.188.41:8080/app/counter/increment', headers=headers, data=json_data, cert=cert, verify=False)

        os.dup2(save[0], 1)
        os.dup2(save[1], 2)
        os.close(null_fds[0])
        os.close(null_fds[1])      
        
        parse_response = json.loads(r.content)
        signature = parse_response['signature']
        value = parse_response['value']
        print("CCF response:"),
        print(value, signature)

		
        encData, encKey, qResult = run_complete(5, cmd, cur_data, cur_key, signature, value)
        
        if encData:
            #If data update, write new data and key files
            open(LOCAL_DATA, "wt").write(encData)
            open(LOCAL_KEY, "wt").write(encKey)
        else:
            #If status query, print result
            print(qResult)
			