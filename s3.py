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

def run_instance(cid, data, command):
    #cid = 59
    #command = "AQICAHjDlQ35nIiO6k4cvEcJooGbQY3jNzV/jZYVN8q3cCqdMAH/kuDMzQ3ZvqvctGPXsoVrAAAAhTCBggYJKoZIhvcNAQcGoHUwcwIBADBuBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDI2CbKXhsN9uwyFfsAIBEIBBMnF0R+J+f6uK5tHLI8F6WMcKMqBsCt00G5c8s0Gnf2Fsu7dnJrbX/ykuBiqo/zXNuY2Qy2ZSHevyADbtNYsZmEE="
    docker_client = docker.from_env()
    container = docker_client.containers.run(image='kmstool-instance', network='host', command='/kmstool_instance --cid "{cid}" "{data}" "{command}"'.format(cid=cid, data=data, command=command), remove = True, stdout = False, stderr = True, detach=False)
    
    #print(container.logs(stdout=True, stderr=True))
    encData = re.findall('EncData": "(.*?)",', container)[0]
    encKey = re.findall('KeyPackage": "(.*?)" }', container)[0]
    
    return msg

def num_to_id(i):
    uuid = str(i)
    #while(len(uuid) < 8):
    #    uuid = '0'+uuid
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
    '''
    encrypted_commands = get_s3_data("encrypted_commands")
    cmd_list = encrypted_commands.split("\n")


    counter = 0
    s3_data_key = "100000_10.enc"
    session = boto3.session.Session(region_name='us-west-2')
    kms_client = session.client('kms')

    plain_cmd_ref = open("cmd.txt","rt").read().split("\n")
    query_times = []
    update_times = []
    upload_times = []
    #for cmd in cmd_list:
    for i in range(20):
        t0 = time.time()
        encrypted_data = get_s3_plaintext(s3_data_key)
        
        if not encrypted_data:
            dat = json.dumps(make_data(100,2))
            print(len(dat))
            encrypted_data = kms_client.encrypt(KeyId=KMS_KEY_ARN, Plaintext=dat)
            print(encrypted_data)
            encrypted_data = base64.b64encode(encrypted_data['CiphertextBlob']).decode()
        
        print(plain_cmd_ref[counter])
        
        msg = run_instance(37, encrypted_data, cmd).replace("\\", "")
        t1 = time.time()
        print("runtime: ", t1 - t0)
        if len(msg) > 1:
            print("Command {c}: Data update, Result: {res}".format(c = counter, res = msg))
            encrypted_data = msg #kms_client.encrypt(KeyId=KMS_KEY_ARN, Plaintext=msg)
            print(encrypted_data)
            #print("DEMO PRINT DATA: %s\n", kms_client.decrypt(CiphertextBlob=base64.b64decode(encrypted_data))['Plaintext'])

            upload_file(s3_data_key, encrypted_data)
            upload_times.append(time.time() - t1)
        else:
            print("Command {c}: Status Query, Result: {res}".format(c = counter, res = msg))
        #break
        
        t1 = time.time()
        print("total time: ", t1 - t0)
        if " " in plain_cmd_ref[counter]:
            update_times.append(t1-t0)
        else:
            query_times.append(t1-t0)
        counter += 1
        #time.sleep(1)
    print("avg upload time:", np.mean(upload_times), np.std(upload_times))
    print("avg update time:", np.mean(update_times), np.std(update_times))
    print("avg query time:", np.mean(query_times), np.std(query_times))
    '''
    '''
    for num_users in [10,100,1000,10000,100000]:
        for tests in [2,10]:
            dat = json.dumps(make_data(num_users,tests))
            open("test_data/{:s}_{:s}.txt".format(str(num_users), str(tests)),"wt").write(dat)
    #print(dat)
    exit(0)
    '''

    key = 'plaintext_commands'
    #decrypt_data(key)
    text = open("cmd.txt","rt").read()
    upload_file(key, text)

    encrypted_commands = []
    commands = text.split("\n")

    session = boto3.session.Session(region_name='us-west-2')
    kms_client = session.client('kms')

    for cmd in commands:
        encrypted_data = kms_client.encrypt(KeyId=KMS_KEY_ARN, Plaintext=cmd)
        encrypted_commands.append(base64.b64encode(encrypted_data['CiphertextBlob']).decode())
    encrypted_commands_str = "\n".join(encrypted_commands)
    key = "encrypted_commands2"
    upload_file(key, encrypted_commands_str)
    open("encrypted_commands.txt","wt").write(encrypted_commands_str)
    print(encrypted_commands_str)
    