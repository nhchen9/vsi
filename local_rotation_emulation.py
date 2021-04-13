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
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
import base64
KMS_KEY_ARN = 'arn:aws:kms:us-west-2:779619664536:key/d3a3ce82-5390-49d8-bd77-400ebbe77946'


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
    encData = None
    encKey = None
    msg = None

    encData = re.findall('EncData": "(.*?)",', container)[0].replace("\\", "")
    encKey = re.findall('KeyPackage": "(.*?)"', container)[0].replace("\\", "")
    try:
        msg = re.findall('Message": "(.*?)" }\n', container)[0].replace('\\', '')
    except:
        pass
    
    return encData, encKey, msg


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


def counter_increment(inputhash, batch_size = 1):
	counter_increment.counter += batch_size
	message = inputhash + str(counter_increment.counter)
	key = RSA.import_key(open('./emulation_prik.pem').read())
	h = SHA256.new(message)
	signature_raw = pkcs1_15.new(key).sign(h)	
	signature_b64 = base64.b64encode(signature_raw)
	return signature_b64,counter_increment.counter
counter_increment.counter = 0
	


if __name__ == '__main__':

    # Data and key are stored locally in encrypted format.
    LOCAL_DATA = "./local_data/data.txt"
    LOCAL_KEY = "./local_data/key.txt"
    cur_data = None
    cur_key = None

    #encrypted_commands = get_s3_data("encrypted_commands2")
    encrypted_commands = open("encrypted_commands.txt", "rt").read()
    cmd_list = encrypted_commands.split("\n")

    session = boto3.session.Session(region_name='us-west-2')
    kms_client = session.client('kms')

    #Local file with plaintext commands, for reference
    plain_cmd_ref = open("cmd.txt","rt").read().split("\n")
    diff = 0
    enclave_id = None
    fails = 0
    start = time.time()

    batch_size = 1

    for i in range(100000):
        
        i = i - diff
        ind = (batch_size * i)%len(cmd_list)
        #i=0
        cmd = ';'.join(cmd_list[ind:(ind+batch_size)])
        try:
            print("loaded")
            cur_data = open(LOCAL_DATA, "rt").read()
            cur_key = open(LOCAL_KEY, "rt").read()
        except:
            print("failed load")
            cur_data = None
            cur_key = None
        t0 = time.time()
		
        print("")        
        print(cmd_list[ind:(ind+batch_size)])

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
		
		# Emulation of counter increment
        signature,value = counter_increment(inputHash, batch_size)
        print("CCF Emulation response:"),
        print(value, signature)
		
        encData = None
        encKey = None
        qResult = None
		
        for attempt in range(10):
            try:
                encData, encKey, qResult = run_complete(5, cmd, cur_data, cur_key, signature, value)
                break
            except:
                print("ENCLAVE FAILED, RETRYING!")
                #time.sleep(5)
                fails += 1
                enclave_id = os.popen("nitro-cli describe-enclaves | jq -r .[0].EnclaveID").read().replace("\n","")
                if enclave_id:
                    os.system("sudo nitro-cli terminate-enclave --enclave-id {:s}".format(enclave_id))
                #time.sleep(5)
                os.system("sudo nitro-cli run-enclave --eif-path kmstool.eif --memory 512 --cpu-count 2 --debug-mode --enclave-cid 5")
                enclave_id = os.popen("nitro-cli describe-enclaves | jq -r .[0].EnclaveID").read().replace("\n","")
                os.system("nitro-cli console --enclave-id {:s} >> out.txt &".format(enclave_id))

        if encData:
            #If data update, write new data and key files
            open(LOCAL_DATA, "wt").write(encData)
            open(LOCAL_KEY, "wt").write(encKey)
            #print("Data: ", encData)
            #print("Key: ", encKey)
        if qResult:
            #If status query, print result
            print(qResult)
        print(round((time.time() - start)/(i+1), 2))
        print(fails, i)
			