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

if __name__ == '__main__':

    text = open("cmd.txt","rt").read()

    encrypted_commands = []
    commands = text.split("\n")

    session = boto3.session.Session(region_name='us-west-2')
    kms_client = session.client('kms')

    for cmd in commands:
        encrypted_data = kms_client.encrypt(KeyId=KMS_KEY_ARN, Plaintext=cmd)
        encrypted_commands.append(base64.b64encode(encrypted_data['CiphertextBlob']).decode())
    encrypted_commands_str = "\n".join(encrypted_commands)
    open("encrypted_commands.txt","wt").write(encrypted_commands_str)
    print(encrypted_commands_str)
