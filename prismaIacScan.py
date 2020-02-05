#!/usr/bin/env python3

import requests
import os
import json
import boto3
from pprint import pprint

def prismaPassword():
     client = boto3.client('ssm')
     response = client.get_parameter(Name='/prismacloud/access/fb309a62-9354-478f-a9fd-bced7a9a0881', WithDecryption=True)
     return(response['Parameter']['Value'])


def getkey(password):
    url = "https://api3.prismacloud.io/login"
    payload = f'{{"username":"fb309a62-9354-478f-a9fd-bced7a9a0881","password":"{password}"}}'
    headers = {
        'accept': "application/json; charset=UTF-8",
        'content-type': "application/json"
        }
    response = requests.request("POST", url, data=payload, headers=headers).json()
    token = response['token']
    return(token)


def getFiles():
    fileList = []
    dotfiles = []
    for root, dirs, files in os.walk(".", topdown=False):
        for name in files:
            #print(os.path.join(root, name))
            fileList.append(os.path.join(root, name))
    for files in fileList:
        if '.git' in files or "./bin" in files or ".terraform" in files:
            dotfiles.append(files)
    for files in dotfiles:
        fileList.remove(files)
    return(fileList)


def scanFolder(files):
    results = []
    for file in files:
        rawresult = {}
        if '.tf' in file or '.yml' in file or '.yaml' in file:
            stream = os.popen(f"curl -X POST https://api3.prismacloud.io/iac_scan -H 'Content-Type: multipart/form-data' -H 'x-redlock-auth: {token}' -F templateFile=@{file}")
            output = json.loads(stream.read())
            if output['result']['is_successful']:
                rawresult[f'{file}'] = output
                results.append(rawresult)
    return(results)

def parseResults(results):
    Keys = []
    for items in results:
        for keys in items:
            Keys.append(keys)
            Keys
            if 'rules_matched' in items[keys]['result'].keys():
                print(f"The file {keys} failed the check with the following message:")
                for rules in items[keys]['result']['rules_matched']:
                    pprint(rules)
            else:
                print(f"All Checks Passed for {keys}")


if __name__ == "__main__":
    password = prismaPassword()
    token = getkey(password)
    fileList = getFiles()
    results = scanFolder(fileList)
    parseResults(results)
