#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2019 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses
               
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

import json
import sys
import requests
import time
from flask import Flask, render_template, request, redirect, url_for, flash


app = Flask(__name__)
app.secret_key = 'some_secret'

@app.route('/')
def index():
    data_list= getAppCategories()
    policy_data_list = getAccessPolicies()
    filePolicy_list = getFilePolicies()
    return render_template('index.html', data=data_list, policy_data = policy_data_list, malware_policy = filePolicy_list )

# FMC server details
server = "Your FMC server" #""https://fmcrestapisandbox.cisco.com"

# Generate Token to access FMC through API
@app.route('/genToken')
def generateToken():


    # Modify the username as required
    username = "fmcusername"
    if len(sys.argv) > 1:
        username = sys.argv[1]

    # Modify the password as required
    password = "fmcpassword"
    if len(sys.argv) > 2:
        password = sys.argv[2]

    r = None
    headers = {'Content-Type': 'application/json'}

    # Create the URL
    api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
    auth_url = server + api_auth_path
    try:
        # Download SSL certificates from your FMC first and provide its path for verification.
        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username, password), verify=False)
        auth_headers = r.headers
        auth_token = auth_headers.get('X-auth-access-token', default=None)
        if auth_token == None:
            print("auth_token not found. Exiting...")
            print(auth_headers)
            sys.exit()
        else:
            return auth_token
    except Exception as err:
        print ("Error in generating auth token --> " + str(err))
        sys.exit()

authToken = generateToken()

# Create AccessPolicies object
def createAccessPolicy(policyaction, policyname):

    name = policyname
    action = policyaction
    auth_token = authToken
    headers = {'Content-Type': 'application/json'}
    r = None
    headers['X-auth-access-token'] = auth_token

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies"  # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]

    # POST OPERATION

    post_data = {
        "type": "AccessPolicy",
        "name": name,
        "defaultAction": {
            "action": action
        }
    }

    # post_data = json.dumps(post_data)
    try:
        # REST call with SSL verification turned off:
        r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
        # REST call with SSL verification turned on:
        #r = requests.post(url, data=json.dumps(post_data), headers=headers, verify='/path/to/ssl_certificate')
        status_code = r.status_code
        resp = r.text
        print("Status code is: " + str(status_code))
        if status_code == 201 or status_code == 202:
            print ("Post was successful...")
            json_resp = json.loads(resp)
            print(json.dumps(json_resp, sort_keys=True, indent=4, separators=(',', ': ')))
            return json_resp.get('id')
        else:
            r.raise_for_status()
            print ("Error occurred in POST --> " + resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> " + str(err))
    finally:
        if r: r.close()


# Create URL object
def createURLObject(urlUI, urlname, urldesc):
    auth_token = authToken
    headers = {'Content-Type': 'application/json'}
    headers['X-auth-access-token'] = auth_token

    api_path = "/api/fmc_config/v1/domain/default/object/urls"  # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]

    # POST OPERATION Sample JSON please modify the input data accordinly.You can learn more on the data model
    # Using REST API Explorer at https://fmcrestapisandbox.cisco.com/api/api-explorer
    post_data = {
        "name": urlname,
        "url": urlUI,
        "description": urldesc,
        "type": "URL"
    }

    try:
        for i in range(0, 10000):
            r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False);
            status_code = r.status_code
            resp = r.text
            if status_code == 201 or status_code == 202:
                print ("Post was successful for " + post_data["name"])
                json_resp = json.loads(resp)
                # print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
                return json_resp
            else:
                r.raise_for_status()
                print ("Error occurred in POST --> " + resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> " + str(err))
    finally:
        if r: r.close()

# Create URL Filtering
@app.route('/urlfiltering', methods=['POST'])
def createACRule():

    r = None
    auth_token = authToken
    headers = {'Content-Type': 'application/json'}
    headers['X-auth-access-token'] = auth_token

    # Access Policy parameters
    policyAction = request.form['action']
    policyName = request.form['nameAp']

    # URL Object parameters
    urlUI = request.form['url']
    urlName = request.form['name']
    urldesc = request.form['desc']

    # Access Rule parameters
    ruleAction = request.form['ruleaction']
    ruleName = request.form['rulename']

    accessPolicyID = createAccessPolicy(policyAction,policyName)
    urlObjectDetails = createURLObject(urlUI, urlName, urldesc)
    try:
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/" + accessPolicyID + "/accessrules"  # param
        url = server + api_path
        if (url[-1] == '/'):
            url = url[:-1]
    except:
        flash('Oops!! Unexpected error', 'danger')
        return redirect(url_for('index'))

    post_data = {
        "action": ruleAction,
        "enabled": "true",
        "name": ruleName,
        "type": "AccessRule",
        "id": accessPolicyID,
        "urls": {
            "objects": [
                {
                    "type": "Url",
                    "name": urlObjectDetails.get('name'),
                    "id": urlObjectDetails.get('id')
                }
            ]
        }
    }

    try:
        # REST call with SSL verification turned off:
        r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
        # REST call with SSL verification turned on:
        # r = requests.post(url, data=json.dumps(post_data), headers=headers, verify='/path/to/ssl_certificate')
        status_code = r.status_code
        resp = r.text
        # print("Status code is: "+str(status_code))
        if status_code == 201 or status_code == 202:
            print ("The rule has now been implemented. The time is %s" % time.ctime())
            json_resp = json.loads(resp)
            # print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
            flash('URL filtering configured','success')
            return redirect(url_for('index'))
        else:
            r.raise_for_status()
            flash('Oops!! Unexpected error', 'danger')
            print ("Error occurred in POST --> " + resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> " + str(err))
    finally:
        if r: r.close()

# Get Application Categories
def getAppCategories():
    r = None
    headers = {'Content-Type': 'application/json'}
    headers['X-auth-access-token'] = authToken

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/applicationcategories"  # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]

    # GET OPERATION
    try:
        # REST call with SSL verification turned off:
        r = requests.get(url, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        data_list = []
        if (status_code == 200):
            json_resp = json.loads(resp)
            for i in range(len(json_resp["items"])):
                data = json_resp["items"][i]["id"],json_resp["items"][i]["name"]
                data_list.append(data)
            return data_list
            # print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
        else:
            r.raise_for_status()
            print("Error occurred in GET --> " + resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> " + str(err))
    finally:
        if r: r.close()
#getAppCategories()

# Create new Application policy filter
@app.route('/appfiltering', methods=['POST'])
def pushApplicationFilterRule():
    r = None
    headers = {'Content-Type': 'application/json'}
    headers['X-auth-access-token'] = authToken

    # Policy Parameters
    appPolicyName = request.form['nameApp']
    appPolicyAction = request.form['actionapp']

    # Rule Parameters
    appRuleName = request.form['nameAppRule']
    appRuleAction = request.form['actionAppRule']
    categoryID = request.form.get('selectCategory')

    # Get Policy ID
    accessPolicyAppID = createAccessPolicy(appPolicyAction, appPolicyName)

    try:
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/" + accessPolicyAppID + "/accessrules"   # param
        url = server + api_path
        if (url[-1] == '/'):
            url = url[:-1]
    except:
        flash('Oops!! Unexpected error', 'danger')
        return redirect(url_for('index'))

    post_data = {
    "action": appRuleAction,
    "enabled": "true",
    "type": "AccessRule",
    "name": appRuleName,
    "id": accessPolicyAppID,
    "vlanTags": {},
    "logFiles": "false",
    "logBegin": "false",
    "logEnd": "false",
    "applications": {
        "inlineApplicationFilters": [
            {
                "categories": [
                    {
                        "name": "category",
                        "id": categoryID,
                        "type": "ApplicationCategory"
                    }
                ]
            }
        ]
    }
}

    try:
        # REST call with SSL verification turned off:
        r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
        # REST call with SSL verification turned on:
        # r = requests.post(url, data=json.dumps(post_data), headers=headers, verify='/path/to/ssl_certificate')
        status_code = r.status_code
        resp = r.text
        # print("Status code is: "+str(status_code))
        if status_code == 201 or status_code == 202:
            print ("The rule has now been implemented. The time is %s" % time.ctime())
            json_resp = json.loads(resp)
            # print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
            flash('Application filtering configured','success')
            return redirect(url_for('index'))
        else:
            r.raise_for_status()
            flash('Oops!! Unexpected error '+ resp, 'danger')
            print ("Error occurred in POST --> " + resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> " + str(err))
    finally:
        if r: r.close()


# Get Access Policies
def getAccessPolicies():
    r = None
    headers = {'Content-Type': 'application/json'}
    headers['X-auth-access-token'] = authToken

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies"  # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]

    # GET OPERATION
    try:
        # REST call with SSL verification turned off:
        r = requests.get(url, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        policy_data_list = []
        if (status_code == 200):
            json_resp = json.loads(resp)
            for i in range(len(json_resp["items"])):
                deviceData = json_resp["items"][i]["id"], json_resp["items"][i]["name"]
                policy_data_list.append(deviceData)
            return policy_data_list
            # print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
        else:
            r.raise_for_status()
            print("Error occurred in GET --> " + resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> " + str(err))
    finally:
        if r: r.close()


# Get Malware & File Policies
def getFilePolicies():
    r = None
    headers = {'Content-Type': 'application/json'}
    headers['X-auth-access-token'] = authToken

    api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/filepolicies"  # param
    url = server + api_path
    if (url[-1] == '/'):
        url = url[:-1]

    # GET OPERATION
    try:
        # REST call with SSL verification turned off:
        r = requests.get(url, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        filePolicy_data_list = []
        if (status_code == 200):
            json_resp = json.loads(resp)
            for i in range(len(json_resp["items"])):
                policyData = json_resp["items"][i]["id"], json_resp["items"][i]["name"]
                filePolicy_data_list.append(policyData)
            return filePolicy_data_list
            # print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
        else:
            r.raise_for_status()
            print("Error occurred in GET --> " + resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> " + str(err))
    finally:
        if r: r.close()

# Create mapping for Malware policy and Application policy
@app.route('/malwarefiltering', methods=['POST'])
def pushMalwareFilterRule():
    r = None
    headers = {'Content-Type': 'application/json'}
    headers['X-auth-access-token'] = authToken

    # Policy Parameters
    ruleActionMalware = request.form['ruleactionMalware']
    ruleNameMalware = request.form['ruleNameMalware']
    filePolicyIdMalware = request.form.get('selectMalwarePolicy')
    accessPolicyIdMalware = request.form.get('selectPolicy')

    try:
        api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/" + accessPolicyIdMalware + "/accessrules"   # param
        url = server + api_path
        if (url[-1] == '/'):
            url = url[:-1]
    except:
        flash('Oops!! Unexpected error', 'danger')
        return redirect(url_for('index'))

    post_data = {
        "action": ruleActionMalware,
        "enabled": "true",
        "name": ruleNameMalware,
        "type": "AccessRule",
        "filePolicy": {
            "id": filePolicyIdMalware,
            "type": "FilePolicy"
        }
 }

    try:
        # REST call with SSL verification turned off:
        r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
        # REST call with SSL verification turned on:
        # r = requests.post(url, data=json.dumps(post_data), headers=headers, verify='/path/to/ssl_certificate')
        status_code = r.status_code
        resp = r.text
        # print("Status code is: "+str(status_code))
        if status_code == 201 or status_code == 202:
            print ("The rule has now been implemented. The time is %s" % time.ctime())
            json_resp = json.loads(resp)
            # print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
            flash('File/Malware policy configured','success')
            return redirect(url_for('index'))
        else:
            flash('Oops!! Unexpected error '+ resp, 'danger')
            print ("Error occurred in POST --> " + resp)
            return redirect(url_for('index'))
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> " + str(err))
    finally:
        if r: r.close()


app.run("0.0.0.0")
