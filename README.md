# Salesforce Light JWT Flow

Lightweight module to implement JWT Flow for Server To Server
integrations in Salesforce. 

## Salesforce-side configuration

Steps:
- Create X509 Certificate on your system and upload it in Salesforce
- Create Named Credential in Salesforce and upload the newly created Certificate.
    - The Named Credential needs the following properties:
        - Access and manage your data (api)
        - Perform requests on your behalf at any time (refresh_token, offline_access)
        - Admin Approved Users are Preauthorized
- Create the Permission Set and assign it to the User you want to integrate

## Getting started for local development

Requirements are:
- python3
- pip
- virtualenv

### Generate virtual environment

Use script:
```
python3 -m venv env
```

and activate it. In Windows, run:

```
.\env\Scripts\activate
```

### Install dependencies

There are no module dependencies that are not satisfied by Python natively.

### Run test class

Execute:
```
python3 .\salesforce_light_jwt_flow_test.py
```

## How to Use

Execute 
```
request_access_token
```
Providing the following arguments:
    - the desired login endpoint
    - the customer key related to the Named Credential
    - the username for the selected user
    - the private key related to the X509 Certificate location
    - the private key password, if it exists

You can now extract the token and use it in future calls.