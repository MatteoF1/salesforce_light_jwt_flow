# Salesforce Light JWT Flow

Lightweight module to implement JWT Flow for Server To Server
integrations in Salesforce. Steps:

## Configuration

- Create X509 Certificate
- Create Named Credential in Salesforce and upload the newly created Certificate.
    - The Named Credential needs the following properties:
        - Access and manage your data (api)
        - Perform requests on your behalf at any time (refresh_token, offline_access)
        - Admin Approved Users are Preauthorized
- Create the Permission Set and assign it to the User you want to integrate

## How to Use

The module can be used as follows:
    - call *request_access_token* providing:
        - the desired login endpoint
        - the customer key related to the Named Credential
        - the username for the selected user
        - the private key related to the X509 Certificate location
        - the private key password, if it exists