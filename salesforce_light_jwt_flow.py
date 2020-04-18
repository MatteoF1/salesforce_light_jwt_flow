'''Lightweight Module to request an access token to Salesforce using the
 JWT Flow for Server To Server integration.
https://help.salesforce.com/articleView?id=remoteaccess_oauth_jwt_flow.htm&type=5
'''
import requests
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from uuid import uuid4
from datetime import datetime
from base64 import urlsafe_b64encode
from pathlib import Path

SALESFORCE_LOGIN_ENDPOINT_PROD = 'https://login.salesforce.com/services/oauth2/token'
SALESFORCE_LOGIN_ENDPOINT_TEST = 'https://test.salesforce.com/services/oauth2/token'
NR_MINUTES_TOKEN_LIFETIME = 2

'''Token lifetime set to NR minutes
'''
def _generate_token_lifetime() -> int:
    ''' 2 minutes lifetime '''
    return _now_utc() + 60 * NR_MINUTES_TOKEN_LIFETIME

'''Find datetime now in UTC
'''
def _now_utc() -> int:
    return int((datetime.today() - datetime.utcfromtimestamp(0)).total_seconds())

'''Create jwt token to authenticate
'''
def _create_encoded_token(customer_id: str, salesforce_username: str, private_key_pem_location: Path, key_password = None) -> str:
    jwt_header = {'alg':'RS256'}

    jwt_claim = {
        "iss": customer_id,
        "aud": 'https://login.salesforce.com',
        "exp": _generate_token_lifetime(),
        "sub": salesforce_username,
        "jti" : str(uuid4())
    }

    # encode header and claim
    encodedToken = urlsafe_b64encode(json.dumps(jwt_header).encode('UTF-8')).decode() + '.' + urlsafe_b64encode(json.dumps(jwt_claim).encode('UTF-8')).decode()
    #sign with private key
    with open(private_key_pem_location, 'rb') as keyfile:
        private_key = serialization.load_pem_private_key(keyfile.read(),password=key_password,backend=default_backend())
        signed = private_key.sign(encodedToken.encode('UTF-8'), padding.PKCS1v15(), hashes.SHA256())    

    return encodedToken + '.' + urlsafe_b64encode(signed).decode()
    
'''Verify an existing digital signature
'''
def _verify_encoded_token(digital_signature: bytes, actual_file: bytes, certificate_pem_location: Path):
    with open(certificate_pem_location, 'rb') as cfile:
        cert = x509.load_pem_x509_certificate(cfile.read(), default_backend())
        public_key = cert.public_key()
        public_key.verify(digital_signature, actual_file, padding.PKCS1v15(), hashes.SHA256())

'''Specific applications can require a specific OAuth 2 scope
'''
def verify_scope(response: dict, scope_to_verify: str):
    return (scope_to_verify in response['scope'])

'''Requesting access
'''
def request_access_token(salesforce_login_endpoint: str, customer_id: str, username: str, private_key_pem_location: str, key_password = None) -> dict:
    encodedToken = _create_encoded_token(customer_id, username, private_key_pem_location, key_password)
    resp = requests.post(salesforce_login_endpoint, \
        headers={'Content-Type':'application/x-www-form-urlencoded'},\
            data={'grant_type':'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion':encodedToken})
    return json.loads(resp.content.decode('UTF-8'))