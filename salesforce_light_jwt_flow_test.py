import salesforce_light_jwt_flow
import unittest

from pathlib import Path
from base64 import urlsafe_b64decode

TEST_CUSTOMER_ID = '123'
TEST_SALESFORCE_USERNAME = 'salesforce_light_jwt_flow@test.com'

''' Test that the token is built in the right way.
 It needs to have three dots in the final string: [first_part].[second_part].[third_part]
  - first_part = jwt_header
  - second_part = jwt_claim
  - third_part = signed(jwt_header + jwt_claim)
'''
class RequestAccessToken(unittest.TestCase):
    def test_sign_token(self):
        encodedToken = salesforce_light_jwt_flow._create_encoded_token(customer_id=TEST_CUSTOMER_ID, salesforce_username=TEST_SALESFORCE_USERNAME, private_key_pem_location=Path('test_key/key_enc.pem'), key_password='mypassphrase')
        strings = encodedToken.split('.')
        
        # string must have only 3 dots
        self.assertEqual(3, len(strings))

        # jwt header
        first_part = strings[0]
        self.assertTrue('RS256' in urlsafe_b64decode(first_part.encode()).decode())

        # jwt claim
        second_part = strings[1]
        self.assertTrue(TEST_SALESFORCE_USERNAME in urlsafe_b64decode(second_part.encode()).decode())
        self.assertTrue(TEST_CUSTOMER_ID in urlsafe_b64decode(second_part.encode()).decode())

        # signature verification
        third_part = strings[2]
        salesforce_light_jwt_flow._verify_encoded_token(urlsafe_b64decode(third_part), (first_part + '.' + second_part).encode('UTF-8'), Path('test_key/cert.pem'))

if __name__ == '__main__':
    unittest.main()