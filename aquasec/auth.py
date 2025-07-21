"""
Authentication module for Andrea library
Handles authentication with Aqua Security platform
"""

import hashlib
import hmac
import json
import requests
import sys
import time
from os import environ


def authenticate(verbose=False):
    """
    Main authentication function that detects auth method and returns token
    """
    api_key = environ.get('AQUA_KEY')
    api_secret = environ.get('AQUA_SECRET')
    api_role = environ.get('AQUA_ROLE')
    user = environ.get('AQUA_USER')
    password = environ.get('AQUA_PASSWORD')
    api_endpoint = environ.get('AQUA_ENDPOINT')
    csp_endpoint = environ.get('CSP_ENDPOINT')
    api_methods = environ.get('AQUA_METHODS')

    # API Keys SaaS auth
    if api_key and api_secret and api_endpoint and csp_endpoint and api_role and api_methods:
        # get methods list
        methods_list = api_methods.split(',')
        methods_json = json.dumps(methods_list)

        if verbose:
            print("Auth method: API Keys SaaS")

        token = api_auth(api_key, api_secret, api_endpoint, api_role, methods_json, verbose)

    # user/pass SaaS auth
    elif user and password and api_endpoint:
        if verbose:
            print("Auth method: User/Pass SaaS")
        token = user_pass_saas_auth(user, password, api_endpoint, verbose)

    # user/pass on-prem auth
    elif user and password and csp_endpoint and not api_endpoint:
        if verbose:
            print("Auth method: User/Pass on-prem")
        token = user_pass_onprem_auth(user, password, csp_endpoint)

    # trying to authenticate with user and password
    else:
        print("""\nMissing credentials, cannot proceed. 

Refer to the docs for info about SaaS API keys auth:
https://docs.aquasec.com/saas/api-reference/getting-started-with-aqua-platform-apis/api-authentication

Example creds file:
----------------------------------------
# Required for SaaS API Keys Auth
AQUA_KEY=xxxxxxxxxxxxxxxxxx
AQUA_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxx
AQUA_ROLE=api_admin_role
AQUA_METHODS=ANY
AQUA_ENDPOINT='https://eu-1.api.cloudsploit.com'

# Required for User/Pass Auth
#AQUA_USER=email@address.com
#AQUA_PASSWORD='password'

# Required for both Auth methods
CSP_ENDPOINT='https://xxxxxxxxxx.cloud.aquasec.com'
----------------------------------------

AUTHENTICATION CANCELLED
""")
        sys.exit(1)

    return token


def api_auth(api_key, api_secret, api_endpoint, api_role, api_methods, verbose=False):
    """
    Authenticate using API keys (SaaS)
    """
    timestamp = str(int(time.time()))
    api_url = api_endpoint + "/v2/tokens"

    # Define the body of the POST request
    post_body_str = str(
        '{"validity":240,"allowed_endpoints":' + api_methods + ',"csp_roles":["' + api_role + '"]}').replace(" ", "")
    if verbose:
        print("post_body_string: %s" % post_body_str)

    # Create the string to sign
    string_to_sign = timestamp + "POST" + "/v2/tokens" + post_body_str

    # Create HMAC signature
    signature = hmac.new(api_secret.encode(), string_to_sign.encode(), hashlib.sha256).hexdigest()

    # Issue the signed request to get authentication token
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
        "X-Timestamp": timestamp,
        "X-Signature": signature
    }

    response = requests.post(api_url, headers=headers, data=post_body_str)

    # Extract status and token from the response
    if response.status_code == 200:
        token = response.json()['data']
    else:
        print("Authentication failed.", response.text)
        sys.exit(1)

    return token


def user_pass_saas_auth(user, passwd, api_endpoint, verbose=False):
    """
    Authenticate using username/password (SaaS)
    """
    # Set schema for saas auth
    auth_info = {"email": user, "password": passwd}

    # Do authentication
    api_url = api_endpoint + "/v2/signin"
    if verbose:
        print(f"Auth URL: {api_url}")
    
    res = requests.post(url=api_url, json=auth_info, verify=False)

    # One of the authentications above succeeded
    if res.status_code == 200:
        response_data = res.json()
        token = response_data["data"]["token"]
        if verbose:
            # Extract user info if available
            user_data = response_data.get("data", {})
            if "user" in user_data:
                print(f"Authenticated as: {user_data['user'].get('email', 'unknown')}")
                print(f"User ID: {user_data['user'].get('id', 'unknown')}")
            # Show token info (first 20 chars only for security)
            print(f"Token (first 20 chars): {token[:20]}...")
    else:
        print(f"Authentication failed: {res.status_code}")
        if verbose:
            print(f"Response: {res.text}")
        sys.exit(1)

    return token


def user_pass_onprem_auth(user, passwd, csp_endpoint):
    """
    Authenticate using username/password (on-prem)
    """
    # Set schema for on-prem auth
    auth_info = {"id": user, "password": passwd}

    # Do authentication
    api_url = csp_endpoint + "/api/v1/login"
    res = requests.post(url=api_url, json=auth_info, verify=False)

    # One of the authentications above succeeded
    if res.status_code == 200:
        token = res.json()["token"]

    # Nothing worked. Exit.
    else:
        print("Authentication failed", res.status_code)
        sys.exit(1)

    return token


def extract_token_from_auth(res, is_account_saas):
    """
    Extract token from authentication response
    """
    if is_account_saas:
        return res.json()["data"]["token"]
    else:
        return res.json()["token"]