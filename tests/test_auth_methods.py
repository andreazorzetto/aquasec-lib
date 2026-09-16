"""
Tests for the token's allowed_endpoints scope (AQUA_METHODS).

``allowed_endpoints`` entries are ``METHOD:path`` pairs. A bare ``ANY`` carries
no path part: the console API tolerates it, but the Supply Chain API rejects
every request made with such a token as "explicit deny in an identity-based
policy". ``ANY:*`` -- any method, any path -- works against both, so it is the
default everywhere.
"""

import os
from unittest.mock import patch

from aquasec import auth as auth_mod
from aquasec.config import authenticate_with


class TestAllowedEndpointsDefault:

    def test_authenticate_with_defaults_to_any_wildcard(self):
        """A config that never stored api_methods must still scope the token to ANY:*."""
        config = {'auth_method': 'api_keys', 'api_endpoint': 'https://eu-1.api.cloudsploit.com'}
        creds = {'api_key': 'k', 'api_secret': 's'}

        # authenticate_with() imports authenticate from .auth at call time, so
        # patching it on the auth module is enough. It also swallows exceptions
        # and returns None, so the env is captured and asserted on afterwards.
        seen = {}
        with patch.object(auth_mod, 'authenticate',
                          side_effect=lambda **kw: seen.update(os.environ) or 'tok'):
            assert authenticate_with(config, creds) == 'tok'

        assert seen['AQUA_METHODS'] == 'ANY:*'

    def test_methods_reach_the_token_body_as_a_json_list(self):
        """AQUA_METHODS is comma-split into the allowed_endpoints list verbatim."""
        env = {"AQUA_KEY": "k", "AQUA_SECRET": "s", "AQUA_ROLE": "r",
               "AQUA_METHODS": "ANY:*", "AQUA_ENDPOINT": "https://eu-1.api.cloudsploit.com"}
        with patch.dict(os.environ, env, clear=True), \
             patch.object(auth_mod, "api_auth", return_value="tok") as m:
            auth_mod.authenticate()

        assert m.call_args[0][4] == '["ANY:*"]'

    def test_multiple_methods_are_split_on_commas(self):
        env = {"AQUA_KEY": "k", "AQUA_SECRET": "s", "AQUA_ROLE": "r",
               "AQUA_METHODS": "GET:/api/v2/*,POST:/v2/build/*",
               "AQUA_ENDPOINT": "https://eu-1.api.cloudsploit.com"}
        with patch.dict(os.environ, env, clear=True), \
             patch.object(auth_mod, "api_auth", return_value="tok") as m:
            auth_mod.authenticate()

        assert m.call_args[0][4] == '["GET:/api/v2/*", "POST:/v2/build/*"]'
