"""
Reset the library's process-wide state between tests.

``common`` keeps the registered token provider and the refreshed-token map;
``auth`` keeps which endpoint issued each token. Any test that signs in (even
against a mocked 200) leaves a record behind that would change how a later
test resolves the Supply Chain or export region.
"""

import pytest

from aquasec import auth as auth_mod
from aquasec.common import set_token_provider, clear_token_cache


@pytest.fixture(autouse=True)
def _reset_library_state():
    set_token_provider(None)
    clear_token_cache()
    auth_mod.set_api_endpoint(None)
    yield
    set_token_provider(None)
    clear_token_cache()
    auth_mod.set_api_endpoint(None)
