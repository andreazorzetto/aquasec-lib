"""
Tests for token refresh on 401 and for the library never exiting the process.

An application that holds its own credentials (secrets manager, vault) signs in
with ``api_auth()`` and never sets ``AQUA_*``. Before 0.13.0 a 401 on any call
sent the library into ``authenticate()``, which found no environment variables,
printed "Missing credentials" and called ``sys.exit(1)`` -- the host process
died on a transient 401. Now the refresh path prefers a registered token
provider, falls back to the environment only when it is complete, and otherwise
hands the 401 back.
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from aquasec import common
from aquasec import auth as auth_mod
from aquasec.common import _request_with_retry, set_token_provider, clear_token_cache
from aquasec.exceptions import (
    AquaError, AuthenticationError, MissingCredentialsError, ApiError,
)
from aquasec.code_repositories import _get_supply_chain_url


def _resp(status, text=""):
    r = MagicMock()
    r.status_code = status
    r.text = text
    return r


class TestRefreshOn401:

    @patch.object(common.requests, "request")
    def test_provider_is_used_and_request_retried(self, req):
        # The retry reuses (and mutates) the same headers dict, so snapshot the
        # Authorization value at call time rather than reading it back later.
        seen = []
        responses = iter([_resp(401), _resp(200)])
        req.side_effect = lambda *a, **kw: seen.append(kw["headers"]["Authorization"]) or next(responses)
        set_token_provider(lambda: "fresh")

        res = _request_with_retry("GET", "https://t/api", "stale")

        assert res.status_code == 200
        assert seen == ["Bearer stale", "Bearer fresh"]

    @patch.object(common.requests, "request")
    def test_env_credentials_used_when_no_provider(self, req):
        req.side_effect = [_resp(401), _resp(200)]
        env = {"AQUA_KEY": "k", "AQUA_SECRET": "s", "AQUA_ROLE": "r",
               "AQUA_METHODS": "ANY:*", "AQUA_ENDPOINT": "https://eu-1.api.cloudsploit.com"}
        with patch.dict(os.environ, env, clear=True), \
             patch.object(auth_mod, "api_auth", return_value="fresh") as api_auth:
            res = _request_with_retry("GET", "https://t/api", "stale")

        assert res.status_code == 200
        assert api_auth.called
        assert req.call_args_list[1].kwargs["headers"]["Authorization"] == "Bearer fresh"

    @patch.object(common.requests, "request")
    def test_401_returned_when_nothing_can_refresh(self, req):
        """The customer's case: api_auth() token, no env vars, no provider."""
        req.return_value = _resp(401)
        with patch.dict(os.environ, {}, clear=True):
            res = _request_with_retry("GET", "https://t/api", "tok")

        assert res.status_code == 401
        assert req.call_count == 1          # no retry without a new token

    @patch.object(common.requests, "request")
    def test_never_raises_systemexit(self, req):
        req.return_value = _resp(401)
        with patch.dict(os.environ, {}, clear=True):
            try:
                _request_with_retry("GET", "https://t/api", "tok")
            except SystemExit:
                pytest.fail("library exited the process on a 401")

    @patch.object(common.requests, "request")
    def test_provider_wins_over_environment(self, req):
        req.side_effect = [_resp(401), _resp(200)]
        env = {"AQUA_KEY": "k", "AQUA_SECRET": "s", "AQUA_ROLE": "r",
               "AQUA_METHODS": "ANY:*", "AQUA_ENDPOINT": "https://x"}
        set_token_provider(lambda: "from-provider")
        with patch.dict(os.environ, env, clear=True), \
             patch.object(auth_mod, "api_auth") as api_auth:
            _request_with_retry("GET", "https://t/api", "stale")

        assert not api_auth.called
        assert req.call_args_list[1].kwargs["headers"]["Authorization"] == "Bearer from-provider"

    @patch.object(common.requests, "request")
    def test_partial_environment_does_not_trigger_reauth(self, req):
        """A stray AQUA_KEY on its own must not send us into authenticate()."""
        req.return_value = _resp(401)
        with patch.dict(os.environ, {"AQUA_KEY": "k"}, clear=True):
            res = _request_with_retry("GET", "https://t/api", "tok")
        assert res.status_code == 401


class TestRefreshCacheIsScopedToTheToken:

    @patch.object(common.requests, "request")
    def test_refreshed_token_reused_for_same_stale_token(self, req):
        req.side_effect = [_resp(401), _resp(200), _resp(200)]
        calls = []
        set_token_provider(lambda: calls.append(1) or "fresh")

        _request_with_retry("GET", "https://t/a", "stale")
        _request_with_retry("GET", "https://t/b", "stale")

        assert len(calls) == 1
        assert req.call_args_list[2].kwargs["headers"]["Authorization"] == "Bearer fresh"

    @patch.object(common.requests, "request")
    def test_other_tokens_are_not_overridden(self, req):
        """A refresh for token A must not hijack a call made with token B."""
        req.side_effect = [_resp(401), _resp(200), _resp(200)]
        set_token_provider(lambda: "fresh-for-a")

        _request_with_retry("GET", "https://t/a", "token-a")
        _request_with_retry("GET", "https://t/b", "token-b")

        assert req.call_args_list[2].kwargs["headers"]["Authorization"] == "Bearer token-b"

    @patch.object(common.requests, "request")
    def test_clear_token_cache_forgets_refreshes(self, req):
        req.side_effect = [_resp(401), _resp(200), _resp(200)]
        set_token_provider(lambda: "fresh")
        _request_with_retry("GET", "https://t/a", "stale")
        clear_token_cache()
        _request_with_retry("GET", "https://t/b", "stale")
        assert req.call_args_list[2].kwargs["headers"]["Authorization"] == "Bearer stale"

    def test_provider_must_be_callable(self):
        with pytest.raises(TypeError):
            set_token_provider("not callable")

    @patch.object(common.requests, "request")
    def test_falsy_provider_result_is_not_used(self, req):
        """A provider that forgot its return (None) or returned '' must not
        be cached and sent as ``Bearer ``; the 401 goes back to the caller."""
        req.return_value = _resp(401)
        set_token_provider(lambda: "")
        res = _request_with_retry("GET", "https://t/a", "stale")
        assert res.status_code == 401
        assert req.call_count == 1
        assert common._refreshed == {}


class TestPersistent401DoesNotHammerSignIn:
    """
    A 401 that survives a refresh is not an expiry -- wrong regional host,
    revoked role, token scope -- and signing in again on every request would
    only hammer the auth endpoint. Within the backoff window the 401 is
    returned; after it a genuine later expiry can still be refreshed.
    """

    @patch.object(common.requests, "request")
    def test_second_401_within_backoff_returns_without_refresh(self, req):
        req.return_value = _resp(401)
        calls = []
        set_token_provider(lambda: calls.append(1) or "fresh")

        _request_with_retry("GET", "https://t/a", "stale")   # 401 -> refresh -> 401
        _request_with_retry("GET", "https://t/a", "stale")   # 401, refreshed just now
        _request_with_retry("GET", "https://t/a", "stale")

        assert len(calls) == 1
        assert req.call_count == 4          # 2 for the first call, 1 each after

    @patch.object(common.requests, "request")
    def test_refresh_allowed_again_after_backoff(self, req):
        req.return_value = _resp(401)
        calls = []
        set_token_provider(lambda: calls.append(1) or "fresh-%d" % len(calls))
        _request_with_retry("GET", "https://t/a", "stale")
        # age the refresh past the window
        tok, at = common._refreshed["stale"]
        common._refreshed["stale"] = (tok, at - common.REFRESH_BACKOFF_SECONDS - 1)
        _request_with_retry("GET", "https://t/a", "stale")
        assert len(calls) == 2


class TestRefreshIsSingleFlight:

    def test_concurrent_401s_sign_in_once(self):
        import threading
        barrier = threading.Barrier(8)
        sign_ins = []

        def provider():
            sign_ins.append(1)
            return "fresh"

        def fake_request(method, url, headers=None, **kw):
            return _resp(200) if headers["Authorization"] == "Bearer fresh" else _resp(401)

        set_token_provider(provider)
        results = []
        def worker():
            barrier.wait()
            results.append(_request_with_retry("GET", "https://t/a", "stale").status_code)

        with patch.object(common.requests, "request", side_effect=fake_request):
            threads = [threading.Thread(target=worker) for _ in range(8)]
            for t in threads: t.start()
            for t in threads: t.join()

        assert results == [200] * 8
        assert len(sign_ins) == 1


class TestTokenMapsAreBounded:

    @staticmethod
    def _jwt(exp):
        import base64, json
        body = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode().rstrip("=")
        return f"h.{body}.s"

    def test_expired_keys_are_pruned(self):
        import time
        dead, live = self._jwt(int(time.time()) - 10), self._jwt(int(time.time()) + 3600)
        m = {dead: 1, live: 2, "not-a-jwt": 3}
        common._prune_token_map(m)
        assert dead not in m and live in m and "not-a-jwt" in m

    def test_capped_at_max_entries_oldest_first(self):
        m = {f"t{i}": i for i in range(common._TOKEN_MAP_MAX + 5)}
        common._prune_token_map(m)
        assert len(m) == common._TOKEN_MAP_MAX
        assert "t0" not in m and f"t{common._TOKEN_MAP_MAX + 4}" in m

    @patch.object(common.requests, "request")
    def test_refresh_map_is_pruned_on_insert(self, req):
        req.side_effect = [_resp(401), _resp(200)]
        set_token_provider(lambda: "fresh")
        for i in range(common._TOKEN_MAP_MAX):
            common._refreshed[f"old{i}"] = ("x", 0)
        _request_with_retry("GET", "https://t/a", "stale")
        assert len(common._refreshed) <= common._TOKEN_MAP_MAX
        assert "stale" in common._refreshed


class TestAuthRaisesInsteadOfExiting:

    def test_missing_credentials_raises(self):
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(MissingCredentialsError) as exc:
                auth_mod.authenticate()
        assert "Missing credentials" in str(exc.value)
        assert "set_token_provider" in str(exc.value)
        assert isinstance(exc.value, AuthenticationError)
        assert isinstance(exc.value, AquaError)

    def test_api_auth_rejection_raises_with_status(self):
        with patch.object(auth_mod.requests, "post", return_value=_resp(403, '{"code":1}')):
            with pytest.raises(AuthenticationError) as exc:
                auth_mod.api_auth("k", "s", "https://x", "role", '["ANY:*"]')
        assert exc.value.status_code == 403
        assert '{"code":1}' in str(exc.value)

    def test_user_pass_saas_rejection_raises(self):
        with patch.object(auth_mod.requests, "post", return_value=_resp(401, "nope")):
            with pytest.raises(AuthenticationError) as exc:
                auth_mod.user_pass_saas_auth("u", "p", "https://x")
        assert exc.value.status_code == 401

    def test_authenticate_with_returns_none_on_failure(self):
        """
        authenticate_with() swallows failures and returns None -- but its
        ``except Exception`` never caught the old SystemExit, so a wrong
        password during setup killed the wizard. Now it is an ordinary error.
        """
        from aquasec.config import authenticate_with
        config = {'auth_method': 'api_keys', 'api_endpoint': 'https://x'}
        with patch.object(auth_mod.requests, "post", return_value=_resp(403, "denied")):
            assert authenticate_with(config, {'api_key': 'k', 'api_secret': 's'}) is None


class TestEnforcersRaiseApiError:

    def test_get_enforcer_groups_raises_api_error(self):
        from aquasec import enforcers
        with patch.object(enforcers, "api_get_enforcer_groups", return_value=_resp(500, "boom")):
            with pytest.raises(ApiError) as exc:
                enforcers.get_enforcer_groups("https://t", "tok")
        assert exc.value.status_code == 500
        assert not isinstance(exc.value, SystemExit)

    def test_get_enforcers_from_group_raises_api_error(self):
        from aquasec import enforcers
        with patch.object(enforcers, "api_get_enforcer_groups", return_value=_resp(503, "down")):
            with pytest.raises(ApiError):
                enforcers.get_enforcers_from_group("https://t", "tok", group="g")


class TestEnvCredentialsPresent:

    def test_complete_api_keys(self):
        env = {"AQUA_KEY": "k", "AQUA_SECRET": "s", "AQUA_ROLE": "r",
               "AQUA_METHODS": "ANY:*", "AQUA_ENDPOINT": "https://x"}
        with patch.dict(os.environ, env, clear=True):
            assert auth_mod.env_credentials_present()

    def test_incomplete_api_keys(self):
        with patch.dict(os.environ, {"AQUA_KEY": "k", "AQUA_SECRET": "s"}, clear=True):
            assert not auth_mod.env_credentials_present()

    def test_user_pass_saas(self):
        with patch.dict(os.environ, {"AQUA_USER": "u", "AQUA_PASSWORD": "p", "AQUA_ENDPOINT": "https://x"}, clear=True):
            assert auth_mod.env_credentials_present()

    def test_user_pass_onprem_requires_no_api_endpoint(self):
        with patch.dict(os.environ, {"AQUA_USER": "u", "AQUA_PASSWORD": "p", "CSP_ENDPOINT": "https://c"}, clear=True):
            assert auth_mod.env_credentials_present()

    def test_empty(self):
        with patch.dict(os.environ, {}, clear=True):
            assert not auth_mod.env_credentials_present()


class TestSupplyChainRegionWithoutEnvironment:
    """
    The Supply Chain host is per region. When the console hostname has no
    region (most tenants: ``xxxx.cloud.aquasec.com``) the only place the
    region is known is the endpoint the token was issued from. That used to
    be read from ``AQUA_ENDPOINT`` alone, so an application signing in with
    ``api_auth()`` and no environment variables was sent to the US host and
    got ``401 Unauthorized`` for a perfectly valid token.
    """

    CONSOLE = "https://c1fae5dbe2.cloud.aquasec.com"

    def test_api_auth_records_its_endpoint_for_that_token(self):
        ok = _resp(200); ok.json = lambda: {"data": "tok-eu"}
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(auth_mod.requests, "post", return_value=ok):
            auth_mod.api_auth("k", "s", "https://eu-1.api.cloudsploit.com", "role", '["ANY:*"]')
        assert auth_mod.get_api_endpoint("tok-eu") == "https://eu-1.api.cloudsploit.com"
        assert _get_supply_chain_url(self.CONSOLE, "tok-eu") == "https://api.eu-1.supply-chain.cloud.aquasec.com"

    def test_user_pass_saas_records_its_endpoint(self):
        ok = _resp(200); ok.json = lambda: {"data": {"token": "tok-asia"}}
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(auth_mod.requests, "post", return_value=ok):
            auth_mod.user_pass_saas_auth("u", "p", "https://asia-1.api.cloudsploit.com")
        assert _get_supply_chain_url(self.CONSOLE, "tok-asia") == "https://api.asia-1.supply-chain.cloud.aquasec.com"

    def test_failed_sign_in_records_nothing(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(auth_mod.requests, "post", return_value=_resp(403, "no")):
            with pytest.raises(AuthenticationError):
                auth_mod.api_auth("k", "s", "https://eu-1.api.cloudsploit.com", "role", '["ANY:*"]')
        assert auth_mod.get_api_endpoint() is None

    def test_two_tenants_in_one_process_do_not_cross(self):
        """The reviewer's case: an eu-1 sign-in must not re-region a US token."""
        auth_mod.set_api_endpoint("https://eu-1.api.cloudsploit.com", "tok-eu")
        auth_mod.set_api_endpoint("https://api.cloudsploit.com", "tok-us")
        with patch.dict(os.environ, {}, clear=True):
            assert _get_supply_chain_url(self.CONSOLE, "tok-eu") == "https://api.eu-1.supply-chain.cloud.aquasec.com"
            assert _get_supply_chain_url(self.CONSOLE, "tok-us") == "https://api.supply-chain.cloud.aquasec.com"

    def test_this_tokens_record_wins_over_environment(self):
        auth_mod.set_api_endpoint("https://asia-1.api.cloudsploit.com", "tok")
        with patch.dict(os.environ, {"AQUA_ENDPOINT": "https://eu-1.api.cloudsploit.com"}, clear=True):
            assert _get_supply_chain_url(self.CONSOLE, "tok") == "https://api.asia-1.supply-chain.cloud.aquasec.com"

    def test_environment_wins_over_someone_elses_sign_in(self):
        """A token obtained elsewhere, with AQUA_ENDPOINT set, is not misled by
        whichever tenant this process signed in to last."""
        auth_mod.set_api_endpoint("https://asia-1.api.cloudsploit.com", "other-tok")
        with patch.dict(os.environ, {"AQUA_ENDPOINT": "https://eu-1.api.cloudsploit.com"}, clear=True):
            assert _get_supply_chain_url(self.CONSOLE, "unknown-tok") == "https://api.eu-1.supply-chain.cloud.aquasec.com"

    def test_last_sign_in_is_the_fallback_when_nothing_else_is_known(self):
        auth_mod.set_api_endpoint("https://eu-1.api.cloudsploit.com", "other-tok")
        with patch.dict(os.environ, {}, clear=True):
            assert _get_supply_chain_url(self.CONSOLE, "unknown-tok") == "https://api.eu-1.supply-chain.cloud.aquasec.com"

    def test_environment_still_honoured_when_nothing_recorded(self):
        with patch.dict(os.environ, {"AQUA_ENDPOINT": "https://eu-1.api.cloudsploit.com"}, clear=True):
            assert _get_supply_chain_url(self.CONSOLE) == "https://api.eu-1.supply-chain.cloud.aquasec.com"

    def test_console_region_wins_over_everything(self):
        auth_mod.set_api_endpoint("https://asia-1.api.cloudsploit.com", "tok")
        assert _get_supply_chain_url("https://x.eu-1.cloud.aquasec.com", "tok") == "https://api.eu-1.supply-chain.cloud.aquasec.com"

    def test_no_region_anywhere_means_us_host(self):
        with patch.dict(os.environ, {}, clear=True):
            assert _get_supply_chain_url(self.CONSOLE) == "https://api.supply-chain.cloud.aquasec.com"
