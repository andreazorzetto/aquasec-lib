"""Tests for runtime policy, assurance policy and enforcer group CRUD."""

import json
import os
import sys
from unittest.mock import Mock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aquasec import assurance_policies as ap
from aquasec import enforcers as eg
from aquasec import runtime_policies as rp
from aquasec.common import set_request_defaults
from aquasec.exceptions import ApiError

SERVER = "https://tenant.cloud.aquasec.com"
TOKEN = "jwt"
GROUP_TOKEN = "fake-group-token-not-real-0000"


def _resp(status=200, payload=None, text=None):
    m = Mock()
    m.status_code = status
    if payload is not None:
        m.json.return_value = payload
        m.text = json.dumps(payload)
    else:
        m.json.side_effect = ValueError("no json")
        m.text = text or ""
    return m


# --------------------------------------------------------------------------- #
# Runtime policies
# --------------------------------------------------------------------------- #

class TestRuntimePolicyGet:

    @patch("aquasec.runtime_policies._request_with_retry")
    def test_returns_the_object(self, req):
        req.return_value = _resp(200, {"name": "p", "block_disallowed_images": True})
        assert rp.get_runtime_policy(SERVER, TOKEN, "p")["block_disallowed_images"] is True

    @patch("aquasec.runtime_policies._request_with_retry")
    def test_missing_is_none_not_an_error(self, req):
        req.return_value = _resp(404, {"message": "runtime policy doesn't exist", "code": 404})
        assert rp.get_runtime_policy(SERVER, TOKEN, "nope") is None

    @patch("aquasec.runtime_policies._request_with_retry")
    def test_other_failures_raise_with_the_server_message(self, req):
        req.return_value = _resp(500, {"message": "database unavailable", "code": 500})
        with pytest.raises(ApiError) as exc:
            rp.get_runtime_policy(SERVER, TOKEN, "p")
        assert exc.value.status_code == 500
        assert "database unavailable" in str(exc.value)

    @patch("aquasec.runtime_policies._request_with_retry")
    def test_names_are_url_encoded(self, req):
        """Aqua names may contain spaces; a slash must not become a path."""
        req.return_value = _resp(200, {})
        rp.get_runtime_policy(SERVER, TOKEN, "Aqua default runtime policy")
        assert req.call_args.args[1].endswith("/api/v2/runtime_policies/Aqua%20default%20runtime%20policy")
        rp.get_runtime_policy(SERVER, TOKEN, "a/b")
        assert req.call_args.args[1].endswith("/runtime_policies/a%2Fb")

    @patch("aquasec.runtime_policies._request_with_retry")
    def test_every_call_has_a_timeout(self, req):
        req.return_value = _resp(200, {"result": [], "count": 0})
        rp.get_runtime_policy(SERVER, TOKEN, "p")
        rp.get_all_runtime_policies(SERVER, TOKEN)
        req.return_value = _resp(201, {})
        rp.create_runtime_policy(SERVER, TOKEN, {"name": "p"})
        rp.update_runtime_policy(SERVER, TOKEN, "p", {"name": "p"})
        rp.delete_runtime_policy(SERVER, TOKEN, "p")
        for call in req.call_args_list:
            assert call.kwargs.get("timeout"), call

    @patch("aquasec.runtime_policies._request_with_retry")
    def test_library_wide_timeout_is_honoured(self, req):
        set_request_defaults(timeout=7)
        req.return_value = _resp(200, {})
        rp.get_runtime_policy(SERVER, TOKEN, "p")
        assert req.call_args.kwargs["timeout"] == 7
        rp.get_runtime_policy(SERVER, TOKEN, "p", timeout=3)
        assert req.call_args.kwargs["timeout"] == 3


class TestRuntimePolicyList:

    @patch("aquasec.runtime_policies._request_with_retry")
    def test_pages_until_count_is_reached(self, req):
        req.side_effect = [
            _resp(200, {"result": [{"name": "a"}, {"name": "b"}], "count": 3}),
            _resp(200, {"result": [{"name": "c"}], "count": 3}),
        ]
        assert [p["name"] for p in rp.get_all_runtime_policies(SERVER, TOKEN, page_size=2)] == ["a", "b", "c"]
        assert req.call_count == 2

    @patch("aquasec.runtime_policies._request_with_retry")
    def test_stops_on_an_empty_page(self, req):
        req.side_effect = [_resp(200, {"result": [{"name": "a"}]}), _resp(200, {"result": []})]
        assert len(rp.get_all_runtime_policies(SERVER, TOKEN)) == 1

    @patch("aquasec.runtime_policies._request_with_retry")
    def test_a_failed_page_raises(self, req):
        req.return_value = _resp(403, {"message": "forbidden"})
        with pytest.raises(ApiError):
            rp.get_all_runtime_policies(SERVER, TOKEN)


class TestRuntimePolicyWrite:

    def test_create_needs_a_name(self):
        with pytest.raises(ValueError):
            rp.create_runtime_policy(SERVER, TOKEN, {"enforce": False})

    @patch("aquasec.runtime_policies._request_with_retry")
    def test_create_posts_the_body(self, req):
        req.return_value = _resp(201, {"name": "p"})
        rp.create_runtime_policy(SERVER, TOKEN, {"name": "p", "block_disallowed_images": False})
        assert req.call_args.args[0] == "POST"
        assert req.call_args.args[1] == SERVER + "/api/v2/runtime_policies"
        assert req.call_args.kwargs["json"]["block_disallowed_images"] is False

    @patch("aquasec.runtime_policies._request_with_retry")
    def test_an_empty_success_body_returns_none(self, req):
        req.return_value = _resp(204, text="")
        assert rp.create_runtime_policy(SERVER, TOKEN, {"name": "p"}) is None

    @patch("aquasec.runtime_policies._request_with_retry")
    def test_conflict_raises(self, req):
        req.return_value = _resp(409, {"message": "already exists"})
        with pytest.raises(ApiError) as exc:
            rp.create_runtime_policy(SERVER, TOKEN, {"name": "p"})
        assert exc.value.status_code == 409

    @patch("aquasec.runtime_policies._request_with_retry")
    def test_update_puts_to_the_named_policy(self, req):
        req.return_value = _resp(204, text="")
        rp.update_runtime_policy(SERVER, TOKEN, "my policy", {"name": "my policy"})
        assert req.call_args.args[0] == "PUT"
        assert req.call_args.args[1].endswith("/runtime_policies/my%20policy")

    @patch("aquasec.runtime_policies._request_with_retry")
    def test_delete_missing_ok(self, req):
        req.return_value = _resp(404, {"message": "doesn't exist"})
        assert rp.delete_runtime_policy(SERVER, TOKEN, "p", missing_ok=True) is False
        with pytest.raises(ApiError):
            rp.delete_runtime_policy(SERVER, TOKEN, "p")

    @patch("aquasec.runtime_policies._request_with_retry")
    def test_delete_success(self, req):
        req.return_value = _resp(204, text="")
        assert rp.delete_runtime_policy(SERVER, TOKEN, "p") is True


# --------------------------------------------------------------------------- #
# Assurance policies
# --------------------------------------------------------------------------- #

class TestAssurancePolicies:

    @pytest.mark.parametrize("atype", ["image", "host", "function", "kubernetes"])
    @patch("aquasec.assurance_policies._request_with_retry")
    def test_type_is_part_of_the_path(self, req, atype):
        req.return_value = _resp(200, {"name": "Default"})
        ap.get_assurance_policy(SERVER, TOKEN, atype, "Default")
        assert req.call_args.args[1] == f"{SERVER}/api/v2/assurance_policy/{atype}/Default"

    @patch("aquasec.assurance_policies._request_with_retry")
    def test_unknown_type_is_rejected_before_any_request(self, req):
        with pytest.raises(ValueError, match="unknown assurance policy type"):
            ap.get_assurance_policy(SERVER, TOKEN, "container", "x")
        req.assert_not_called()

    @patch("aquasec.assurance_policies._request_with_retry")
    def test_missing_is_none(self, req):
        req.return_value = _resp(404, {"message": "assurance policy doesn't exist"})
        assert ap.get_assurance_policy(SERVER, TOKEN, "image", "nope") is None

    @patch("aquasec.assurance_policies._request_with_retry")
    def test_create_and_delete(self, req):
        req.return_value = _resp(201, {"name": "p"})
        ap.create_assurance_policy(SERVER, TOKEN, "image", {"name": "p"})
        assert req.call_args.args[:2] == ("POST", f"{SERVER}/api/v2/assurance_policy/image")
        req.return_value = _resp(204, text="")
        assert ap.delete_assurance_policy(SERVER, TOKEN, "image", "p") is True

    @patch("aquasec.assurance_policies._request_with_retry")
    def test_list_pages(self, req):
        req.side_effect = [_resp(200, {"result": [{"name": "a"}], "count": 2}),
                           _resp(200, {"result": [{"name": "b"}], "count": 2})]
        assert len(ap.get_all_assurance_policies(SERVER, TOKEN, "host", page_size=1)) == 2


# --------------------------------------------------------------------------- #
# Enforcer groups -- including secret handling
# --------------------------------------------------------------------------- #

def _group(**extra):
    g = {"id": "cluster-a", "logicalname": "", "type": "agent", "enforce": False,
         "token": GROUP_TOKEN,
         "install_command": f"docker run -e AQUA_TOKEN={GROUP_TOKEN} ...",
         "command": {"default": f"--token {GROUP_TOKEN}"}}
    g.update(extra)
    return g


class TestEnforcerGroupSecrets:

    def test_split_separates_settings_from_secrets(self):
        settings, secrets = eg.split_enforcer_group_secrets(_group())
        assert GROUP_TOKEN not in json.dumps(settings)
        assert secrets["token"] == GROUP_TOKEN
        assert set(secrets) == {"token", "install_command", "command"}
        assert settings["id"] == "cluster-a"

    def test_split_does_not_mutate_the_input(self):
        g = _group()
        eg.split_enforcer_group_secrets(g)
        assert g["token"] == GROUP_TOKEN

    @patch("aquasec.enforcers._request_with_retry")
    def test_errors_never_carry_the_token(self, req):
        """A failure response that echoes the group must not leak into the error."""
        req.return_value = _resp(409, {"message": "conflict", "group": _group()})
        with pytest.raises(ApiError) as exc:
            eg.create_enforcer_group(SERVER, TOKEN, {"id": "cluster-a"})
        assert GROUP_TOKEN not in str(exc.value)
        assert GROUP_TOKEN not in exc.value.response_text
        assert "REDACTED" in exc.value.response_text

    @patch("aquasec.enforcers._request_with_retry")
    def test_a_token_in_a_sibling_field_is_redacted(self, req):
        req.return_value = _resp(400, {"message": "bad", "token": GROUP_TOKEN})
        with pytest.raises(ApiError) as exc:
            eg.update_enforcer_group(SERVER, TOKEN, {"id": "cluster-a"})
        assert GROUP_TOKEN not in str(exc.value) + exc.value.response_text

    @patch("aquasec.enforcers._request_with_retry")
    def test_a_token_repeated_inside_the_message_text_is_redacted(self, req):
        """Field redaction alone would miss this: the token is in free text."""
        req.return_value = _resp(400, {
            "message": f"token {GROUP_TOKEN} is not valid for this gateway",
            "group": _group(),
        })
        with pytest.raises(ApiError) as exc:
            eg.update_enforcer_group(SERVER, TOKEN, {"id": "cluster-a"})
        assert GROUP_TOKEN not in str(exc.value)
        assert GROUP_TOKEN not in exc.value.response_text
        assert "is not valid for this gateway" in str(exc.value)  # still useful

    @patch("aquasec.enforcers._request_with_retry")
    def test_a_non_json_error_body_is_not_echoed(self, req):
        req.return_value = _resp(502, text=f"upstream said {GROUP_TOKEN}")
        with pytest.raises(ApiError) as exc:
            eg.get_enforcer_group(SERVER, TOKEN, "cluster-a")
        assert GROUP_TOKEN not in str(exc.value) + exc.value.response_text
        assert "not shown" in exc.value.response_text

    @patch("aquasec.enforcers._request_with_retry")
    def test_verbose_output_never_contains_the_token(self, req, capsys):
        req.return_value = _resp(200, _group())
        eg.get_enforcer_group(SERVER, TOKEN, "cluster-a", verbose=True)
        req.return_value = _resp(201, _group())
        eg.create_enforcer_group(SERVER, TOKEN, {"id": "cluster-a"}, verbose=True)
        req.return_value = _resp(204, text="")
        eg.update_enforcer_group(SERVER, TOKEN, _group(), verbose=True)
        assert GROUP_TOKEN not in capsys.readouterr().out


class TestEnforcerGroupCrud:

    @patch("aquasec.enforcers._request_with_retry")
    def test_get_by_id(self, req):
        req.return_value = _resp(200, _group())
        assert eg.get_enforcer_group(SERVER, TOKEN, "cluster a")["id"] == "cluster-a"
        assert req.call_args.args[1] == f"{SERVER}/api/v1/hostsbatch/cluster%20a"

    @patch("aquasec.enforcers._request_with_retry")
    def test_missing_is_none(self, req):
        req.return_value = _resp(404, {"message": "Enforcer group (x) not found", "code": 404})
        assert eg.get_enforcer_group(SERVER, TOKEN, "x") is None

    def test_create_needs_an_id(self):
        with pytest.raises(ValueError):
            eg.create_enforcer_group(SERVER, TOKEN, {"logicalname": "x"})

    @patch("aquasec.enforcers._request_with_retry")
    def test_update_strips_secrets_from_the_body_by_default(self, req):
        req.return_value = _resp(204, text="")
        eg.update_enforcer_group(SERVER, TOKEN, _group(enforce=True))
        body = req.call_args.kwargs["json"]
        assert body["id"] == "cluster-a" and body["enforce"] is True
        assert GROUP_TOKEN not in json.dumps(body)
        assert req.call_args.args[:2] == ("PUT", f"{SERVER}/api/v1/hostsbatch")
        assert req.call_args.kwargs["params"] == {"update_enforcers": "true"}

    @patch("aquasec.enforcers._request_with_retry")
    def test_update_can_send_secrets_when_asked(self, req):
        req.return_value = _resp(204, text="")
        eg.update_enforcer_group(SERVER, TOKEN, _group(), strip_secrets=False)
        assert req.call_args.kwargs["json"]["token"] == GROUP_TOKEN

    @patch("aquasec.enforcers._request_with_retry")
    def test_delete_does_not_take_enforcers_with_it_by_default(self, req):
        req.return_value = _resp(204, text="")
        eg.delete_enforcer_group(SERVER, TOKEN, "cluster-a")
        assert req.call_args.kwargs["params"] is None
        eg.delete_enforcer_group(SERVER, TOKEN, "cluster-a", delete_related=True)
        assert req.call_args.kwargs["params"] == {"delete_related": "true"}

    @patch("aquasec.enforcers._request_with_retry")
    def test_delete_missing_ok(self, req):
        req.return_value = _resp(404, {"message": "not found"})
        assert eg.delete_enforcer_group(SERVER, TOKEN, "x", missing_ok=True) is False
