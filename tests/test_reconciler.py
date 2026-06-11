"""Offline tests for the reconciler, with the API mocked.

These exercise the client's etag handling and error mapping without a live
deployment. The recorded responses mirror the live API shapes verified
against a real Semgrep deployment.
"""

from __future__ import annotations

import pytest
import responses

from reconciler.client import PoliciesApiError
from reconciler.client import PoliciesClient

_BASE = "https://example.test"
_DEPLOYMENT = 524
_PREFIX = f"{_BASE}/api/policies/v2/deployments/{_DEPLOYMENT}"


def _client() -> PoliciesClient:
    return PoliciesClient(_DEPLOYMENT, token="fake-token", base_url=_BASE)


@responses.activate
def test_get_detection_policy_returns_bundle_and_etag():
    responses.get(
        f"{_PREFIX}/detection-policy/code",
        json={"bundle": {"rulesets": ["p/default"]}, "state_version": "abc123"},
    )

    bundle = _client().get_detection_policy("code")

    assert bundle.data["rulesets"] == ["p/default"]
    assert bundle.state_version == "abc123"


@responses.activate
def test_apply_sends_if_match_header():
    responses.put(
        f"{_PREFIX}/remediation-policies",
        json={"bundle": {"policies": []}, "state_version": "def456"},
    )

    _client().apply_remediation_policies({"policies": []}, "abc123")

    assert responses.calls[0].request.headers["If-Match"] == "abc123"


@responses.activate
def test_state_version_mismatch_raises_with_code_and_current_version():
    responses.put(
        f"{_PREFIX}/remediation-policies",
        status=409,
        json={
            "error": "The bundle changed since the state_version in If-Match was read.",
            "code": "STATE_VERSION_MISMATCH",
            "current_state_version": "newsv",
        },
    )

    with pytest.raises(PoliciesApiError) as exc_info:
        _client().apply_remediation_policies({"policies": []}, "stale")

    assert exc_info.value.status == 409
    assert exc_info.value.code == "STATE_VERSION_MISMATCH"
    assert exc_info.value.details["current_state_version"] == "newsv"


@responses.activate
def test_missing_dependent_action_surfaces_companion():
    responses.put(
        f"{_PREFIX}/remediation-policies",
        status=400,
        json={
            "error": "block requires pr_comment",
            "code": "MISSING_DEPENDENT_ACTION",
            "missing_companion": "pr_comment",
        },
    )

    with pytest.raises(PoliciesApiError) as exc_info:
        _client().apply_remediation_policies({"policies": []}, "abc")

    assert exc_info.value.code == "MISSING_DEPENDENT_ACTION"
    assert exc_info.value.details["missing_companion"] == "pr_comment"


def test_missing_token_is_a_clear_error(monkeypatch):
    monkeypatch.delenv("SEMGREP_API_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="SEMGREP_API_TOKEN"):
        PoliciesClient(_DEPLOYMENT, base_url=_BASE)
