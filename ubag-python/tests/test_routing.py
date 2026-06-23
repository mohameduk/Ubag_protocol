"""Tests for the three-branch routing matrix."""
import pytest
from ubag._routing import RoutingBranch, resolve_branch
from ubag._credential import issue_credential, validate_credential

SECRET = "test-secret-32-chars-minimum-ok!"


def _validate(token):
    return validate_credential(token, SECRET)


def test_valid_credential_routes_to_agent():
    token = issue_credential("test-agent", SECRET)
    branch = resolve_branch("python-httpx/0.27", "*/*", token, _validate)
    assert branch == RoutingBranch.AGENT


def test_expired_credential_routes_to_sandbox():
    import jwt, time
    expired = jwt.encode(
        {"sub": "agent", "iat": 0, "exp": 1, "agent_class": "test", "paths": ["/*"]},
        SECRET, algorithm="HS256"
    )
    branch = resolve_branch("python-httpx/0.27", "*/*", expired, _validate)
    assert branch == RoutingBranch.SANDBOX


def test_machine_ua_no_credential_routes_to_sandbox():
    branch = resolve_branch("python-requests/2.31", "*/*", None, _validate)
    assert branch == RoutingBranch.SANDBOX


def test_curl_routes_to_sandbox():
    branch = resolve_branch("curl/8.5.0", "*/*", None, _validate)
    assert branch == RoutingBranch.SANDBOX


def test_known_bot_routes_to_sandbox():
    branch = resolve_branch("GPTBot/1.0", "*/*", None, _validate)
    assert branch == RoutingBranch.SANDBOX


def test_browser_with_html_accept_routes_to_human():
    branch = resolve_branch(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
        "text/html,application/xhtml+xml,*/*",
        None,
        _validate,
    )
    assert branch == RoutingBranch.HUMAN


def test_browser_without_html_accept_routes_to_sandbox():
    # UA claims browser but no text/html Accept — library impersonation
    branch = resolve_branch(
        "Mozilla/5.0 Chrome/120",
        "application/json",
        None,
        _validate,
    )
    assert branch == RoutingBranch.SANDBOX


def test_no_ua_no_credential_routes_to_human():
    # Fail open — ambiguous traffic goes to human path
    branch = resolve_branch("", "text/html", None, _validate)
    assert branch == RoutingBranch.HUMAN
