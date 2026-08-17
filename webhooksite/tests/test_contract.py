"""Contract tests generated from the selected request."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from agentis import AuthError, is_marked

from webhooksite import cli, commands, transport
from webhooksite.commands import REDACTED, compact, sanitize

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contract" / "endpoint.json"
FIXTURE = ROOT / "tests" / "fixtures" / "response.json"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "webhooksite", *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def test_only_one_command_is_registered():
    source = (ROOT / "src" / "webhooksite" / "cli.py").read_text()
    assert source.count("@app.command") == 1
    assert "def get(" in source


def test_contract_is_a_get_and_contains_no_credential_values():
    endpoint = json.loads(CONTRACT.read_text())
    assert endpoint["method"] == "GET"
    assert all(set(item) == {"env", "location", "name"} for item in endpoint["auth"])
    assert all(item["location"] in {"header", "cookie", "query"} for item in endpoint["auth"])
    assert all(not item["name"].startswith(":") for item in endpoint["headers"])
    assert all(
        item["location"] != "header" or not item["name"].startswith(":")
        for item in endpoint["auth"]
    )
    packaged = json.loads((ROOT / "src" / "webhooksite" / "endpoint.json").read_text())
    assert packaged == endpoint


def test_response_fixture_is_valid_json():
    json.loads(FIXTURE.read_text())


def test_large_output_admits_it_was_cut():
    result = compact({"body": "x" * 40_000})
    assert is_marked(result["response_json"])


def test_runtime_output_is_redacted_before_raw_can_emit_it():
    result = sanitize(
        {
            "access_token": "secret",
            "opaque": "plaincredential123",
            "plaincredential123": "visible",
        },
        exact_secrets=("plaincredential123",),
    )
    assert result["access_token"] == REDACTED
    assert result["opaque"] == REDACTED
    assert "plaincredential123" not in json.dumps(result)


def test_transport_injects_each_credential_location():
    endpoint = {
        "origin": "https://api.example.test",
        "path": "/items",
        "headers": [
            {"name": ":authority", "value": "api.example.test"},
            {"name": "Accept", "value": "application/json"},
        ],
        "query": [{"name": "page", "value": "2"}],
        "auth": [
            {"name": ":path", "location": "header"},
            {"name": "token", "location": "header"},
            {"name": "token", "location": "cookie"},
            {"name": "key", "location": "query"},
        ],
    }
    credentials = {
        "header:token": "header-value",
        "cookie:token": "cookie-value",
        "query:key": "query-value",
    }

    class Response:
        status_code = 200

        def json(self):
            return {"ok": True}

    class Client:
        call = None

        @classmethod
        def get(cls, url, **kwargs):
            cls.call = (url, kwargs)
            return Response()

    assert transport.request_endpoint(endpoint, credentials, client=Client) == {"ok": True}
    url, kwargs = Client.call
    assert url == "https://api.example.test/items"
    assert all(not name.startswith(":") for name in kwargs["headers"])
    assert kwargs["headers"]["token"] == "header-value"
    assert kwargs["cookies"]["token"] == "cookie-value"
    assert ("key", "query-value") in kwargs["params"]


def test_transport_recognizes_login_redirects_and_login_html():
    endpoint = {
        "origin": "https://api.example.test",
        "path": "/items",
        "headers": [],
        "query": [],
        "auth": [],
    }

    class Response:
        def __init__(self, status_code, headers, text=""):
            self.status_code = status_code
            self.headers = headers
            self.text = text
            self.is_redirect = 300 <= status_code < 400

        def json(self):
            raise ValueError

    responses = (
        Response(302, {"location": "/login"}),
        Response(
            200,
            {"content-type": "text/html"},
            '<form><input type="password"></form>',
        ),
    )
    for response in responses:
        class Client:
            @staticmethod
            def get(*args, **kwargs):
                return response

        with pytest.raises(AuthError):
            transport.request_endpoint(endpoint, {}, client=Client)
    ordinary_redirect = Response(302, {"location": "/authors"})
    assert transport._authentication_failed(ordinary_redirect) is False


def test_command_calls_refresh_and_rediscovery_hooks(monkeypatch):
    events = []
    endpoint = {"path": "/items", "auth": []}

    monkeypatch.setattr(
        transport,
        "refresh_credentials",
        lambda: events.append("refresh"),
    )
    monkeypatch.setattr(transport, "load_contract", lambda: endpoint)

    def rediscover(value):
        events.append("rediscover")
        return value

    monkeypatch.setattr(transport, "rediscover", rediscover)
    monkeypatch.setattr(transport, "load_credentials", lambda auth: {})
    monkeypatch.setattr(
        transport,
        "request_endpoint",
        lambda selected, credentials: {"ok": True},
    )

    class Guard:
        def check(self, amount, what):
            events.append("guard")

    class Out:
        def emit(self, result, **kwargs):
            events.append("emit")

    class Session:
        guard = Guard()
        out = Out()

    commands.get(Session())
    assert events == ["guard", "refresh", "rediscover", "emit"]


def test_help_carries_agentis_exit_codes():
    output = run("--help")
    assert output.returncode == 0
    assert "not_found" in output.stdout
    assert max(len(line) for line in cli.AGENT_NOTES.splitlines()) <= 76


def test_agentis_mechanical_checks_still_pass():
    from agentis.checks import run_checks

    failed = [item for item in run_checks(ROOT) if not item["ok"] and not item["manual"]]
    assert not failed, failed


def test_readme_keeps_the_dumb_agent_reminder():
    assert "dumb-agent test" in (ROOT / "README.md").read_text()
