"""Agent-facing contract tests that must survive adapting the scaffold."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from agtcli import ExitCode, RefusedError, estimate_tokens, is_marked

from har2cli import api, cli

ROOT = Path(__file__).resolve().parents[1]


def run(*args: str, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "har2cli", *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        **kw,
    )


class TestHelpCarriesTheContract:
    def test_help_lists_every_exit_code(self):
        out = run("--help", env={"COLUMNS": "100", "PATH": "/usr/bin:/bin"}).stdout
        for code in ExitCode:
            assert code.kind in out

    def test_help_lists_exactly_the_v1_commands(self):
        out = run("--help").stdout
        for command in (
            "import",
            "endpoints",
            "inspect",
            "replay",
            "auth-bisect",
            "scaffold",
        ):
            assert command in out
        for removed_placeholder in ("│ submit ", "│ find ", "auth --paste"):
            assert removed_placeholder not in out

    def test_help_does_not_hand_write_the_exit_table(self):
        assert "exit code" not in cli.AGENT_NOTES.lower()

    def test_notes_fit_a_narrow_terminal(self):
        assert max(len(line) for line in cli.AGENT_NOTES.splitlines()) <= 76

    def test_no_arguments_prints_help(self):
        assert "Usage" in run().stdout


class TestReplayOutputStaysSafeAndSmall:
    def test_compact_text_marks_a_cut(self):
        compact = api.compact_response({"status": 200, "body": "word " * 5_000})
        assert is_marked(compact["body"])

    def test_compact_text_leaves_a_whole_label_alone(self):
        compact = api.compact_response({"status": 200, "body": "Horario General"})
        assert compact["body"] == "Horario General"
        assert not is_marked(compact["body"])

    def test_compact_output_stays_inside_the_context_budget(self):
        record = {"status": 200, "body": "x" * 100_000, "headers": {"x": "y"}}
        assert estimate_tokens(json.dumps(api.compact_response(record))) < 5_000

    def test_compact_json_stays_inside_the_context_budget_and_marks_the_cut(self):
        record = {"status": 200, "body": {"items": ["x" * 100_000]}}
        compact = api.compact_response(record)
        assert estimate_tokens(json.dumps(compact)) < 5_000
        assert is_marked(compact["body"]["json"])

    def test_response_redacts_auth_headers_and_json_fields(self):
        response = httpx.Response(
            200,
            headers={
                "content-type": "application/json",
                "set-cookie": "session=top-secret",
            },
            json={"name": "Ada", "access_token": "top-secret"},
            request=httpx.Request("GET", "https://example.test/me"),
        )
        record = api.response_record(
            response,
            request_url="https://example.test/me",
        )
        assert record["headers"]["set-cookie"] == "<redacted>"
        assert record["body"] == {"name": "Ada", "access_token": "<redacted>"}
        assert "top-secret" not in json.dumps(record)

    def test_response_redacts_exact_secrets_used_as_json_keys(self):
        response = httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"echoed-cookie": "visible"},
            request=httpx.Request("GET", "https://example.test/me"),
        )
        record = api.response_record(
            response,
            request_url="https://example.test/me",
            secret_values=("echoed-cookie",),
        )
        assert "echoed-cookie" not in json.dumps(record)

    def test_response_redacts_redirects_text_secrets_and_echoed_credentials(self):
        response = httpx.Response(
            200,
            headers={
                "content-type": "text/plain",
                "location": "https://x.test/cb?code=redirect-secret",
            },
            text="token=body-secret; echoed-cookie; Bearer abcdefghijklmnop",
            request=httpx.Request("GET", "https://example.test/me"),
        )
        record = api.response_record(
            response,
            request_url="https://example.test/me",
            secret_values=("echoed-cookie",),
        )
        rendered = json.dumps(record)
        for leaked in (
            "redirect-secret",
            "body-secret",
            "echoed-cookie",
            "abcdefghijklmnop",
        ):
            assert leaked not in rendered

    def test_auth_signature_distinguishes_logged_in_and_public_json_shapes(self):
        request = httpx.Request("GET", "https://example.test/me")
        private = httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"user": {"id": "1"}},
            request=request,
        )
        public = httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"public": True},
            request=request,
        )
        assert api.auth_signature(private) != api.auth_signature(public)

    def test_auth_failure_does_not_treat_auth_prefixes_as_login_paths(self):
        response = httpx.Response(
            302,
            headers={"location": "/authors"},
            request=httpx.Request("GET", "https://example.test/me"),
        )
        assert api.authentication_failed(response) is False

    def test_replay_drops_http2_pseudo_headers_before_httpx(self, monkeypatch):
        def network(method, url, **kwargs):
            assert kwargs["headers"] == [("accept", "application/json")]
            return httpx.Response(200, request=httpx.Request(method, url))

        monkeypatch.setattr(httpx, "request", network)
        api.replay(
            {
                "method": "GET",
                "url": "https://1.1.1.1/form-builder",
                "headers": [
                    {"name": ":authority", "value": "webhook.site"},
                    {"name": ":method", "value": "GET"},
                    {"name": ":path", "value": "/form-builder"},
                    {"name": ":scheme", "value": "https"},
                    {"name": "accept", "value": "application/json"},
                ],
            }
        )

    def test_private_destination_is_refused_before_httpx(self, monkeypatch):
        def network(*args, **kwargs):
            raise AssertionError("network should not be reached")

        monkeypatch.setattr(httpx, "request", network)
        with pytest.raises(RefusedError) as raised:
            api.replay(
                {"method": "GET", "url": "http://169.254.169.254/latest"}
            )
        assert "non-public address" in str(raised.value)


class TestTheChecklistStillPasses:
    def test_no_mechanical_check_fails(self):
        from agtcli.checks import run_checks

        failed = [r for r in run_checks(ROOT) if not r["ok"] and not r["manual"]]
        assert not failed, (
            "agtcli check would fail on: "
            + ", ".join(f"{r['name']} ({r['detail']})" for r in failed)
        )


class TestTheBrowserToCliSkill:
    def test_it_exists_and_ships_with_the_tool(self):
        assert (ROOT / "skill" / "SKILL.md").exists()
        assert (ROOT / "skill" / "agents" / "openai.yaml").exists()
        assert (ROOT / "skill" / "references" / "browser-to-cli.md").exists()
        project_skill = ROOT / ".agents" / "skills" / "har2cli"
        assert project_skill.resolve() == (ROOT / "skill").resolve()

    def test_it_covers_the_safe_browser_to_cli_handoff(self):
        skill = (ROOT / "skill" / "SKILL.md").read_text()
        workflow = (
            ROOT / "skill" / "references" / "browser-to-cli.md"
        ).read_text()
        body = skill + workflow
        for marker in (
            "$chrome",
            "HAR (with sensitive data)",
            "har2cli import",
            "har2cli replay",
            "--accept-auth-bisect",
            "uv run --project",
        ):
            assert marker in body
        assert len(skill.splitlines()) < 45
