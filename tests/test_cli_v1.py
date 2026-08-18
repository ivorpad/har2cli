"""Black-box contract for the deliberately small har2cli v1.

The command surface came from Codex session 019fd719-b11e, event 93.  These
tests avoid naming storage modules or an on-disk manifest filename.  The two
in-process network tests assume replay and auth-bisect send through
``har2cli.commands.api.replay``; the HTTP module exposes that as its GET-only
transport seam.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from agtcli import ExitCode


ROOT = Path(__file__).resolve().parents[1]
HAR = ROOT / "tests" / "fixtures" / "v1.har"

COMMANDS = (
    "import",
    "endpoints",
    "inspect",
    "replay",
    "auth-bisect",
    "scaffold",
)

# Every value is synthetic.  Their only job is to prove that all common HAR
# secret locations are scrubbed before the imported capture reaches disk or
# command output.
SECRET_VALUES = (
    "HAR2CLI_TEST_QUERY_SECRET_81F2",
    "HAR2CLI_TEST_BEARER_SECRET_7F3A",
    "HAR2CLI_TEST_COOKIE_SECRET_4C2E",
    "HAR2CLI_TEST_CSRF_SECRET_D9B1",
    "HAR2CLI_TEST_ROTATED_SECRET_A6C8",
    "HAR2CLI_TEST_API_KEY_SECRET_3E5D",
    "HAR2CLI_TEST_BODY_SECRET_B7A4",
    "HAR2CLI_TEST_ANALYTICS_SECRET_C5F9",
)


def cli_env(config_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "HAR2CLI_CONFIG_DIR": str(config_dir),
            "COLUMNS": "120",
            "NO_COLOR": "1",
            "TERM": "dumb",
        }
    )
    # A developer shell should not be able to redirect a test into real state.
    env.pop("har2cli_CONFIG_DIR", None)
    env.pop("HAR2CLI_MAX", None)
    env.pop("HAR2CLI_MAX_COST", None)
    return env


def run_cli(config_dir: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "har2cli", *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=cli_env(config_dir),
    )


def parsed_stdout(result: subprocess.CompletedProcess[str]) -> Any:
    """Parse the whole stream, rejecting prose or a second JSON document."""
    assert result.stdout.strip(), f"stdout was empty; stderr: {result.stderr}"
    return json.loads(result.stdout)


def import_fixture(config_dir: Path) -> subprocess.CompletedProcess[str]:
    result = run_cli(config_dir, "import", str(HAR), "--json")
    assert result.returncode == ExitCode.OK, result.stderr or result.stdout
    parsed_stdout(result)
    return result


def walk_dicts(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_dicts(child)


def local_method(record: dict[str, Any]) -> str:
    for key in ("method", "verb", "http_method"):
        value = record.get(key)
        if isinstance(value, str):
            return value.upper()
    return ""


def endpoint_record(payload: Any, method: str, path: str) -> dict[str, Any]:
    candidates = [
        record
        for record in walk_dicts(payload)
        if local_method(record) == method
        and path in json.dumps(record, sort_keys=True)
    ]
    assert candidates, f"no {method} {path} group in {payload!r}"
    # Prefer the leaf endpoint record over a possible enclosing result object.
    return min(candidates, key=lambda item: len(json.dumps(item, sort_keys=True)))


def grouped_count(record: dict[str, Any]) -> int | None:
    for key in ("count", "calls", "occurrences", "frequency"):
        value = record.get(key)
        if isinstance(value, int):
            return value
    for key in ("request_ids", "requests", "ids"):
        value = record.get(key)
        if isinstance(value, list):
            return len(value)
    return None


def request_ids(record: dict[str, Any]) -> list[str]:
    found: list[str] = []

    def visit(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                visit(child, child_key.lower())
            return
        if isinstance(value, list):
            for child in value:
                visit(child, key)
            return
        if not isinstance(value, (str, int)):
            return
        candidate = str(value)
        if "id" in key and re.fullmatch(r"req[-_][A-Za-z0-9._-]+", candidate):
            found.append(candidate)

    visit(record)
    return list(dict.fromkeys(found))


def imported_endpoints(config_dir: Path) -> Any:
    import_fixture(config_dir)
    result = run_cli(config_dir, "endpoints", "--json")
    assert result.returncode == ExitCode.OK, result.stderr or result.stdout
    return parsed_stdout(result)


def id_for(config_dir: Path, method: str, path: str) -> str:
    payload = imported_endpoints(config_dir)
    ids = request_ids(endpoint_record(payload, method, path))
    assert ids, "endpoints must expose req-* ids for inspect/replay"
    return ids[0]


def auth_candidates(config_dir: Path, request_id: str) -> list[str]:
    from har2cli import har, store

    capture = store.load_active_capture(config_dir)
    record = har.find_request(capture, request_id)
    return har.credential_candidates(record)


def save_auth_partition(
    config_dir: Path,
    request_id: str,
    *,
    required: list[str],
    unnecessary: list[str],
    authoritative: bool = False,
) -> None:
    from har2cli import store

    capture = store.load_active_capture(config_dir)
    store.save_auth_result(
        config_dir,
        capture,
        request_id,
        {
            "request_id": request_id,
            "required": required,
            "unnecessary": unnecessary,
            "authoritative": authoritative,
        },
    )


def assert_no_secrets(*chunks: str | bytes) -> None:
    body = b"\n".join(
        chunk if isinstance(chunk, bytes) else chunk.encode() for chunk in chunks
    )
    for value in SECRET_VALUES:
        assert value.encode() not in body


def registered_command_names() -> set[str]:
    from har2cli import cli

    names: set[str] = set()
    for info in cli.app.registered_commands:
        name = info.name
        if name is None and info.callback is not None:
            # Typer maps underscores to dashes.  ``import_`` needs the trailing
            # dash removed, or the Python keyword leaks into the CLI contract.
            name = info.callback.__name__.replace("_", "-").strip("-")
        assert name is not None
        names.add(name)
    return names


class TestTheV1CommandSurface:
    def test_help_has_exactly_the_six_proposed_commands(self, tmp_path: Path):
        result = run_cli(tmp_path / "state", "--help")
        assert result.returncode == ExitCode.OK
        assert registered_command_names() == set(COMMANDS)
        for command in COMMANDS:
            assert re.search(rf"\b{re.escape(command)}\b", result.stdout)

    @pytest.mark.parametrize("command", COMMANDS)
    def test_every_command_has_help(self, tmp_path: Path, command: str):
        result = run_cli(tmp_path / "state", command, "--help")
        assert result.returncode == ExitCode.OK, result.stderr or result.stdout
        assert f"har2cli {command}" in result.stdout

    def test_scaffold_help_requires_one_selected_request(self, tmp_path: Path):
        out = run_cli(tmp_path / "state", "scaffold", "--help").stdout
        assert "--request" in out
        assert "--accept-auth-bisect" in out


class TestImport:
    def test_writes_only_owner_readable_sanitized_state(self, tmp_path: Path):
        config_dir = tmp_path / "state"
        result = import_fixture(config_dir)

        files = [path for path in config_dir.rglob("*") if path.is_file()]
        assert files, "import did not persist a sanitized capture"
        for path in files:
            assert stat.S_IMODE(path.stat().st_mode) == 0o600, path

        sidecars = [
            path
            for path in files
            if re.search(r"(?:replay|secret)", path.name, re.IGNORECASE)
        ]
        sanitized_files = [path for path in files if path not in sidecars]
        assert sidecars, "the replay/secret sidecar must be separately identifiable"
        assert sanitized_files, "import did not persist a sanitized capture or index"

        sanitized = b"\n".join(path.read_bytes() for path in sanitized_files)
        assert b"app.example.test" in sanitized
        assert b"/api/orders" in sanitized
        assert_no_secrets(sanitized, result.stdout, result.stderr)

        # Secret bytes are allowed only in the explicit owner-only sidecar.
        for path in files:
            if any(value.encode() in path.read_bytes() for value in SECRET_VALUES):
                assert path in sidecars, path


class TestEndpoints:
    def test_filters_noise_and_groups_equivalent_calls(self, tmp_path: Path):
        payload = imported_endpoints(tmp_path / "state")
        rendered = json.dumps(payload, sort_keys=True).lower()

        assert "app.css" not in rendered
        assert "google-analytics" not in rendered
        get_orders = endpoint_record(payload, "GET", "/api/orders")
        endpoint_record(payload, "GET", "/api/profile")
        endpoint_record(payload, "POST", "/api/orders")
        assert grouped_count(get_orders) == 2
        assert_no_secrets(rendered)


class TestInspect:
    def test_reports_names_and_never_captured_values(self, tmp_path: Path):
        config_dir = tmp_path / "state"
        request_id = id_for(config_dir, "GET", "/api/orders")
        result = run_cli(config_dir, "inspect", request_id, "--json")

        assert result.returncode == ExitCode.OK, result.stderr or result.stdout
        payload = parsed_stdout(result)
        rendered = json.dumps(payload, sort_keys=True).lower()
        assert "get" in rendered
        assert "/api/orders" in rendered
        for name in ("limit", "access_token", "authorization", "x-csrf-token"):
            assert name in rendered
        assert "session_id" in rendered or '"cookie"' in rendered
        assert "theme=dark" not in rendered
        assert "bearer har2cli" not in rendered
        assert_no_secrets(result.stdout, result.stderr)


def invoke_in_process(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    config_dir: Path,
    *args: str,
) -> tuple[int, str, str]:
    """Run through agtcli error handling while keeping monkeypatches active."""
    from agtcli import run
    from agtcli import output as agtcli_output
    from har2cli import cli

    monkeypatch.setenv("HAR2CLI_CONFIG_DIR", str(config_dir))
    agtcli_output._STDOUT_HAS_JSON = False
    code = int(run(cli.app, args))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def install_network_tripwire(monkeypatch: pytest.MonkeyPatch) -> None:
    def live_network_was_attempted(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("test attempted live network instead of api.replay")

    monkeypatch.setattr(httpx, "request", live_network_was_attempted)
    monkeypatch.setattr(httpx.Client, "request", live_network_was_attempted)
    monkeypatch.setattr(httpx.Client, "send", live_network_was_attempted)


def call_method(args: Iterable[Any], kwargs: dict[str, Any]) -> str:
    method = kwargs.get("method")
    if isinstance(method, str):
        return method.upper()
    for value in args:
        if isinstance(value, str) and value.upper() in {
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }:
            return value.upper()
        if isinstance(value, dict):
            nested = value.get("method")
            if isinstance(nested, str):
                return nested.upper()
    return ""


class TestReplay:
    def test_get_is_capped_at_one_transport_call(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        config_dir = tmp_path / "state"
        request_id = id_for(config_dir, "GET", "/api/orders")
        from har2cli import commands

        calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

        def fake_replay(*args: Any, **kwargs: Any) -> httpx.Response:
            calls.append((args, kwargs))
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={"ok": True, "transport": "fixture"},
                request=httpx.Request("GET", "https://app.example.test/api/orders"),
            )

        install_network_tripwire(monkeypatch)
        monkeypatch.setattr(commands.api, "replay", fake_replay)

        code, stdout, stderr = invoke_in_process(
            monkeypatch,
            capsys,
            config_dir,
            "replay",
            request_id,
            "--max-cost",
            "1",
            "--json",
        )
        assert code == ExitCode.OK, stderr or stdout
        assert len(calls) == 1
        assert call_method(*calls[0]) == "GET"
        assert '"ok": true' in stdout.lower()

        calls.clear()
        code, stdout, stderr = invoke_in_process(
            monkeypatch,
            capsys,
            config_dir,
            "replay",
            request_id,
            "--max-cost",
            "0",
            "--json",
        )
        assert code == ExitCode.REFUSED, stderr or stdout
        assert not calls
        assert json.loads(stdout)["exit_code"] == ExitCode.REFUSED

    def test_post_is_refused_before_transport(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        config_dir = tmp_path / "state"
        request_id = id_for(config_dir, "POST", "/api/orders")
        install_network_tripwire(monkeypatch)
        code, stdout, stderr = invoke_in_process(
            monkeypatch,
            capsys,
            config_dir,
            "replay",
            request_id,
            "--max-cost",
            "1",
            "--json",
        )

        assert code == ExitCode.REFUSED, stderr or stdout
        assert json.loads(stdout)["exit_code"] == ExitCode.REFUSED


class TestAuthBisect:
    def test_reports_only_required_names_and_obeys_call_budget(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        config_dir = tmp_path / "state"
        request_id = id_for(config_dir, "GET", "/api/orders")
        from har2cli import commands

        calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

        def fake_replay(*args: Any, **kwargs: Any) -> httpx.Response:
            calls.append((args, kwargs))
            rendered = json.dumps([args, kwargs], default=str).lower()
            has_cookie = "session_id" in rendered or '"cookie"' in rendered
            status = 200 if "authorization" in rendered and has_cookie else 401
            return httpx.Response(
                status,
                headers={"content-type": "application/json"},
                json={"ok": status == 200},
                request=httpx.Request("GET", "https://app.example.test/api/orders"),
            )

        install_network_tripwire(monkeypatch)
        monkeypatch.setattr(commands.api, "replay", fake_replay)
        code, stdout, stderr = invoke_in_process(
            monkeypatch,
            capsys,
            config_dir,
            "auth-bisect",
            request_id,
            "--max-cost",
            "8",
            "--json",
        )

        assert code == ExitCode.OK, stderr or stdout
        assert 1 <= len(calls) <= 8
        rendered = json.dumps(json.loads(stdout), sort_keys=True).lower()
        assert "authorization" in rendered
        assert "session_id" in rendered or '"cookie"' in rendered
        assert_no_secrets(stdout, stderr)

        evidence = json.loads(stdout)
        code, stdout, stderr = invoke_in_process(
            monkeypatch,
            capsys,
            config_dir,
            "scaffold",
            "bisectedcli",
            "--request",
            request_id,
            "--accept-auth-bisect",
            "--dest",
            str(tmp_path),
            "--max-cost",
            "1",
            "--json",
        )
        assert code == ExitCode.OK, stderr or stdout
        scaffolded = json.loads(stdout)
        assert scaffolded["auth_names"] == evidence["required"]
        assert scaffolded["omitted_auth_names"] == evidence["unnecessary"]

        calls.clear()
        code, stdout, stderr = invoke_in_process(
            monkeypatch,
            capsys,
            config_dir,
            "auth-bisect",
            request_id,
            "--max-cost",
            "1",
            "--json",
        )
        assert code == ExitCode.REFUSED, stderr or stdout
        assert len(calls) <= 1
        assert json.loads(stdout)["exit_code"] == ExitCode.REFUSED


class TestScaffold:
    def test_cli_handoff_creates_one_packaged_redacted_get(self, tmp_path: Path):
        config_dir = tmp_path / "state"
        import_fixture(config_dir)
        result = run_cli(
            config_dir,
            "scaffold",
            "orderscli",
            "--request",
            "req-1",
            "--dest",
            str(tmp_path),
            "--max-cost",
            "1",
            "--json",
        )
        assert result.returncode == ExitCode.OK, result.stderr or result.stdout
        payload = parsed_stdout(result)
        project = Path(payload["created"])
        assert (project / "contract" / "endpoint.json").is_file()
        assert (project / "src" / "orderscli" / "endpoint.json").is_file()
        generated = b"\n".join(
            path.read_bytes() for path in project.rglob("*") if path.is_file()
        )
        assert_no_secrets(generated, result.stdout, result.stderr)

    def test_default_scaffold_keeps_candidates_after_auth_bisect(
        self, tmp_path: Path
    ):
        config_dir = tmp_path / "state"
        import_fixture(config_dir)
        candidates = auth_candidates(config_dir, "req-1")
        save_auth_partition(
            config_dir,
            "req-1",
            required=[],
            unnecessary=candidates,
            authoritative=True,
        )

        result = run_cli(
            config_dir,
            "scaffold",
            "safecli",
            "--request",
            "req-1",
            "--dest",
            str(tmp_path),
            "--max-cost",
            "1",
            "--json",
        )
        assert result.returncode == ExitCode.OK, result.stderr or result.stdout
        payload = parsed_stdout(result)
        assert payload["auth_source"] == "captured-candidates"
        assert payload["auth_names"] == candidates
        assert payload["omitted_auth_names"] == []

    def test_accept_auth_bisect_can_scaffold_without_false_credentials(
        self, tmp_path: Path
    ):
        config_dir = tmp_path / "state"
        import_fixture(config_dir)
        candidates = auth_candidates(config_dir, "req-1")
        save_auth_partition(
            config_dir,
            "req-1",
            required=[],
            unnecessary=candidates,
        )

        result = run_cli(
            config_dir,
            "scaffold",
            "publiccli",
            "--request",
            "req-1",
            "--accept-auth-bisect",
            "--dest",
            str(tmp_path),
            "--max-cost",
            "1",
            "--json",
        )
        assert result.returncode == ExitCode.OK, result.stderr or result.stdout
        payload = parsed_stdout(result)
        assert payload["auth_source"] == "accepted-auth-bisect"
        assert payload["auth_names"] == []
        assert payload["omitted_auth_names"] == candidates
        contract = json.loads(
            (Path(payload["created"]) / "contract" / "endpoint.json").read_text()
        )
        assert contract["auth"] == []
        readme = (Path(payload["created"]) / "README.md").read_text()
        assert "No runtime credentials are required" in readme
        assert "Set those variables" not in readme

    def test_accept_auth_bisect_requires_current_complete_evidence(
        self, tmp_path: Path
    ):
        config_dir = tmp_path / "state"
        import_fixture(config_dir)
        missing = run_cli(
            config_dir,
            "scaffold",
            "missingevidence",
            "--request",
            "req-1",
            "--accept-auth-bisect",
            "--dest",
            str(tmp_path),
            "--max-cost",
            "1",
            "--json",
        )
        assert missing.returncode == ExitCode.REFUSED
        assert "auth-bisect" in parsed_stdout(missing)["remedy"]
        assert not (tmp_path / "missingevidence").exists()

        candidates = auth_candidates(config_dir, "req-1")
        save_auth_partition(
            config_dir,
            "req-1",
            required=[],
            unnecessary=candidates[:-1],
        )
        stale = run_cli(
            config_dir,
            "scaffold",
            "staleevidence",
            "--request",
            "req-1",
            "--accept-auth-bisect",
            "--dest",
            str(tmp_path),
            "--max-cost",
            "1",
            "--json",
        )
        assert stale.returncode == ExitCode.REFUSED
        assert "auth-bisect" in parsed_stdout(stale)["remedy"]
        assert not (tmp_path / "staleevidence").exists()


class TestJsonStdout:
    def test_success_is_one_json_document_with_notes_off_stdout(self, tmp_path: Path):
        config_dir = tmp_path / "state"
        import_fixture(config_dir)
        result = run_cli(config_dir, "endpoints", "--json")
        assert result.returncode == ExitCode.OK, result.stderr or result.stdout
        parsed_stdout(result)

    def test_usage_error_is_one_typed_json_document(self, tmp_path: Path):
        result = run_cli(tmp_path / "state", "inspect", "--json")
        assert result.returncode == ExitCode.USAGE
        payload = parsed_stdout(result)
        assert {
            "error",
            "message",
            "exit_code",
            "retryable",
            "remedy",
        } <= payload.keys()
        assert payload["exit_code"] == ExitCode.USAGE

    @pytest.mark.parametrize("value", ["-1", "nan", "inf"])
    def test_non_finite_or_negative_max_cost_is_a_typed_usage_error(
        self, tmp_path: Path, value: str
    ):
        result = run_cli(
            tmp_path / "state",
            "endpoints",
            f"--max-cost={value}",
            "--json",
        )
        assert result.returncode == ExitCode.USAGE
        assert parsed_stdout(result)["exit_code"] == ExitCode.USAGE

    def test_old_max_flag_refuses_and_names_max_cost(self, tmp_path: Path):
        result = run_cli(
            tmp_path / "state",
            "endpoints",
            "--max",
            "1",
            "--json",
        )
        assert result.returncode == ExitCode.USAGE
        assert "--max-cost" in parsed_stdout(result)["remedy"]

    def test_nan_timeout_is_a_typed_usage_error(self, tmp_path: Path):
        result = run_cli(
            tmp_path / "state",
            "replay",
            "req-1",
            "--timeout",
            "nan",
            "--json",
        )
        assert result.returncode == ExitCode.USAGE
        assert parsed_stdout(result)["exit_code"] == ExitCode.USAGE
