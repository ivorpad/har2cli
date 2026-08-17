"""Turn one inspected GET request into a small Agentis CLI project.

The public entry point is :func:`scaffold_project`.  Agentis owns creation and
the refusal to overwrite an existing target.  This module only replaces the
generic files after ``agentis new`` succeeds.
"""

from __future__ import annotations

import json
import keyword
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from agentis import UpstreamError, UsageError, write_atomic

REDACTED = "<redacted>"

_AUTH_LOCATIONS = {"header", "cookie", "query"}
_BROWSER_HEADERS = {
    "accept-encoding",
    "connection",
    "content-length",
    "cookie",
    "host",
    "origin",
    "referer",
    "user-agent",
}
_SECRET_WORDS = {
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "csrf",
    "jwt",
    "key",
    "passwd",
    "password",
    "secret",
    "session",
    "sessionid",
    "token",
    "xsrf",
}
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")


def scaffold_project(
    project_name: str,
    dest_parent: str | Path,
    request: Mapping[str, Any],
    response_fixture: Any,
    auth_names: Iterable[str],
) -> Path:
    """Create an Agentis project for one captured GET endpoint.

    ``dest_parent`` is the directory in which Agentis creates
    ``project_name``. ``request`` may be a flat request mapping or a stored
    record with the request under a ``request`` key. HAR-style name/value
    lists and ordinary mappings are both accepted for headers, cookies and
    query parameters.

    Credential names can be bare (their location is inferred from the
    request) or explicit, for example ``cookie:session_id`` and
    ``header:Authorization``. Values are never accepted separately and are
    never written to the generated project. ``response_fixture`` must already
    be sanitized; secret-shaped keys and values are scrubbed again here.
    """
    _validate_project_name(project_name)
    if not isinstance(request, Mapping):
        raise UsageError("the selected request is not an object")

    names = tuple(str(name).strip() for name in auth_names)
    contract = _build_contract(request, names, project_name)
    try:
        fixture = _fixture_shape(
            _redact_json(response_fixture, _auth_spec_keys(contract["auth"]))
        )
    except RecursionError as exc:
        raise UsageError(
            "the response fixture is too deeply nested",
            remedy="select a smaller JSON response fixture",
        ) from exc
    try:
        fixture_json = json.dumps(
            fixture, ensure_ascii=False, indent=2, sort_keys=True
        ) + "\n"
    except (TypeError, ValueError) as exc:
        raise UsageError(
            "the response fixture is not JSON serializable",
            remedy="select a response body that har2cli imported as JSON",
        ) from exc

    dest = Path(dest_parent).expanduser().resolve()
    target = (dest / project_name).resolve()
    if target.exists():
        raise UsageError(
            f"{target} already exists",
            remedy="pick another name or --dest; har2cli never overwrites a project",
        )
    dest.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".har2cli-scaffold-", dir=dest))
    staged_target = staging / project_name
    try:
        result = _run_agentis(project_name, staging)
        if result.returncode:
            message, remedy = _agentis_failure(result)
            error = UsageError if result.returncode == 2 else UpstreamError
            raise error(message, remedy=remedy)

        source = staged_target / "src" / project_name
        if not source.is_dir():
            raise UpstreamError(
                f"Agentis reported success but did not create {source}",
                remedy="check the Agentis checkout and run its scaffold tests",
            )

        rendered = _rendered_files(project_name, contract, fixture_json)
        pyproject = (staged_target / "pyproject.toml").read_text()
        rendered[Path("pyproject.toml")] = pyproject + (
            "\n[tool.hatch.build.targets.wheel.force-include]\n"
            f'"src/{project_name}/endpoint.json" = '
            f'"{project_name}/endpoint.json"\n'
        )
        for relative, body in rendered.items():
            path = staged_target / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            write_atomic(path, body, mode=0o644)
        try:
            os.rename(staged_target, target)
        except OSError as exc:
            raise UsageError(
                f"could not reserve scaffold target {target}: {exc.strerror}",
                remedy="pick another name or destination",
            ) from exc
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return target


def _validate_project_name(name: str) -> None:
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", name):
        raise UsageError(
            f"{name!r} is not a safe project name",
            remedy="use at most 32 lowercase letters, digits, or underscores",
        )
    collisions = {"agentis", "httpx", "pytest", "typer"}
    if keyword.iskeyword(name) or name in sys.stdlib_module_names or name in collisions:
        raise UsageError(
            f"{name!r} collides with Python or a generated dependency",
            remedy="choose a distinct package name",
        )


def _run_agentis(project_name: str, dest: Path) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        "-m",
        "agentis",
        "new",
        project_name,
        "--description",
        "Call one GET endpoint derived from a redacted browser request.",
        "--triggers",
        f"{project_name}, call the captured endpoint",
        "--dest",
        str(dest),
        "--json",
    ]
    try:
        return subprocess.run(command, capture_output=True, text=True)
    except OSError as exc:
        raise UpstreamError(
            f"could not start Agentis: {exc}",
            remedy="install the Agentis dependency in this Python environment",
        ) from exc


def _agentis_failure(
    result: subprocess.CompletedProcess[str],
) -> tuple[str, str]:
    try:
        envelope = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        envelope = None
    if isinstance(envelope, Mapping):
        message = str(envelope.get("message") or "Agentis refused the scaffold")
        remedy = str(envelope.get("remedy") or "read `agentis new --help`")
        return message, remedy
    return (
        "Agentis failed while creating the project",
        "run `python -m agentis new --help` and check the Agentis installation",
    )


def _build_contract(
    record: Mapping[str, Any], auth_names: Sequence[str], project_name: str
) -> dict[str, Any]:
    nested = record.get("request")
    request = nested if isinstance(nested, Mapping) else record
    method = str(request.get("method", "")).upper()
    if method != "GET":
        raise UsageError(
            f"only sanitized GET requests can be scaffolded, got {method or 'no method'}",
            remedy="select a GET request; POST and DELETE are outside this version",
        )

    raw_url = request.get("url")
    if not isinstance(raw_url, str) or not raw_url:
        raise UsageError("the selected GET request has no URL")
    parts = urlsplit(raw_url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise UsageError("the selected request URL must be absolute HTTP(S)")
    if parts.username is not None or parts.password is not None:
        raise UsageError(
            "the selected request URL contains user information",
            remedy="redact URL credentials before scaffolding",
        )

    header_pairs = _pairs(request.get("headers"))
    cookie_pairs = _pairs(request.get("cookies"))
    raw_query = request.get("queryString")
    if raw_query is None:
        raw_query = request.get("query")
    query_pairs = (
        _pairs(raw_query)
        if raw_query is not None
        else [(name, value) for name, value in parse_qsl(parts.query, keep_blank_values=True)]
    )

    auth = _auth_specs(
        auth_names,
        project_name,
        record,
        header_pairs,
        cookie_pairs,
        query_pairs,
    )
    auth_keys = _auth_spec_keys(auth)
    safe_headers = []
    for name, value in header_pairs:
        lowered = name.casefold()
        if (
            name.startswith(":")
            or lowered in _BROWSER_HEADERS
            or lowered.startswith("sec-")
        ):
            continue
        safe_headers.append(
            {
                "name": name,
                "value": _safe_wire_value(name, value, auth_keys),
            }
        )
    safe_query = [
        {"name": name, "value": _safe_wire_value(name, value, auth_keys)}
        for name, value in query_pairs
    ]

    request_id = record.get("id", request.get("id", "selected"))
    if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", request_id):
        request_id = "selected"

    return {
        "schema_version": 1,
        "request_id": request_id,
        "method": "GET",
        "origin": f"{parts.scheme}://{parts.netloc}",
        "path": parts.path or "/",
        "headers": safe_headers,
        "query": safe_query,
        "auth": auth,
    }


def _auth_specs(
    auth_names: Sequence[str],
    project_name: str,
    record: Mapping[str, Any],
    headers: Sequence[tuple[str, Any]],
    cookies: Sequence[tuple[str, Any]],
    query: Sequence[tuple[str, Any]],
) -> list[dict[str, str]]:
    explicit_locations = record.get("auth_locations")
    location_map = (
        {str(k).casefold(): str(v).casefold() for k, v in explicit_locations.items()}
        if isinstance(explicit_locations, Mapping)
        else {}
    )
    header_names = {name.casefold() for name, _ in headers}
    cookie_names = {name.casefold() for name, _ in cookies}
    query_names = {name.casefold() for name, _ in query}
    specs: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for raw in auth_names:
        if not raw:
            raise UsageError("auth names cannot be empty")
        location, name = _split_auth_name(raw)
        lowered = name.casefold()
        if location is None:
            candidate = location_map.get(lowered)
            if candidate in _AUTH_LOCATIONS:
                location = candidate
            elif lowered in header_names:
                location = "header"
            elif lowered in cookie_names:
                location = "cookie"
            elif lowered in query_names:
                location = "query"
            elif any(word in lowered for word in ("cookie", "session", "sid")):
                location = "cookie"
            else:
                location = "header"
        if location == "header" and name.startswith(":"):
            continue
        key = (location, lowered)
        if key in seen:
            continue
        seen.add(key)
        specs.append(
            {
                "name": name,
                "location": location,
                "env": _env_name(project_name, location, name),
            }
        )
    return specs


def _auth_spec_keys(specs: Sequence[Mapping[str, Any]]) -> set[str]:
    return {_normal_key(str(item.get("name", ""))) for item in specs}


def _split_auth_name(raw: str) -> tuple[str | None, str]:
    prefix, separator, rest = raw.partition(":")
    if separator and prefix.casefold() in _AUTH_LOCATIONS:
        name = rest.strip()
        if not name:
            raise UsageError(f"auth name {raw!r} has no name after its location")
        return prefix.casefold(), name
    return None, raw


def _env_name(project_name: str, location: str, credential_name: str) -> str:
    prefix = re.sub(r"[^A-Za-z0-9]+", "_", project_name).strip("_").upper()
    suffix = re.sub(r"[^A-Za-z0-9]+", "_", credential_name).strip("_").upper()
    if not suffix:
        raise UsageError(f"auth name {credential_name!r} cannot form an environment name")
    return f"{prefix}_{location.upper()}_{suffix}"


def _pairs(value: Any) -> list[tuple[str, Any]]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        return [(str(name), item) for name, item in value.items()]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        pairs: list[tuple[str, Any]] = []
        for item in value:
            if isinstance(item, Mapping) and "name" in item:
                pairs.append((str(item["name"]), item.get("value", "")))
            elif (
                isinstance(item, Sequence)
                and not isinstance(item, (str, bytes, bytearray))
                and len(item) == 2
            ):
                pairs.append((str(item[0]), item[1]))
            else:
                raise UsageError("request fields must be mappings or name/value pairs")
        return pairs
    raise UsageError("request fields must be mappings or name/value pairs")


def _safe_wire_value(name: str, value: Any, auth_keys: set[str]) -> str:
    if _is_sensitive_name(name, auth_keys):
        return REDACTED
    safe = _redact_json(value, auth_keys, key=name)
    if safe == REDACTED:
        return REDACTED
    if isinstance(safe, str):
        return safe
    if safe is None:
        return ""
    return json.dumps(safe, ensure_ascii=False, separators=(",", ":"))


def _normal_key(name: str) -> str:
    expanded = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(name))
    return re.sub(r"[^a-z0-9]+", "", expanded.casefold())


def _is_sensitive_name(name: str, auth_keys: set[str]) -> bool:
    expanded = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(name))
    words = {part for part in re.split(r"[^a-z0-9]+", expanded.casefold()) if part}
    normalized = _normal_key(name)
    return (
        normalized in auth_keys
        or normalized in _SECRET_WORDS
        or bool(words & _SECRET_WORDS)
    )


def _looks_like_secret(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.casefold()
    return (
        (lowered.startswith("bearer ") and len(stripped) > 12)
        or (lowered.startswith("basic ") and len(stripped) > 12)
        or bool(_JWT_RE.fullmatch(stripped))
        or "secret" in lowered
        or "access_token" in lowered
        or "refresh_token" in lowered
        or bool(
            len(stripped) >= 24
            and " " not in stripped
            and re.fullmatch(r"[A-Za-z0-9._~+/=-]+", stripped)
        )
    )


def _looks_like_secret_key(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.casefold()
    return (
        (lowered.startswith("bearer ") and len(stripped) > 12)
        or (lowered.startswith("basic ") and len(stripped) > 12)
        or bool(_JWT_RE.fullmatch(stripped))
        or bool(
            len(stripped) >= 24
            and " " not in stripped
            and re.fullmatch(r"[A-Za-z0-9._~+/=-]+", stripped)
        )
    )


def _redact_json(value: Any, auth_keys: set[str], *, key: str = "") -> Any:
    if key and _is_sensitive_name(key, auth_keys):
        return REDACTED
    if isinstance(value, Mapping):
        safe: dict[str, Any] = {}
        for item_key, item in value.items():
            raw_key = str(item_key)
            safe_key = REDACTED if _looks_like_secret_key(raw_key) else raw_key
            safe[safe_key] = _redact_json(item, auth_keys, key=raw_key)
        return safe
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_redact_json(item, auth_keys) for item in value]
    if isinstance(value, str) and _looks_like_secret(value):
        return REDACTED
    return value


def _fixture_shape(value: Any) -> Any:
    """Keep response structure without committing captured user data."""
    if value == REDACTED:
        return REDACTED
    if isinstance(value, Mapping):
        return {str(key): _fixture_shape(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_fixture_shape(value[0])] if value else []
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return 0
    if isinstance(value, float):
        return 0.0
    if value is None:
        return None
    return "<string>"


def _rendered_files(
    project_name: str, contract: Mapping[str, Any], fixture_json: str
) -> dict[Path, str]:
    contract_json = json.dumps(
        contract, ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n"
    credential_lines = "\n".join(
        f"- `{item['env']}` for {item['location']} name "
        f"{_markdown_string(item['name'])}"
        for item in contract["auth"]
    )
    credentials = (
        credential_lines
        + "\n\nSet those variables from a fresh browser session. Do not put their "
        "values in\nshell arguments, source, fixtures, issue text, or an agent "
        "transcript."
        if credential_lines
        else "No runtime credentials are required by this endpoint contract."
    )
    replacements = {
        "__PROJECT__": project_name,
        "__CREDENTIALS__": credentials,
    }

    files = {
        Path("contract/endpoint.json"): contract_json,
        Path(f"src/{project_name}/endpoint.json"): contract_json,
        Path("tests/fixtures/response.json"): fixture_json,
        Path(f"src/{project_name}/credentials.py"): _CREDENTIALS_PY,
        Path(f"src/{project_name}/transport.py"): _TRANSPORT_PY,
        Path(f"src/{project_name}/api.py"): _API_PY,
        Path(f"src/{project_name}/commands.py"): _COMMANDS_PY,
        Path(f"src/{project_name}/cli.py"): _CLI_PY,
        Path("tests/test_contract.py"): _TEST_CONTRACT_PY,
        Path("README.md"): _README_MD,
        Path("skill/SKILL.md"): _SKILL_MD,
    }
    for token, replacement in replacements.items():
        files = {path: body.replace(token, replacement) for path, body in files.items()}
    return files


def _markdown_string(value: str) -> str:
    return (
        json.dumps(value, ensure_ascii=False)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("`", "\\u0060")
    )


_CREDENTIALS_PY = '''\
"""Credential hook for the captured endpoint.

Values come from the environment at call time. They are not part of the
contract, fixtures, command line, or generated source.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence

from agentis import AuthError


def load_credentials(
    auth: Sequence[Mapping[str, str]],
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Load each named credential without printing or persisting its value."""
    source = os.environ if environ is None else environ
    values: dict[str, str] = {}
    missing: list[str] = []
    for item in auth:
        env_name = item["env"]
        value = source.get(env_name)
        if value:
            values[f"{item['location']}:{item['name']}"] = value
        else:
            missing.append(env_name)
    if missing:
        names = ", ".join(missing)
        raise AuthError(
            f"missing credential environment variable(s): {names}",
            remedy=f"set {names} from a fresh browser session and retry",
        )
    return values


def refresh_credentials() -> None:
    """Hook for service-specific refresh or browser import.

    Keep secret extraction inside this CLI. Implement this only when the
    service's credential lifecycle is known.
    """
    return None
'''


_TRANSPORT_PY = '''\
"""HTTP transport for the one captured endpoint."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx
from agentis import AuthError, NotFoundError, TimeoutedError, UpstreamError

from .credentials import load_credentials, refresh_credentials

CONTRACT_PATH = Path(__file__).with_name("endpoint.json")
REDACTED = "<redacted>"
LOGIN_LOCATION = re.compile(
    r"(?:^|[/._?&=#-])(?:login|log-in|signin|sign-in|auth|authenticate|"
    r"authentication|oauth)(?:$|[/._?&=#-])",
    re.IGNORECASE,
)


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    return json.loads(path.read_text())


def rediscover(endpoint: Mapping[str, Any]) -> Mapping[str, Any]:
    """Rotation hook for captured paths, keys, ids, or filter values.

    The generated contract is last-known-good. Replace this no-op after the
    service's stale signal and rediscovery source have been established.
    """
    return endpoint


def fetch(*, client: Any = httpx) -> Any:
    refresh_credentials()
    endpoint = rediscover(load_contract())
    credentials = load_credentials(endpoint.get("auth", []))
    return request_endpoint(endpoint, credentials, client=client)


def request_endpoint(
    endpoint: Mapping[str, Any],
    credentials: Mapping[str, str],
    *,
    client: Any = httpx,
) -> Any:
    headers = {
        item["name"]: item["value"]
        for item in endpoint.get("headers", [])
        if item.get("value") != REDACTED
        and not str(item.get("name", "")).startswith(":")
    }
    params = [
        (item["name"], item["value"])
        for item in endpoint.get("query", [])
        if item.get("value") != REDACTED
    ]
    cookies: dict[str, str] = {}
    for item in endpoint.get("auth", []):
        name = item["name"]
        location = item["location"]
        if location == "header" and name.startswith(":"):
            continue
        value = credentials[f"{location}:{name}"]
        if location == "header":
            headers[name] = value
        elif location == "cookie":
            cookies[name] = value
        elif location == "query":
            params.append((name, value))

    url = f"{endpoint['origin']}{endpoint['path']}"
    try:
        response = client.get(
            url,
            headers=headers,
            params=params,
            cookies=cookies,
            timeout=30.0,
            follow_redirects=False,
        )
    except httpx.TimeoutException as exc:
        raise TimeoutedError(f"GET {endpoint['path']} timed out") from exc
    except httpx.HTTPError as exc:
        # Exception text can contain the full URL, including secret query
        # values. The type is enough to diagnose the transport class.
        raise UpstreamError(
            f"GET {endpoint['path']} failed: {type(exc).__name__}"
        ) from exc

    if _authentication_failed(response):
        raise AuthError(
            "captured credentials were rejected",
            remedy="set fresh values from a working browser session and retry",
        )
    if response.status_code == 404:
        raise NotFoundError(f"captured endpoint no longer exists: {endpoint['path']}")
    if response.status_code >= 400:
        raise UpstreamError(f"upstream returned {response.status_code}")
    try:
        return response.json()
    except ValueError:
        return {"status": response.status_code, "text": response.text}


def _authentication_failed(response: Any) -> bool:
    status = int(response.status_code)
    headers = getattr(response, "headers", {})
    location = str(headers.get("location", "")).lower()
    is_redirect = bool(getattr(response, "is_redirect", 300 <= status < 400))
    if status in (401, 403) or (
        is_redirect
        and LOGIN_LOCATION.search(location)
    ):
        return True

    content_type = str(headers.get("content-type", "")).lower()
    if "json" in content_type:
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if isinstance(payload, Mapping):
            for key in ("authenticated", "isAuthenticated", "loggedIn"):
                if payload.get(key) is False:
                    return True
            message = " ".join(
                str(payload.get(key, ""))
                for key in ("error", "message", "detail")
            ).lower()
            if any(
                text in message
                for text in ("unauthorized", "not authenticated", "login required")
            ):
                return True
    if "html" in content_type:
        body = str(getattr(response, "text", ""))[:20_000].lower()
        if 'type="password"' in body or 'name="password"' in body:
            return True
    return False
'''


_API_PY = '''\
"""Compatibility seam for callers that want the generated HTTP operation."""

from .transport import fetch, load_contract, request_endpoint

__all__ = ["fetch", "load_contract", "request_endpoint"]
'''


_COMMANDS_PY = '''\
"""Implementation of the generated CLI's single command."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from agentis import trim

from . import transport

REDACTED = "<redacted>"
SENSITIVE_NAME = re.compile(
    r"(?:auth|cookie|csrf|xsrf|token|secret|password|passwd|api[-_]?key|"
    r"session|signature|jwt)",
    re.IGNORECASE,
)
SENSITIVE_TEXT = re.compile(
    r"(?i)(\\b(?:token|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"api[_-]?key|csrf|xsrf|password|passwd|session|secret|signature|jwt)\\b"
    r"[\\\"']?\\s*[:=]\\s*[\\\"']?)([^\\\"',\\s<&}]+)|"
    r"\\b(?:bearer|basic)\\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"\\b[A-Za-z0-9_-]{12,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b"
)


def sanitize(
    value: Any,
    *,
    key: str = "",
    exact_secrets: tuple[str, ...] = (),
) -> Any:
    """Remove credential-shaped response fields before compact and --raw."""
    if key and SENSITIVE_NAME.search(key):
        return REDACTED
    if isinstance(value, Mapping):
        safe: dict[str, Any] = {}
        for name, item in value.items():
            raw_name = str(name)
            safe_name = sanitize(raw_name, exact_secrets=exact_secrets)
            safe[str(safe_name)] = sanitize(
                item,
                key=raw_name,
                exact_secrets=exact_secrets,
            )
        return safe
    if isinstance(value, list):
        return [sanitize(item, exact_secrets=exact_secrets) for item in value]
    if isinstance(value, str):
        safe = value
        if "<html" in safe.lower() or "<form" in safe.lower() or "<input" in safe.lower():
            return "<html body omitted>"
        for secret in sorted(exact_secrets, key=len, reverse=True):
            if secret:
                safe = safe.replace(secret, REDACTED)

        def replace(match: re.Match[str]) -> str:
            prefix = match.group(1)
            return f"{prefix}{REDACTED}" if prefix else REDACTED

        if "secret" in safe.lower() or (
            len(safe) >= 24
            and " " not in safe
            and re.fullmatch(r"[A-Za-z0-9._~+/=-]+", safe)
        ):
            return REDACTED
        return SENSITIVE_TEXT.sub(replace, safe)
    return value


def compact(record: Any) -> Any:
    """Keep ordinary JSON intact and mark unusually large responses as cut."""
    encoded = json.dumps(record, ensure_ascii=False, default=str)
    if len(encoded) <= 16_000:
        return record
    return {"response_json": trim(encoded, 16_000)}


def get(session) -> None:
    endpoint = transport.load_contract()
    session.guard.check(1, f"GET {endpoint['path']}")
    transport.refresh_credentials()
    endpoint = transport.rediscover(endpoint)
    credentials = transport.load_credentials(endpoint.get("auth", []))
    result = transport.request_endpoint(endpoint, credentials)
    session.out.emit(
        sanitize(result, exact_secrets=tuple(credentials.values())),
        compact=compact,
    )
'''


_CLI_PY = '''\
"""Command surface for the generated one-endpoint CLI."""

from __future__ import annotations

import typer

import agentis
from agentis import Session

from . import commands

AGENT_NOTES = """\\
examples:

  __PROJECT__ get --max-cost 1   call the captured GET endpoint once
  __PROJECT__ get --json         compact JSON, with errors as JSON too
  __PROJECT__ get --json --raw   the full upstream JSON response

credentials:

  Read README.md for the environment variable names. Never put their values
  in flags, source, fixtures, output, or an agent transcript.

if you are an agent:

  * Treat contract/endpoint.json as last-known-good captured evidence.
  * A value marked "[... truncated" is cut. Never invent its missing text.
  * On auth failure, refresh credentials rather than retrying stale values.
  * Before adapting this CLI, run the dumb-agent test described in
    README.md.
"""

app = agentis.build(
    "__PROJECT__",
    help="Call one GET endpoint from a redacted browser request.",
    notes=AGENT_NOTES,
    unit="requests",
)


@app.command()
@agentis.costly
def get(ctx: typer.Context) -> None:
    """Call the captured GET endpoint once."""
    commands.get(Session.get(ctx))


main = agentis.main_for(app)
'''


_TEST_CONTRACT_PY = '''\
"""Contract tests generated from the selected request."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from agentis import AuthError, is_marked

from __PROJECT__ import cli, commands, transport
from __PROJECT__.commands import REDACTED, compact, sanitize

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contract" / "endpoint.json"
FIXTURE = ROOT / "tests" / "fixtures" / "response.json"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "__PROJECT__", *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def test_only_one_command_is_registered():
    source = (ROOT / "src" / "__PROJECT__" / "cli.py").read_text()
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
    packaged = json.loads((ROOT / "src" / "__PROJECT__" / "endpoint.json").read_text())
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
'''


_README_MD = '''\
# __PROJECT__

This CLI calls one GET endpoint selected from a browser HAR. Its checked-in
contract is redacted and its response fixture keeps structure, not captured
user values. Credential values are loaded only at runtime.

## Install

```bash
uv sync
uv tool install --editable .
__PROJECT__ --help
```

From the parent directory instead:

```bash
uv run --project ./__PROJECT__ __PROJECT__ --help
```

## Credentials

__CREDENTIALS__

## Recipes

```bash
__PROJECT__ get --max-cost 1
__PROJECT__ get --max-cost 1 --json
__PROJECT__ get --max-cost 1 --json --raw
```

The checked-in request contract is `contract/endpoint.json`. Update the
transport and credential hooks in `src/__PROJECT__/transport.py` and
`src/__PROJECT__/credentials.py` when the upstream service rotates.

## Before shipping

```bash
uv run pytest -q
uv run agentis check .
```

Run the dumb-agent test too: give a weak agent the command and a vague task,
record every command it runs, then verify its answer against the real endpoint.
Do not accept the agent's own claim that nothing confused it.
'''


_SKILL_MD = '''\
---
name: __PROJECT__
description: Call the single browser-derived GET endpoint packaged by __PROJECT__.
---

# __PROJECT__

Run the CLI. Its help owns the operating rules:

```bash
__PROJECT__ --help
__PROJECT__ get --max-cost 1
```

Do not replace a failed call with web search. Report the typed error and its
remedy. Credential values belong in the documented environment variables,
never in a command argument or transcript.
'''
