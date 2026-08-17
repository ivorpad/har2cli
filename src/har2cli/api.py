"""Small, deliberately GET-only HTTP transport for captured requests.

Captured parameters are rediscovered by importing a fresh HAR. This transport
does not guess that a 401, 403, or 404 means a rotated value and retry with the
same stale capture.
"""

from __future__ import annotations

import json
import re
import hashlib
import ipaddress
import socket
from collections.abc import Mapping, Sequence
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

import httpx

from agentis import RefusedError, TimeoutedError, UpstreamError, trim

ALLOWED_METHOD = "GET"
AUTH_FAILURES = {401, 403}
HOP_BY_HOP = {
    "accept-encoding",
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
SENSITIVE_NAME = re.compile(
    r"(?:auth|cookie|csrf|xsrf|token|secret|password|passwd|api[-_]?key|"
    r"session|signature|jwt)",
    re.IGNORECASE,
)
REDACTED = "<redacted>"
SECRET_SCALAR = re.compile(
    r"^(?:bearer|basic)\s+\S{8,}$|"
    r"^[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$",
    re.IGNORECASE,
)
TEXT_SECRET = re.compile(
    r"(?i)(\b(?:token|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|"
    r"csrf|xsrf|password|passwd|session|secret|signature|jwt)\b"
    r"[\"']?\s*[:=]\s*[\"']?)([^\"',\s<&}]+)|"
    r"\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"\b[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
LOGIN_LOCATION = re.compile(
    r"(?:^|[/._?&=#-])(?:login|log-in|signin|sign-in|auth|authenticate|"
    r"authentication|oauth)(?:$|[/._?&=#-])",
    re.IGNORECASE,
)


def replay(
    prepared: Mapping[str, Any],
    *,
    timeout: float = 30.0,
    allow_private: bool = False,
) -> httpx.Response:
    """Send one prepared request without redirects or implicit retries."""
    method = str(prepared.get("method", "")).upper()
    if method != ALLOWED_METHOD:
        raise RefusedError(
            f"{method or 'unknown'} replay is disabled in v1",
            remedy="select a captured GET request; writes are not implemented",
        )

    url = str(prepared.get("url", ""))
    if urlsplit(url).scheme not in {"http", "https"}:
        raise RefusedError(
            "only HTTP and HTTPS requests can be replayed",
            remedy="inspect the request and select an http(s) endpoint",
        )
    _check_destination(url, allow_private=allow_private)

    headers = _transport_headers(prepared.get("headers", []))
    try:
        return httpx.request(
            method,
            url,
            headers=headers,
            timeout=timeout,
            follow_redirects=False,
        )
    except httpx.TimeoutException as exc:
        raise TimeoutedError("captured GET timed out") from exc
    except httpx.HTTPError as exc:
        # Do not include the original URL: its query string may contain a token.
        raise UpstreamError(f"captured GET failed: {type(exc).__name__}") from exc


def _check_destination(url: str, *, allow_private: bool) -> None:
    if allow_private:
        return
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host:
        raise RefusedError("captured URL has no host")
    addresses: set[str] = set()
    try:
        addresses.add(str(ipaddress.ip_address(host)))
    except ValueError:
        if host.lower() == "localhost" or host.lower().endswith(".localhost"):
            addresses.add("127.0.0.1")
        else:
            try:
                try:
                    port = parts.port or 443
                except ValueError as exc:
                    raise RefusedError("captured URL has an invalid port") from exc
                for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
                    addresses.add(item[4][0])
            except socket.gaierror:
                return  # httpx will return the ordinary typed network error.
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise RefusedError(
                f"captured host resolves to non-public address {ip}",
                remedy="inspect the HAR, then pass --allow-private if this is an intended intranet host",
            )


def _transport_headers(raw: Any) -> list[tuple[str, str]]:
    """Normalize HAR-style headers and drop ones the client must recalculate."""
    pairs: list[tuple[str, str]] = []
    if isinstance(raw, Mapping):
        source = raw.items()
    elif isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
        source = (
            (item.get("name"), item.get("value"))
            for item in raw
            if isinstance(item, Mapping)
        )
    else:
        source = ()
    for name, value in source:
        if (
            not isinstance(name, str)
            or name.startswith(":")
            or name.lower() in HOP_BY_HOP
        ):
            continue
        if value is None:
            continue
        pairs.append((name, str(value)))
    return pairs


def auth_signature(response: httpx.Response) -> tuple[int, str, bool, str]:
    """Coarse response shape used while eliminating credential candidates."""
    content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
    location = response.headers.get("location", "").lower()
    login_redirect = response.is_redirect and bool(LOGIN_LOCATION.search(location))
    shape = _response_shape(response, content_type)
    return response.status_code, content_type, login_redirect, shape


def authentication_failed(response: httpx.Response) -> bool:
    status, content_type, login_redirect, _ = auth_signature(response)
    if status in AUTH_FAILURES or login_redirect:
        return True
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
            if any(text in message for text in ("unauthorized", "not authenticated", "login required")):
                return True
    if "html" in content_type:
        body = response.text[:20_000].lower()
        if "type=\"password\"" in body or "name=\"password\"" in body:
            return True
    return False


def response_record(
    response: httpx.Response,
    *,
    request_url: str,
    secret_values: Iterable[str] = (),
) -> dict[str, Any]:
    """Turn a live response into output that cannot echo auth headers."""
    content_type = response.headers.get("content-type", "")
    exact_secrets = tuple(value for value in secret_values if value)
    payload: Any
    if "html" in content_type.lower():
        payload = "<html body omitted>"
    elif "json" in content_type.lower():
        try:
            payload = _redact_json(response.json(), exact_secrets=exact_secrets)
        except (json.JSONDecodeError, ValueError):
            payload = _redact_text(response.text, exact_secrets)
        except RecursionError:
            payload = "<response body too deeply nested>"
    else:
        payload = _redact_text(response.text, exact_secrets)

    headers = {}
    for name, value in response.headers.items():
        if name.lower() == "location" or SENSITIVE_NAME.search(name):
            headers[name] = REDACTED
        else:
            headers[name] = _redact_text(value, exact_secrets)
    return {
        "status": response.status_code,
        "reason": response.reason_phrase,
        "url": request_url,
        "content_type": content_type,
        "headers": headers,
        "body": payload,
    }


def compact_response(record: Mapping[str, Any]) -> dict[str, Any]:
    """Keep replay output useful without letting one body consume the context."""
    body = record.get("body")
    if isinstance(body, str):
        body = trim(body, 4_000)
    elif body is not None:
        encoded = json.dumps(body, ensure_ascii=False, default=str)
        if len(encoded) > 16_000:
            body = {"json": trim(encoded, 16_000)}
    return {
        "status": record.get("status"),
        "reason": record.get("reason"),
        "url": record.get("url"),
        "content_type": record.get("content_type"),
        "body": body,
    }


def _redact_json(value: Any, *, exact_secrets: tuple[str, ...] = ()) -> Any:
    if isinstance(value, Mapping):
        safe: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            safe_name = (
                REDACTED
                if name in exact_secrets or SECRET_SCALAR.match(name)
                else _redact_text(name, exact_secrets)
            )
            safe[safe_name] = (
                REDACTED
                if SENSITIVE_NAME.search(name)
                else _redact_json(item, exact_secrets=exact_secrets)
            )
        return safe
    if isinstance(value, list):
        return [_redact_json(item, exact_secrets=exact_secrets) for item in value]
    if isinstance(value, str):
        if value in exact_secrets or SECRET_SCALAR.match(value):
            return REDACTED
        return _redact_text(value, exact_secrets)
    return value


def _redact_text(value: str, exact_secrets: tuple[str, ...]) -> str:
    safe = value
    for secret in sorted(exact_secrets, key=len, reverse=True):
        safe = safe.replace(secret, REDACTED)

    def replace(match: re.Match[str]) -> str:
        prefix = match.group(1)
        return f"{prefix}{REDACTED}" if prefix else REDACTED

    return TEXT_SECRET.sub(replace, safe)


def _response_shape(response: httpx.Response, content_type: str) -> str:
    """Hash keys and container types, not values that naturally rotate."""
    if "json" in content_type:
        try:
            shape = _json_shape(response.json())
            encoded = json.dumps(shape, sort_keys=True, separators=(",", ":"))
            return hashlib.sha256(encoded.encode()).hexdigest()[:16]
        except (ValueError, RecursionError):
            pass
    text = re.sub(r"\s+", " ", response.text[:4_000]).strip().lower()
    text = re.sub(r"\d+", "#", text)
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _json_shape(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_shape(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return [(_json_shape(value[0]) if value else "empty-list")]
    if value is None:
        return "null"
    return type(value).__name__
