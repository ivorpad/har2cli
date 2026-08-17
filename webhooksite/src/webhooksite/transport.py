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
