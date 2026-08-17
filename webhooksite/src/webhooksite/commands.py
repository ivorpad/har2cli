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
    r"(?i)(\b(?:token|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"api[_-]?key|csrf|xsrf|password|passwd|session|secret|signature|jwt)\b"
    r"[\"']?\s*[:=]\s*[\"']?)([^\"',\s<&}]+)|"
    r"\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"\b[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
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
