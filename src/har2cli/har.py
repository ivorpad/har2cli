"""Pure HAR parsing, redaction, classification, and request reconstruction."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from agentis import NotFoundError, UsageError, trim

REDACTED = "<redacted>"
REDACTED_BODY = "<redacted body>"

_SECRET_WORDS = {
    "apikey",
    "authorization",
    "assertion",
    "cid",
    "code",
    "cookie",
    "credential",
    "csrf",
    "jwt",
    "key",
    "passwd",
    "password",
    "referer",
    "samlresponse",
    "secret",
    "session",
    "sessionid",
    "signature",
    "sig",
    "token",
    "ticket",
    "xsrf",
}
_ANALYTICS_HOSTS = (
    "amplitude.com",
    "doubleclick.net",
    "google-analytics.com",
    "googletagmanager.com",
    "hotjar.com",
    "mixpanel.com",
    "newrelic.com",
    "segment.io",
    "sentry.io",
)
_ASSET_EXTENSIONS = {
    ".avif",
    ".css",
    ".eot",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".map",
    ".mp3",
    ".mp4",
    ".png",
    ".svg",
    ".ttf",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
}
_ASSET_TYPES = {"font", "image", "media", "script", "stylesheet"}
_SECRET_VALUE = re.compile(
    r"^(?:bearer|basic)\s+\S{8,}$|"
    r"^[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$",
    re.IGNORECASE,
)
_TEXT_SECRET = re.compile(
    r"(?i)(\b(?:token|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"api[_-]?key|csrf|xsrf|password|passwd|session|secret|signature|jwt)\b"
    r"[\"']?\s*[:=]\s*[\"']?)([^\"',\s<&}]+)|"
    r"\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"\b[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
_PATH_ID = re.compile(
    r"(?<=/)(?:\d{2,}|[0-9a-f]{8}-[0-9a-f-]{20,})(?=/|$)",
    re.IGNORECASE,
)
_PATH_SECRET_LABELS = {"invite", "jwt", "magic", "reset", "secret", "signature", "token"}


def parse_har(
    payload: Any,
    *,
    capture_id: str,
    source_name: str,
) -> tuple[dict[str, Any], dict[str, dict[str, str]]]:
    """Convert a HAR object into a sanitized capture and replay sidecar."""
    if not isinstance(payload, Mapping):
        raise UsageError("HAR root must be a JSON object")
    log = payload.get("log")
    if not isinstance(log, Mapping) or not isinstance(log.get("entries"), list):
        raise UsageError(
            "file does not contain HAR log.entries",
            remedy="export the browser network log as HAR and import that file",
        )

    records: list[dict[str, Any]] = []
    sidecar: dict[str, dict[str, str]] = {}
    for index, entry in enumerate(log["entries"], start=1):
        if not isinstance(entry, Mapping):
            continue
        request_id = f"req-{index}"
        record, secrets = _entry(entry, request_id)
        records.append(record)
        if secrets:
            sidecar[request_id] = secrets

    if not records:
        raise UsageError("HAR contains no usable request entries")

    capture = {
        "schema_version": 1,
        "capture_id": capture_id,
        "source_name": source_name,
        "imported_at": datetime.now(UTC).isoformat(),
        "request_count": len(records),
        "application_count": sum(not item["excluded"] for item in records),
        "requests": records,
    }
    return capture, sidecar


def _entry(
    entry: Mapping[str, Any], request_id: str
) -> tuple[dict[str, Any], dict[str, str]]:
    raw_request = entry.get("request")
    raw_response = entry.get("response")
    request = raw_request if isinstance(raw_request, Mapping) else {}
    response = raw_response if isinstance(raw_response, Mapping) else {}
    method = str(request.get("method", "")).upper()
    raw_url = str(request.get("url", ""))
    classification = classify(entry, method=method, url=raw_url, response=response)
    force_query_redaction = classification == "analytics"
    secrets: dict[str, str] = {}

    raw_query = request.get("queryString")
    query_source = (
        _pairs(raw_query)
        if isinstance(raw_query, Sequence) and not isinstance(raw_query, (str, bytes))
        else _query_from_url(raw_url)
    )
    query = _sanitize_pairs(
        query_source,
        location="query",
        secrets=secrets,
        force=force_query_redaction,
    )
    cookies = _sanitize_pairs(
        _pairs(request.get("cookies")),
        location="cookie",
        secrets=secrets,
        force=True,
    )
    existing_cookie_names = {str(item["name"]).lower() for item in cookies}
    cookies.extend(
        _cookies_from_headers(
            request.get("headers"),
            secrets,
            skip=existing_cookie_names,
        )
    )
    headers = _sanitize_headers(request.get("headers"), secrets)
    _sanitize_echoes(query, "query", secrets)
    _sanitize_echoes(cookies, "cookie", secrets)
    _sanitize_echoes(headers, "header", secrets)
    safe_url = _safe_url(raw_url, query)
    if classification == "application" and _path_was_redacted(raw_url, safe_url):
        classification = "secret-path"

    safe_request: dict[str, Any] = {
        "method": method,
        "url": safe_url,
        "http_version": request.get("httpVersion", ""),
        "headers": headers,
        "query": query,
        "cookies": cookies,
    }
    post_data = request.get("postData")
    if isinstance(post_data, Mapping):
        safe_request["body"] = {
            "mime_type": str(post_data.get("mimeType", "")),
            "text": REDACTED_BODY if post_data.get("text") else "",
        }

    parts = urlsplit(safe_url)
    record = {
        "id": request_id,
        "started_at": entry.get("startedDateTime"),
        "duration_ms": entry.get("time"),
        "classification": classification,
        "excluded": classification != "application",
        "endpoint_key": endpoint_key(method, parts.hostname or "", parts.path),
        "auth_names": _candidate_names(query, cookies, headers),
        "request": safe_request,
        "response": _sanitize_response(response, exact_secrets=tuple(secrets.values())),
    }
    return record, secrets


def classify(
    entry: Mapping[str, Any],
    *,
    method: str,
    url: str,
    response: Mapping[str, Any],
) -> str:
    try:
        parts = urlsplit(url)
        parts.port
    except ValueError:
        return "non-http"
    host = (parts.hostname or "").lower()
    if parts.scheme not in {"http", "https"}:
        return "non-http"
    if method == "OPTIONS":
        return "preflight"
    if any(host == item or host.endswith(f".{item}") for item in _ANALYTICS_HOSTS):
        return "analytics"
    resource_type = str(entry.get("_resourceType", "")).lower()
    content = response.get("content")
    mime = (
        str(content.get("mimeType", "")).lower()
        if isinstance(content, Mapping)
        else ""
    )
    suffix = next((ext for ext in _ASSET_EXTENSIONS if parts.path.lower().endswith(ext)), None)
    if resource_type in _ASSET_TYPES or suffix or mime.startswith(("image/", "font/", "audio/", "video/")):
        return "asset"
    if mime in {"text/css", "application/javascript", "text/javascript"}:
        return "asset"
    return "application"


def endpoint_key(method: str, host: str, path: str) -> str:
    normalized = _PATH_ID.sub("{id}", path or "/")
    return f"{method} {host.lower()}{normalized}"


def group_endpoints(
    capture: Mapping[str, Any], *, include_excluded: bool = False
) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for record in capture.get("requests", []):
        if not isinstance(record, Mapping):
            continue
        if record.get("excluded") and not include_excluded:
            continue
        request = record.get("request")
        if not isinstance(request, Mapping):
            continue
        key = str(record.get("endpoint_key", record.get("id", "")))
        try:
            parts = urlsplit(str(request.get("url", "")))
        except ValueError:
            continue
        group = groups.setdefault(
            key,
            {
                "method": request.get("method"),
                "host": parts.hostname or "",
                "path": _PATH_ID.sub("{id}", parts.path or "/"),
                "count": 0,
                "request_ids": [],
                "statuses": [],
            },
        )
        group["count"] += 1
        group["request_ids"].append(record.get("id"))
        status = (record.get("response") or {}).get("status")
        if status not in group["statuses"]:
            group["statuses"].append(status)
    return list(groups.values())


def find_request(capture: Mapping[str, Any], request_id: str) -> dict[str, Any]:
    for record in capture.get("requests", []):
        if isinstance(record, dict) and record.get("id") == request_id:
            return record
    raise NotFoundError(
        f"no request {request_id!r} in the active capture",
        remedy="run `har2cli endpoints` and use one of its req-* ids",
    )


def credential_candidates(record: Mapping[str, Any]) -> list[str]:
    values = record.get("auth_names", [])
    return [
        item
        for item in values
        if isinstance(item, str) and not item.casefold().startswith("header::")
    ]


def rehydrate_request(
    record: Mapping[str, Any],
    secrets_for_request: Mapping[str, str],
    omit: set[str] | None = None,
) -> dict[str, Any]:
    """Rebuild one request in memory, optionally dropping auth candidates."""
    omitted = omit or set()
    request = record.get("request")
    if not isinstance(request, Mapping):
        raise UsageError("stored request is malformed")

    headers: list[dict[str, str]] = []
    for item in request.get("headers", []):
        if not isinstance(item, Mapping):
            continue
        secret_id = item.get("secret_id")
        if isinstance(secret_id, str):
            candidate = str(item.get("candidate", secret_id.split("#", 1)[0]))
            if candidate in omitted:
                continue
            value = secrets_for_request.get(secret_id)
            if value is None:
                continue
        else:
            value = item.get("value", "")
            if value == REDACTED:
                continue
        name = str(item.get("name", ""))
        if name.lower() == "cookie":
            continue
        headers.append({"name": name, "value": str(value)})

    cookie_values = []
    for item in request.get("cookies", []):
        if not isinstance(item, Mapping):
            continue
        secret_id = item.get("secret_id")
        candidate = str(item.get("candidate", str(secret_id).split("#", 1)[0]))
        if not isinstance(secret_id, str) or candidate in omitted:
            continue
        value = secrets_for_request.get(secret_id)
        if value is not None:
            cookie_values.append(f"{item.get('name', '')}={value}")
    if cookie_values:
        headers.append({"name": "Cookie", "value": "; ".join(cookie_values)})

    query: list[tuple[str, str]] = []
    for item in request.get("query", []):
        if not isinstance(item, Mapping):
            continue
        secret_id = item.get("secret_id")
        if isinstance(secret_id, str):
            candidate = str(item.get("candidate", secret_id.split("#", 1)[0]))
            if candidate in omitted:
                continue
            value = secrets_for_request.get(secret_id)
            if value is None:
                continue
        else:
            value = item.get("value", "")
        query.append((str(item.get("name", "")), str(value)))

    safe_url = str(request.get("url", ""))
    try:
        parts = urlsplit(safe_url)
    except ValueError as exc:
        raise UsageError("stored request URL is malformed") from exc
    url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
    return {"method": str(request.get("method", "")).upper(), "url": url, "headers": headers}


def _pairs(value: Any) -> list[tuple[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [
        (str(item.get("name", "")), item.get("value", ""))
        for item in value
        if isinstance(item, Mapping) and item.get("name") is not None
    ]


def _query_from_url(url: str) -> list[tuple[str, str]]:
    try:
        return list(parse_qsl(urlsplit(url).query, keep_blank_values=True))
    except ValueError:
        return []


def _sanitize_pairs(
    pairs: Sequence[tuple[str, Any]],
    *,
    location: str,
    secrets: dict[str, str],
    force: bool = False,
) -> list[dict[str, Any]]:
    out = []
    for name, raw_value in pairs:
        value = str(raw_value)
        sensitive = force or _sensitive_name(name) or bool(_SECRET_VALUE.match(value))
        item: dict[str, Any] = {"name": name, "value": REDACTED if sensitive else value}
        if sensitive:
            candidate = f"{location}:{name}"
            secret_id = _store_secret(secrets, candidate, value)
            item["candidate"] = candidate
            item["secret_id"] = secret_id
        out.append(item)
    return out


def _sanitize_headers(value: Any, secrets: dict[str, str]) -> list[dict[str, Any]]:
    out = []
    for name, raw_value in _pairs(value):
        if name.startswith(":"):
            continue
        header_value = str(raw_value)
        if name.lower() == "cookie":
            out.append({"name": name, "value": REDACTED})
            continue
        sensitive = _sensitive_name(name) or bool(_SECRET_VALUE.match(header_value))
        item: dict[str, Any] = {
            "name": name,
            "value": REDACTED if sensitive else header_value,
        }
        if sensitive:
            candidate = f"header:{name}"
            secret_id = _store_secret(secrets, candidate, header_value)
            item["candidate"] = candidate
            item["secret_id"] = secret_id
        out.append(item)
    return out


def _cookies_from_headers(
    value: Any,
    secrets: dict[str, str],
    *,
    skip: set[str] | None = None,
) -> list[dict[str, Any]]:
    cookies = []
    skipped = skip or set()
    for name, raw_value in _pairs(value):
        if name.lower() != "cookie":
            continue
        for part in str(raw_value).split(";"):
            cookie_name, separator, cookie_value = part.strip().partition("=")
            if not separator or not cookie_name or cookie_name.lower() in skipped:
                continue
            candidate = f"cookie:{cookie_name}"
            secret_id = _store_secret(secrets, candidate, cookie_value)
            cookies.append(
                {
                    "name": cookie_name,
                    "value": REDACTED,
                    "candidate": candidate,
                    "secret_id": secret_id,
                }
            )
    return cookies


def _store_secret(secrets: dict[str, str], candidate: str, value: str) -> str:
    secret_id = candidate
    occurrence = 2
    while secret_id in secrets:
        secret_id = f"{candidate}#{occurrence}"
        occurrence += 1
    secrets[secret_id] = value
    return secret_id


def _sanitize_echoes(
    items: list[dict[str, Any]],
    location: str,
    secrets: dict[str, str],
) -> None:
    known = tuple(value for value in secrets.values() if value)
    for item in items:
        value = item.get("value")
        if value == REDACTED or not isinstance(value, str):
            continue
        if not any(secret in value for secret in known):
            continue
        candidate = f"{location}:{item.get('name', '')}"
        item["value"] = REDACTED
        item["candidate"] = candidate
        item["secret_id"] = _store_secret(secrets, candidate, value)


def _candidate_names(*groups: Sequence[Mapping[str, Any]]) -> list[str]:
    names = []
    for group in groups:
        for item in group:
            candidate = item.get("candidate")
            if isinstance(candidate, str) and candidate not in names:
                names.append(candidate)
    return names


def _safe_url(raw_url: str, query: Sequence[Mapping[str, Any]]) -> str:
    try:
        parts = urlsplit(raw_url)
    except ValueError:
        return "<invalid-url>"
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port_number = parts.port
    except ValueError:
        return "<invalid-url>"
    port = f":{port_number}" if port_number else ""
    netloc = f"{host}{port}"
    safe_query = [(str(item.get("name", "")), str(item.get("value", ""))) for item in query]
    # Fragments are not sent in HTTP requests and sometimes contain OAuth
    # tokens. Dropping them preserves the wire contract and removes the risk.
    return urlunsplit(
        (
            parts.scheme,
            netloc,
            _redacted_path(parts.path),
            urlencode(safe_query),
            "",
        )
    )


def _redacted_path(path: str) -> str:
    segments = path.split("/")
    out = list(segments)
    for index, segment in enumerate(segments):
        previous = segments[index - 1].lower() if index else ""
        if _SECRET_VALUE.match(segment) or (previous in _PATH_SECRET_LABELS and segment):
            out[index] = REDACTED
    return "/".join(out)


def _path_was_redacted(raw_url: str, safe_url: str) -> bool:
    try:
        return urlsplit(raw_url).path != urlsplit(safe_url).path
    except ValueError:
        return False


def _sanitize_response(
    response: Mapping[str, Any], *, exact_secrets: tuple[str, ...] = ()
) -> dict[str, Any]:
    content = response.get("content")
    content = content if isinstance(content, Mapping) else {}
    mime = str(content.get("mimeType", ""))
    text = content.get("text", "")
    if content.get("encoding") == "base64":
        body: Any = "<base64 body omitted>"
    elif "html" in mime.lower():
        body = "<html body omitted>"
    elif "json" in mime.lower() and isinstance(text, str):
        try:
            body = _redact_json(json.loads(text), exact_secrets=exact_secrets)
        except json.JSONDecodeError:
            body = _redact_text(text, exact_secrets)
        except RecursionError:
            body = "<response body too deeply nested>"
    elif isinstance(text, str):
        body = trim(_redact_text(text, exact_secrets), 32_000)
    else:
        body = None
    return {
        "status": response.get("status"),
        "status_text": response.get("statusText", ""),
        "mime_type": mime,
        "size": content.get("size"),
        "headers": _sanitize_response_pairs(
            response.get("headers"),
            exact_secrets=exact_secrets,
        ),
        "cookies": _sanitize_response_pairs(
            response.get("cookies"),
            force=True,
            exact_secrets=exact_secrets,
        ),
        "body": body,
    }


def _sanitize_response_pairs(
    value: Any,
    *,
    force: bool = False,
    exact_secrets: tuple[str, ...] = (),
) -> list[dict[str, str]]:
    out = []
    for name, raw_value in _pairs(value):
        rendered = str(raw_value)
        if (
            force
            or name.lower() == "location"
            or _sensitive_name(name)
            or _SECRET_VALUE.match(rendered)
            or any(secret and secret in rendered for secret in exact_secrets)
        ):
            rendered = REDACTED
        out.append({"name": name, "value": rendered})
    return out


def _redact_json(
    value: Any,
    *,
    key: str = "",
    exact_secrets: tuple[str, ...] = (),
) -> Any:
    if key and _sensitive_name(key):
        return REDACTED
    if isinstance(value, Mapping):
        safe: dict[str, Any] = {}
        for name, item in value.items():
            raw_name = str(name)
            safe_name = (
                REDACTED
                if raw_name in exact_secrets or _looks_like_secret(raw_name)
                else _redact_text(raw_name, exact_secrets)
            )
            safe[safe_name] = _redact_json(
                item,
                key=raw_name,
                exact_secrets=exact_secrets,
            )
        return safe
    if isinstance(value, list):
        return [_redact_json(item, exact_secrets=exact_secrets) for item in value]
    if isinstance(value, str):
        if value in exact_secrets or _looks_like_secret(value):
            return REDACTED
        return _redact_text(value, exact_secrets)
    return value


def _redact_text(value: str, exact_secrets: tuple[str, ...] = ()) -> str:
    safe = value
    for secret in sorted((item for item in exact_secrets if item), key=len, reverse=True):
        safe = safe.replace(secret, REDACTED)

    def replace(match: re.Match[str]) -> str:
        prefix = match.group(1)
        return f"{prefix}{REDACTED}" if prefix else REDACTED

    return _TEXT_SECRET.sub(replace, safe)


def _looks_like_secret(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.lower()
    if _SECRET_VALUE.match(stripped):
        return True
    if any(word in lowered for word in ("secret", "access_token", "refresh_token")):
        return True
    return bool(
        len(stripped) >= 24
        and " " not in stripped
        and re.fullmatch(r"[A-Za-z0-9._~+/=-]+", stripped)
    )


def _sensitive_name(name: str) -> bool:
    expanded = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    words = {item for item in re.split(r"[^a-z0-9]+", expanded.lower()) if item}
    normalized = "".join(words)
    return normalized in _SECRET_WORDS or bool(words & _SECRET_WORDS)
