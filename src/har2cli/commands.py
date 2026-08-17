"""Implementation of the six har2cli verbs."""

from __future__ import annotations

from collections.abc import Mapping
import math
from pathlib import Path
from typing import Any

from agentis import (
    AuthError,
    NotFoundError,
    RefusedError,
    UpstreamError,
    UsageError,
)

from . import api, har, scaffolder, store

MAX_TIMEOUT = 120.0
MAX_BISECT_REQUESTS = 32


def compact(record: Mapping[str, Any]) -> dict[str, Any]:
    """Compact an imported request without weakening its redaction."""
    request = record.get("request")
    if not isinstance(request, Mapping):
        return dict(record)
    response = record.get("response")
    response = response if isinstance(response, Mapping) else {}
    return {
        "id": record.get("id"),
        "classification": record.get("classification"),
        "method": request.get("method"),
        "url": request.get("url"),
        "headers": request.get("headers", []),
        "query": request.get("query", []),
        "cookies": request.get("cookies", []),
        "auth_names": record.get("auth_names", []),
        "response": {
            "status": response.get("status"),
            "mime_type": response.get("mime_type"),
        },
    }


def import_har(session, path: Path) -> None:
    summary = store.import_har(session.state, path)
    session.out.emit(summary, compact=lambda value: value)
    session.out.note(
        f"[green]active[/] {summary['capture_id']}; next: har2cli endpoints"
    )


def endpoints(session) -> None:
    capture = store.load_active_capture(session.state)
    groups = har.group_endpoints(capture)
    result = {
        "capture_id": capture.get("capture_id"),
        "count": len(groups),
        "endpoints": groups,
    }
    session.out.emit(result, compact=lambda value: value)
    if groups:
        session.out.note("Inspect one: har2cli inspect <req-id>")


def inspect_request(session, request_id: str) -> None:
    capture = store.load_active_capture(session.state)
    record = har.find_request(capture, request_id)
    session.out.emit(record, compact=compact)


def replay(
    session,
    request_id: str,
    *,
    timeout: float = 30.0,
    allow_private: bool = False,
) -> None:
    timeout = _checked_timeout(timeout)
    capture = store.load_active_capture(session.state)
    record = har.find_request(capture, request_id)
    _require_get(record)
    secrets = store.load_secrets(session.state, capture).get(request_id, {})
    prepared = har.rehydrate_request(record, secrets)
    session.guard.check(1, f"replaying {request_id}")
    response = api.replay(
        prepared,
        timeout=timeout,
        allow_private=allow_private,
    )
    safe_url = str((record.get("request") or {}).get("url", ""))
    result = api.response_record(
        response,
        request_url=safe_url,
        secret_values=secrets.values(),
    )
    session.out.emit(result, compact=api.compact_response)


def auth_bisect(
    session,
    request_id: str,
    *,
    timeout: float = 30.0,
    allow_private: bool = False,
) -> None:
    """Find a locally minimal authenticating set by candidate elimination."""
    timeout = _checked_timeout(timeout)
    capture = store.load_active_capture(session.state)
    record = har.find_request(capture, request_id)
    _require_get(record)
    candidates = har.credential_candidates(record)
    if not candidates:
        session.guard.waive("the capture has no credential candidates to probe")
        result = {
            "request_id": request_id,
            "required": [],
            "unnecessary": [],
            "calls": 0,
        }
        store.save_auth_result(session.state, capture, request_id, result)
        session.out.emit(result, compact=lambda value: value)
        return

    calls = len(candidates) + 1
    if calls > MAX_BISECT_REQUESTS:
        raise RefusedError(
            f"auth bisection needs {calls} requests; hard limit is "
            f"{MAX_BISECT_REQUESTS}",
            remedy="import a capture with fewer credential-like fields",
        )
    session.guard.check(calls, f"auth bisection for {request_id}")

    all_secrets = store.load_secrets(session.state, capture)
    request_secrets = all_secrets.get(request_id, {})
    baseline_request = har.rehydrate_request(record, request_secrets)
    baseline = api.replay(
        baseline_request,
        timeout=timeout,
        allow_private=allow_private,
    )
    if api.authentication_failed(baseline):
        raise AuthError(
            "the captured credentials already fail on the baseline GET",
            remedy="import a fresh HAR captured from a working browser session",
        )
    if baseline.status_code == 404:
        raise NotFoundError("the captured endpoint returned 404 on the baseline GET")
    if baseline.status_code >= 500:
        raise UpstreamError(
            f"the captured endpoint returned {baseline.status_code} on the baseline GET"
        )
    signature = api.auth_signature(baseline)

    omitted: set[str] = set()
    # Reverse order removes preference cookies before session cookies in the
    # common HAR layout. The final set is locally minimal either way.
    for candidate in reversed(candidates):
        trial_omitted = omitted | {candidate}
        prepared = har.rehydrate_request(
            record,
            request_secrets,
            omit=trial_omitted,
        )
        response = api.replay(
            prepared,
            timeout=timeout,
            allow_private=allow_private,
        )
        if response.status_code == 429 or response.status_code >= 500:
            raise UpstreamError(
                f"auth probe returned {response.status_code}; stopping the bisection"
            )
        if not api.authentication_failed(response) and api.auth_signature(response) == signature:
            omitted = trial_omitted

    required = [name for name in candidates if name not in omitted]
    unnecessary = [name for name in candidates if name in omitted]
    result = {
        "request_id": request_id,
        "required": required,
        "unnecessary": unnecessary,
        "calls": calls,
        "baseline": {
            "status": signature[0],
            "content_type": signature[1],
            "response_shape": signature[3],
        },
        "evidence": "status, content type, login redirect, and response shape",
        "caveat": "domain-specific login states can still look identical",
        "authoritative": False,
    }
    store.save_auth_result(session.state, capture, request_id, result)
    session.out.emit(result, compact=lambda value: value)


def scaffold(
    session,
    name: str,
    request_id: str,
    *,
    dest: Path,
    accept_auth_bisect: bool = False,
) -> None:
    capture = store.load_active_capture(session.state)
    record = har.find_request(capture, request_id)
    _require_get(record)
    candidates = har.credential_candidates(record)
    auth_result = store.load_auth_result(session.state, capture, request_id)
    auth_names = candidates
    omitted_auth_names: list[str] = []
    auth_source = "captured-candidates"
    if accept_auth_bisect:
        if not isinstance(auth_result, dict):
            raise RefusedError(
                f"no auth-bisect result exists for {request_id}",
                remedy=f"run `har2cli auth-bisect {request_id} --max-cost N` and review its evidence",
            )
        auth_names, omitted_auth_names = _auth_partition(
            auth_result,
            candidates,
            request_id,
        )
        auth_source = "accepted-auth-bisect"

    session.guard.check(1, f"scaffolding {request_id}")
    response = record.get("response")
    fixture = response.get("body") if isinstance(response, Mapping) else None
    target = scaffolder.scaffold_project(
        name,
        dest,
        record,
        fixture,
        auth_names,
    )
    result = {
        "created": str(target),
        "request_id": request_id,
        "auth_source": auth_source,
        "auth_names": list(auth_names),
        "omitted_auth_names": omitted_auth_names,
    }
    session.out.emit(result, compact=lambda value: value)
    session.out.note(
        "Next: enter the created directory, then run: uv sync && uv run pytest -q"
    )
    session.out.note(
        f"From its parent: uv run --project ./{name} {name} --help"
    )


def _auth_partition(
    result: Mapping[str, Any],
    candidates: list[str],
    request_id: str,
) -> tuple[list[str], list[str]]:
    required = result.get("required")
    unnecessary = result.get("unnecessary")
    valid_lists = all(
        isinstance(items, list)
        and all(isinstance(item, str) for item in items)
        for items in (required, unnecessary)
    )
    if not valid_lists or result.get("request_id") != request_id:
        raise RefusedError(
            "stored auth-bisect evidence is malformed or stale",
            remedy=f"run `har2cli auth-bisect {request_id} --max-cost N` again and review its evidence",
        )

    required_names = list(required)
    unnecessary_names = list(unnecessary)
    required_set = set(required_names)
    unnecessary_set = set(unnecessary_names)
    candidate_set = set(candidates)
    valid_partition = (
        len(required_names) == len(required_set)
        and len(unnecessary_names) == len(unnecessary_set)
        and required_set.isdisjoint(unnecessary_set)
        and required_set | unnecessary_set == candidate_set
    )
    if not valid_partition:
        raise RefusedError(
            "stored auth-bisect evidence does not match the selected request",
            remedy=f"run `har2cli auth-bisect {request_id} --max-cost N` again and review its evidence",
        )
    return (
        [name for name in candidates if name in required_set],
        [name for name in candidates if name in unnecessary_set],
    )


def _require_get(record: Mapping[str, Any]) -> None:
    if record.get("classification") == "secret-path":
        raise RefusedError(
            "this URL contained a secret-shaped path segment that was discarded",
            remedy="v1 cannot replay or scaffold secrets embedded in URL paths",
        )
    request = record.get("request")
    method = str(request.get("method", "")).upper() if isinstance(request, Mapping) else ""
    if method != "GET":
        raise RefusedError(
            f"{method or 'unknown'} replay is disabled in v1",
            remedy="select a GET request; mutating methods are not implemented",
        )


def _checked_timeout(value: float) -> float:
    if not math.isfinite(value) or value <= 0 or value > MAX_TIMEOUT:
        raise UsageError(
            f"--timeout must be greater than 0 and at most {MAX_TIMEOUT:g} seconds"
        )
    return value
