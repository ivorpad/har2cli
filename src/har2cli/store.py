"""Owner-only, atomic storage for sanitized captures and replay values."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from agentis import NotFoundError, UsageError, read_json, write_json

from . import har

MAX_HAR_BYTES = 200 * 1024 * 1024
CAPTURE_FILE = "capture.json"
REPLAY_FILE = "replay-secrets.json"
ACTIVE_FILE = "active.json"
AUTH_RESULTS_DIR = "auth-results"


def import_har(state: Path, source: Path) -> dict[str, Any]:
    source = Path(source).expanduser()
    try:
        size = source.stat().st_size
    except OSError:
        raise NotFoundError(f"HAR file not found: {source.name}") from None
    if size > MAX_HAR_BYTES:
        raise UsageError(
            f"HAR is {size} bytes; the v1 limit is {MAX_HAR_BYTES}",
            remedy="export a shorter browser flow and import that HAR",
        )
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise UsageError(f"could not read HAR file {source.name!r}: {exc.strerror}") from exc
    try:
        payload = json.loads(raw)
    except UnicodeDecodeError as exc:
        raise UsageError("HAR must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise UsageError(f"invalid HAR JSON at line {exc.lineno}, column {exc.colno}") from exc
    except RecursionError as exc:
        raise UsageError("HAR JSON is too deeply nested") from exc

    capture_id = _capture_id(source.stem, raw)
    capture, secrets = har.parse_har(
        payload,
        capture_id=capture_id,
        source_name=source.name,
    )
    capture_dir = _capture_dir(state, capture_id)
    _private_dir(Path(state))
    _private_dir(Path(state) / "captures")
    _private_dir(capture_dir)
    write_json(capture_dir / CAPTURE_FILE, capture)
    write_json(capture_dir / REPLAY_FILE, secrets)
    write_json(Path(state) / ACTIVE_FILE, {"capture_id": capture_id})
    return {
        "capture_id": capture_id,
        "source_name": source.name,
        "requests": capture["request_count"],
        "application_requests": capture["application_count"],
        "excluded_requests": capture["request_count"] - capture["application_count"],
    }


def load_active_capture(state: Path) -> dict[str, Any]:
    return load_capture(state)


def load_capture(state: Path, capture_id: str | None = None) -> dict[str, Any]:
    if capture_id is None:
        active = read_json(Path(state) / ACTIVE_FILE, default=None)
        capture_id = active.get("capture_id") if isinstance(active, dict) else None
    if not isinstance(capture_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,95}", capture_id):
        raise NotFoundError(
            "no active HAR capture",
            remedy="run `har2cli import <file.har>` first",
        )
    capture = read_json(_capture_dir(state, capture_id) / CAPTURE_FILE, default=None)
    if not isinstance(capture, dict):
        raise NotFoundError(
            f"capture {capture_id!r} is missing",
            remedy="import the HAR again",
        )
    return capture


def load_secrets(state: Path, capture: dict[str, Any]) -> dict[str, dict[str, str]]:
    capture_id = _validated_capture_id(capture.get("capture_id"))
    values = read_json(_capture_dir(state, capture_id) / REPLAY_FILE, default={})
    return values if isinstance(values, dict) else {}


def save_auth_result(
    state: Path,
    capture: dict[str, Any],
    request_id: str,
    result: dict[str, Any],
) -> None:
    capture_id = _validated_capture_id(capture.get("capture_id"))
    results_dir = _capture_dir(state, capture_id) / AUTH_RESULTS_DIR
    _private_dir(results_dir)
    write_json(results_dir / f"{_validated_request_id(request_id)}.json", result)


def load_auth_result(
    state: Path, capture: dict[str, Any], request_id: str
) -> dict[str, Any] | None:
    capture_id = _validated_capture_id(capture.get("capture_id"))
    path = (
        _capture_dir(state, capture_id)
        / AUTH_RESULTS_DIR
        / f"{_validated_request_id(request_id)}.json"
    )
    value = read_json(path, default=None)
    return value if isinstance(value, dict) else None


def _capture_id(stem: str, raw: bytes) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", stem.lower()).strip("-") or "capture"
    slug = slug[:64].rstrip("-")
    return f"{slug}-{hashlib.sha256(raw).hexdigest()[:12]}"


def _capture_dir(state: Path, capture_id: str) -> Path:
    return Path(state) / "captures" / capture_id


def _validated_capture_id(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,95}", value):
        raise NotFoundError("stored capture id is invalid")
    return value


def _validated_request_id(value: str) -> str:
    if not re.fullmatch(r"req-\d+", value):
        raise NotFoundError(f"stored request id is invalid: {value!r}")
    return value


def _private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
