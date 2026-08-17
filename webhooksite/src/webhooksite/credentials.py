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
