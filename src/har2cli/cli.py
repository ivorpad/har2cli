"""The six-command har2cli workbench surface."""

from __future__ import annotations

import functools
import math
import os
from pathlib import Path

import typer

import agentis
from agentis import Session

from . import commands

AGENT_NOTES = """\
examples:

  har2cli import flow.har             redact and store an existing HAR
  har2cli endpoints                   group likely application requests
  har2cli inspect req-42              inspect a redacted HTTP contract
  har2cli replay req-42 --max-cost 1       send one captured GET
  har2cli auth-bisect req-42 --max-cost 10 find required auth names
  har2cli scaffold mycli --request req-42

operating rules:

  * Commands use the most recently imported capture.
  * Import stores a redacted capture and a 0600 replay sidecar.
  * inspect and --raw never reveal captured credential values.
  * replay and auth-bisect only send GET. Redirects are not followed.
  * Non-public hosts require --allow-private after you inspect the HAR.
  * POST, PUT, PATCH and DELETE are disabled in this version.
  * Use --max-cost to cap network requests before they begin.
  * Accept auth-bisect evidence only after reviewing its caveat.
  * A value marked "[... truncated" is cut. Never invent its ending.

with --json, stdout is only ever JSON, errors included; everything else is
stderr.
"""

app = agentis.build(
    "har2cli",
    help="Turn authenticated HAR flows into safe Agentis CLI scaffolds.",
    notes=AGENT_NOTES,
    unit="requests",
)

# Agentis currently lets NaN/infinity reach its Pydantic guard and turns a
# negative limit into an uncaught validation error. Keep this CLI's advertised
# typed JSON contract while the framework checkout is fixed separately.
_agentis_root = app.registered_callback.callback


@functools.wraps(_agentis_root)
def _validated_root(
    ctx: typer.Context,
    as_json: bool = False,
    raw: bool = False,
    max_cost: float | None = None,
    max_legacy: float | None = None,
) -> None:
    if max_cost is not None and (not math.isfinite(max_cost) or max_cost < 0):
        raise agentis.UsageError(
            "--max-cost must be a finite number at least zero"
        )
    if max_cost is None and (ambient := os.environ.get("HAR2CLI_MAX_COST")):
        try:
            parsed = float(ambient)
        except ValueError:
            parsed = None  # Agentis supplies the existing typed remedy.
        if parsed is not None and (not math.isfinite(parsed) or parsed < 0):
            raise agentis.RefusedError(
                "HAR2CLI_MAX_COST must be a finite number at least zero",
                remedy="fix or unset HAR2CLI_MAX_COST",
            )
    _agentis_root(
        ctx,
        as_json=as_json,
        raw=raw,
        max_cost=max_cost,
        max_legacy=max_legacy,
    )


app.registered_callback.callback = _validated_root


@app.command("import")
def import_har(
    ctx: typer.Context,
    path: Path = typer.Argument(..., help="existing .har file"),
) -> None:
    """Redact and store a HAR, then make it the active capture."""
    commands.import_har(Session.get(ctx), path)


@app.command()
def endpoints(ctx: typer.Context) -> None:
    """Group likely application calls; suppress assets and analytics."""
    commands.endpoints(Session.get(ctx))


@app.command("inspect")
def inspect_request(
    ctx: typer.Context,
    request_id: str = typer.Argument(..., help="request id, such as req-42"),
) -> None:
    """Show one redacted request, its parameters, and auth names."""
    commands.inspect_request(Session.get(ctx), request_id)


@app.command()
@agentis.costly
def replay(
    ctx: typer.Context,
    request_id: str = typer.Argument(..., help="captured GET request id"),
    timeout: float = typer.Option(30.0, "--timeout", help="seconds, at most 120"),
    allow_private: bool = typer.Option(
        False,
        "--allow-private",
        help="allow loopback, private, or link-local destinations",
    ),
) -> None:
    """Replay one GET once. Other methods are refused before the network."""
    commands.replay(
        Session.get(ctx),
        request_id,
        timeout=timeout,
        allow_private=allow_private,
    )


@app.command("auth-bisect")
@agentis.costly
def auth_bisect(
    ctx: typer.Context,
    request_id: str = typer.Argument(..., help="captured GET request id"),
    timeout: float = typer.Option(30.0, "--timeout", help="seconds, at most 120"),
    allow_private: bool = typer.Option(
        False,
        "--allow-private",
        help="allow loopback, private, or link-local destinations",
    ),
) -> None:
    """Eliminate auth candidates; report names and never their values."""
    commands.auth_bisect(
        Session.get(ctx),
        request_id,
        timeout=timeout,
        allow_private=allow_private,
    )


@app.command()
@agentis.costly
def scaffold(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="new CLI package and command name"),
    request_id: str = typer.Option(..., "--request", help="one selected GET"),
    dest: Path = typer.Option(Path("."), "--dest", help="parent directory"),
    accept_auth_bisect: bool = typer.Option(
        False,
        "--accept-auth-bisect",
        help="use a reviewed auth-bisect result",
    ),
) -> None:
    """Pass one selected redacted GET to Agentis and adapt its scaffold."""
    commands.scaffold(
        Session.get(ctx),
        name,
        request_id,
        dest=dest,
        accept_auth_bisect=accept_auth_bisect,
    )


main = agentis.main_for(app)
