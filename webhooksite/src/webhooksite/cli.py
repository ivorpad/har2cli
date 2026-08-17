"""Command surface for the generated one-endpoint CLI."""

from __future__ import annotations

import typer

import agentis
from agentis import Session

from . import commands

AGENT_NOTES = """\
examples:

  webhooksite get --max-cost 1   call the captured GET endpoint once
  webhooksite get --json         compact JSON, with errors as JSON too
  webhooksite get --json --raw   the full upstream JSON response

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
    "webhooksite",
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
