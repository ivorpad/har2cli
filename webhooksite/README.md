# webhooksite

This directory is transport smoke evidence from the supplied HAR. Its selected
contract is the public `GET /form-builder` navigation; it does not read or list
webhook requests. Recapture the intended read-only webhook action before using
it as a semantic webhook.site CLI.

This CLI calls one GET endpoint selected from a browser HAR. Its checked-in
contract is redacted and its response fixture keeps structure, not captured
user values. Credential values are loaded only at runtime.

## Install

```bash
uv sync
uv tool install --editable .
webhooksite --help
```

From the parent directory instead:

```bash
uv run --project ./webhooksite webhooksite --help
```

## Credentials

This GET endpoint does not require runtime credentials. A three-request probe
confirmed that omitting the captured `url` query and `referer` preserves its
HTTP status, content type, redirect behavior, and response shape.

## Recipes

```bash
webhooksite get --max-cost 1
webhooksite get --max-cost 1 --json
webhooksite get --max-cost 1 --json --raw
```

The checked-in request contract is `contract/endpoint.json`. Update the
transport and credential hooks in `src/webhooksite/transport.py` and
`src/webhooksite/credentials.py` when the upstream service rotates.

## Before shipping

```bash
uv run pytest -q
uv run agentis check .
```

Run the dumb-agent test too: give a weak agent the command and a vague task,
record every command it runs, then verify its answer against the real endpoint.
Do not accept the agent's own claim that nothing confused it.
