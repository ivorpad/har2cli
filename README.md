# har2cli

Turn an authenticated browser HAR into a redacted HTTP contract, then hand one
GET endpoint to [Agentis](../2026-08-06-agentis-cli-fw/) for packaging as a
CLI.

`har2cli` derives and tests the request. Agentis owns the generated CLI
contract. A HAR does not explain domain intent, so the generated `get` command
is a starting point, not a claim that the API has been understood completely.

## Agent skill

The checkout exposes `skill/` as the project-local `$har2cli` skill through
`.agents/skills/har2cli`. Agents launched in this repo can use it to learn one
read-only action with `$chrome`, guide a focused HAR export, and generate the
CLI. The detailed workflow stays with the code and calls `har2cli --help` for
the current command contract.

## Install

```bash
uv sync
uv tool install --editable .
har2cli --help
```

## Recipes

Import an existing HAR, then inspect likely application calls:

```bash
har2cli import orders.har
har2cli endpoints
har2cli inspect req-42
```

The latest import becomes active. `endpoints` hides static assets, analytics,
preflights, and non-HTTP entries. The classifier is intentionally inspectable,
not an SDK generator.

Replay one captured GET. `--max-cost 1` makes the intended request budget
explicit:

```bash
har2cli replay req-42 --max-cost 1
```

Redirects are returned rather than followed. POST, PUT, PATCH, and DELETE are
refused before a connection is opened. Loopback, private, link-local, and
reserved destinations are refused by default. After inspecting a trusted HAR,
use `--allow-private` for an intended intranet service.

Find which captured credential names are needed:

```bash
har2cli auth-bisect req-42 --max-cost 10
```

This sends a baseline GET followed by capped elimination probes. It reports
names such as `cookie:session` or `header:Authorization`; values never enter
the output. It compares status, content type, login redirects, and response
shape. Treat the result as evidence for this endpoint and session, not a
general authentication specification. Two domain states can still have the
same shape.

The probe is not authoritative without a service-specific login predicate, so
scaffolding keeps every captured credential candidate by default. After you
review and accept the endpoint-specific evidence, opt in for that one scaffold:

```bash
har2cli scaffold orders --request req-42 --accept-auth-bisect
```

The command refuses missing, malformed, or stale bisection evidence. Its JSON
output records whether auth came from captured candidates or an accepted
bisection and lists every omitted candidate name.

Generate one Agentis CLI from the selected contract:

```bash
har2cli scaffold orders --request req-42
cd orders
uv sync
uv run pytest -q
```

The generated project contains a redacted endpoint manifest, a structure-only
response fixture, credential and transport hooks, one `get` command, contract
tests, and the weak-agent-test reminder.

From the scaffold's parent directory, target its uv project explicitly:

```bash
uv run --project ./orders orders --help
```

## Stored data

State lives in `~/.har2cli/`; set `HAR2CLI_CONFIG_DIR` to relocate it. Imported
captures are sanitized before they are written. Replay-only values are kept in
a separate `0600` sidecar and are never returned by `inspect`, including with
`--raw`. State directories are `0700`.

Redaction recognizes common credential names and shapes, echoed request
secrets, cookies, signed query fields, and obvious secret-bearing path
segments. It cannot infer every domain-specific identifier, so keep capture
state private and inspect a contract before scaffolding it.

The source HAR is not modified or deleted. It still contains the browser's
original credentials, so handle it as a secret.

A HAR is also executable network input. Import can inspect any HAR, but replay
only one you trust. Captured field names remain data in the endpoint contract;
generated Markdown escapes them instead of treating them as instructions.

## Version-one boundary

This version imports an existing HAR and handles ordinary HTTP GET requests.
Browser capture, mutating methods, pagination, refresh tokens, WebSockets, and
lifecycle probing are not implemented.

## For agents

`har2cli --help` owns the operating rules and exit-code table. Under `--json`,
stdout is one JSON document; notes and errors also go to stderr.

## Development

```bash
uv sync
uv run pytest -q
uv run agentis check .
```

`pyproject.toml` points Agentis at its absolute editable checkout because it is
not published. Moving that checkout breaks `uv sync` until the source path is
updated.
