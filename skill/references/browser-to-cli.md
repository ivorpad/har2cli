# Browser-to-CLI workflow

Use Chrome for the site's meaning and har2cli for the HTTP evidence. From the
har2cli source checkout, substitute `uv run har2cli` for `har2cli` below.

## Learn one flow in Chrome

Open or claim the target tab with `$chrome`. If authentication blocks access,
ask the user to sign in there and tell you when it is ready.

Identify one visible, read-only action for the CLI. Record what it means, its
user inputs, and the expected result. Do not select an endpoint from its URL
alone; a HAR contains traffic, not domain intent.

If the desired action writes data, explain that har2cli v1 cannot replay it.
Do not substitute an unrelated GET.

## Obtain a focused HAR

Check the current Chrome capability documentation for a supported network or
HAR export. If none exists, use this user-assisted handoff:

1. Ask the user to open DevTools and select **Network**.
2. Ask them to enable **Preserve log**, clear the request list, and tell you
   when recording is ready.
3. Reproduce only the target read-only action with `$chrome`.
4. Ask the user to export the listed requests as **HAR (with sensitive data)**
   and provide the local path, not the file contents.

Chrome exports a sanitized HAR by default. Authenticated replay normally needs
**Settings > Preferences > Network > Allow to generate HAR with sensitive
data**, followed by **Export HAR (with sensitive data)**. Explain first that
the file can contain cookies and authorization headers. See the
[Chrome Network reference](https://developer.chrome.com/docs/devtools/network/reference/).
As soon as the export finishes, ask the user to disable **Allow to generate HAR
with sensitive data** again.

If the user supplies only a sanitized HAR, use it for endpoint discovery but
do not claim authenticated replay will work. Keep the HAR outside the generated
project. har2cli never modifies or deletes the source file.

## Import and select a GET

Use task-specific temporary state when the capture should not persist. Run
`mktemp -d /tmp/har2cli-state.XXXXXX`, then use the exact returned directory as
`HAR2CLI_CONFIG_DIR` for every har2cli command.

```bash
har2cli import /absolute/path/to/capture.har --json
har2cli endpoints --json
har2cli inspect req-N --json
```

Inspect the selected request's method, host, path, status, parameters, and
credential names. Choose only a GET that matches the observed Chrome action.
If several requests remain plausible, make a narrower capture.

Do not scaffold POST, PUT, PATCH, DELETE, or a request classified
`secret-path`.

## Verify the request

Confirm that the redacted host matches the site visited. State the one-request
budget before replaying:

```bash
har2cli replay req-N --max-cost 1 --json
```

Redirects are returned, not followed. Use `--allow-private` only after
inspection and confirmation that the private destination is intended.

Run auth bisection only when credential candidates remain. It sends one
baseline plus one probe per candidate. State that exact count and cap it; the
hard limit is 32 calls.

```bash
har2cli auth-bisect req-N --max-cost N --json
```

Treat `required` and `unnecessary` as evidence for this endpoint and session,
not as a general authentication specification. Show the result and caveat to
the user. If they accept it, add `--accept-auth-bisect` to the scaffold command.
Without acceptance, omit the flag and keep every captured candidate.

## Generate and test the CLI

Choose a new name matching `[a-z][a-z0-9_]{0,31}` and a destination that does
not already contain that name.

```bash
har2cli scaffold mycli --request req-N --dest /absolute/parent --max-cost 1 --json
```

After accepted auth evidence, use:

```bash
har2cli scaffold mycli --request req-N --accept-auth-bisect \
  --dest /absolute/parent --max-cost 1 --json
```

Read the generated `README.md` and `contract/endpoint.json`. Report credential
environment-variable names only. Ask the user to set fresh values outside the
agent transcript.

```bash
cd /absolute/parent/mycli
uv sync
uv run pytest -q
uv run agentis check .
uv run mycli --help
```

From the parent directory, run:

```bash
uv run --project ./mycli mycli --help
```

With required credentials set and approval for one live call:

```bash
uv run --project ./mycli mycli get --max-cost 1 --json
```

On authentication failure, request fresh credentials or a fresh focused HAR.
Do not retry stale values.

Finish only when the selected GET maps to the observed action, an approved
replay returned the expected state or the user accepted an unverified scaffold,
generated tests and `agentis check .` pass, and no credential value entered
source, fixtures, output, the repository, or the transcript.

Delete only task-specific temporary state you created. Never delete the source
HAR. Before shipping, run the dumb-agent test described in the generated
README.
