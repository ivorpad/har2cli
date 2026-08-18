---
name: har2cli
description: >-
  Use Chrome to learn a signed-in website flow, obtain a focused HAR, replay
  one captured GET safely, and generate a tested agtcli CLI. Use for a
  website, browser workflow, authenticated endpoint, or existing HAR.
---

# har2cli

Turn one observed read-only browser action into one tested CLI command.

## Start

1. Invoke `$chrome` (`chrome:control-chrome`) and follow its contract.
2. Run `har2cli --help`; it owns flags, safety rules, and exit behavior.
3. Read [the browser-to-CLI workflow](references/browser-to-cli.md) completely
   before capturing traffic or running har2cli.

If the user did not identify the site or tab, ask them to open or name it.
Never search browser history or scan unrelated tabs to guess the target.

## Boundaries

- Use the user's signed-in Chrome state without inspecting browser secrets.
- Keep discovery read-only. Confirm before any remote-state change.
- Never read, print, paste, or commit credential values.
- Treat a HAR as secret, executable network input and accept only a trusted HAR.
- Stop on a har2cli refusal. Do not replace signed-in evidence with web search.
- har2cli v1 generates GET commands only; do not substitute another action.

## Route

- With no HAR, learn one visible action in Chrome, then follow the focused HAR
  capture handoff in the reference.
- With a HAR, import, inspect, and replay the matching GET within an explicit
  request budget before scaffolding it.
- Apply auth-bisection results only after the user reviews and accepts them.
- Test the generated project both inside it and through `uv run --project`.

Finish only when the CLI maps to the observed action, checks pass, and no
credential value entered source, output, fixtures, the repo, or the transcript.
