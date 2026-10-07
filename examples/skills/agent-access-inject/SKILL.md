---
name: agent-access-inject
description: Use credentials (username, password, TOTP, API keys) from the user's Bitwarden vault without ever seeing them. aac injects them as environment variables into the command that needs them, after the user approves (e.g. in Telegram).
user-invocable: true
metadata: {"openclaw":{"requires":{"bins":["aac"]}}}
---

Use this skill when a command needs a login, password, TOTP code or API key from the user's vault.

**Never print, echo, log or write credentials to files.** Use `aac run`, which fetches the credential over an end-to-end encrypted
channel and passes it only to the child process as environment variables. Don't use `aac connect --output json` or
`aac --domain ... --output json`, because they print the secret into your context.

## Usage

```bash
aac run --domain github.com --env GH_USER=username --env GH_TOKEN=password -- ./script-that-uses-env.sh
aac run --domain example.com --env-all -- some-command        # AAC_USERNAME, AAC_PASSWORD, AAC_TOTP, ...
aac run --id <vault-item-id> --env DB_PASSWORD=password -- psql "host=db user=app"
```

Fields: `username`, `password`, `totp`, `uri`, `notes`, `domain`, `credential_id`.

Use the bare domain (`github.com`, not `https://github.com/login`).

## Approval

Every request is approved by the user (usually by tapping a button in Telegram). `aac run` waits until then (default timeout
120 s). When approved, it exits with your command's own exit code. If the request is denied, auto-declined by the approver's
timeout, or no matching item exists, it exits 4 and the command doesn't run. It exits 3 if `aac run`'s own timeout hits, and 2 if
the relay can't be reached. If a request is denied, tell the user what you were trying to access and why. Don't retry in a loop.

## First-time pairing

If `aac connections list` shows no session, ask the user for the pairing token, then:

```bash
aac run --token <TOKEN> --domain example.com --env X=username -- true
```

The session is cached in `~/.access-protocol/` afterwards.
