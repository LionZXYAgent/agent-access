# Telegram approval for `aac listen`

> Fork feature (not part of upstream Bitwarden Agent Access). Opt-in; nothing changes unless you pass `--telegram`.

`aac listen` is the trusted, vault-holding side of Agent Access (the *user client*). Normally every credential request
from a paired agent has to be approved in its terminal UI. With `--telegram`, `aac listen` also sends each request that
needs a decision to your Telegram chat with inline buttons, and acts on the button you press:

| Button | Effect |
|---|---|
| **✅ Allow once** | Release the credential for this request only |
| **Allow 15m** / **Allow 1h** / **Allow forever** | Release it **and** create a standing grant (see [Grants](#grants)) |
| **❌ Decline** | Refuse the request |

Two modes:

- **TUI + Telegram** (`aac listen --telegram`): the prompt shows in the terminal *and* in Telegram. The first answer wins; the
  other side is updated ("ALLOWED locally (terminal)" in Telegram, "approved via Telegram" in the TUI). The TUI's
  `[a]` 10-minute auto-approve keeps working as before.
- **Headless** (`aac listen --headless --telegram`): no TUI, no TTY needed. Telegram is the only approver. This is the mode
  for a server, an Alpine box, a container, systemd or OpenRC. (Upstream issues #147 / #156 / #142.)

## Where this plugs in, and what Telegram sees

```
 OpenClaw agent host (untrusted)            relay (zero-knowledge)          trusted host: aac listen (user client)
 aac run --domain github.com ... -- cmd ──► E2E Noise channel ───────────►  decrypt request ─► vault lookup (bw)
                                                                             │
                                                                             ├─► Telegram: "Allow / Decline?" (metadata only)
                                                                             │◄── owner presses a button (long polling)
 child process gets env vars  ◄──────────── E2E Noise channel ◄────────────  send credential (only if allowed)
```

- The decision is made **inside `aac listen`**, at the same point where the TUI asks today (the `UserClientRequest::CredentialRequest`
  reply). The credential still travels **only** over the existing end-to-end encrypted Agent Access channel. It never goes
  through Telegram.
- A Telegram message contains: requesting device (connection name + identity fingerprint), the query (domain / item id / search),
  the matched vault item's domain and id, **which fields** would be released (e.g. `username, password, totp`), the request ID,
  the device's request timestamp and the time received. It never contains passwords, TOTP secrets, notes, usernames, PSKs or
  session keys. Requester-supplied text is shown as plain text (no Markdown/HTML), with control characters removed and a length limit,
  so it can't forge extra lines.
- **Reason:** Agent Access protocol v0 has no "purpose" field (it's an open item in `protocol-v0.md` §5.4), so the message says
  "Reason: not provided". Treat the query, not a story, as what you're approving.
- Pairing (rendezvous mode, headless only): the 6-character handshake fingerprint is sent to Telegram with Allow / Decline, so you
  can compare it with the one shown on the agent side. PSK pairing needs no such check.

### Does the model ever see the secret?

That depends on the **requesting** side, not on Telegram:

- `aac run --domain X --env VAR=password -- cmd`: the credential goes straight into the child process environment. It isn't printed,
  so an agent that only sees the command's output never sees it. **Use this for agents.**
- `aac connect --domain X --output json` (and the upstream OpenClaw skill, which uses it) prints the password to stdout, which ends up
  in the model's context. See [examples/skills/agent-access-inject/SKILL.md](../examples/skills/agent-access-inject/SKILL.md) for a
  skill that only uses `aac run`.

## Security properties

- **Owner only:** button presses and bot commands are accepted only from the configured `--telegram-owner-id`, and only in the
  configured chat (default: your private chat with the bot). Presses from anyone else get "Not authorized" and the request stays pending.
- **Unguessable, single-use callbacks:** each prompt gets a 128-bit random id from the OS CSPRNG (`aac:<id>:<action>`). The first
  accepted press (or the timeout) consumes it. Replays, presses after a timeout and forged ids get "expired or already handled".
- **Timeout:** an unanswered prompt is declined after `--telegram-timeout` seconds (default 90, under the requester's default
  120 s timeout), and the message is edited to show "TIMED OUT".
- **Outcome shown:** every resolved prompt is edited to show what happened (allowed once, allowed with grant, declined, timed out,
  answered in terminal, cancelled) and loses its buttons.
- **Token handling:** the bot token comes from `AAC_TELEGRAM_BOT_TOKEN` or `--telegram-bot-token-file` (deliberately not a
  command-line value, since those show up in `ps`). It is held as a secret, never logged, and stripped from HTTP error messages.
- **No inbound port:** Telegram is polled with `getUpdates` (long polling). No webhook, no listening socket.
- **Fail closed:** if Telegram can't be reached, the request is denied (headless) or left to the terminal (TUI).
- **Only real decisions are messaged:** requests auto-approved under a grant, and requests denied without asking (no matching item,
  vault locked), send nothing to Telegram. They are written to the local log only.

## Grants

**Allow 15m**, **Allow 1h** and **Allow forever** approve the current request and create a *standing grant*. Later requests that match
the grant are approved automatically, without a prompt and **without any Telegram message**. Each one is recorded in the local log
(`Auto-approved request <id> from <device> for <query> under grant <grant-id> (...)`), and the TUI shows it too.

**Scope.** A grant matches only when all three are the same:

1. the requesting device (remote identity fingerprint), and
2. the query (e.g. `domain: github.com`; domains are compared case-insensitively), and
3. the vault item the query resolves to (if `github.com` later resolves to a different item, you're asked again).

So a grant for agent A reading `github.com` doesn't cover agent B, doesn't cover `gitlab.com`, and doesn't cover fetching the same item
by `--id` instead of `--domain`.

**Lifetime and storage.** Grants live **in memory only**. They're never written to disk and are all cleared when `aac listen` restarts
(`aac listen` does have a state directory, `~/.access-protocol/`, but a standing approval is security policy and shouldn't silently
survive a restart). "Forever" means until revoked or until the listener restarts.

**Revoking.**

- The edited approval message keeps a **🗑 Revoke grant** button.
- `/grants` lists active grants (`#1 agent-name (abcdef123456) · domain "github.com" → item <id> · until 2026-10-07 21:45:00 UTC`),
  with a revoke button for each.
- `/revoke <number>` revokes one grant, `/revoke all` revokes everything.
- `/help` (or `/start`) shows a short help.

## Setup

1. **Create a bot:** message [@BotFather](https://t.me/BotFather), `/newbot`, and copy the token (`123456789:AA...`).
2. **Find your numeric user id:** for example message [@userinfobot](https://t.me/userinfobot), or call
   `https://api.telegram.org/bot<TOKEN>/getUpdates` after sending your bot a message and read `message.from.id`.
3. **Open a chat with your bot and press Start.** Bots can't message you first.
4. **Store the token in a file only you can read:**
   ```shell
   install -m 600 /dev/null ~/.config/aac-telegram-token
   printf '%s\n' '123456789:AA...' > ~/.config/aac-telegram-token
   ```
5. **Run the listener:**
   ```shell
   # Interactive TUI + Telegram
   aac listen --telegram --telegram-bot-token-file ~/.config/aac-telegram-token --telegram-owner-id 123456789

   # Headless (servers / containers), reusable PSK so agents can reconnect after restarts
   export BW_SESSION=...   # unlocked Bitwarden CLI session (see below)
   aac listen --headless --telegram --reusable-psk --connection-name openclaw \
     --telegram-bot-token-file /etc/aac/telegram-token --telegram-owner-id 123456789 \
     --token-file /var/lib/aac/psk-token
   ```
   In headless mode the pairing token is written to `--token-file` (mode 0600) or printed to stdout. Give it to the agent host once:
   `aac run --token "$(cat psk-token)" --domain ... -- true`. After that the session is cached on the agent side.

### Options

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--telegram` | `AAC_TELEGRAM` | off | Enable Telegram approvals |
| `--telegram-bot-token-file <PATH>` | `AAC_TELEGRAM_BOT_TOKEN_FILE` | | File with the bot token |
| (env only) | `AAC_TELEGRAM_BOT_TOKEN` | | Bot token (if no file is given) |
| `--telegram-owner-id <ID>` | `AAC_TELEGRAM_OWNER_ID` | required | Only this Telegram user can approve |
| `--telegram-chat-id <ID>` | `AAC_TELEGRAM_CHAT_ID` | owner id | Chat for prompts (presses still must come from the owner) |
| `--telegram-timeout <S>` | `AAC_TELEGRAM_TIMEOUT` | 90 | Auto-decline after S seconds (5–3600) |
| `--telegram-api-url <URL>` | `AAC_TELEGRAM_API_URL` | `https://api.telegram.org` | Self-hosted Bot API server / testing |
| `--headless` | `AAC_HEADLESS` | off | No TUI; requires `--telegram` |
| `--connection-name <NAME>` | | | Headless: name for newly paired devices (shown in prompts) |
| `--token-file <PATH>` | | stdout | Headless: write pairing token / rendezvous code here (0600) |

Boolean env vars accept `1/0`, `true/false`, `yes/no`, `on/off`.

### Unlocking Bitwarden for a headless listener

The built-in `bitwarden` provider uses the Bitwarden CLI (`bw`). Headless there's no `/unlock` prompt, so start `aac listen` with an
unlocked session in `BW_SESSION`:

```shell
bw config server https://vault.example.com     # only for self-hosted / Vaultwarden
bw login                                       # once; state lives in ~/.config/Bitwarden CLI
export BW_SESSION="$(bw unlock --raw)"         # or: bw unlock --passwordfile /run/secrets/bw-master --raw
```

If the vault is locked, requests are denied (logged locally, no Telegram message).

## OpenClaw

- Run `aac listen --headless --telegram` on a host you trust with the vault (a home server, a small Alpine VM or container). It can be
  the OpenClaw host, but a separate host keeps the vault session away from the agents.
- On the OpenClaw host install `aac` and pair once with the PSK token.
- Have agents use **`aac run`**, so secrets are injected into the command's environment instead of printed:
  ```shell
  aac run --domain github.com --env GH_USER=username --env GH_PASS=password -- ./login.sh
  ```
  Install the inject-only skill: `examples/skills/agent-access-inject/SKILL.md` → `~/.openclaw/skills/agent-access-inject/SKILL.md`.
- While a prompt is pending, `aac run` waits (default up to 120 s; keep `--telegram-timeout` lower). Once you press **Allow 1h** for a
  task, the agent's repeated logins in that hour go through without pinging you.

## Alpine Linux

`aac` builds as a musl binary with OpenSSL linked statically (only musl libc is dynamic; about 12 MB). See
[examples/alpine/](../examples/alpine/):

- `Dockerfile`: multi-stage build → Alpine runtime image with `aac` and the Bitwarden CLI. Bitwarden doesn't ship an Alpine package, so
  `bw` is installed from npm (`nodejs` + `npm i -g @bitwarden/cli`), about 200 MB. Without `bw` the image is about 29 MB.
- `aac-listen.initd` / `aac-listen.confd`: OpenRC service running `aac listen --headless --telegram` as an unprivileged user.
- Building directly on Alpine: `apk add rust cargo musl-dev openssl-dev openssl-libs-static pkgconf perl make` then
  `OPENSSL_STATIC=1 cargo build --release -p ap-cli`.

Recent `bw` versions refuse plain-HTTP servers. Self-hosted Vaultwarden needs HTTPS. For a private CA, set `NODE_EXTRA_CA_CERTS`.

## Testing

- Unit tests (`cargo test -p ap-cli telegram`) run the approver against an in-process mock Bot API: allow, decline, wrong user,
  wrong chat, timeout, replay / single-use, forged ids, terminal-wins, grant scope, expiry, forever-until-revoked,
  revoke via button / `/revoke n` / `/revoke all`, no messages for auto-approvals, and no secrets in messages or errors.
- End-to-end runs against real `ap-relay` + `aac listen` + `aac run` / `aac connect` with a mock Telegram server, including
  the TUI driven through a pseudo-terminal, the headless listener inside an Alpine container, and the `bitwarden` provider
  (Alpine + `bw`) against a local Vaultwarden test vault.

## Limitations

- Agent Access is an upstream **early preview**; protocol and APIs may change.
- No purpose/reason field in protocol v0.
- Grants are in-memory and per listener process.
- In TUI mode the terminal still handles one prompt at a time (upstream behaviour). A new request replaces an unanswered one, and its
  Telegram message is marked "CANCELLED". Headless mode handles several pending prompts at once.
- An approved credential is visible to whatever runs on the agent host, including the child process. Telegram approval controls
  *whether* it's released, not what the agent does with it afterwards.
