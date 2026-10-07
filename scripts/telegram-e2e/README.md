# Telegram approval end-to-end tests (fork)

Black-box tests for `aac listen --telegram` using real `ap-relay`, `aac listen` and `aac run` / `aac connect` processes, the
built-in `example` provider (demo credentials, no vault), and a mock Telegram Bot API (`mock_telegram.py`) that records
messages and lets the test press buttons or send bot commands. Nothing talks to the real Telegram.

```shell
cargo build -p ap-cli -p ap-relay
python3 scripts/telegram-e2e/e2e.py target/debug/aac target/debug/ap-relay        # headless: 32 checks
python3 scripts/telegram-e2e/e2e_tui.py target/debug/aac target/debug/ap-relay    # TUI via a pty: 10 checks

# Listener inside an Alpine container (image with /usr/local/bin/aac), remote side on the host:
LISTENER_AAC=/usr/local/bin/aac python3 scripts/telegram-e2e/e2e.py target/debug/aac target/debug/ap-relay \
  --listener-cmd-prefix "docker run --rm --name aac-e2e-listener --network host --user $(id -u):$(id -g) --entrypoint '' aac-listen"
```

Ports used: 18080/18081 (headless), 18090/18091 (TUI).

Covered: allow once (credential injected into the child env, never printed), decline, replayed callback, wrong user / wrong
chat, timeout auto-decline + late press, not-found (no Telegram message), Allow 15m (silent auto-approvals, scope by
domain), `/grants`, `/revoke all`, Allow forever + revoke button, SIGTERM shutdown, no secret / PSK / bot token in logs or
Telegram messages, rendezvous pairing approved in Telegram, and in TUI mode: Telegram-wins, terminal-wins (`y` / `n`, with
the Telegram message updated) and Telegram grants.
