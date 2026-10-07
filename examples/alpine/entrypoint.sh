#!/bin/sh
# Unlock the Bitwarden CLI (if needed) and run the headless listener with Telegram approvals.
#
# Environment:
#   BW_SESSION         already-unlocked session key (takes precedence), or
#   BW_PASSWORD_FILE   file with the master password, used once to run `bw unlock`
#   AAC_TELEGRAM_BOT_TOKEN_FILE / AAC_TELEGRAM_BOT_TOKEN, AAC_TELEGRAM_OWNER_ID   (required)
#   AAC_RELAY_URL      optional relay override
# One-time login (stored in the /var/lib/aac volume):
#   docker run -it --rm -v aac-data:/var/lib/aac --entrypoint sh aac-listen -c 'bw config server https://vault.example.com; bw login'
set -eu

if [ -z "${BW_SESSION:-}" ] && [ -n "${BW_PASSWORD_FILE:-}" ] && command -v bw >/dev/null 2>&1; then
    BW_SESSION="$(bw unlock --passwordfile "$BW_PASSWORD_FILE" --raw)"
    export BW_SESSION
    bw sync >/dev/null 2>&1 || true
fi

set -- --headless --telegram ${AAC_RELAY_URL:+--relay-url "$AAC_RELAY_URL"} "$@"
exec aac listen "$@"
