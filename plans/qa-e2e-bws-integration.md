# QA Test Plan — End-to-End: Bitwarden Secrets Manager (`bws`) Provider

**Scope:** Manual/scriptable end-to-end verification of the `bws` credential provider integrated into the
`aac` CLI, covering the full flow: relay → user-client (`listen --provider bws`) → remote-client
(`connect`) → credential delivery. Includes authentication, lookup semantics, single-shot mode, session
resumption, security properties, and regression of the existing `bitwarden` (bw CLI) provider.

**Out of scope:** Unit/integration tests already automated in `cargo test`; load testing; the
`python-pyo3` / wasm examples.

---

## 1. Test Environment & Fixtures

### 1.1 Builds

| Item | Value |
|------|-------|
| Build under test | `cargo build --workspace` at the BWS-integration commit (debug is fine) |
| Binaries | `aac` (CLI), `ap-relay` (relay server) |
| Baseline build (for TC-PQ-01 only) | Latest `main` build prior to the `ml-dsa` rc.9 bump |

### 1.2 Bitwarden Secrets Manager fixtures

Create in a test organization (cloud `bitwarden.com`, and optionally one self-hosted instance):

| Fixture | Value |
|---------|-------|
| Project | `aac-e2e` |
| Secret S1 | key `db.example.com`, value `s3cret-value-1`, note `primary db` |
| Secret S2 | key `API_KEY`, value `s3cret-value-2`, note empty |
| Secret S3 | key `Db.Example.COM` — **only if** the org allows a second key differing only by case; otherwise skip TC-LKP-05b |
| Secret S4 | key `unicode-ключ-🔑`, value 4 KB random ASCII string, note 1 KB text |
| Machine account token T-RW | access token with read access to `aac-e2e` |
| Token T-REVOKED | a token created then revoked before testing |
| Token T-NOORG | *(if creatable)* token not associated with an organization — otherwise simulate by expectation only |

Record the UUID of S1 as `S1_ID` (from the BWS web vault or `bws secret list`).

### 1.3 Environment reset (run before every test case unless stated)

```bash
pkill -f ap-relay || true
rm -rf ~/.access-protocol/          # identity keys + session caches
unset BWS_ACCESS_TOKEN BWS_SERVER_URL BW_SESSION
```

Standard relay startup: `cargo run --bin ap-relay` (listens on `ws://localhost:8080`).

**Conventions:** "Listen side" = `cargo run --bin aac -- listen --provider bws`.
"Connect side" = `cargo run --bin aac -- connect ...`. Pairing token = the 9-char `ABC-DEF-GHI`
code printed by the listen side.

---

## 2. Provider Status & Authentication (TUI listen side)

### TC-AUTH-01 — No token configured → Locked prompt
**Priority:** P0
**Steps:**
1. Reset env. Start relay. Start listen side with `--provider bws` and no `BWS_ACCESS_TOKEN`.
**Expected:**
- TUI header shows provider name **"Bitwarden Secrets Manager"**.
- Status shows locked state with prompt **"BWS access token"** (not "Master password").
- No network call to Bitwarden is made (verify no auth error appears without input).

### TC-AUTH-02 — Unlock with valid access token via TUI
**Priority:** P0
**Precondition:** TC-AUTH-01 running.
**Steps:**
1. Paste token T-RW at the unlock prompt.
**Expected:**
- Status transitions to Ready; user info shows `org <uuid>` matching the test org's ID.
- The pasted token is never echoed to screen or logs.

### TC-AUTH-03 — Unlock with malformed token
**Priority:** P0
**Steps:**
1. As TC-AUTH-01, then enter `not-a-token` at the prompt.
**Expected:**
- Error message "Invalid Bitwarden Secrets Manager access token: …".
- The entered string does **not** appear in the error message or logs.
- Provider remains locked; retry with T-RW then succeeds (recovery works).

### TC-AUTH-04 — Valid token via `BWS_ACCESS_TOKEN` env
**Priority:** P0
**Steps:**
1. `export BWS_ACCESS_TOKEN=<T-RW>`; start listen side.
**Expected:** Status is Ready immediately (after one login round-trip); no unlock prompt required.

### TC-AUTH-05 — Well-formed but revoked/expired token
**Priority:** P1
**Steps:**
1. `export BWS_ACCESS_TOKEN=<T-REVOKED>`; start listen side.
**Expected:**
- Status shows **Unavailable** with reason "Bitwarden Secrets Manager login failed: …".
- Reason text contains no token material.

### TC-AUTH-06 — Empty env var treated as absent
**Priority:** P2
**Steps:**
1. `export BWS_ACCESS_TOKEN=""`; start listen side.
**Expected:** Behaves exactly like TC-AUTH-01 (Locked, prompt shown), not a login failure.

### TC-AUTH-07 — Self-hosted `BWS_SERVER_URL`
**Priority:** P1 *(requires self-hosted instance; else verify via mitm/hosts-file that URLs are derived correctly)*
**Steps:**
1. `export BWS_SERVER_URL=https://vault.selfhosted.example` (test once with and once without trailing `/`).
2. `export BWS_ACCESS_TOKEN=<self-hosted T-RW>`; start listen side.
**Expected:**
- Login targets `<url>/identity`, API calls target `<url>/api` (no double slash in either form).
- Status Ready; lookups (Section 4) work identically.

### TC-AUTH-08 — Unknown provider name rejected
**Priority:** P2
**Steps:**
1. `aac listen --provider nope`
**Expected:** Clean error listing available providers: `bitwarden, bws, example`. Exit code 1.

### TC-AUTH-09 — Alias `bitwarden-sm`
**Priority:** P2
**Steps:**
1. Start listen side with `--provider bitwarden-sm` and T-RW in env.
**Expected:** Identical behavior to `--provider bws` (Ready, name "Bitwarden Secrets Manager").

---

## 3. End-to-End Pairing + Credential Delivery

### TC-E2E-01 — Rendezvous pairing, Domain query matches secret key
**Priority:** P0
**Steps:**
1. Reset env, start relay. Listen side with T-RW (Ready).
2. Note the pairing token; connect side: `aac connect --token <CODE>` (interactive TUI).
3. Verify the 6-char handshake fingerprint matches on both TUIs; approve on listen side.
4. On connect side, request domain `db.example.com`.
5. Approve the credential request on the listen side.
**Expected:**
- Credential arrives on connect side: password = `s3cret-value-1`, username = `db.example.com`
  (the secret **key**), notes = `primary db`, credential_id = `S1_ID`, domain = `db.example.com`,
  no TOTP/URI.
- Relay logs (INFO) show only fingerprints — never plaintext values (spot-check).

### TC-E2E-02 — PSK pairing
**Priority:** P0
**Steps:**
1. Listen side with `--psk` flag + T-RW. Copy the 129-char PSK token (`<psk>_<fingerprint>`).
2. Connect side: `aac connect --token <PSK-TOKEN>`.
3. Request `API_KEY`; approve.
**Expected:**
- No fingerprint-verification step required (PSK authenticates both sides).
- Credential: password `s3cret-value-2`, username `API_KEY`, **notes absent** (empty note omitted).

### TC-E2E-03 — Denied approval
**Priority:** P0
**Steps:**
1. As TC-E2E-01 but **deny** the credential request on the listen side.
**Expected:** Connect side receives a clean denial (no credential, no crash); listen side returns to
idle and can serve a subsequent approved request in the same session.

### TC-E2E-04 — Lookup miss
**Priority:** P0
**Steps:**
1. Paired session; request domain `nonexistent.example`.
**Expected:** Connect side gets "not found" (not an auth error, not a hang); listen side stays Ready.

### TC-E2E-05 — Token revoked mid-session
**Priority:** P1
**Steps:**
1. Pair with T-RW, do one successful lookup.
2. Revoke T-RW in the BWS console. Request `db.example.com` again.
**Expected:** Connect side receives a "provider not ready"-class failure (message mentions login/fetch
failure), **not** "not found". No panic; TUI remains responsive.
*(Note: the session caches the SDK client — depending on SDK token refresh timing the first post-revocation
lookup may still succeed. Repeat after ~1h token expiry if needed; record actual behavior.)*

---

## 4. Lookup Semantics (paired session, T-RW)

### TC-LKP-01 — Exact key match preferred
**Steps:** Request `db.example.com`. **Expected:** S1 returned. **P0**

### TC-LKP-02 — Case-insensitive fallback
**Steps:** Request `api_key` (lowercase). **Expected:** S2 returned (case-insensitive match). **P1**

### TC-LKP-03 — Id query with valid UUID
**Steps:** From connect side use an ID query (or single-shot `--id` equivalent if exposed): `S1_ID`.
**Expected:** S1 returned; `domain` field empty (Id queries don't set domain). **P1**

### TC-LKP-04 — Id query with non-UUID string
**Steps:** Id query `not-a-uuid`. **Expected:** Not found (graceful; no API call, no error). **P2**

### TC-LKP-05a — Unicode key
**Steps:** Request `unicode-ключ-🔑`. **Expected:** S4 returned intact; 4 KB value delivered unmodified
(byte-compare). **P2**

### TC-LKP-05b — Duplicate keys differing only by case *(if S3 creatable)*
**Steps:** Request `db.example.com`. **Expected:** Exact-case match (S1) wins deterministically. **P2**

### TC-LKP-06 — Secret updated between lookups
**Steps:** Look up S1; change S1's value in the BWS console; look up again in the same session.
**Expected:** Second lookup returns the **new** value (no stale caching of secret values). **P1**

---

## 5. Single-Shot / Agent Mode (`aac connect --domain … --output …`)

All cases: relay running, listen side Ready with T-RW and a pre-paired cached session (run TC-E2E-01
first without clearing `~/.access-protocol`), unless stated.

### TC-SS-01 — JSON success
**Priority:** P0
**Steps:** `aac connect --domain db.example.com --output json`
**Expected:**
- Exit code **0**; stdout is exactly one JSON object `{"success": true, "credential": {...}}` with the
  S1 mapping from TC-E2E-01; all status chatter on stderr only (`stdout | jq .` parses cleanly).

### TC-SS-02 — Text output
**Steps:** Same with `--output text`. **Expected:** key-value lines incl. password on stdout; exit 0. **P1**

### TC-SS-03 — Credential not found → exit 4
**Steps:** `aac connect --domain nonexistent.example --output json`
**Expected:** Exit code **4**; JSON (or stderr) indicates not-found; nothing sensitive on stdout. **P0**

### TC-SS-04 — Relay down → exit 2
**Steps:** Stop relay; run TC-SS-01 command. **Expected:** Exit code **2**, connection-failed message
on stderr, no hang beyond the connection timeout. **P0**

### TC-SS-05 — Listen side locked (no BWS token) → provider-not-ready surface
**Steps:** Restart listen side **without** `BWS_ACCESS_TOKEN` (Locked); run TC-SS-01 command.
**Expected:** Non-zero exit; error clearly indicates the provider/vault is not ready (distinguishable
from "not found"). Record actual exit code and message. **P1**

### TC-SS-06 — Multiple cached sessions require `--session`
**Steps:** Pair the connect identity with two different listen identities; run `aac connect --domain …`
without `--session`. **Expected:** Error demanding `--session`, listing candidates; with `--session
<fingerprint>` it succeeds. **P2**

---

## 6. Session Resumption & Connection Management

### TC-SESS-01 — Resume without re-handshake
**Priority:** P0
**Steps:**
1. Complete TC-E2E-01. Quit both TUIs (relay stays up). Restart listen side (T-RW), restart connect
   side **without** `--token`.
2. Request `API_KEY`; approve.
**Expected:** No rendezvous/PSK step, no fingerprint verification; lookup succeeds via cached
transport state from `~/.access-protocol/session_cache_*.json`.

### TC-SESS-02 — `connections list` / `clear`
**Steps:** After TC-SESS-01: `aac connections list`, then `aac connections clear`, then attempt
single-shot connect. **Expected:** List shows the session with fingerprint + timestamps; after clear,
single-shot fails with a "no cached session" error until re-paired. **P1**

### TC-SESS-03 — Relay restart mid-session
**Steps:** With both sides connected, restart the relay; wait for client reconnect/backoff; request a
credential. **Expected:** Both sides reconnect (watch logs), lookup succeeds without re-pairing. **P1**

---

## 7. Security Verification

### TC-SEC-01 — No secrets or tokens in logs at debug/trace
**Priority:** P0
**Steps:**
1. Run TC-E2E-01 with `RUST_LOG=debug` on listen/connect sides and relay; capture all output.
2. `grep` captures for: the access token (T-RW string), `s3cret-value-1`, `s3cret-value-2`.
**Expected:** Zero hits in all three logs. Repeat with `RUST_LOG=ap_noise=trace`: transport traces show
ciphertext/lengths only.

### TC-SEC-02 — No BWS auth state persisted to disk
**Priority:** P0
**Steps:** After TC-E2E-01, inspect `~/.access-protocol/` and `~/.config` / platform dirs.
**Expected:** No file containing the access token or SDK auth state (design: `state_file: None`).
`grep -r <token-prefix> ~/.access-protocol ~/.config` finds nothing.

### TC-SEC-03 — Relay never sees plaintext
**Priority:** P1
**Steps:** Run TC-E2E-01 with the relay under `RUST_LOG=trace`; optionally capture loopback traffic
(`tcpdump -i lo0 port 8080`).
**Expected:** WebSocket frames contain base64 Noise ciphertext; `s3cret-value-1` (and its base64
encoding) absent from capture and relay logs.

### TC-SEC-04 — MITM verification still enforced (rendezvous)
**Priority:** P1
**Steps:** During TC-E2E-01 step 3, **reject** the fingerprint on the listen side.
**Expected:** Handshake aborted; no credential path possible; connect side informed. (Single-shot mode
documents no fingerprint check — confirm docs/behavior match.)

---

## 8. Regression

### TC-REG-01 — `bitwarden` (bw CLI) provider unchanged
**Priority:** P0
**Steps:** Run the pre-existing demo flow (README/CLAUDE.md) with `--provider bitwarden` and an
unlocked `bw` vault: rendezvous pair, request a domain with a known login item.
**Expected:** Behavior identical to pre-integration: unlock via master password/session key works,
login item maps username/password/totp/uri as before.

### TC-REG-02 — `example` provider
**Steps:** `aac listen --provider example`; pair; request the example domain. **Expected:** works as
before (sanity check that the async-trait refactor didn't break the third impl). **P2**

### TC-REG-03 — Workspace gates
**Steps:** `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
**Expected:** All pass. *(Known pre-existing: unawaited-future warning in `ap-uniffi` tests — track separately.)* **P0**

### TC-PQ-01 — Mixed-build PQ pairing (ml-dsa rc.7 → rc.9 bump)
**Priority:** P1
**Steps:**
1. Build baseline `aac`/`ap-relay` from pre-bump `main`; build current branch.
2. Cross-test with `experimental-post-quantum-crypto` enabled: (a) old listen ↔ new connect via new
   relay, (b) new listen ↔ old connect via old relay, (c) old identity key file
   (`~/.access-protocol/*.key`) loaded by the new build.
**Expected:** Either full interop **or** a documented, clean failure (auth/signature rejection with a
clear error, no panic). Record the outcome — this determines whether the bump is a breaking change for
PQ identities and must be release-noted.

---

## 9. Reporting

For each case record: pass/fail, build SHA, OS, cloud vs self-hosted, actual vs expected on failure,
and captured logs for any P0/P1 failure. Any P0 failure blocks merge; P1 failures need a filed issue
before release.
