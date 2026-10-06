# `aac openshell-driver` — operator note

Bitwarden as an external credential driver for an
[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) gateway. The binding
contract is §M8 of `apps/desktop/src/agent-access/agent-access-architecture.md`
in the clients repo; this note covers the aac side only.

Code: `crates/ap-openshell` (no dependency on ap-cli or sdk-sm), wired into
`aac` behind the `openshell` cargo feature (on by default).

## What it does

```
openshell-gateway ──spawns──▶ aac openshell-driver --gateway <name> --bind-socket <driverSock>
        │  gRPC CredentialDriver over the 0600 driver socket
        ▼
aac ──(read-only lookups: GetProvider, ListSandboxes, ListSandboxProviders,
       GetProviderProfile, GetSandboxPolicyStatus; mTLS or loopback plaintext)──▶ gateway API
aac ──one JSON line "openshellResolve"──▶ ~/.bitwarden-agent-access-openshell.sock (desktop)
        ▼ human approval in Bitwarden desktop
aac ──ResolvedCredential{value, expiration_time}──▶ gateway ──▶ supervisor (placeholders only in the sandbox)
```

- `StoreCredential` accepts only `bw://item/<uuid>#username`,
  `bw://item/<uuid>#password` or `bw://secret/<uuid>` (or an already-encoded
  `bw1:` handle) and returns a `bw1:` handle. No I/O. Anything else is
  `INVALID_ARGUMENT "Bitwarden driver accepts only bw:// references"`, so the
  gateway database never holds a real secret.
- `ResolveCredentials` resolves one provider's batch with one desktop approval,
  all or nothing, bounded at 27 s (gateway allows 30 s), or at the caller's
  `grpc-timeout` minus 3 s when that is shorter. One at a time. A request with
  under 2 s of approval time left fails `DEADLINE_EXCEEDED` without contacting
  desktop; anything above that is sent, because desktop can answer an identical
  retry at once from a carried decision (clients architecture §M8.18).
- Sandbox attribution fails closed unless exactly one sandbox has the provider
  attached. An empty endpoint set, an IPv6 literal, a `**` glob, a port range
  over 64 entries or any lookup error/timeout (3 s each) also fails closed.
- `expiration_time` comes from the desktop's approval lifetime (`perRequest`,
  `ttl`, or unset for `sandboxLifetime`).

## Setup (user)

1. Turn on Agent Access and the OpenShell toggle in Bitwarden desktop
   (macOS / Linux, not Snap or AppImage).
2. Merge the `gateway.toml` snippet the desktop shows, then restart the gateway.
   The snippet's `command` must point at the aac bundled with the desktop app,
   and the gateway must spawn it directly (attestation checks the parent is
   `openshell-gateway`). The driver serves only the process that spawned it:
   every driver-socket connection must come from the same uid and from aac's
   parent pid, and aac refuses to start when its parent is pid 0 or 1. aac
   also refuses a desktop socket that isn't a 0600 socket owned by the same
   uid, with a listener running as the same uid.
3. `openshell provider create --name <provider>-<sandbox> --type <profile> --credential KEY=bw://item/<uuid>#password`
4. `openshell sandbox provider attach <sandbox> <provider>-<sandbox>` — exactly
   one sandbox per provider.

## Flags and environment

| Flag | Default | Notes |
| --- | --- | --- |
| `--gateway <name>` | required | Selects `<cfg>/gateways/<name>/metadata.json`. `.`/`..` refused. |
| `--bind-socket <path>` | appended by the gateway | Parent dir must be owned by the user and not group/world-writable. A non-socket file at the path is never deleted. |
| `--desktop-socket <path>` / `AAC_OPENSHELL_SOCKET` | `~/.bitwarden-agent-access-openshell.sock` | Desktop listener exists only while the toggle is on. |
| `--openshell-config-dir <dir>` | `$XDG_CONFIG_HOME/openshell`, else `~/.config/openshell` | |

Gateway auth for the lookups: `auth_mode` `mtls` (client identity from
`mtls/{ca.crt,tls.crt,tls.key}`) or `plaintext` with a loopback `http://`
endpoint. Anything else — including a missing `auth_mode` — makes every
resolve fail with "unsupported gateway auth mode"; `StoreCredential` keeps
working.

## Error mapping (whole batch)

| Desktop outcome | gRPC |
| --- | --- |
| denied | `PERMISSION_DENIED` |
| timeout | `DEADLINE_EXCEEDED` |
| locked | `UNAVAILABLE` |
| rateLimited | `RESOURCE_EXHAUSTED` |
| notFound, error, desktop off, malformed reply | `FAILED_PRECONDITION` |

Status messages are fixed strings; the desktop's free-form message is never
echoed and no message contains vault data.

## Logging

`provider_id`, `sandbox_id`, status code and duration only. Never values,
handles with values, key material, or item/secret names.

## Verification

```
cargo test -p ap-openshell
cargo clippy -p ap-openshell --all-targets -- -D warnings
cargo fmt --check -p ap-openshell
```

`ap-cli` with `--features openshell` needs the sdk-sm sibling (bitwarden-scan)
to build.

## Known gaps / unverified (see §M8.15)

- Not exercised against a live gateway. U1 (value pass-through), U3 (expiry
  honoured by gateway and supervisor), U4 (supervisor tolerates ~25 s), U6 (no
  re-entrancy deadlock on lookups), U7 (direct spawn) and U12 (metadata field
  names) are read from source only.
- `advisorEnabled` is sent as `true` only when an endpoint is
  `advisor_proposed`; otherwise it is omitted (unknown), which the desktop
  shows as "may be on". The driver never claims `false`.
- The desktop build (`apps/desktop/desktop_native/build.js`) compiles aac with
  `--no-default-features --features openshell` on macOS and Linux and checks
  `aac openshell-driver --help` after the copy. Not run here (needs sdk-sm).
- Handle cross-check (§M8.17): applied only when `GetProvider` returns
  `credential_handles` (U13, unverified).
- In this checkout the sdk-sm sibling lacks `crates/bitwarden-scan`, so the
  workspace does not load. The ap-openshell checks were run from a scratch
  overlay workspace that omits ap-cli and ap-uniffi.
