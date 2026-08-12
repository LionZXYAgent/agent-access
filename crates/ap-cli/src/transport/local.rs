//! Local transport client for the Bitwarden desktop agent-access endpoint.
//!
//! Speaks "Local wire protocol v1" exactly as specified in the desktop app's
//! binding contract (`agent-access-architecture.md`, section "Local wire
//! protocol v1"): one connection per request. The client sends a single
//! `\n`-terminated JSON request line (UTF-8, camelCase field names), the
//! server replies with a single JSON response line and closes the
//! connection. Unknown response fields are ignored (forward compatibility).
//! Responses over 64 KiB are rejected. Server-side approval is
//! human-in-the-loop and can take up to 60s, so the client read timeout is
//! held well above that, at 120s.
//!
//! This module never prints credential values — callers are responsible for
//! keeping [`WireCredential`] contents out of logs and error messages, and
//! every [`LocalTransportError`] variant here is constructed without one.

use std::path::PathBuf;
use std::time::Duration;

use ap_client::CredentialQuery;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use zeroize::Zeroizing;

/// Local wire protocol version implemented by this client.
const PROTOCOL_VERSION: u32 = 1;

/// Read timeout for a full request/response round trip. Server-side
/// approval can take up to 60s; this stays comfortably above that per the
/// protocol contract ("clients must use a read timeout >= 120s").
const READ_TIMEOUT: Duration = Duration::from_secs(120);

/// Maximum accepted response line length, per wire protocol v1 ("Max line
/// length 64 KiB").
const MAX_LINE_BYTES: usize = 64 * 1024;

/// Reference URI scheme used for value-free item pointers
/// (`bw://item/<credentialId>`). Redeeming one is a fresh `id`-query
/// request with its own approval — it is not a capability token.
const REFERENCE_PREFIX: &str = "bw://item/";

/// If `value` looks like a `bw://item/<id>` reference, return the bare id;
/// otherwise return `value` unchanged. Lets `--id`/`--ref` accept either
/// form.
pub fn strip_reference(value: &str) -> &str {
    value.strip_prefix(REFERENCE_PREFIX).unwrap_or(value)
}

/// Reference URI scheme used for value-free Secrets Manager secret pointers
/// (`bw://secret/<secretId>`) — distinct from `bw://item/<id>` (architecture
/// doc, M4: "Reference scheme is `bw://secret/<id>` — distinct from
/// `bw://item/<id>`"). Redeeming one is a fresh `id`-query `secretRequest`
/// with its own approval, exactly like items.
pub const SECRET_REFERENCE_PREFIX: &str = "bw://secret/";

/// If `value` looks like a `bw://secret/<id>` reference, return the bare id;
/// otherwise return `value` unchanged. Mirrors [`strip_reference`] for the
/// secrets reference scheme.
pub fn strip_secret_reference(value: &str) -> &str {
    value.strip_prefix(SECRET_REFERENCE_PREFIX).unwrap_or(value)
}

/// Build a [`SecretQueryInput`] from a `--secret <name-or-bw://secret/id>`
/// CLI-style value: a `bw://secret/<id>` reference resolves to an `Id` query
/// (redeeming the reference, with its own fresh approval); anything else is
/// treated as a `Name` query (exact match, falling back to a unique
/// case-insensitive match — bws prior art). Shared by `aac connect --secret`,
/// `aac run --secret`, and the top-level shorthand.
pub fn secret_query_from_flag(value: &str) -> SecretQueryInput {
    if value.starts_with(SECRET_REFERENCE_PREFIX) {
        SecretQueryInput::Id(strip_secret_reference(value).to_string())
    } else {
        SecretQueryInput::Name(value.to_string())
    }
}

/// Derive the default environment-variable name for a secret's own name:
/// uppercased, with every character outside `[A-Z0-9_]` replaced by `_`, and
/// `_`-prefixed if the result would otherwise start with a digit (env var
/// names can't start with a digit). Shared by `aac run --secret` and the
/// `run_with_secret` MCP tool; `--secret-env`/`env` explicitly override this.
pub fn secret_env_var_name(name: &str) -> String {
    let mut out: String = name
        .to_uppercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// Sanitize a username for embedding in a Windows named-pipe path: every
/// character NOT in `[A-Za-z0-9_-]` (spaces, domain separators, unicode,
/// ...) is replaced with `_`, never dropped.
///
/// Must stay identical to WINDOWS_PIPE_NAME_SANITIZER in bitwarden/clients
/// apps/desktop/src/agent-access/main/main-agent-access.service.ts — the two
/// sides derive the same pipe name independently from the same OS username,
/// so any divergence (e.g. dropping vs. replacing disallowed characters)
/// causes the client to connect to a pipe name the server never binds,
/// silently falling back to the relay.
///
/// Pure string logic kept platform-independent so it's covered by tests on
/// every CI platform even though its only call site is windows-only.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn sanitize_username(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Resolved address of the local agent-access endpoint.
#[derive(Debug, Clone)]
pub enum LocalEndpoint {
    /// Unix domain socket path (macOS/Linux).
    #[cfg(unix)]
    Unix(PathBuf),
    /// Windows named pipe path (`\\.\pipe\...`).
    #[cfg(windows)]
    Pipe(String),
}

impl LocalEndpoint {
    /// Build an endpoint from an explicit override (`--socket` flag or
    /// `AAC_SOCKET` env var). The override is used verbatim as a path
    /// (unix) or pipe name (windows).
    pub fn from_override(value: &str) -> Self {
        #[cfg(unix)]
        {
            LocalEndpoint::Unix(PathBuf::from(value))
        }
        #[cfg(windows)]
        {
            LocalEndpoint::Pipe(value.to_string())
        }
    }

    /// The platform default endpoint (both sides hardcode the same
    /// default; see architecture doc "Socket path (fixed,
    /// userData-independent)"). Returns `None` when the default cannot be
    /// computed (e.g. no resolvable home directory on unix) — callers
    /// should treat that as "local unavailable" and use the relay.
    pub fn default_endpoint() -> Option<Self> {
        #[cfg(unix)]
        {
            dirs::home_dir()
                .map(|home| home.join(".bitwarden-agent-access.sock"))
                .map(LocalEndpoint::Unix)
        }
        #[cfg(windows)]
        {
            let user = std::env::var("USERNAME").unwrap_or_default();
            Some(LocalEndpoint::Pipe(format!(
                r"\\.\pipe\bitwarden.agent-access.{}",
                sanitize_username(&user)
            )))
        }
    }
}

/// Delivery mode requested for a credential response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum WireDelivery {
    /// Values are returned to `aac` for exec-injection — never printed.
    Inject,
    /// No secret values are ever included in the reply.
    Reference,
    /// No secret values are ever included in the reply. The desktop resolves
    /// the credential and hands it directly to the browser extension, which
    /// fills the active tab — the value never enters this process
    /// (architecture doc, M5). Request-side only: the desktop side either
    /// speaks this delivery mode or rejects it as unknown; there is nothing
    /// for this client to deserialize back out of `delivery` itself.
    Fill,
}

/// Identifies this client to the desktop app.
#[derive(Debug, Clone, Serialize)]
struct WireClientInfo {
    name: &'static str,
    version: &'static str,
}

/// Query payload, adjacently tagged to match the wire protocol exactly:
/// `{"type":"domain","value":"github.com"}`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
enum WireQuery {
    Domain(String),
    Id(String),
    Search(String),
}

impl From<&CredentialQuery> for WireQuery {
    fn from(query: &CredentialQuery) -> Self {
        match query {
            CredentialQuery::Domain(d) => WireQuery::Domain(d.clone()),
            CredentialQuery::Id(id) => WireQuery::Id(id.clone()),
            CredentialQuery::Search(s) => WireQuery::Search(s.clone()),
        }
    }
}

/// Query for a Secrets Manager secret over the local transport. Mirrors
/// [`ap_client::CredentialQuery`], with `Name` in place of `Domain` — SM
/// secrets have no domain notion; `name` is an exact key match, falling back
/// to a unique case-insensitive match (bws prior art), per the architecture
/// doc's `secretRequest` wire shape.
#[derive(Debug, Clone)]
pub enum SecretQueryInput {
    /// Look up by secret name (exact, falling back to unique
    /// case-insensitive match).
    Name(String),
    /// Look up by secret UUID.
    Id(String),
    /// Free-text search, exact-name-first ranking.
    Search(String),
}

/// Query payload for a `secretRequest`, adjacently tagged to match the wire
/// protocol exactly: `{"type":"name","value":"DB_PASSWORD"}`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
enum WireSecretQuery {
    Name(String),
    Id(String),
    Search(String),
}

impl From<&SecretQueryInput> for WireSecretQuery {
    fn from(query: &SecretQueryInput) -> Self {
        match query {
            SecretQueryInput::Name(n) => WireSecretQuery::Name(n.clone()),
            SecretQueryInput::Id(id) => WireSecretQuery::Id(id.clone()),
            SecretQueryInput::Search(s) => WireSecretQuery::Search(s.clone()),
        }
    }
}

/// Input to a local `secretCreate` request: the new secret's name and value,
/// plus an optional note and an optional project-name hint. Public,
/// caller-facing counterpart of [`WireSecretCreate`] — mirrors how
/// [`SecretQueryInput`] relates to [`WireSecretQuery`]. Create-only, per the
/// architecture doc's M4b: no update, no delete.
#[derive(Clone)]
pub struct SecretCreateInput {
    pub name: String,
    pub value: Zeroizing<String>,
    pub note: Option<String>,
    pub project: Option<String>,
}

// Manual Debug: never print the value, even in a derived debug string.
impl std::fmt::Debug for SecretCreateInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretCreateInput")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .field("note", &self.note.as_ref().map(|_| "[present]"))
            .field("project", &self.project)
            .finish()
    }
}

/// The `fill` sub-object of a `credentialRequest` with `delivery: "fill"`
/// (architecture doc, M5 §2). Value-free by construction — `fields` names
/// which roles to fill and `target_token` optionally echoes a plan a prior
/// `describeFillTarget` call produced; neither ever carries a credential
/// value. `submit` is cut from v1 entirely (M5 decision 7) and does not
/// appear here.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct WireFill {
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_token: Option<String>,
}

impl From<&FillInput> for WireFill {
    fn from(input: &FillInput) -> Self {
        Self {
            fields: input.fields.clone(),
            target_token: input.target_token.clone(),
        }
    }
}

/// A single request line, `\n`-terminated and sent as-is. Generic over the
/// query payload shape so `credentialRequest` and `secretRequest` — which
/// carry differently-tagged `query` objects — can share one wire-framing
/// type; `op` selects which resource kind the desktop side dispatches to.
/// `fill` is only ever populated for a `credentialRequest` with `delivery:
/// "fill"` (architecture doc, M5 §2) — `skip_serializing_if` keeps every
/// other op's wire bytes byte-identical to before this field existed.
#[derive(Debug, Clone, Serialize)]
struct WireRequest<Q: Serialize> {
    version: u32,
    op: &'static str,
    query: Q,
    delivery: WireDelivery,
    #[serde(skip_serializing_if = "Option::is_none")]
    fill: Option<WireFill>,
    client: WireClientInfo,
}

impl<Q: Serialize> WireRequest<Q> {
    fn for_op(op: &'static str, query: Q, delivery: WireDelivery) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            op,
            query,
            delivery,
            fill: None,
            client: WireClientInfo {
                name: "aac",
                version: env!("CARGO_PKG_VERSION"),
            },
        }
    }
}

impl WireRequest<WireQuery> {
    /// Credential request constructor — kept as a dedicated 2-arg
    /// constructor (rather than requiring every existing call site to pass
    /// `"credentialRequest"`) so the pre-existing call sites don't churn.
    fn new(query: &CredentialQuery, delivery: WireDelivery) -> Self {
        Self::for_op("credentialRequest", WireQuery::from(query), delivery)
    }

    /// `credentialRequest` + `delivery: "fill"` constructor (architecture
    /// doc, M5 §2). `fill_params` is the caller's optional `fill` object;
    /// `None` here means the `fill` key is omitted from the wire request
    /// entirely, not sent as an empty object.
    fn fill(query: &CredentialQuery, fill_params: Option<&FillInput>) -> Self {
        let mut request = Self::for_op(
            "credentialRequest",
            WireQuery::from(query),
            WireDelivery::Fill,
        );
        request.fill = fill_params.map(WireFill::from);
        request
    }
}

impl WireRequest<WireSecretQuery> {
    fn secret(query: &SecretQueryInput, delivery: WireDelivery) -> Self {
        Self::for_op("secretRequest", WireSecretQuery::from(query), delivery)
    }
}

/// The `create` payload of a `secretCreate` request, per the architecture
/// doc's M4b wire shape: `{"name":"DB_PASSWORD","value":"…","note":"…",
/// "project":"my-app"}`. `name`/`value` are required non-empty (validated by
/// callers, e.g. the `create_secret` MCP tool); `note` and `project` are
/// omitted entirely when absent rather than serialized as `null`.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct WireSecretCreate {
    name: String,
    value: Zeroizing<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<String>,
}

// Manual Debug: never print the value, even in a derived debug string.
impl std::fmt::Debug for WireSecretCreate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireSecretCreate")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .field("note", &self.note.as_ref().map(|_| "[present]"))
            .field("project", &self.project)
            .finish()
    }
}

impl From<&SecretCreateInput> for WireSecretCreate {
    fn from(input: &SecretCreateInput) -> Self {
        Self {
            name: input.name.clone(),
            value: input.value.clone(),
            note: input.note.clone(),
            project: input.project.clone(),
        }
    }
}

/// A `secretCreate` request line. Structurally distinct from [`WireRequest`]
/// — it carries a `create` object instead of `query`/`delivery` — per the
/// architecture doc's M4b wire shape: `{"version":1,"op":"secretCreate",
/// "create":{...},"client":{...}}`. No `query`, no `delivery` field.
#[derive(Debug, Clone, Serialize)]
struct WireCreateRequest {
    version: u32,
    op: &'static str,
    create: WireSecretCreate,
    client: WireClientInfo,
}

impl WireCreateRequest {
    fn new(create: WireSecretCreate) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            op: "secretCreate",
            create,
            client: WireClientInfo {
                name: "aac",
                version: env!("CARGO_PKG_VERSION"),
            },
        }
    }
}

/// A `describeFillTarget` request line (architecture doc, M5 §2). A peer of
/// `credentialRequest`, not a delivery mode — it resolves no credential and
/// touches no vault, so it carries no `query`/`delivery`/`fill`, only
/// `{version, op, client}`.
#[derive(Debug, Clone, Serialize)]
struct WireDescribeRequest {
    version: u32,
    op: &'static str,
    client: WireClientInfo,
}

impl WireDescribeRequest {
    fn new() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            op: "describeFillTarget",
            client: WireClientInfo {
                name: "aac",
                version: env!("CARGO_PKG_VERSION"),
            },
        }
    }
}

/// Response status, per wire protocol v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
enum WireStatus {
    Approved,
    Denied,
    NotFound,
    Locked,
    Timeout,
    RateLimited,
    Error,
    /// `delivery: "fill"` only: the extension-reported active-tab origin
    /// does not match any of the resolved item's saved URIs. The desktop
    /// refuses mechanically — no approval prompt is shown (architecture
    /// doc, M5 §3).
    OriginMismatch,
    /// `delivery: "fill"` only: the origin matched but no requested field
    /// has a safe target on the page (architecture doc, M5 §4.1). Also
    /// refused without a prompt.
    NoSafeTarget,
}

/// Value-bearing credential payload from an `approved` + `inject` response.
///
/// `notes` is intentionally absent: the desktop side never includes it in a
/// local reply (plan W4; per-field opt-in is a later phase).
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireCredential {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<Zeroizing<String>>,
    #[serde(default)]
    pub totp: Option<String>,
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub credential_id: Option<String>,
}

// Manual Debug: never print credential values, even in a derived debug string.
impl std::fmt::Debug for WireCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireCredential")
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("totp", &self.totp.as_ref().map(|_| "[REDACTED]"))
            .field("uri", &self.uri)
            .field("credential_id", &self.credential_id)
            .finish()
    }
}

/// Value-free item summary from an `approved` + `reference` response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireItem {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
}

// ── browser-fill response types (architecture doc, M5) ──────────────────
//
// Everything below this point is value-free by construction: a fill reply
// carries a status, a target selector string (e.g. "input#email (login
// form)"), and a reason code — never a filled value. Plain `derive(Debug)`
// is deliberately fine on every one of these, unlike `WireCredential` and
// `WireSecret` above, which need a manual `Debug` specifically to redact a
// value they do carry.

/// Outcome for one requested field of a fill (architecture doc, M5 §2).
/// `target` is a human-readable element selector, not a value; `reason` is
/// populated when `status` is e.g. `"skipped"`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireFillFieldOutcome {
    pub role: String,
    pub status: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// The `fill` sub-object of an `approved` `credentialRequest` response
/// (architecture doc, M5 §2): `status` is `filled | partial |
/// target-changed | origin-changed | extension-unavailable` on a completed
/// attempt. `status` is `#[serde(default)]` (despite being a plain
/// `String`, not `Option`) because the desktop's pre-prompt refusal
/// replies (`originMismatch`/`noSafeTarget`) may include a minimal `fill`
/// object — e.g. just `{"origin": "..."}` — with no `status` key at all;
/// tolerating a missing key there is strictly more robust than failing to
/// parse the whole response over it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireFillResult {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub origin: Option<String>,
    #[serde(default)]
    pub fields: Vec<WireFillFieldOutcome>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// One candidate fill target from a `describeFillTarget` reply
/// (architecture doc, M5 §4.2).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireFillCandidate {
    pub role: String,
    pub target: String,
    #[serde(default)]
    pub visible: bool,
    #[serde(default)]
    pub frame: Option<String>,
}

/// One field with no safe target, and why, from a `describeFillTarget`
/// reply (architecture doc, M5 §4.1/§4.2).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireFillRefusal {
    pub role: String,
    pub reason: String,
}

/// The `fillTarget` object of an `approved` `describeFillTarget` response
/// (architecture doc, M5 §4.2): a read-only, vault-free description of the
/// active browser tab.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireFillTarget {
    pub origin: String,
    pub form_class: String,
    #[serde(default)]
    pub candidates: Vec<WireFillCandidate>,
    #[serde(default)]
    pub refusals: Vec<WireFillRefusal>,
    #[serde(default)]
    pub target_token: Option<String>,
    #[serde(default)]
    pub expires_in_ms: Option<u64>,
}

/// Value-bearing Secrets Manager secret payload from an `approved` +
/// `inject` `secretRequest` response.
///
/// `note` is intentionally absent: the desktop side never includes it in a
/// local reply (architecture doc, M4 invariant #2 — the secrets analogue of
/// the credential `notes` invariant).
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireSecret {
    pub name: String,
    pub value: Zeroizing<String>,
    pub secret_id: String,
}

// Manual Debug: never print the secret value, even in a derived debug string.
impl std::fmt::Debug for WireSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireSecret")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .field("secret_id", &self.secret_id)
            .finish()
    }
}

/// Raw response line, deserialized before status interpretation.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireResponse {
    version: u32,
    status: WireStatus,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    credential: Option<WireCredential>,
    #[serde(default)]
    reference: Option<String>,
    #[serde(default)]
    item: Option<WireItem>,
    #[serde(default)]
    secret: Option<WireSecret>,
    #[serde(default)]
    fill: Option<WireFillResult>,
    #[serde(default)]
    fill_target: Option<WireFillTarget>,
}

/// The interpreted, successful outcome of a local credential request.
#[derive(Debug)]
pub enum WireOutcome {
    /// `delivery: "inject"` — value-bearing credential, plus the reference
    /// that would redeem the same item (present per protocol, currently
    /// unused by callers).
    Credential(WireCredential),
    /// `delivery: "reference"` — no secret values, ever.
    Reference { reference: String, item: WireItem },
}

/// The interpreted, successful outcome of a local `secretRequest`.
#[derive(Debug)]
pub enum SecretOutcome {
    /// `delivery: "inject"` — value-bearing secret.
    Secret(WireSecret),
    /// `delivery: "reference"` — no secret value, ever. `item_name` mirrors
    /// the wire protocol's `item: {"name": ...}` (secrets have no analogue
    /// of a credential's `username`).
    Reference {
        reference: String,
        item_name: Option<String>,
    },
}

/// The interpreted, successful outcome of a local `secretCreate` request.
/// Always reference-shaped — the created value is never echoed back
/// (architecture doc, M4b invariant: "The stored value is NEVER echoed
/// back") — so unlike [`SecretOutcome`] there is no value-bearing variant to
/// distinguish; `secret_id` is derived client-side from `reference` via
/// [`strip_secret_reference`].
#[derive(Debug, Clone)]
pub struct SecretCreateOutcome {
    pub secret_id: String,
    pub reference: String,
    pub name: Option<String>,
}

/// Errors from the local transport. Never carries a credential value.
#[derive(Debug, Error)]
pub enum LocalTransportError {
    /// Could not establish the connection at all (socket/pipe missing, no
    /// listener, permission denied, ...). Callers use this specifically to
    /// decide whether falling back to the relay is safe — it's the only
    /// variant that means "nothing was dispatched to the server".
    #[error("could not connect to local agent-access endpoint: {0}")]
    ConnectFailed(String),

    /// The full request/response round trip exceeded the read timeout.
    #[error("local agent-access endpoint did not respond within 120s")]
    ReadTimeout,

    /// The response line exceeded the 64 KiB protocol limit.
    #[error("response from local agent-access endpoint exceeded the 64 KiB limit")]
    ResponseTooLarge,

    /// The response was not well-formed per the wire protocol.
    #[error("malformed response from local agent-access endpoint: {0}")]
    Protocol(String),

    /// The server replied with a protocol version this client doesn't speak.
    #[error(
        "local agent-access endpoint speaks protocol version {0}, this aac build speaks v{PROTOCOL_VERSION}"
    )]
    UnsupportedVersion(u32),

    /// Low-level I/O failure after the connection was established.
    #[error("i/o error talking to local agent-access endpoint: {0}")]
    Io(String),

    /// `status: "denied"` — the user declined the request.
    #[error("denied by user: {0}")]
    Denied(String),

    /// `status: "notFound"` — no matching vault item.
    #[error("no matching item found: {0}")]
    NotFound(String),

    /// `status: "locked"` — the vault is locked.
    #[error("vault is locked: {0}")]
    Locked(String),

    /// `status: "timeout"` — server-side approval timed out.
    #[error("approval timed out: {0}")]
    ServerTimeout(String),

    /// `status: "rateLimited"`.
    #[error("rate limited: {0}")]
    RateLimited(String),

    /// `status: "error"`.
    #[error("local agent-access endpoint error: {0}")]
    ServerError(String),

    /// `status: "originMismatch"` — `delivery: "fill"` only. The
    /// extension-reported active-tab origin does not match any of the
    /// resolved item's saved URIs; the desktop refused mechanically, with
    /// no approval prompt (architecture doc, M5 §3). Value-free: `origin`
    /// is the tab's origin, never a credential value.
    #[error(
        "The active browser tab ({origin}) does not match any saved website for the requested login"
    )]
    OriginMismatch {
        origin: String,
        item_name: Option<String>,
    },

    /// `status: "noSafeTarget"` — `delivery: "fill"` only. The origin
    /// matched but no requested field has a safe target on the page
    /// (architecture doc, M5 §4.1: registration form, ambiguous
    /// candidates, no password field, hidden-field-only, cross-origin
    /// frame, or no login form at all). `reason` is the machine-readable
    /// code, never a value.
    #[error("No safe fill target on the page: {reason}")]
    NoSafeTarget { reason: String },
}

/// Connect to a Unix domain socket, mapping any failure to
/// [`LocalTransportError::ConnectFailed`].
#[cfg(unix)]
async fn connect(endpoint: &LocalEndpoint) -> Result<tokio::net::UnixStream, LocalTransportError> {
    let LocalEndpoint::Unix(path) = endpoint;
    tokio::net::UnixStream::connect(path)
        .await
        .map_err(|e| LocalTransportError::ConnectFailed(format!("{}: {e}", path.display())))
}

/// Connect to a Windows named pipe, mapping any failure to
/// [`LocalTransportError::ConnectFailed`]. Retries briefly on
/// `ERROR_PIPE_BUSY`, the standard pattern for named-pipe clients.
///
/// Structurally mirrors the unix path; this cannot be exercised on macOS —
/// keep changes here minimal and validate on Windows CI.
#[cfg(windows)]
async fn connect(
    endpoint: &LocalEndpoint,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient, LocalTransportError> {
    use tokio::net::windows::named_pipe::ClientOptions;

    const ERROR_PIPE_BUSY: i32 = 231;
    const MAX_ATTEMPTS: u32 = 5;

    let LocalEndpoint::Pipe(name) = endpoint;
    for attempt in 0..MAX_ATTEMPTS {
        match ClientOptions::new().open(name) {
            Ok(client) => return Ok(client),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempt + 1 < MAX_ATTEMPTS => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                return Err(LocalTransportError::ConnectFailed(format!("{name}: {e}")));
            }
        }
    }
    Err(LocalTransportError::ConnectFailed(format!(
        "{name}: pipe busy after {MAX_ATTEMPTS} attempts"
    )))
}

/// Read one `\n`-terminated line, rejecting anything over
/// [`MAX_LINE_BYTES`]. The trailing newline is stripped from the result.
async fn read_capped_line<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
) -> Result<Vec<u8>, LocalTransportError> {
    // Cap the underlying read at MAX_LINE_BYTES + 1: if `read_until` fills
    // the cap without finding '\n', the line was too long.
    let mut limited = BufReader::new(reader).take(MAX_LINE_BYTES as u64 + 1);
    let mut buf = Vec::new();
    limited
        .read_until(b'\n', &mut buf)
        .await
        .map_err(|e| LocalTransportError::Io(e.to_string()))?;

    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.len() > MAX_LINE_BYTES {
            return Err(LocalTransportError::ResponseTooLarge);
        }
        Ok(buf)
    } else if buf.len() as u64 > MAX_LINE_BYTES as u64 {
        Err(LocalTransportError::ResponseTooLarge)
    } else {
        Err(LocalTransportError::Protocol(
            "connection closed before a newline-terminated response was received".to_string(),
        ))
    }
}

/// Send one request line and read one response line over an already
/// connected stream, within the read timeout. Generic over the request shape
/// so `WireRequest<Q>` (`credentialRequest`/`secretRequest`) and
/// `WireCreateRequest` (`secretCreate`) — which serialize differently but
/// share the same one-line-out/one-line-in framing — can share this
/// implementation.
async fn run_request<S, Req>(
    mut stream: S,
    request: &Req,
) -> Result<WireResponse, LocalTransportError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    Req: Serialize,
{
    tokio::time::timeout(READ_TIMEOUT, async {
        let mut line = serde_json::to_string(request)
            .map_err(|e| LocalTransportError::Protocol(e.to_string()))?;
        line.push('\n');
        stream
            .write_all(line.as_bytes())
            .await
            .map_err(|e| LocalTransportError::Io(e.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|e| LocalTransportError::Io(e.to_string()))?;

        let raw = read_capped_line(stream).await?;
        serde_json::from_slice(&raw)
            .map_err(|e| LocalTransportError::Protocol(format!("invalid JSON: {e}")))
    })
    .await
    .map_err(|_| LocalTransportError::ReadTimeout)?
}

/// Interpret a parsed [`WireResponse`] into a [`WireOutcome`] or the
/// corresponding [`LocalTransportError`].
fn interpret(resp: WireResponse) -> Result<WireOutcome, LocalTransportError> {
    if resp.version != PROTOCOL_VERSION {
        return Err(LocalTransportError::UnsupportedVersion(resp.version));
    }

    let message = |fallback: &str| resp.message.clone().unwrap_or_else(|| fallback.to_string());

    match resp.status {
        WireStatus::Approved => {
            if let Some(credential) = resp.credential {
                Ok(WireOutcome::Credential(credential))
            } else if let Some(item) = resp.item {
                let reference = resp.reference.ok_or_else(|| {
                    LocalTransportError::Protocol(
                        "approved reference response missing 'reference'".to_string(),
                    )
                })?;
                Ok(WireOutcome::Reference { reference, item })
            } else {
                Err(LocalTransportError::Protocol(
                    "approved response missing both 'credential' and 'item'".to_string(),
                ))
            }
        }
        WireStatus::Denied => Err(LocalTransportError::Denied(message("Denied by user"))),
        WireStatus::NotFound => Err(LocalTransportError::NotFound(message(
            "No matching item found",
        ))),
        WireStatus::Locked => Err(LocalTransportError::Locked(message("Vault is locked"))),
        WireStatus::Timeout => Err(LocalTransportError::ServerTimeout(message(
            "Approval timed out",
        ))),
        WireStatus::RateLimited => Err(LocalTransportError::RateLimited(message("Rate limited"))),
        WireStatus::Error => Err(LocalTransportError::ServerError(message(
            "Local agent-access endpoint returned an error",
        ))),
        // Fill-only statuses; nonsensical for `inject`/`reference` delivery.
        // Matched explicitly (rather than a wildcard) so a future added
        // `WireStatus` variant fails to compile here instead of silently
        // falling through.
        WireStatus::OriginMismatch => Err(LocalTransportError::Protocol(
            "unexpected 'originMismatch' status for a non-fill request".to_string(),
        )),
        WireStatus::NoSafeTarget => Err(LocalTransportError::Protocol(
            "unexpected 'noSafeTarget' status for a non-fill request".to_string(),
        )),
    }
}

/// Perform one full local credential request: connect, send, receive,
/// interpret. One connection per request, per protocol.
pub async fn request_credential(
    endpoint: &LocalEndpoint,
    query: &CredentialQuery,
    delivery: WireDelivery,
) -> Result<WireOutcome, LocalTransportError> {
    let stream = connect(endpoint).await?;
    let request = WireRequest::new(query, delivery);
    let response = run_request(stream, &request).await?;
    interpret(response)
}

/// Interpret a parsed [`WireResponse`] into a [`SecretOutcome`] or the
/// corresponding [`LocalTransportError`]. Mirrors [`interpret`] exactly,
/// substituting `secret` for `credential` — whichever of `secret`/`item` the
/// desktop side populated determines whether this was an inject- or
/// reference-shaped reply.
fn interpret_secret(resp: WireResponse) -> Result<SecretOutcome, LocalTransportError> {
    if resp.version != PROTOCOL_VERSION {
        return Err(LocalTransportError::UnsupportedVersion(resp.version));
    }

    let message = |fallback: &str| resp.message.clone().unwrap_or_else(|| fallback.to_string());

    match resp.status {
        WireStatus::Approved => {
            if let Some(secret) = resp.secret {
                Ok(SecretOutcome::Secret(secret))
            } else if let Some(item) = resp.item {
                let reference = resp.reference.ok_or_else(|| {
                    LocalTransportError::Protocol(
                        "approved reference response missing 'reference'".to_string(),
                    )
                })?;
                Ok(SecretOutcome::Reference {
                    reference,
                    item_name: item.name,
                })
            } else {
                Err(LocalTransportError::Protocol(
                    "approved response missing both 'secret' and 'item'".to_string(),
                ))
            }
        }
        WireStatus::Denied => Err(LocalTransportError::Denied(message("Denied by user"))),
        WireStatus::NotFound => Err(LocalTransportError::NotFound(message(
            "No matching secret found",
        ))),
        WireStatus::Locked => Err(LocalTransportError::Locked(message("Vault is locked"))),
        WireStatus::Timeout => Err(LocalTransportError::ServerTimeout(message(
            "Approval timed out",
        ))),
        WireStatus::RateLimited => Err(LocalTransportError::RateLimited(message("Rate limited"))),
        WireStatus::Error => Err(LocalTransportError::ServerError(message(
            "Local agent-access endpoint returned an error",
        ))),
        // Fill-only statuses; nonsensical for a `secretRequest`.
        WireStatus::OriginMismatch => Err(LocalTransportError::Protocol(
            "unexpected 'originMismatch' status for a secretRequest".to_string(),
        )),
        WireStatus::NoSafeTarget => Err(LocalTransportError::Protocol(
            "unexpected 'noSafeTarget' status for a secretRequest".to_string(),
        )),
    }
}

/// Perform one full local Secrets Manager secret request: connect, send,
/// receive, interpret. One connection per request, per protocol. Secrets are
/// local-transport-only (architecture doc, M4) — callers must not fall back
/// to the relay on [`LocalTransportError::ConnectFailed`], unlike
/// [`request_credential`].
pub async fn request_secret(
    endpoint: &LocalEndpoint,
    query: &SecretQueryInput,
    delivery: WireDelivery,
) -> Result<SecretOutcome, LocalTransportError> {
    let stream = connect(endpoint).await?;
    let request = WireRequest::secret(query, delivery);
    let response = run_request(stream, &request).await?;
    interpret_secret(response)
}

/// Interpret a parsed [`WireResponse`] into a [`SecretCreateOutcome`] or the
/// corresponding [`LocalTransportError`]. `secretCreate` responses reuse the
/// reference-shaped fields of [`WireResponse`] (`reference` + `item`) — there
/// is no value-bearing counterpart, since the created value is never echoed
/// back. A missing or unparseable `reference` on an `approved` response is a
/// protocol error rather than a panic. `notFound` is not an expected status
/// for a create (architecture doc, M4b: "`notFound` does not apply"), but is
/// still handled like any other non-approved status rather than special-cased
/// or treated as unreachable.
fn interpret_secret_create(resp: WireResponse) -> Result<SecretCreateOutcome, LocalTransportError> {
    if resp.version != PROTOCOL_VERSION {
        return Err(LocalTransportError::UnsupportedVersion(resp.version));
    }

    let message = |fallback: &str| resp.message.clone().unwrap_or_else(|| fallback.to_string());

    match resp.status {
        WireStatus::Approved => {
            let reference = resp.reference.ok_or_else(|| {
                LocalTransportError::Protocol(
                    "approved secretCreate response missing 'reference'".to_string(),
                )
            })?;
            if !reference.starts_with(SECRET_REFERENCE_PREFIX) {
                return Err(LocalTransportError::Protocol(format!(
                    "approved secretCreate response has an unparseable 'reference': {reference}"
                )));
            }
            let secret_id = strip_secret_reference(&reference).to_string();
            if secret_id.is_empty() {
                return Err(LocalTransportError::Protocol(
                    "approved secretCreate response has an empty secret id in 'reference'"
                        .to_string(),
                ));
            }
            Ok(SecretCreateOutcome {
                secret_id,
                reference,
                name: resp.item.and_then(|item| item.name),
            })
        }
        WireStatus::Denied => Err(LocalTransportError::Denied(message("Denied by user"))),
        WireStatus::NotFound => Err(LocalTransportError::NotFound(message("Not found"))),
        WireStatus::Locked => Err(LocalTransportError::Locked(message("Vault is locked"))),
        WireStatus::Timeout => Err(LocalTransportError::ServerTimeout(message(
            "Approval timed out",
        ))),
        WireStatus::RateLimited => Err(LocalTransportError::RateLimited(message("Rate limited"))),
        WireStatus::Error => Err(LocalTransportError::ServerError(message(
            "Local agent-access endpoint returned an error",
        ))),
        // Fill-only statuses; nonsensical for a `secretCreate`.
        WireStatus::OriginMismatch => Err(LocalTransportError::Protocol(
            "unexpected 'originMismatch' status for a secretCreate".to_string(),
        )),
        WireStatus::NoSafeTarget => Err(LocalTransportError::Protocol(
            "unexpected 'noSafeTarget' status for a secretCreate".to_string(),
        )),
    }
}

/// Perform one full local Secrets Manager secret *creation*: connect, send,
/// receive, interpret. One connection per request, per protocol. Secrets
/// (including creates) are local-transport-only — same no-relay-fallback
/// contract as [`request_secret`]. There is deliberately no CLI-facing
/// constructor for this request: a plaintext secret value on argv/shell
/// history is exactly the anti-pattern this feature exists to remove
/// (architecture doc, M4b) — only the `create_secret` MCP tool (and any
/// future stdin-based CLI) may call this.
pub async fn request_secret_create(
    endpoint: &LocalEndpoint,
    input: &SecretCreateInput,
) -> Result<SecretCreateOutcome, LocalTransportError> {
    let stream = connect(endpoint).await?;
    let request = WireCreateRequest::new(WireSecretCreate::from(input));
    let response = run_request(stream, &request).await?;
    interpret_secret_create(response)
}

// ── browser fill (architecture doc, M5) ──────────────────────────────────

/// Input to a local browser-fill request: which credential fields to fill
/// and an optional `targetToken` echoing a plan a prior
/// `describeFillTarget` call produced (§4.4). Value-free by construction —
/// nothing here is ever a secret, so deriving `Debug` is fine, unlike
/// [`SecretCreateInput`].
#[derive(Debug, Clone, Default)]
pub struct FillInput {
    pub fields: Option<Vec<String>>,
    pub target_token: Option<String>,
}

/// The interpreted, successful outcome of a local browser-fill request.
/// Value-free by construction: `item`/`reference` mirror the existing
/// reference-mode shape (a fill reply is "closer to reference than inject"
/// on the wire — architecture doc, M5 §1), and `fields` carries only
/// per-field outcome descriptors, never a value.
#[derive(Debug)]
pub struct FillOutcome {
    /// `filled | partial | target-changed | origin-changed |
    /// extension-unavailable`.
    pub status: String,
    /// The extension-reported active-tab origin, never the caller-supplied
    /// query.
    pub origin: Option<String>,
    pub fields: Vec<WireFillFieldOutcome>,
    pub reason: Option<String>,
    pub item: Option<WireItem>,
    pub reference: Option<String>,
}

/// Interpret a parsed [`WireResponse`] into a [`FillOutcome`] or the
/// corresponding [`LocalTransportError`]. Mirrors [`interpret`]'s shape for
/// the shared statuses, with two fill-specific terminal statuses
/// (`originMismatch`/`noSafeTarget`) mapped to their own
/// [`LocalTransportError`] variants instead.
fn interpret_fill(resp: WireResponse) -> Result<FillOutcome, LocalTransportError> {
    if resp.version != PROTOCOL_VERSION {
        return Err(LocalTransportError::UnsupportedVersion(resp.version));
    }

    // Defensive: a fill-delivery reply must never carry a value-bearing
    // credential — mirror the reference-mode guard used elsewhere
    // (`run_find_logins` in `command/mcp.rs`, `fetch_credential_dispatch`
    // in `command/connect.rs`) for the corner where a server ignores
    // `delivery` and returns one anyway.
    if resp.credential.is_some() {
        return Err(LocalTransportError::Protocol(
            "value-bearing reply to a fill request".to_string(),
        ));
    }

    let message = |fallback: &str| resp.message.clone().unwrap_or_else(|| fallback.to_string());

    match resp.status {
        WireStatus::Approved => {
            let fill = resp.fill.ok_or_else(|| {
                LocalTransportError::Protocol("approved fill response missing 'fill'".to_string())
            })?;
            Ok(FillOutcome {
                status: fill.status,
                origin: fill.origin,
                fields: fill.fields,
                reason: fill.reason,
                item: resp.item,
                reference: resp.reference,
            })
        }
        WireStatus::OriginMismatch => {
            let origin = resp
                .fill
                .as_ref()
                .and_then(|f| f.origin.clone())
                .or_else(|| resp.message.clone())
                .unwrap_or_else(|| "unknown".to_string());
            Err(LocalTransportError::OriginMismatch {
                origin,
                item_name: resp.item.and_then(|item| item.name),
            })
        }
        WireStatus::NoSafeTarget => {
            let reason = resp
                .message
                .clone()
                .or_else(|| resp.fill.and_then(|f| f.reason))
                .unwrap_or_else(|| "no-safe-target".to_string());
            Err(LocalTransportError::NoSafeTarget { reason })
        }
        WireStatus::Denied => Err(LocalTransportError::Denied(message("Denied by user"))),
        WireStatus::NotFound => Err(LocalTransportError::NotFound(message(
            "No matching item found",
        ))),
        WireStatus::Locked => Err(LocalTransportError::Locked(message("Vault is locked"))),
        WireStatus::Timeout => Err(LocalTransportError::ServerTimeout(message(
            "Approval timed out",
        ))),
        WireStatus::RateLimited => Err(LocalTransportError::RateLimited(message("Rate limited"))),
        WireStatus::Error => Err(LocalTransportError::ServerError(message(
            "Local agent-access endpoint returned an error",
        ))),
    }
}

/// Perform one full local browser-fill request: connect, send, receive,
/// interpret. `delivery: "fill"` — the credential value never enters this
/// process; the desktop resolves it and hands it directly to the browser
/// extension (architecture doc, M5 §1).
pub async fn request_fill(
    endpoint: &LocalEndpoint,
    query: &CredentialQuery,
    fill: Option<FillInput>,
) -> Result<FillOutcome, LocalTransportError> {
    let stream = connect(endpoint).await?;
    let request = WireRequest::fill(query, fill.as_ref());
    let response = run_request(stream, &request).await?;
    interpret_fill(response)
}

/// Interpret a parsed [`WireResponse`] into a [`WireFillTarget`] or the
/// corresponding [`LocalTransportError`]. `describeFillTarget` is
/// vault-free and approval-free (architecture doc, M5 §4.2) — `approved`
/// here means only "the description was produced", not that the user
/// approved a credential release.
fn interpret_describe(resp: WireResponse) -> Result<WireFillTarget, LocalTransportError> {
    if resp.version != PROTOCOL_VERSION {
        return Err(LocalTransportError::UnsupportedVersion(resp.version));
    }

    let message = |fallback: &str| resp.message.clone().unwrap_or_else(|| fallback.to_string());

    match resp.status {
        WireStatus::Approved => resp.fill_target.ok_or_else(|| {
            LocalTransportError::Protocol(
                "approved describeFillTarget response missing 'fillTarget'".to_string(),
            )
        }),
        WireStatus::Denied => Err(LocalTransportError::Denied(message("Denied by user"))),
        WireStatus::NotFound => Err(LocalTransportError::NotFound(message(
            "No matching item found",
        ))),
        WireStatus::Locked => Err(LocalTransportError::Locked(message("Vault is locked"))),
        WireStatus::Timeout => Err(LocalTransportError::ServerTimeout(message(
            "Approval timed out",
        ))),
        WireStatus::RateLimited => Err(LocalTransportError::RateLimited(message("Rate limited"))),
        WireStatus::Error => Err(LocalTransportError::ServerError(message(
            "Local agent-access endpoint returned an error",
        ))),
        WireStatus::OriginMismatch => Err(LocalTransportError::Protocol(
            "unexpected 'originMismatch' status for describeFillTarget".to_string(),
        )),
        WireStatus::NoSafeTarget => Err(LocalTransportError::Protocol(
            "unexpected 'noSafeTarget' status for describeFillTarget".to_string(),
        )),
    }
}

/// Perform one full local `describeFillTarget` request: connect, send,
/// receive, interpret. Vault-free and approval-free (architecture doc, M5
/// §4.2) — describes the active browser tab only.
pub async fn request_describe_fill_target(
    endpoint: &LocalEndpoint,
) -> Result<WireFillTarget, LocalTransportError> {
    let stream = connect(endpoint).await?;
    let request = WireDescribeRequest::new();
    let response = run_request(stream, &request).await?;
    interpret_describe(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approved_inject_json() -> &'static str {
        r#"{"version":1,"status":"approved",
 "credential":{"username":"u","password":"p","totp":"123456","uri":"https://github.com",
               "credentialId":"11111111-1111-1111-1111-111111111111"},
 "reference":"bw://item/11111111-1111-1111-1111-111111111111"}"#
    }

    // ── wire request serde ──────────────────────────────────────────

    #[test]
    fn wire_request_serializes_domain_query_exactly() {
        let query = CredentialQuery::Domain("github.com".to_string());
        let request = WireRequest::new(&query, WireDelivery::Inject);
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert_eq!(json["version"], 1);
        assert_eq!(json["op"], "credentialRequest");
        assert_eq!(json["query"]["type"], "domain");
        assert_eq!(json["query"]["value"], "github.com");
        assert_eq!(json["delivery"], "inject");
        assert_eq!(json["client"]["name"], "aac");
    }

    #[test]
    fn wire_request_serializes_id_and_search_queries() {
        let id_req = WireRequest::new(
            &CredentialQuery::Id("abc-123".to_string()),
            WireDelivery::Reference,
        );
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&id_req).expect("serialize"))
                .expect("parse");
        assert_eq!(json["query"]["type"], "id");
        assert_eq!(json["query"]["value"], "abc-123");
        assert_eq!(json["delivery"], "reference");

        let search_req = WireRequest::new(
            &CredentialQuery::Search("bank".to_string()),
            WireDelivery::Inject,
        );
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&search_req).expect("serialize"))
                .expect("parse");
        assert_eq!(json["query"]["type"], "search");
        assert_eq!(json["query"]["value"], "bank");
    }

    #[test]
    fn wire_request_secret_serializes_name_query_exactly() {
        let query = SecretQueryInput::Name("DB_PASSWORD".to_string());
        let request = WireRequest::secret(&query, WireDelivery::Reference);
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert_eq!(json["version"], 1);
        assert_eq!(json["op"], "secretRequest");
        assert_eq!(json["query"]["type"], "name");
        assert_eq!(json["query"]["value"], "DB_PASSWORD");
        assert_eq!(json["delivery"], "reference");
        assert_eq!(json["client"]["name"], "aac");
    }

    #[test]
    fn wire_request_secret_serializes_id_and_search_queries() {
        let id_req = WireRequest::secret(
            &SecretQueryInput::Id("11111111-1111-1111-1111-111111111111".to_string()),
            WireDelivery::Reference,
        );
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&id_req).expect("serialize"))
                .expect("parse");
        assert_eq!(json["query"]["type"], "id");
        assert_eq!(
            json["query"]["value"],
            "11111111-1111-1111-1111-111111111111"
        );

        let search_req = WireRequest::secret(
            &SecretQueryInput::Search("db".to_string()),
            WireDelivery::Inject,
        );
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&search_req).expect("serialize"))
                .expect("parse");
        assert_eq!(json["query"]["type"], "search");
        assert_eq!(json["query"]["value"], "db");
    }

    // ── fill / describeFillTarget wire request serde ─────────────────

    #[test]
    fn fill_request_serializes_op_and_delivery_exactly() {
        let query = CredentialQuery::Domain("bitnotes.io".to_string());
        let request = WireRequest::fill(&query, None);
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert_eq!(json["version"], 1);
        assert_eq!(json["op"], "credentialRequest");
        assert_eq!(json["query"]["type"], "domain");
        assert_eq!(json["query"]["value"], "bitnotes.io");
        assert_eq!(json["delivery"], "fill");
        assert_eq!(json["client"]["name"], "aac");
    }

    #[test]
    fn fill_request_with_no_params_omits_fill_key() {
        let query = CredentialQuery::Domain("bitnotes.io".to_string());
        let request = WireRequest::fill(&query, None);
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert!(
            json.get("fill").is_none(),
            "fill key must be absent when no fill params were given: {json}"
        );
    }

    #[test]
    fn fill_request_with_params_serializes_fields_and_target_token() {
        let query = CredentialQuery::Domain("bitnotes.io".to_string());
        let fill_params = FillInput {
            fields: Some(vec!["username".to_string(), "password".to_string()]),
            target_token: Some("ft_abc123".to_string()),
        };
        let request = WireRequest::fill(&query, Some(&fill_params));
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert_eq!(
            json["fill"]["fields"],
            serde_json::json!(["username", "password"])
        );
        assert_eq!(json["fill"]["targetToken"], "ft_abc123");
    }

    #[test]
    fn fill_request_omits_absent_fields_and_target_token() {
        let query = CredentialQuery::Domain("bitnotes.io".to_string());
        let fill_params = FillInput {
            fields: None,
            target_token: None,
        };
        let request = WireRequest::fill(&query, Some(&fill_params));
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        // A present-but-empty `fill` object, not an absent key: the caller
        // explicitly asked for a fill request (`Some(FillInput{..})`), just
        // with no fields/token narrowing.
        assert!(json.get("fill").is_some());
        assert!(json["fill"].get("fields").is_none());
        assert!(json["fill"].get("targetToken").is_none());
    }

    #[test]
    fn fill_request_never_carries_a_submit_key() {
        // `submit` is cut from v1 entirely (architecture doc, M5 decision
        // 7) — not in the wire protocol at all, not even as an omittable
        // `Option`. Assert the whole serialized request, not just the
        // `fill` sub-object, so this test would catch a `submit` field
        // added anywhere in the request shape.
        let query = CredentialQuery::Domain("bitnotes.io".to_string());
        let fill_params = FillInput {
            fields: Some(vec!["password".to_string()]),
            target_token: None,
        };
        let request = WireRequest::fill(&query, Some(&fill_params));
        let json = serde_json::to_string(&request).expect("serialize");
        assert!(
            !json.contains("submit"),
            "submit leaked into the wire request: {json}"
        );
    }

    #[test]
    fn describe_fill_target_request_serializes_contract_shape_exactly() {
        let request = WireDescribeRequest::new();
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert_eq!(json["version"], 1);
        assert_eq!(json["op"], "describeFillTarget");
        assert_eq!(json["client"]["name"], "aac");

        // No `query`/`delivery`/`fill` — this op carries none of them.
        assert!(json.get("query").is_none());
        assert!(json.get("delivery").is_none());
        assert!(json.get("fill").is_none());

        let mut top_level: Vec<&str> = json
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        top_level.sort_unstable();
        assert_eq!(top_level, vec!["client", "op", "version"]);
    }

    // ── wire response serde / interpretation ────────────────────────

    #[test]
    fn response_approved_inject_round_trips() {
        let resp: WireResponse = serde_json::from_str(approved_inject_json()).expect("parse");
        let outcome = interpret(resp).expect("should be Ok");
        match outcome {
            WireOutcome::Credential(cred) => {
                assert_eq!(cred.username.as_deref(), Some("u"));
                assert_eq!(cred.password.as_ref().map(|p| p.as_str()), Some("p"));
                assert_eq!(cred.totp.as_deref(), Some("123456"));
                assert_eq!(cred.uri.as_deref(), Some("https://github.com"));
                assert_eq!(
                    cred.credential_id.as_deref(),
                    Some("11111111-1111-1111-1111-111111111111")
                );
            }
            WireOutcome::Reference { .. } => panic!("expected Credential outcome"),
        }
    }

    #[test]
    fn response_approved_reference_round_trips() {
        let json = r#"{"version":1,"status":"approved",
 "item":{"name":"GitHub","username":"u"},
 "reference":"bw://item/11111111-1111-1111-1111-111111111111"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let outcome = interpret(resp).expect("should be Ok");
        match outcome {
            WireOutcome::Reference { reference, item } => {
                assert_eq!(reference, "bw://item/11111111-1111-1111-1111-111111111111");
                assert_eq!(item.name.as_deref(), Some("GitHub"));
                assert_eq!(item.username.as_deref(), Some("u"));
            }
            WireOutcome::Credential(_) => panic!("expected Reference outcome"),
        }
    }

    #[test]
    fn response_ignores_unknown_fields() {
        let json = r#"{"version":1,"status":"denied","message":"Denied by user",
 "someFutureField":{"nested":true},"anotherOne":42}"#;
        let resp: WireResponse =
            serde_json::from_str(json).expect("unknown fields must be ignored");
        let err = interpret(resp).expect_err("denied should error");
        assert!(matches!(err, LocalTransportError::Denied(m) if m == "Denied by user"));
    }

    #[test]
    fn response_status_mapping() {
        let cases = [
            ("denied", "Denied by user"),
            ("notFound", "No matching item found"),
            ("locked", "Vault is locked"),
            ("timeout", "Approval timed out"),
            ("rateLimited", "Rate limited"),
            ("error", "Local agent-access endpoint returned an error"),
        ];
        for (status, default_msg) in cases {
            let json = format!(r#"{{"version":1,"status":"{status}"}}"#);
            let resp: WireResponse = serde_json::from_str(&json).expect("parse");
            let err = interpret(resp).expect_err("non-approved status must error");
            assert!(err.to_string().contains(default_msg), "status {status}");
        }
    }

    #[test]
    fn response_custom_message_overrides_default() {
        let json = r#"{"version":1,"status":"locked","message":"Vault locked - unlock in the desktop app"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret(resp).expect_err("locked must error");
        assert!(
            matches!(err, LocalTransportError::Locked(m) if m == "Vault locked - unlock in the desktop app")
        );
    }

    #[test]
    fn response_unsupported_version_errors() {
        let json =
            r#"{"version":2,"status":"approved","item":{"name":"x"},"reference":"bw://item/x"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret(resp).expect_err("version 2 must error");
        assert!(matches!(err, LocalTransportError::UnsupportedVersion(2)));
    }

    #[test]
    fn response_approved_missing_both_payloads_is_protocol_error() {
        let json = r#"{"version":1,"status":"approved"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret(resp).expect_err("must error");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[test]
    fn non_fill_status_rejects_origin_mismatch_and_no_safe_target() {
        // `originMismatch`/`noSafeTarget` only make sense for a fill
        // request; a non-fill interpreter seeing either is a protocol
        // anomaly, not a silent success.
        for status in ["originMismatch", "noSafeTarget"] {
            let json = format!(r#"{{"version":1,"status":"{status}"}}"#);
            let resp: WireResponse = serde_json::from_str(&json).expect("parse");
            let err = interpret(resp).expect_err("must error");
            assert!(
                matches!(err, LocalTransportError::Protocol(_)),
                "status {status}"
            );
        }
    }

    // ── fill response serde / interpretation ──────────────────────────

    #[test]
    fn fill_response_approved_filled_round_trips() {
        let json = r#"{"version":1,"status":"approved",
 "item":{"name":"bitnotes.io","username":"demo@bitnotes.io"},
 "reference":"bw://item/11111111-1111-1111-1111-111111111111",
 "fill":{"status":"filled","origin":"https://bitnotes.io","fields":[
   {"role":"username","status":"filled","target":"input#email (login form)"},
   {"role":"password","status":"filled","target":"input[type=password]#pw"},
   {"role":"totp","status":"skipped","reason":"no one-time-code field on page"}
 ]}}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let outcome = interpret_fill(resp).expect("should be Ok");

        assert_eq!(outcome.status, "filled");
        assert_eq!(outcome.origin.as_deref(), Some("https://bitnotes.io"));
        assert_eq!(
            outcome.reference.as_deref(),
            Some("bw://item/11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(
            outcome.item.as_ref().and_then(|i| i.name.as_deref()),
            Some("bitnotes.io")
        );
        assert_eq!(outcome.fields.len(), 3);
        assert_eq!(outcome.fields[0].role, "username");
        assert_eq!(outcome.fields[0].status, "filled");
        assert_eq!(outcome.fields[2].status, "skipped");
        assert_eq!(
            outcome.fields[2].reason.as_deref(),
            Some("no one-time-code field on page")
        );
    }

    #[test]
    fn fill_response_approved_partial_round_trips() {
        let json = r#"{"version":1,"status":"approved",
 "item":{"name":"bitnotes.io"},
 "reference":"bw://item/item-1",
 "fill":{"status":"partial","origin":"https://bitnotes.io","fields":[
   {"role":"username","status":"filled","target":"input#email"},
   {"role":"password","status":"skipped","reason":"no password field on page"}
 ]}}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let outcome = interpret_fill(resp).expect("should be Ok");
        assert_eq!(outcome.status, "partial");
        assert_eq!(outcome.fields[1].status, "skipped");
    }

    #[test]
    fn fill_response_approved_missing_fill_is_protocol_error() {
        let json = r#"{"version":1,"status":"approved",
 "item":{"name":"bitnotes.io"},"reference":"bw://item/item-1"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_fill(resp).expect_err("must error");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[test]
    fn fill_response_credential_bearing_reply_is_refused() {
        // Defensive guard: a fill-delivery reply must never carry a
        // value-bearing credential, regardless of what else it carries.
        let json = r#"{"version":1,"status":"approved",
 "credential":{"username":"u","password":"p"}}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_fill(resp).expect_err("must error");
        match err {
            LocalTransportError::Protocol(msg) => {
                assert!(msg.contains("value-bearing"), "unexpected message: {msg}");
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn fill_response_origin_mismatch_maps_to_origin_mismatch_error() {
        let json = r#"{"version":1,"status":"originMismatch",
 "item":{"name":"bitnotes.io"},
 "fill":{"origin":"https://evil.example"}}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_fill(resp).expect_err("originMismatch must error");
        // Value-free: only the origin appears in the error's Display text.
        assert!(format!("{err}").contains("https://evil.example"));
        match err {
            LocalTransportError::OriginMismatch { origin, item_name } => {
                assert_eq!(origin, "https://evil.example");
                assert_eq!(item_name.as_deref(), Some("bitnotes.io"));
            }
            other => panic!("expected OriginMismatch, got {other:?}"),
        }
    }

    #[test]
    fn fill_response_origin_mismatch_falls_back_to_message() {
        let json = r#"{"version":1,"status":"originMismatch",
 "message":"https://evil.example"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_fill(resp).expect_err("originMismatch must error");
        assert!(
            matches!(err, LocalTransportError::OriginMismatch { ref origin, .. } if origin == "https://evil.example")
        );
    }

    #[test]
    fn fill_response_no_safe_target_maps_with_each_reason_string() {
        for reason in [
            "looks-like-registration",
            "ambiguous-target",
            "no-password-field",
            "hidden-field-only",
            "cross-origin-frame",
            "no-login-form",
        ] {
            let json = format!(r#"{{"version":1,"status":"noSafeTarget","message":"{reason}"}}"#);
            let resp: WireResponse = serde_json::from_str(&json).expect("parse");
            let err = interpret_fill(resp).expect_err("noSafeTarget must error");
            match err {
                LocalTransportError::NoSafeTarget { reason: r } => assert_eq!(r, reason),
                other => panic!("expected NoSafeTarget, got {other:?}"),
            }
        }
    }

    #[test]
    fn fill_response_no_safe_target_falls_back_to_fill_reason_then_default() {
        let json = r#"{"version":1,"status":"noSafeTarget","fill":{"reason":"ambiguous-target"}}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_fill(resp).expect_err("must error");
        assert!(
            matches!(err, LocalTransportError::NoSafeTarget { reason } if reason == "ambiguous-target")
        );

        let json = r#"{"version":1,"status":"noSafeTarget"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_fill(resp).expect_err("must error");
        assert!(
            matches!(err, LocalTransportError::NoSafeTarget { reason } if reason == "no-safe-target")
        );
    }

    #[test]
    fn fill_response_error_status_maps_to_server_error() {
        // Unknown-delivery rejection is desktop-side (an old desktop that
        // doesn't understand `delivery: "fill"` answers with the existing
        // `status: "error"`), so this client-side test covers that the
        // existing `error` status is what such a rejection maps to.
        let json = r#"{"version":1,"status":"error","message":"unknown delivery mode: fill"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_fill(resp).expect_err("must error");
        assert!(
            matches!(err, LocalTransportError::ServerError(m) if m == "unknown delivery mode: fill")
        );
    }

    #[test]
    fn fill_response_status_mapping() {
        let cases = [
            ("denied", "Denied by user"),
            ("notFound", "No matching item found"),
            ("locked", "Vault is locked"),
            ("timeout", "Approval timed out"),
            ("rateLimited", "Rate limited"),
        ];
        for (status, default_msg) in cases {
            let json = format!(r#"{{"version":1,"status":"{status}"}}"#);
            let resp: WireResponse = serde_json::from_str(&json).expect("parse");
            let err = interpret_fill(resp).expect_err("non-approved status must error");
            assert!(err.to_string().contains(default_msg), "status {status}");
        }
    }

    // ── describeFillTarget response serde / interpretation ────────────

    #[test]
    fn describe_fill_target_response_approved_round_trips() {
        let json = r#"{"version":1,"status":"approved",
 "fillTarget":{"origin":"https://bitnotes.io","formClass":"login","candidates":[
   {"role":"username","target":"input#email (login form)","visible":true,"frame":"top"},
   {"role":"password","target":"input[type=password]#pw","visible":true,"frame":"top"}
 ],"refusals":[],"targetToken":"ft_abc123","expiresInMs":30000}}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let target = interpret_describe(resp).expect("should be Ok");

        assert_eq!(target.origin, "https://bitnotes.io");
        assert_eq!(target.form_class, "login");
        assert_eq!(target.candidates.len(), 2);
        assert_eq!(target.candidates[0].role, "username");
        assert!(target.candidates[0].visible);
        assert_eq!(target.candidates[0].frame.as_deref(), Some("top"));
        assert!(target.refusals.is_empty());
        assert_eq!(target.target_token.as_deref(), Some("ft_abc123"));
        assert_eq!(target.expires_in_ms, Some(30000));
    }

    #[test]
    fn describe_fill_target_response_with_refusals_round_trips() {
        let json = r#"{"version":1,"status":"approved",
 "fillTarget":{"origin":"https://bitnotes.io","formClass":"registration","candidates":[],
 "refusals":[{"role":"password","reason":"looks-like-registration"}]}}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let target = interpret_describe(resp).expect("should be Ok");
        assert_eq!(target.form_class, "registration");
        assert!(target.candidates.is_empty());
        assert_eq!(target.refusals.len(), 1);
        assert_eq!(target.refusals[0].reason, "looks-like-registration");
        // Optional fields absent from the JSON default to None.
        assert_eq!(target.target_token, None);
        assert_eq!(target.expires_in_ms, None);
    }

    #[test]
    fn describe_fill_target_response_approved_missing_fill_target_is_protocol_error() {
        let json = r#"{"version":1,"status":"approved"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_describe(resp).expect_err("must error");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[test]
    fn describe_fill_target_response_error_status_maps_to_server_error() {
        let json = r#"{"version":1,"status":"error","message":"extension not connected"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_describe(resp).expect_err("must error");
        assert!(
            matches!(err, LocalTransportError::ServerError(m) if m == "extension not connected")
        );
    }

    // ── secretRequest response serde / interpretation ────────────────

    #[test]
    fn secret_response_approved_inject_round_trips() {
        let json = r#"{"version":1,"status":"approved",
 "secret":{"name":"DB_PASSWORD","value":"hunter2",
           "secretId":"22222222-2222-2222-2222-222222222222"},
 "reference":"bw://secret/22222222-2222-2222-2222-222222222222"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let outcome = interpret_secret(resp).expect("should be Ok");
        match outcome {
            SecretOutcome::Secret(secret) => {
                assert_eq!(secret.name, "DB_PASSWORD");
                assert_eq!(secret.value.as_str(), "hunter2");
                assert_eq!(secret.secret_id, "22222222-2222-2222-2222-222222222222");
            }
            SecretOutcome::Reference { .. } => panic!("expected Secret outcome"),
        }
    }

    #[test]
    fn secret_response_approved_reference_round_trips() {
        let json = r#"{"version":1,"status":"approved",
 "item":{"name":"DB_PASSWORD"},
 "reference":"bw://secret/22222222-2222-2222-2222-222222222222"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let outcome = interpret_secret(resp).expect("should be Ok");
        match outcome {
            SecretOutcome::Reference {
                reference,
                item_name,
            } => {
                assert_eq!(
                    reference,
                    "bw://secret/22222222-2222-2222-2222-222222222222"
                );
                assert_eq!(item_name.as_deref(), Some("DB_PASSWORD"));
            }
            SecretOutcome::Secret(_) => panic!("expected Reference outcome"),
        }
    }

    #[test]
    fn secret_response_denied_maps_to_denied_error() {
        let json = r#"{"version":1,"status":"denied","message":"Denied by user"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_secret(resp).expect_err("denied should error");
        assert!(matches!(err, LocalTransportError::Denied(m) if m == "Denied by user"));
    }

    #[test]
    fn secret_response_not_found_uses_secret_specific_default_message() {
        let json = r#"{"version":1,"status":"notFound"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_secret(resp).expect_err("notFound should error");
        assert!(matches!(err, LocalTransportError::NotFound(m) if m == "No matching secret found"));
    }

    #[test]
    fn secret_response_approved_missing_both_payloads_is_protocol_error() {
        let json = r#"{"version":1,"status":"approved"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_secret(resp).expect_err("must error");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[test]
    fn secret_response_ignores_unknown_fields() {
        let json = r#"{"version":1,"status":"denied","message":"Denied by user",
 "someFutureField":{"nested":true}}"#;
        let resp: WireResponse =
            serde_json::from_str(json).expect("unknown fields must be ignored");
        let err = interpret_secret(resp).expect_err("denied should error");
        assert!(matches!(err, LocalTransportError::Denied(m) if m == "Denied by user"));
    }

    // ── secretCreate wire request serde ────────────────────────────────

    #[test]
    fn secret_create_request_serializes_contract_shape_exactly() {
        let input = SecretCreateInput {
            name: "DB_PASSWORD".to_string(),
            value: Zeroizing::new("hunter2".to_string()),
            note: Some("prod db".to_string()),
            project: Some("my-app".to_string()),
        };
        let request = WireCreateRequest::new(WireSecretCreate::from(&input));
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert_eq!(json["version"], 1);
        assert_eq!(json["op"], "secretCreate");
        assert_eq!(json["create"]["name"], "DB_PASSWORD");
        assert_eq!(json["create"]["value"], "hunter2");
        assert_eq!(json["create"]["note"], "prod db");
        assert_eq!(json["create"]["project"], "my-app");
        assert_eq!(json["client"]["name"], "aac");

        // No `query`/`delivery` — this op does not carry either.
        assert!(json.get("query").is_none());
        assert!(json.get("delivery").is_none());

        // Exactly the contract's field set, nothing extra.
        let mut top_level: Vec<&str> = json
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        top_level.sort_unstable();
        assert_eq!(top_level, vec!["client", "create", "op", "version"]);
    }

    #[test]
    fn secret_create_request_omits_absent_note_and_project() {
        let input = SecretCreateInput {
            name: "API_KEY".to_string(),
            value: Zeroizing::new("s3cr3t".to_string()),
            note: None,
            project: None,
        };
        let request = WireCreateRequest::new(WireSecretCreate::from(&input));
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert!(json["create"].get("note").is_none());
        assert!(json["create"].get("project").is_none());
    }

    #[test]
    fn secret_create_input_debug_never_prints_value() {
        let input = SecretCreateInput {
            name: "DB_PASSWORD".to_string(),
            value: Zeroizing::new("hunter2".to_string()),
            note: Some("a secret note".to_string()),
            project: Some("my-app".to_string()),
        };
        let debug = format!("{input:?}");
        assert!(!debug.contains("hunter2"), "value leaked: {debug}");
        assert!(!debug.contains("a secret note"), "note leaked: {debug}");
        assert!(debug.contains("DB_PASSWORD"));
        assert!(debug.contains("my-app"));
    }

    #[test]
    fn wire_secret_create_debug_never_prints_value() {
        let input = SecretCreateInput {
            name: "DB_PASSWORD".to_string(),
            value: Zeroizing::new("hunter2".to_string()),
            note: None,
            project: None,
        };
        let wire = WireSecretCreate::from(&input);
        let debug = format!("{wire:?}");
        assert!(!debug.contains("hunter2"), "value leaked: {debug}");
    }

    // ── secretCreate response interpretation ─────────────────────────

    #[test]
    fn secret_create_response_approved_derives_outcome() {
        let json = r#"{"version":1,"status":"approved",
 "reference":"bw://secret/33333333-3333-3333-3333-333333333333",
 "item":{"name":"DB_PASSWORD"}}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let outcome = interpret_secret_create(resp).expect("should be Ok");
        assert_eq!(outcome.secret_id, "33333333-3333-3333-3333-333333333333");
        assert_eq!(
            outcome.reference,
            "bw://secret/33333333-3333-3333-3333-333333333333"
        );
        assert_eq!(outcome.name.as_deref(), Some("DB_PASSWORD"));
    }

    #[test]
    fn secret_create_response_approved_without_item_still_derives_outcome() {
        // `item` is nice-to-have (display name) but not required to derive
        // the id — only `reference` is load-bearing.
        let json = r#"{"version":1,"status":"approved",
 "reference":"bw://secret/33333333-3333-3333-3333-333333333333"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let outcome = interpret_secret_create(resp).expect("should be Ok");
        assert_eq!(outcome.secret_id, "33333333-3333-3333-3333-333333333333");
        assert_eq!(outcome.name, None);
    }

    #[test]
    fn secret_create_response_approved_missing_reference_is_protocol_error() {
        let json = r#"{"version":1,"status":"approved","item":{"name":"DB_PASSWORD"}}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_secret_create(resp).expect_err("must error");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[test]
    fn secret_create_response_approved_unparseable_reference_is_protocol_error() {
        let json = r#"{"version":1,"status":"approved","reference":"not-a-secret-ref"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_secret_create(resp).expect_err("must error");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[test]
    fn secret_create_response_approved_empty_id_reference_is_protocol_error() {
        let json = r#"{"version":1,"status":"approved","reference":"bw://secret/"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_secret_create(resp).expect_err("must error");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[test]
    fn secret_create_response_status_mapping() {
        let cases = [
            ("denied", "Denied by user"),
            ("locked", "Vault is locked"),
            ("timeout", "Approval timed out"),
            ("rateLimited", "Rate limited"),
            ("error", "Local agent-access endpoint returned an error"),
        ];
        for (status, default_msg) in cases {
            let json = format!(r#"{{"version":1,"status":"{status}"}}"#);
            let resp: WireResponse = serde_json::from_str(&json).expect("parse");
            let err = interpret_secret_create(resp).expect_err("non-approved status must error");
            assert!(err.to_string().contains(default_msg), "status {status}");
        }
    }

    #[test]
    fn secret_create_response_not_found_does_not_panic() {
        // Contract: "`notFound` does not apply" to creates, but the server
        // must not panic if it somehow shows up — treated like any other
        // non-approved status.
        let json = r#"{"version":1,"status":"notFound"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_secret_create(resp).expect_err("must error, not panic");
        assert!(matches!(err, LocalTransportError::NotFound(_)));
    }

    // ── reference parsing ────────────────────────────────────────────

    #[test]
    fn strip_reference_extracts_id() {
        assert_eq!(
            strip_reference("bw://item/11111111-1111-1111-1111-111111111111"),
            "11111111-1111-1111-1111-111111111111"
        );
    }

    #[test]
    fn strip_reference_passes_through_plain_id() {
        assert_eq!(strip_reference("plain-id-123"), "plain-id-123");
    }

    #[test]
    fn strip_secret_reference_extracts_id() {
        assert_eq!(
            strip_secret_reference("bw://secret/22222222-2222-2222-2222-222222222222"),
            "22222222-2222-2222-2222-222222222222"
        );
    }

    #[test]
    fn strip_secret_reference_passes_through_plain_id() {
        assert_eq!(strip_secret_reference("plain-id-123"), "plain-id-123");
    }

    #[test]
    fn strip_secret_reference_does_not_strip_item_reference() {
        // Sanity check the two reference schemes stay distinct — a
        // `bw://item/...` value must not be mistaken for a secret reference.
        assert_eq!(
            strip_secret_reference("bw://item/11111111-1111-1111-1111-111111111111"),
            "bw://item/11111111-1111-1111-1111-111111111111"
        );
    }

    #[test]
    fn secret_query_from_flag_treats_reference_as_id() {
        let query = secret_query_from_flag("bw://secret/22222222-2222-2222-2222-222222222222");
        assert!(
            matches!(query, SecretQueryInput::Id(id) if id == "22222222-2222-2222-2222-222222222222")
        );
    }

    #[test]
    fn secret_query_from_flag_treats_plain_value_as_name() {
        let query = secret_query_from_flag("DB_PASSWORD");
        assert!(matches!(query, SecretQueryInput::Name(n) if n == "DB_PASSWORD"));
    }

    // ── secret env var name derivation ────────────────────────────────

    #[test]
    fn secret_env_var_name_derivation_table() {
        let cases = [
            ("db_password", "DB_PASSWORD"),
            ("DB_PASSWORD", "DB_PASSWORD"),
            ("api.key!", "API_KEY_"),
            ("3prod-secret", "_3PROD_SECRET"),
            ("already_valid_NAME", "ALREADY_VALID_NAME"),
            ("with spaces", "WITH_SPACES"),
            ("9", "_9"),
            ("", ""),
        ];
        for (input, expected) in cases {
            assert_eq!(secret_env_var_name(input), expected, "input was {input:?}");
        }
    }

    // ── username sanitization (windows pipe name) ────────────────────

    #[test]
    fn sanitize_username_keeps_allowed_chars() {
        assert_eq!(sanitize_username("max-power_01"), "max-power_01");
    }

    #[test]
    fn sanitize_username_replaces_disallowed_chars_with_underscore() {
        // Must match the desktop's WINDOWS_PIPE_NAME_SANITIZER exactly:
        // disallowed characters are replaced with `_`, never dropped.
        assert_eq!(sanitize_username(r"CORP\max power!"), "CORP_max_power_");
        assert_eq!(sanitize_username("üser"), "_ser");
    }

    #[test]
    fn sanitize_username_matches_desktop_vectors() {
        assert_eq!(sanitize_username("john.doe"), "john_doe");
        assert_eq!(sanitize_username(r"CORP\max power!"), "CORP_max_power_");
        assert_eq!(sanitize_username("plainuser"), "plainuser");
    }

    // ── capped line reader ────────────────────────────────────────────

    #[tokio::test]
    async fn read_capped_line_reads_normal_line() {
        let data = b"hello world\n".to_vec();
        let line = read_capped_line(std::io::Cursor::new(data))
            .await
            .expect("should read");
        assert_eq!(line, b"hello world");
    }

    #[tokio::test]
    async fn read_capped_line_rejects_oversized_line() {
        let mut data = vec![b'a'; MAX_LINE_BYTES + 10];
        data.push(b'\n');
        let err = read_capped_line(std::io::Cursor::new(data))
            .await
            .expect_err("should reject oversized line");
        assert!(matches!(err, LocalTransportError::ResponseTooLarge));
    }

    #[tokio::test]
    async fn read_capped_line_rejects_missing_newline() {
        let data = b"no newline here".to_vec();
        let err = read_capped_line(std::io::Cursor::new(data))
            .await
            .expect_err("should reject missing newline");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }
}

// ── unix integration test: mock socket server end to end ───────────────
#[cfg(all(test, unix))]
mod unix_integration_tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use tokio::net::{UnixListener, UnixStream as TokioUnixStream};

    /// Unique per-test socket path. `sockaddr_un` caps the path around
    /// 100-108 bytes depending on platform, so this deliberately avoids
    /// `std::env::temp_dir()` (which can be a long, deeply nested path on
    /// macOS) in favor of `/tmp` directly.
    fn unique_socket_path() -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        PathBuf::from(format!(
            "/tmp/aac-lt-{}-{n}.sock",
            std::process::id() % 100_000
        ))
    }

    /// Spawn a one-shot mock server on a unique temp socket path that reads
    /// one request line and replies with the given canned response line.
    /// Returns the endpoint to connect to.
    async fn spawn_mock_server(response_line: &'static str) -> LocalEndpoint {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind mock socket");

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                handle_one_request(&mut stream, response_line).await;
            }
        });

        // Give the listener a moment to be ready to accept.
        tokio::task::yield_now().await;

        LocalEndpoint::Unix(path)
    }

    async fn handle_one_request(stream: &mut TokioUnixStream, response_line: &str) {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match stream.read(&mut byte).await {
                Ok(0) => break,
                Ok(_) => {
                    if byte[0] == b'\n' {
                        break;
                    }
                    buf.push(byte[0]);
                }
                Err(_) => break,
            }
        }
        // Ensure we actually received a well-formed request line before replying.
        let _: serde_json::Value =
            serde_json::from_slice(&buf).expect("mock server received invalid JSON request");

        let mut out = response_line.as_bytes().to_vec();
        out.push(b'\n');
        let _ = stream.write_all(&out).await;
        let _ = stream.flush().await;
    }

    #[tokio::test]
    async fn end_to_end_approved_inject() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","credential":{"username":"u","password":"p","totp":"123456","uri":"https://github.com","credentialId":"item-1"},"reference":"bw://item/item-1"}"#,
        )
        .await;

        let outcome = request_credential(
            &endpoint,
            &CredentialQuery::Domain("github.com".to_string()),
            WireDelivery::Inject,
        )
        .await
        .expect("should succeed");

        match outcome {
            WireOutcome::Credential(cred) => {
                assert_eq!(cred.username.as_deref(), Some("u"));
                assert_eq!(cred.password.as_ref().map(|p| p.as_str()), Some("p"));
            }
            WireOutcome::Reference { .. } => panic!("expected Credential outcome"),
        }
    }

    #[tokio::test]
    async fn end_to_end_approved_reference() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","item":{"name":"GitHub","username":"u"},"reference":"bw://item/item-1"}"#,
        )
        .await;

        let outcome = request_credential(
            &endpoint,
            &CredentialQuery::Domain("github.com".to_string()),
            WireDelivery::Reference,
        )
        .await
        .expect("should succeed");

        match outcome {
            WireOutcome::Reference { reference, item } => {
                assert_eq!(reference, "bw://item/item-1");
                assert_eq!(item.name.as_deref(), Some("GitHub"));
            }
            WireOutcome::Credential(_) => panic!("expected Reference outcome"),
        }
    }

    #[tokio::test]
    async fn end_to_end_denied() {
        let endpoint =
            spawn_mock_server(r#"{"version":1,"status":"denied","message":"Denied by user"}"#)
                .await;

        let err = request_credential(
            &endpoint,
            &CredentialQuery::Domain("github.com".to_string()),
            WireDelivery::Reference,
        )
        .await
        .expect_err("should be denied");

        assert!(matches!(err, LocalTransportError::Denied(m) if m == "Denied by user"));
    }

    #[tokio::test]
    async fn end_to_end_not_found() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"notFound","message":"No matching item found"}"#,
        )
        .await;

        let err = request_credential(
            &endpoint,
            &CredentialQuery::Domain("nonexistent.example".to_string()),
            WireDelivery::Reference,
        )
        .await
        .expect_err("should be not found");

        assert!(matches!(err, LocalTransportError::NotFound(_)));
    }

    #[tokio::test]
    async fn connect_failed_when_no_listener() {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);
        let endpoint = LocalEndpoint::Unix(path);

        let err = request_credential(
            &endpoint,
            &CredentialQuery::Domain("github.com".to_string()),
            WireDelivery::Reference,
        )
        .await
        .expect_err("should fail to connect");

        assert!(matches!(err, LocalTransportError::ConnectFailed(_)));
    }

    // ── secretRequest end-to-end ─────────────────────────────────────

    #[tokio::test]
    async fn secret_end_to_end_approved_inject() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","secret":{"name":"DB_PASSWORD","value":"hunter2","secretId":"secret-1"},"reference":"bw://secret/secret-1"}"#,
        )
        .await;

        let outcome = request_secret(
            &endpoint,
            &SecretQueryInput::Name("DB_PASSWORD".to_string()),
            WireDelivery::Inject,
        )
        .await
        .expect("should succeed");

        match outcome {
            SecretOutcome::Secret(secret) => {
                assert_eq!(secret.name, "DB_PASSWORD");
                assert_eq!(secret.value.as_str(), "hunter2");
                assert_eq!(secret.secret_id, "secret-1");
            }
            SecretOutcome::Reference { .. } => panic!("expected Secret outcome"),
        }
    }

    #[tokio::test]
    async fn secret_end_to_end_approved_reference() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","item":{"name":"DB_PASSWORD"},"reference":"bw://secret/secret-1"}"#,
        )
        .await;

        let outcome = request_secret(
            &endpoint,
            &SecretQueryInput::Name("DB_PASSWORD".to_string()),
            WireDelivery::Reference,
        )
        .await
        .expect("should succeed");

        match outcome {
            SecretOutcome::Reference {
                reference,
                item_name,
            } => {
                assert_eq!(reference, "bw://secret/secret-1");
                assert_eq!(item_name.as_deref(), Some("DB_PASSWORD"));
            }
            SecretOutcome::Secret(_) => panic!("expected Reference outcome"),
        }
    }

    #[tokio::test]
    async fn secret_end_to_end_denied() {
        let endpoint =
            spawn_mock_server(r#"{"version":1,"status":"denied","message":"Denied by user"}"#)
                .await;

        let err = request_secret(
            &endpoint,
            &SecretQueryInput::Name("DB_PASSWORD".to_string()),
            WireDelivery::Reference,
        )
        .await
        .expect_err("should be denied");

        assert!(matches!(err, LocalTransportError::Denied(m) if m == "Denied by user"));
    }

    #[tokio::test]
    async fn secret_end_to_end_not_found() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"notFound","message":"No matching secret found"}"#,
        )
        .await;

        let err = request_secret(
            &endpoint,
            &SecretQueryInput::Name("NONEXISTENT".to_string()),
            WireDelivery::Reference,
        )
        .await
        .expect_err("should be not found");

        assert!(matches!(err, LocalTransportError::NotFound(_)));
    }

    #[tokio::test]
    async fn secret_connect_failed_when_no_listener() {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);
        let endpoint = LocalEndpoint::Unix(path);

        let err = request_secret(
            &endpoint,
            &SecretQueryInput::Name("DB_PASSWORD".to_string()),
            WireDelivery::Reference,
        )
        .await
        .expect_err("should fail to connect");

        assert!(matches!(err, LocalTransportError::ConnectFailed(_)));
    }

    // ── fill end-to-end ────────────────────────────────────────────────

    #[tokio::test]
    async fn fill_end_to_end_approved_filled() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","item":{"name":"bitnotes.io","username":"demo@bitnotes.io"},"reference":"bw://item/item-1","fill":{"status":"filled","origin":"https://bitnotes.io","fields":[{"role":"username","status":"filled","target":"input#email"},{"role":"password","status":"filled","target":"input[type=password]#pw"}]}}"#,
        )
        .await;

        let outcome = request_fill(
            &endpoint,
            &CredentialQuery::Domain("bitnotes.io".to_string()),
            Some(FillInput {
                fields: Some(vec!["username".to_string(), "password".to_string()]),
                target_token: None,
            }),
        )
        .await
        .expect("should succeed");

        assert_eq!(outcome.status, "filled");
        assert_eq!(outcome.origin.as_deref(), Some("https://bitnotes.io"));
        assert_eq!(outcome.fields.len(), 2);
    }

    #[tokio::test]
    async fn fill_end_to_end_target_token_reaches_the_server() {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind mock socket");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                match stream.read(&mut byte).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) if byte[0] == b'\n' => break,
                    Ok(_) => buf.push(byte[0]),
                }
            }
            let request: serde_json::Value =
                serde_json::from_slice(&buf).expect("mock server received invalid JSON request");

            let response = r#"{"version":1,"status":"approved","item":{"name":"bitnotes.io"},"reference":"bw://item/item-1","fill":{"status":"filled","origin":"https://bitnotes.io","fields":[]}}"#;
            let mut out = response.as_bytes().to_vec();
            out.push(b'\n');
            let _ = stream.write_all(&out).await;
            let _ = stream.flush().await;

            request
        });

        tokio::task::yield_now().await;
        let endpoint = LocalEndpoint::Unix(path);

        let _ = request_fill(
            &endpoint,
            &CredentialQuery::Domain("bitnotes.io".to_string()),
            Some(FillInput {
                fields: None,
                target_token: Some("ft_abc123".to_string()),
            }),
        )
        .await
        .expect("should succeed");

        let request = server.await.expect("server task");
        assert_eq!(request["fill"]["targetToken"], "ft_abc123");
    }

    #[tokio::test]
    async fn fill_end_to_end_origin_mismatch() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"originMismatch","item":{"name":"bitnotes.io"},"fill":{"origin":"https://evil.example"}}"#,
        )
        .await;

        let err = request_fill(
            &endpoint,
            &CredentialQuery::Domain("bitnotes.io".to_string()),
            None,
        )
        .await
        .expect_err("should be refused");

        match err {
            LocalTransportError::OriginMismatch { origin, item_name } => {
                assert_eq!(origin, "https://evil.example");
                assert_eq!(item_name.as_deref(), Some("bitnotes.io"));
            }
            other => panic!("expected OriginMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fill_end_to_end_no_safe_target() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"noSafeTarget","message":"no-password-field"}"#,
        )
        .await;

        let err = request_fill(
            &endpoint,
            &CredentialQuery::Domain("bitnotes.io".to_string()),
            None,
        )
        .await
        .expect_err("should be refused");

        assert!(
            matches!(err, LocalTransportError::NoSafeTarget { reason } if reason == "no-password-field")
        );
    }

    #[tokio::test]
    async fn fill_end_to_end_denied() {
        let endpoint =
            spawn_mock_server(r#"{"version":1,"status":"denied","message":"Denied by user"}"#)
                .await;

        let err = request_fill(
            &endpoint,
            &CredentialQuery::Domain("bitnotes.io".to_string()),
            None,
        )
        .await
        .expect_err("should be denied");

        assert!(matches!(err, LocalTransportError::Denied(m) if m == "Denied by user"));
    }

    #[tokio::test]
    async fn fill_connect_failed_when_no_listener() {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);
        let endpoint = LocalEndpoint::Unix(path);

        let err = request_fill(
            &endpoint,
            &CredentialQuery::Domain("bitnotes.io".to_string()),
            None,
        )
        .await
        .expect_err("should fail to connect");

        assert!(matches!(err, LocalTransportError::ConnectFailed(_)));
    }

    // ── describeFillTarget end-to-end ─────────────────────────────────

    #[tokio::test]
    async fn describe_fill_target_end_to_end_approved() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","fillTarget":{"origin":"https://bitnotes.io","formClass":"login","candidates":[{"role":"username","target":"input#email","visible":true,"frame":"top"}],"refusals":[],"targetToken":"ft_abc123","expiresInMs":30000}}"#,
        )
        .await;

        let target = request_describe_fill_target(&endpoint)
            .await
            .expect("should succeed");

        assert_eq!(target.origin, "https://bitnotes.io");
        assert_eq!(target.form_class, "login");
        assert_eq!(target.candidates.len(), 1);
        assert_eq!(target.target_token.as_deref(), Some("ft_abc123"));
    }

    #[tokio::test]
    async fn describe_fill_target_end_to_end_error_status() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"error","message":"The Bitwarden browser extension is not connected"}"#,
        )
        .await;

        let err = request_describe_fill_target(&endpoint)
            .await
            .expect_err("should error");

        assert!(matches!(err, LocalTransportError::ServerError(_)));
    }

    #[tokio::test]
    async fn describe_fill_target_connect_failed_when_no_listener() {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);
        let endpoint = LocalEndpoint::Unix(path);

        let err = request_describe_fill_target(&endpoint)
            .await
            .expect_err("should fail to connect");

        assert!(matches!(err, LocalTransportError::ConnectFailed(_)));
    }

    // ── secretCreate end-to-end ──────────────────────────────────────

    fn make_secret_create_input() -> SecretCreateInput {
        SecretCreateInput {
            name: "DB_PASSWORD".to_string(),
            value: Zeroizing::new("hunter2".to_string()),
            note: Some("prod db".to_string()),
            project: Some("my-app".to_string()),
        }
    }

    #[tokio::test]
    async fn secret_create_end_to_end_approved() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","reference":"bw://secret/secret-1","item":{"name":"DB_PASSWORD"}}"#,
        )
        .await;

        let outcome = request_secret_create(&endpoint, &make_secret_create_input())
            .await
            .expect("should succeed");

        assert_eq!(outcome.secret_id, "secret-1");
        assert_eq!(outcome.reference, "bw://secret/secret-1");
        assert_eq!(outcome.name.as_deref(), Some("DB_PASSWORD"));
    }

    #[tokio::test]
    async fn secret_create_end_to_end_denied() {
        let endpoint =
            spawn_mock_server(r#"{"version":1,"status":"denied","message":"Denied by user"}"#)
                .await;

        let err = request_secret_create(&endpoint, &make_secret_create_input())
            .await
            .expect_err("should be denied");

        assert!(matches!(err, LocalTransportError::Denied(m) if m == "Denied by user"));
    }

    #[tokio::test]
    async fn secret_create_end_to_end_missing_reference_is_protocol_error() {
        let endpoint =
            spawn_mock_server(r#"{"version":1,"status":"approved","item":{"name":"x"}}"#).await;

        let err = request_secret_create(&endpoint, &make_secret_create_input())
            .await
            .expect_err("should be a protocol error");

        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[tokio::test]
    async fn secret_create_connect_failed_when_no_listener() {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);
        let endpoint = LocalEndpoint::Unix(path);

        let err = request_secret_create(&endpoint, &make_secret_create_input())
            .await
            .expect_err("should fail to connect");

        assert!(matches!(err, LocalTransportError::ConnectFailed(_)));
    }
}
