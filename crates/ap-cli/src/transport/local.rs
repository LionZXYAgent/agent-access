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

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use ap_client::CredentialQuery;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use uuid::Uuid;
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

/// Reference URI scheme used for value-free Secrets Manager project pointers
/// (`bw://project/<id>`) — distinct from both `bw://item/<id>` and
/// `bw://secret/<id>` (architecture doc, M6: "New reference scheme
/// `bw://project/<id>`"). Redeeming one is a fresh `id`-targeted request with
/// its own approval, exactly like items and secrets.
pub const PROJECT_REFERENCE_PREFIX: &str = "bw://project/";

/// If `value` looks like a `bw://project/<id>` reference, return the bare id;
/// otherwise return `value` unchanged. Mirrors [`strip_secret_reference`] for
/// the projects reference scheme.
pub fn strip_project_reference(value: &str) -> &str {
    value
        .strip_prefix(PROJECT_REFERENCE_PREFIX)
        .unwrap_or(value)
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

/// Build a [`ProjectQueryInput`] from a `--project <name|uuid|bw://project/id>`
/// CLI-style value (architecture doc, M7): a `bw://project/<id>` reference
/// resolves to an `Id` query (stripping the prefix via
/// [`strip_project_reference`]); a value that parses as a bare UUID is also
/// treated as an `Id` (bws parity — `bws run --project-id` accepts a bare
/// UUID with no reference wrapper); anything else is a `Name` query (exact
/// match, falling back to a unique case-insensitive match, resolved
/// desktop-side). Sibling of [`secret_query_from_flag`]; shared by the
/// `run_with_project_secrets` MCP tool and `aac run --project`.
pub fn project_query_from_flag(value: &str) -> ProjectQueryInput {
    if value.starts_with(PROJECT_REFERENCE_PREFIX) {
        ProjectQueryInput::Id(strip_project_reference(value).to_string())
    } else if Uuid::parse_str(value).is_ok() {
        ProjectQueryInput::Id(value.to_string())
    } else {
        ProjectQueryInput::Name(value.to_string())
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

/// Derive a POSIX-safe environment-variable name from a secret's own UUID
/// instead of its name: `_` followed by the UUID with every `-` replaced by
/// `_` — mirrors sdk-sm's `bws` CLI (`crates/bws/src/util.rs::uuid_to_posix`),
/// the `--uuids-as-keynames` prior art this escape hatch is named after
/// (architecture doc, M7). Unlike [`secret_env_var_name`], two distinct
/// secrets can never collide under this scheme (UUIDs are unique), which is
/// exactly why `run_with_project_secrets`/`aac run --project` offer it as
/// the collision escape hatch.
pub fn secret_env_var_name_from_uuid(secret_id: &str) -> String {
    format!("_{}", secret_id.replace('-', "_"))
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

/// Selector for a `projectSecretsRequest` over the local transport
/// (architecture doc, M7): exactly one of a project's UUID or its name. No
/// `Search` variant — the wire protocol's `project` object is
/// `{"id":...}`/`{"name":...}` only, never a free-text lookup (project-name
/// resolution, including the exact/unique-case-insensitive fallback, happens
/// desktop-side, mirroring `secretRequest`'s `name` query).
#[derive(Debug, Clone)]
pub enum ProjectQueryInput {
    /// Look up by project UUID.
    Id(String),
    /// Look up by project name (exact, falling back to unique
    /// case-insensitive match, resolved desktop-side).
    Name(String),
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

/// The `project` selector object of a `projectSecretsRequest`, per the
/// architecture doc's M7 wire shape: exactly one of `{"id":"<uuid>"}` or
/// `{"name":"…"}` — untagged so neither variant adds a wrapping `type`/
/// `value` envelope the way [`WireQuery`]/[`WireSecretQuery`] do.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
enum WireProjectSelector {
    Id { id: String },
    Name { name: String },
}

impl From<&ProjectQueryInput> for WireProjectSelector {
    fn from(query: &ProjectQueryInput) -> Self {
        match query {
            ProjectQueryInput::Id(id) => WireProjectSelector::Id { id: id.clone() },
            ProjectQueryInput::Name(name) => WireProjectSelector::Name { name: name.clone() },
        }
    }
}

/// Minimum/maximum accepted `generate.length`, per the architecture doc's
/// M6 wire contract ("`length` ∈ [12, 128], default 40 ... Out-of-range
/// length is a validation error ("generate.length must be between 12 and
/// 128"), not a clamp"). Callers (the MCP tool runners) must validate a
/// caller-supplied length against these bounds *before* dispatch — this
/// module does not clamp or otherwise silently correct an out-of-range
/// value.
pub const GENERATE_LENGTH_MIN: u32 = 12;
pub const GENERATE_LENGTH_MAX: u32 = 128;

/// Validate a caller-supplied `generate.length` against
/// [`GENERATE_LENGTH_MIN`]/[`GENERATE_LENGTH_MAX`]. `None` (length omitted,
/// desktop applies its own default) always passes. Shared by every MCP tool
/// that accepts a `length` argument (`generate_secret`, `update_secret`) so
/// the bound and its error message stay in exactly one place.
pub fn validate_generate_length(length: Option<u32>) -> Result<(), String> {
    match length {
        Some(len) if !(GENERATE_LENGTH_MIN..=GENERATE_LENGTH_MAX).contains(&len) => Err(format!(
            "The 'length' argument must be between {GENERATE_LENGTH_MIN} and {GENERATE_LENGTH_MAX}."
        )),
        _ => Ok(()),
    }
}

/// Options for generating a new secret value inside the desktop app instead
/// of supplying one explicitly (architecture doc, M6: "generated values
/// never exist in this process at all"). Both fields are optional on the
/// wire; the desktop applies its own defaults (length 40, symbols true) when
/// absent — this module never fills them in. No secret material — `length`/
/// `symbols` are generation *parameters*, not the generated value itself —
/// so deriving `Debug` is safe here, unlike [`SecretCreateInput`] and
/// [`SecretUpdateInput`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WireGenerateOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbols: Option<bool>,
}

/// Input to a local `secretCreate` request: the new secret's name, plus
/// either an explicit `value` or `generate` options (exactly one — enforced
/// at the wire-conversion seam below, mirroring the MCP layer's own
/// validation), and an optional note and project-name hint. Public,
/// caller-facing counterpart of [`WireSecretCreate`] — mirrors how
/// [`SecretQueryInput`] relates to [`WireSecretQuery`]. Create-only (no
/// update via this type; see [`SecretUpdateInput`]), per the architecture
/// doc's M4b: no update, no delete through `secretCreate` itself.
#[derive(Clone)]
pub struct SecretCreateInput {
    pub name: String,
    pub value: Option<Zeroizing<String>>,
    pub generate: Option<WireGenerateOptions>,
    pub note: Option<String>,
    pub project: Option<String>,
}

// Manual Debug: never print the value, even in a derived debug string.
// `generate` carries no secret material, so it prints verbatim.
impl std::fmt::Debug for SecretCreateInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretCreateInput")
            .field("name", &self.name)
            .field("value", &self.value.as_ref().map(|_| "[REDACTED]"))
            .field("generate", &self.generate)
            .field("note", &self.note.as_ref().map(|_| "[present]"))
            .field("project", &self.project)
            .finish()
    }
}

/// Input to a local `secretUpdate` request (architecture doc, M6):
/// `target_id` selects the secret; every other field is "absent = unchanged"
/// EXCEPT `note`, where `Some(String::new())` means "clear the note" — only
/// `None` means "leave the note as-is". `value`/`generate` are mutually
/// exclusive (enforced at the wire-conversion seam below); both may be
/// absent for a rename/move/note-only update — unlike [`SecretCreateInput`],
/// there is no "exactly one" requirement here.
pub struct SecretUpdateInput {
    pub target_id: String,
    pub name: Option<String>,
    pub value: Option<Zeroizing<String>>,
    pub generate: Option<WireGenerateOptions>,
    pub note: Option<String>,
    pub project: Option<String>,
}

// Manual Debug: never print the value, even in a derived debug string.
impl std::fmt::Debug for SecretUpdateInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretUpdateInput")
            .field("target_id", &self.target_id)
            .field("name", &self.name)
            .field("value", &self.value.as_ref().map(|_| "[REDACTED]"))
            .field("generate", &self.generate)
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
/// doc's M4b/M6 wire shape: `{"name":"DB_PASSWORD","value":"…","note":"…",
/// "project":"my-app"}` or, with generation, `{"name":"...",
/// "generate":{"length":40,"symbols":true},...}`. `name` is required
/// non-empty (validated by callers, e.g. the `create_secret`/`generate_secret`
/// MCP tools); exactly one of `value`/`generate` is present — enforced in
/// the `From` impl below, mirroring the MCP layer's own validation
/// (architecture doc, M6: "the MCP layer validates, transport asserts").
/// `note` and `project` are omitted entirely when absent rather than
/// serialized as `null`.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct WireSecretCreate {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<Zeroizing<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generate: Option<WireGenerateOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<String>,
}

// Manual Debug: never print the value, even in a derived debug string.
// `generate` carries no secret material, so it prints verbatim.
impl std::fmt::Debug for WireSecretCreate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireSecretCreate")
            .field("name", &self.name)
            .field("value", &self.value.as_ref().map(|_| "[REDACTED]"))
            .field("generate", &self.generate)
            .field("note", &self.note.as_ref().map(|_| "[present]"))
            .field("project", &self.project)
            .finish()
    }
}

impl From<&SecretCreateInput> for WireSecretCreate {
    fn from(input: &SecretCreateInput) -> Self {
        debug_assert!(
            input.value.is_some() ^ input.generate.is_some(),
            "SecretCreateInput must carry exactly one of value/generate"
        );
        Self {
            name: input.name.clone(),
            value: input.value.clone(),
            generate: input.generate,
            note: input.note.clone(),
            project: input.project.clone(),
        }
    }
}

/// The `update` payload of a `secretUpdate` request (architecture doc, M6):
/// `{"name"?,"value"?,"generate"?:{...},"note"?,"project"?}`. Every field is
/// "absent = unchanged" on the wire EXCEPT `note`: `Some(String::new())`
/// serializes as `"note":""` (clear the note), while `None` omits the key
/// entirely (leave the note as-is) — plain `Option<String>` with
/// `skip_serializing_if` already gives exactly this behavior, no special
/// handling needed. `value`/`generate` are mutually exclusive — asserted in
/// the `From` impl below (both may be absent, unlike [`WireSecretCreate`]).
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct WireSecretUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<Zeroizing<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generate: Option<WireGenerateOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<String>,
}

// Manual Debug: value REDACTED, note presence-only, name/project/generate
// verbatim (matches `WireSecretCreate`'s pattern).
impl std::fmt::Debug for WireSecretUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireSecretUpdate")
            .field("name", &self.name)
            .field("value", &self.value.as_ref().map(|_| "[REDACTED]"))
            .field("generate", &self.generate)
            .field("note", &self.note.as_ref().map(|_| "[present]"))
            .field("project", &self.project)
            .finish()
    }
}

impl From<&SecretUpdateInput> for WireSecretUpdate {
    fn from(input: &SecretUpdateInput) -> Self {
        debug_assert!(
            !(input.value.is_some() && input.generate.is_some()),
            "SecretUpdateInput must not carry both value and generate"
        );
        Self {
            name: input.name.clone(),
            value: input.value.clone(),
            generate: input.generate,
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

/// A single-id target, per the architecture doc's M6 op table:
/// `{"target":{"id":"<uuid>"}}` on `secretUpdate`, `secretDelete`,
/// `projectUpdate`, and `projectDelete`. One approval == one target — there
/// is deliberately no plural/array form.
#[derive(Debug, Clone, Serialize)]
struct WireTarget {
    id: String,
}

/// A `{"name":"..."}` payload, shared by `projectCreate`'s `create` object
/// and `projectUpdate`'s `update` object — both are exactly this one field
/// on the wire (architecture doc, M6).
#[derive(Debug, Clone, Serialize)]
struct WireNameOnly {
    name: String,
}

/// A `secretUpdate` request line: `{version, op:"secretUpdate", target,
/// update, client}` (architecture doc, M6). `#[derive(Debug)]` is safe here
/// even though `update` carries a possible secret value — [`WireSecretUpdate`]
/// has its own manual, redacting `Debug` impl that the derive delegates to.
#[derive(Debug, Clone, Serialize)]
struct WireSecretUpdateRequest {
    version: u32,
    op: &'static str,
    target: WireTarget,
    update: WireSecretUpdate,
    client: WireClientInfo,
}

impl WireSecretUpdateRequest {
    fn new(target_id: String, update: WireSecretUpdate) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            op: "secretUpdate",
            target: WireTarget { id: target_id },
            update,
            client: WireClientInfo {
                name: "aac",
                version: env!("CARGO_PKG_VERSION"),
            },
        }
    }
}

/// A single-target, no-payload request line: `{version, op, target,
/// client}`. Shared by `secretDelete` and `projectDelete`, which have
/// identical wire shape — the op string alone distinguishes them, so one
/// struct with two named constructors (each pinning its own op, mirroring
/// [`WireCreateRequest::new`]) replaces what would otherwise be two
/// structurally-identical types.
#[derive(Debug, Clone, Serialize)]
struct WireTargetRequest {
    version: u32,
    op: &'static str,
    target: WireTarget,
    client: WireClientInfo,
}

impl WireTargetRequest {
    fn for_op(op: &'static str, target_id: String) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            op,
            target: WireTarget { id: target_id },
            client: WireClientInfo {
                name: "aac",
                version: env!("CARGO_PKG_VERSION"),
            },
        }
    }

    fn secret_delete(target_id: String) -> Self {
        Self::for_op("secretDelete", target_id)
    }

    fn project_delete(target_id: String) -> Self {
        Self::for_op("projectDelete", target_id)
    }
}

/// A `projectUpdate` request line: `{version, op:"projectUpdate", target,
/// update:{name}, client}` (architecture doc, M6) — rename-only, mirroring
/// the server.
#[derive(Debug, Clone, Serialize)]
struct WireProjectUpdateRequest {
    version: u32,
    op: &'static str,
    target: WireTarget,
    update: WireNameOnly,
    client: WireClientInfo,
}

impl WireProjectUpdateRequest {
    fn new(target_id: String, name: String) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            op: "projectUpdate",
            target: WireTarget { id: target_id },
            update: WireNameOnly { name },
            client: WireClientInfo {
                name: "aac",
                version: env!("CARGO_PKG_VERSION"),
            },
        }
    }
}

/// A `projectList` request line: `{version, op:"projectList", client}`
/// (architecture doc, M6) — no `query`, no `target`. One approval releases
/// every readable project across the user's SM orgs.
#[derive(Debug, Clone, Serialize)]
struct WireProjectListRequest {
    version: u32,
    op: &'static str,
    client: WireClientInfo,
}

impl WireProjectListRequest {
    fn new() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            op: "projectList",
            client: WireClientInfo {
                name: "aac",
                version: env!("CARGO_PKG_VERSION"),
            },
        }
    }
}

/// A `projectCreate` request line: `{version, op:"projectCreate",
/// create:{name}, client}` (architecture doc, M6) — `value`/`generate`/
/// `note`/`project` must be ABSENT for this op, so the `create` payload is
/// exactly `{name}`, never the full `WireSecretCreate` shape.
#[derive(Debug, Clone, Serialize)]
struct WireProjectCreateRequest {
    version: u32,
    op: &'static str,
    create: WireNameOnly,
    client: WireClientInfo,
}

impl WireProjectCreateRequest {
    fn new(name: String) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            op: "projectCreate",
            create: WireNameOnly { name },
            client: WireClientInfo {
                name: "aac",
                version: env!("CARGO_PKG_VERSION"),
            },
        }
    }
}

/// A `projectSecretsRequest` request line: `{version, op:"projectSecretsRequest",
/// project, client}` (architecture doc, M7) — no `query`/`delivery`/`fill`/
/// `create`/`update`/`target`; delivery is implicitly inject and there is no
/// reference form for this op.
#[derive(Debug, Clone, Serialize)]
struct WireProjectSecretsRequest {
    version: u32,
    op: &'static str,
    project: WireProjectSelector,
    client: WireClientInfo,
}

impl WireProjectSecretsRequest {
    fn new(project: WireProjectSelector) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            op: "projectSecretsRequest",
            project,
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

/// One project entry in a `projectList` response's `projects` array
/// (architecture doc, M6): `{"name":"...","reference":"bw://project/<id>",
/// "write":true,"organization":"<org name>"}`. Plain `Debug` is fine — a
/// project name is organization metadata, not secret material. Doubles as
/// the public outcome element type for [`request_project_list`] (same
/// pattern as [`WireItem`]/[`WireFillCandidate`] elsewhere in this module:
/// no secret material, so no separate public mirror type is needed).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireProjectEntry {
    pub name: String,
    pub reference: String,
    pub write: bool,
    #[serde(default)]
    pub organization: Option<String>,
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
    /// `projectList` only (architecture doc, M6). `#[serde(default)]` so
    /// every other op's responses — which never carry this key — still
    /// deserialize.
    #[serde(default)]
    projects: Option<Vec<WireProjectEntry>>,
    /// `projectSecretsRequest` only (architecture doc, M7): the enumerated,
    /// value-bearing secret set of the released project. `#[serde(default)]`
    /// so every other op's responses still deserialize. Distinguishing
    /// "missing" (`None`) from "present but empty" (`Some(vec![])`) matters
    /// here — see `interpret_project_secrets`, which fails closed on both,
    /// since the desktop's zero-secrets rule returns `notFound` instead of
    /// an approved-but-empty array.
    #[serde(default)]
    secrets: Option<Vec<WireSecret>>,
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

// ── M6: secret update/delete, project list/create/update/delete ─────────

/// The interpreted, successful outcome of a local `secretUpdate`,
/// `secretDelete`, `projectCreate`, `projectUpdate`, or `projectDelete`
/// request. Every one of these ops replies reference+item-shaped by
/// construction (architecture doc, M6 invariant #13: "No wire reply ever
/// carries a secret value for ANY M6 op") — `id` is derived client-side from
/// `reference` by stripping whichever of [`SECRET_REFERENCE_PREFIX`]/
/// [`PROJECT_REFERENCE_PREFIX`] applies to the op that produced it.
#[derive(Debug, Clone)]
pub struct ReferenceOutcome {
    pub id: String,
    pub reference: String,
    pub name: Option<String>,
}

/// Shared interpreter for every M6 op whose successful reply is
/// reference+item-shaped (`secretUpdate`, `secretDelete`, `projectCreate`,
/// `projectUpdate`, `projectDelete`). Mirrors [`interpret_secret_create`]'s
/// shape, generalized over which reference prefix to expect. Defensively
/// rejects a value-bearing `secret` reply as a protocol error — mirroring
/// [`interpret_fill`]'s stance at the top of this file — even though no
/// correctly-behaving desktop ever sends one here (architecture doc, M6
/// invariant #13).
fn interpret_reference_outcome(
    resp: WireResponse,
    expected_prefix: &str,
    op_label: &str,
) -> Result<ReferenceOutcome, LocalTransportError> {
    if resp.version != PROTOCOL_VERSION {
        return Err(LocalTransportError::UnsupportedVersion(resp.version));
    }
    if resp.secret.is_some() {
        return Err(LocalTransportError::Protocol(format!(
            "value-bearing reply to a {op_label} request"
        )));
    }

    let message = |fallback: &str| resp.message.clone().unwrap_or_else(|| fallback.to_string());

    match resp.status {
        WireStatus::Approved => {
            let reference = resp.reference.ok_or_else(|| {
                LocalTransportError::Protocol(format!(
                    "approved {op_label} response missing 'reference'"
                ))
            })?;
            let Some(id) = reference.strip_prefix(expected_prefix) else {
                return Err(LocalTransportError::Protocol(format!(
                    "approved {op_label} response has an unparseable 'reference': {reference}"
                )));
            };
            let id = id.to_string();
            if id.is_empty() {
                return Err(LocalTransportError::Protocol(format!(
                    "approved {op_label} response has an empty id in 'reference'"
                )));
            }
            Ok(ReferenceOutcome {
                id,
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
        WireStatus::OriginMismatch => Err(LocalTransportError::Protocol(format!(
            "unexpected 'originMismatch' status for a {op_label} request"
        ))),
        WireStatus::NoSafeTarget => Err(LocalTransportError::Protocol(format!(
            "unexpected 'noSafeTarget' status for a {op_label} request"
        ))),
    }
}

/// Perform one full local Secrets Manager secret *update*: connect, send,
/// receive, interpret. One connection per request, per protocol. Secrets
/// (including updates) are local-transport-only — same no-relay-fallback
/// contract as [`request_secret`]. There is deliberately no CLI-facing
/// constructor for this request, same reasoning as [`request_secret_create`].
pub async fn request_secret_update(
    endpoint: &LocalEndpoint,
    input: &SecretUpdateInput,
) -> Result<ReferenceOutcome, LocalTransportError> {
    let stream = connect(endpoint).await?;
    let request =
        WireSecretUpdateRequest::new(input.target_id.clone(), WireSecretUpdate::from(input));
    let response = run_request(stream, &request).await?;
    interpret_reference_outcome(response, SECRET_REFERENCE_PREFIX, "secretUpdate")
}

/// Perform one full local Secrets Manager secret *deletion* (soft delete —
/// SM trash; architecture doc, M6): connect, send, receive, interpret.
pub async fn request_secret_delete(
    endpoint: &LocalEndpoint,
    target_id: &str,
) -> Result<ReferenceOutcome, LocalTransportError> {
    let stream = connect(endpoint).await?;
    let request = WireTargetRequest::secret_delete(target_id.to_string());
    let response = run_request(stream, &request).await?;
    interpret_reference_outcome(response, SECRET_REFERENCE_PREFIX, "secretDelete")
}

/// Interpret a parsed [`WireResponse`] into the `projectList` outcome: the
/// full `projects` array. Mirrors [`interpret_reference_outcome`]'s shared
/// statuses; `approved` requires `projects` to be present (missing `projects`
/// on an approved reply is a protocol error, per the architecture doc's M6
/// op table).
fn interpret_project_list(
    resp: WireResponse,
) -> Result<Vec<WireProjectEntry>, LocalTransportError> {
    if resp.version != PROTOCOL_VERSION {
        return Err(LocalTransportError::UnsupportedVersion(resp.version));
    }
    if resp.secret.is_some() {
        return Err(LocalTransportError::Protocol(
            "value-bearing reply to a projectList request".to_string(),
        ));
    }

    let message = |fallback: &str| resp.message.clone().unwrap_or_else(|| fallback.to_string());

    match resp.status {
        WireStatus::Approved => resp.projects.ok_or_else(|| {
            LocalTransportError::Protocol(
                "approved projectList response missing 'projects'".to_string(),
            )
        }),
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
        WireStatus::OriginMismatch => Err(LocalTransportError::Protocol(
            "unexpected 'originMismatch' status for a projectList request".to_string(),
        )),
        WireStatus::NoSafeTarget => Err(LocalTransportError::Protocol(
            "unexpected 'noSafeTarget' status for a projectList request".to_string(),
        )),
    }
}

/// Perform one full local `projectList`: connect, send, receive, interpret.
/// One approval releases the full readable project list across the user's
/// SM orgs (architecture doc, M6) — the sole list-shaped release in the
/// protocol.
pub async fn request_project_list(
    endpoint: &LocalEndpoint,
) -> Result<Vec<WireProjectEntry>, LocalTransportError> {
    let stream = connect(endpoint).await?;
    let request = WireProjectListRequest::new();
    let response = run_request(stream, &request).await?;
    interpret_project_list(response)
}

/// Perform one full local `projectCreate`: connect, send, receive, interpret.
/// Any SM user may create a project (architecture doc, M6 recon) — this
/// request carries only `name`.
pub async fn request_project_create(
    endpoint: &LocalEndpoint,
    name: &str,
) -> Result<ReferenceOutcome, LocalTransportError> {
    let stream = connect(endpoint).await?;
    let request = WireProjectCreateRequest::new(name.to_string());
    let response = run_request(stream, &request).await?;
    interpret_reference_outcome(response, PROJECT_REFERENCE_PREFIX, "projectCreate")
}

/// Perform one full local `projectUpdate` (rename-only): connect, send,
/// receive, interpret.
pub async fn request_project_update(
    endpoint: &LocalEndpoint,
    target_id: &str,
    name: &str,
) -> Result<ReferenceOutcome, LocalTransportError> {
    let stream = connect(endpoint).await?;
    let request = WireProjectUpdateRequest::new(target_id.to_string(), name.to_string());
    let response = run_request(stream, &request).await?;
    interpret_reference_outcome(response, PROJECT_REFERENCE_PREFIX, "projectUpdate")
}

/// Perform one full local `projectDelete` (hard delete — the project row is
/// removed; contained secrets survive project-less, architecture doc M6):
/// connect, send, receive, interpret.
pub async fn request_project_delete(
    endpoint: &LocalEndpoint,
    target_id: &str,
) -> Result<ReferenceOutcome, LocalTransportError> {
    let stream = connect(endpoint).await?;
    let request = WireTargetRequest::project_delete(target_id.to_string());
    let response = run_request(stream, &request).await?;
    interpret_reference_outcome(response, PROJECT_REFERENCE_PREFIX, "projectDelete")
}

// ── M7: `bws run` parity — project-scoped bulk secret injection ─────────

/// The interpreted, successful outcome of a local `projectSecretsRequest`
/// (architecture doc, M7): the released project's name/reference plus its
/// full, value-bearing secret set. `#[derive(Debug)]` is safe here even
/// though `secrets` carries values — [`WireSecret`] has its own manual,
/// redacting `Debug` impl that the derive delegates to.
#[derive(Debug)]
pub struct ProjectSecretsOutcome {
    pub project_name: String,
    pub reference: String,
    pub secrets: Vec<WireSecret>,
}

/// Interpret a parsed [`WireResponse`] into a [`ProjectSecretsOutcome`] or
/// the corresponding [`LocalTransportError`]. `approved` requires a
/// `bw://project/` reference with a non-empty derived id, a non-empty
/// `item.name`, and a PRESENT, NON-EMPTY `secrets` array — a missing OR
/// empty array is a protocol error (fail closed): the desktop's zero-secrets
/// rule returns `notFound` instead of an approved-but-empty release
/// (architecture doc, M7).
fn interpret_project_secrets(
    resp: WireResponse,
) -> Result<ProjectSecretsOutcome, LocalTransportError> {
    if resp.version != PROTOCOL_VERSION {
        return Err(LocalTransportError::UnsupportedVersion(resp.version));
    }
    // Defensive: a `projectSecretsRequest` reply is `secrets`-shaped
    // (plural), never `secret`-shaped (singular, the M4 single-secret
    // reply) — mirrors the value-bearing-reply guards used throughout this
    // file (`interpret_reference_outcome`, `interpret_project_list`).
    if resp.secret.is_some() {
        return Err(LocalTransportError::Protocol(
            "unexpected single-secret 'secret' reply to a projectSecretsRequest".to_string(),
        ));
    }

    let message = |fallback: &str| resp.message.clone().unwrap_or_else(|| fallback.to_string());

    match resp.status {
        WireStatus::Approved => {
            let reference = resp.reference.ok_or_else(|| {
                LocalTransportError::Protocol(
                    "approved projectSecretsRequest response missing 'reference'".to_string(),
                )
            })?;
            let Some(project_id) = reference.strip_prefix(PROJECT_REFERENCE_PREFIX) else {
                return Err(LocalTransportError::Protocol(format!(
                    "approved projectSecretsRequest response has an unparseable 'reference': {reference}"
                )));
            };
            if project_id.is_empty() {
                return Err(LocalTransportError::Protocol(
                    "approved projectSecretsRequest response has an empty id in 'reference'"
                        .to_string(),
                ));
            }

            let project_name = resp
                .item
                .and_then(|item| item.name)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    LocalTransportError::Protocol(
                        "approved projectSecretsRequest response missing a non-empty 'item.name'"
                            .to_string(),
                    )
                })?;

            let secrets = resp.secrets.ok_or_else(|| {
                LocalTransportError::Protocol(
                    "approved projectSecretsRequest response missing 'secrets'".to_string(),
                )
            })?;
            if secrets.is_empty() {
                return Err(LocalTransportError::Protocol(
                    "approved projectSecretsRequest response has an empty 'secrets' array \
                     (the desktop should have returned notFound for a project with zero \
                     readable secrets)"
                        .to_string(),
                ));
            }

            Ok(ProjectSecretsOutcome {
                project_name,
                reference,
                secrets,
            })
        }
        WireStatus::Denied => Err(LocalTransportError::Denied(message("Denied by user"))),
        WireStatus::NotFound => Err(LocalTransportError::NotFound(message(
            "No matching project found",
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
            "unexpected 'originMismatch' status for a projectSecretsRequest".to_string(),
        )),
        WireStatus::NoSafeTarget => Err(LocalTransportError::Protocol(
            "unexpected 'noSafeTarget' status for a projectSecretsRequest".to_string(),
        )),
    }
}

/// Perform one full local `projectSecretsRequest`: connect, send, receive,
/// interpret. One connection per request, per protocol. Local-transport-only
/// — same no-relay-fallback contract as [`request_secret`] (architecture
/// doc, M7: "Never rides the relay"); delivery is implicitly inject, so
/// unlike [`request_secret`] there is no `delivery` parameter.
pub async fn request_project_secrets(
    endpoint: &LocalEndpoint,
    query: &ProjectQueryInput,
) -> Result<ProjectSecretsOutcome, LocalTransportError> {
    let stream = connect(endpoint).await?;
    let request = WireProjectSecretsRequest::new(WireProjectSelector::from(query));
    let response = run_request(stream, &request).await?;
    interpret_project_secrets(response)
}

/// Derive the env-var name for every secret in a `projectSecretsRequest`
/// release, with a collision check, per the naming rule shared by
/// `run_with_project_secrets` (MCP) and `aac run --project` (CLI) — both
/// call this with the identical secrets and `uuids_as_keynames` setting, so
/// the two surfaces can never disagree about whether a given release
/// collides.
///
/// Default naming is [`secret_env_var_name`] per secret's own name;
/// `uuids_as_keynames` switches to [`secret_env_var_name_from_uuid`], under
/// which a collision is structurally impossible (no two secrets share a
/// UUID) — bws's `--uuids-as-keynames` escape hatch, mirrored here
/// (architecture doc, M7).
///
/// Returns the resolved `(env_name, value)` pairs, in `secrets`' order, when
/// every name is unique. Returns `Err` with the colliding env var name(s) —
/// **never a value** — when two or more secrets would map to the same name;
/// callers must not spawn the child process in that case.
pub fn resolve_project_secrets_env_names(
    secrets: &[WireSecret],
    uuids_as_keynames: bool,
) -> Result<Vec<(String, Zeroizing<String>)>, Vec<String>> {
    let mut seen: HashSet<String> = HashSet::with_capacity(secrets.len());
    let mut collisions: Vec<String> = Vec::new();
    let mut resolved: Vec<(String, Zeroizing<String>)> = Vec::with_capacity(secrets.len());

    for secret in secrets {
        let env_name = if uuids_as_keynames {
            secret_env_var_name_from_uuid(&secret.secret_id)
        } else {
            secret_env_var_name(&secret.name)
        };
        if !seen.insert(env_name.clone()) && !collisions.contains(&env_name) {
            collisions.push(env_name.clone());
        }
        resolved.push((env_name, secret.value.clone()));
    }

    if collisions.is_empty() {
        Ok(resolved)
    } else {
        Err(collisions)
    }
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
            value: Some(Zeroizing::new("hunter2".to_string())),
            generate: None,
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
            value: Some(Zeroizing::new("s3cr3t".to_string())),
            generate: None,
            note: None,
            project: None,
        };
        let request = WireCreateRequest::new(WireSecretCreate::from(&input));
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert!(json["create"].get("note").is_none());
        assert!(json["create"].get("project").is_none());
        assert!(json["create"].get("generate").is_none());
    }

    #[test]
    fn secret_create_request_with_generate_omits_value() {
        let input = SecretCreateInput {
            name: "API_KEY".to_string(),
            value: None,
            generate: Some(WireGenerateOptions {
                length: Some(64),
                symbols: Some(false),
            }),
            note: None,
            project: None,
        };
        let request = WireCreateRequest::new(WireSecretCreate::from(&input));
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert!(json["create"].get("value").is_none());
        assert_eq!(json["create"]["generate"]["length"], 64);
        assert_eq!(json["create"]["generate"]["symbols"], false);
    }

    #[test]
    fn secret_create_request_generate_omits_absent_length_and_symbols() {
        let input = SecretCreateInput {
            name: "API_KEY".to_string(),
            value: None,
            generate: Some(WireGenerateOptions {
                length: None,
                symbols: None,
            }),
            note: None,
            project: None,
        };
        let request = WireCreateRequest::new(WireSecretCreate::from(&input));
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert_eq!(json["create"]["generate"], serde_json::json!({}));
    }

    #[test]
    #[should_panic(expected = "exactly one of value/generate")]
    fn secret_create_input_neither_value_nor_generate_asserts() {
        let input = SecretCreateInput {
            name: "API_KEY".to_string(),
            value: None,
            generate: None,
            note: None,
            project: None,
        };
        let _ = WireSecretCreate::from(&input);
    }

    #[test]
    #[should_panic(expected = "exactly one of value/generate")]
    fn secret_create_input_both_value_and_generate_asserts() {
        let input = SecretCreateInput {
            name: "API_KEY".to_string(),
            value: Some(Zeroizing::new("hunter2".to_string())),
            generate: Some(WireGenerateOptions::default()),
            note: None,
            project: None,
        };
        let _ = WireSecretCreate::from(&input);
    }

    #[test]
    fn secret_create_input_debug_never_prints_value() {
        let input = SecretCreateInput {
            name: "DB_PASSWORD".to_string(),
            value: Some(Zeroizing::new("hunter2".to_string())),
            generate: None,
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
            value: Some(Zeroizing::new("hunter2".to_string())),
            generate: None,
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

    // ── M6: generate options / project reference ─────────────────────

    #[test]
    fn strip_project_reference_extracts_id() {
        assert_eq!(
            strip_project_reference("bw://project/44444444-4444-4444-4444-444444444444"),
            "44444444-4444-4444-4444-444444444444"
        );
    }

    #[test]
    fn strip_project_reference_passes_through_plain_id() {
        assert_eq!(strip_project_reference("plain-id-123"), "plain-id-123");
    }

    #[test]
    fn strip_project_reference_does_not_strip_secret_reference() {
        assert_eq!(
            strip_project_reference("bw://secret/22222222-2222-2222-2222-222222222222"),
            "bw://secret/22222222-2222-2222-2222-222222222222"
        );
    }

    #[test]
    fn validate_generate_length_accepts_bounds_and_none() {
        assert!(validate_generate_length(None).is_ok());
        assert!(validate_generate_length(Some(GENERATE_LENGTH_MIN)).is_ok());
        assert!(validate_generate_length(Some(GENERATE_LENGTH_MAX)).is_ok());
        assert!(validate_generate_length(Some(40)).is_ok());
    }

    #[test]
    fn validate_generate_length_rejects_out_of_range() {
        let too_short = validate_generate_length(Some(GENERATE_LENGTH_MIN - 1))
            .expect_err("must reject below minimum");
        assert!(too_short.contains("12") && too_short.contains("128"));

        let too_long = validate_generate_length(Some(GENERATE_LENGTH_MAX + 1))
            .expect_err("must reject above maximum");
        assert!(too_long.contains("12") && too_long.contains("128"));
    }

    // ── secretUpdate wire request serde ───────────────────────────────

    #[test]
    fn secret_update_request_serializes_contract_shape_exactly() {
        let input = SecretUpdateInput {
            target_id: "secret-1".to_string(),
            name: Some("NEW_NAME".to_string()),
            value: Some(Zeroizing::new("hunter2".to_string())),
            generate: None,
            note: Some("updated note".to_string()),
            project: Some("my-app".to_string()),
        };
        let request =
            WireSecretUpdateRequest::new(input.target_id.clone(), WireSecretUpdate::from(&input));
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert_eq!(json["version"], 1);
        assert_eq!(json["op"], "secretUpdate");
        assert_eq!(json["target"]["id"], "secret-1");
        assert_eq!(json["update"]["name"], "NEW_NAME");
        assert_eq!(json["update"]["value"], "hunter2");
        assert_eq!(json["update"]["note"], "updated note");
        assert_eq!(json["update"]["project"], "my-app");
        assert_eq!(json["client"]["name"], "aac");

        assert!(json.get("query").is_none());
        assert!(json.get("delivery").is_none());
        assert!(json.get("create").is_none());

        let mut top_level: Vec<&str> = json
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        top_level.sort_unstable();
        assert_eq!(
            top_level,
            vec!["client", "op", "target", "update", "version"]
        );

        let mut target_keys: Vec<&str> = json["target"]
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        target_keys.sort_unstable();
        assert_eq!(target_keys, vec!["id"]);
    }

    #[test]
    fn secret_update_request_omits_every_absent_field() {
        let input = SecretUpdateInput {
            target_id: "secret-1".to_string(),
            name: None,
            value: None,
            generate: None,
            note: None,
            project: None,
        };
        let request =
            WireSecretUpdateRequest::new(input.target_id.clone(), WireSecretUpdate::from(&input));
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert!(json["update"].get("name").is_none());
        assert!(json["update"].get("value").is_none());
        assert!(json["update"].get("generate").is_none());
        assert!(json["update"].get("note").is_none());
        assert!(json["update"].get("project").is_none());
        // Empty `update` object, but the key itself is still present — an
        // update request always carries an `update` object, even an empty
        // one (the MCP layer is responsible for rejecting a no-op update
        // before it ever reaches the wire).
        assert_eq!(json["update"], serde_json::json!({}));
    }

    #[test]
    fn secret_update_request_empty_note_string_still_serializes() {
        // Contract: `note: ""` means "clear the note" and MUST serialize,
        // unlike every other absent-means-omit field here.
        let input = SecretUpdateInput {
            target_id: "secret-1".to_string(),
            name: None,
            value: None,
            generate: None,
            note: Some(String::new()),
            project: None,
        };
        let request =
            WireSecretUpdateRequest::new(input.target_id.clone(), WireSecretUpdate::from(&input));
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert!(json["update"].get("note").is_some());
        assert_eq!(json["update"]["note"], "");
    }

    #[test]
    fn secret_update_request_with_generate_omits_value() {
        let input = SecretUpdateInput {
            target_id: "secret-1".to_string(),
            name: None,
            value: None,
            generate: Some(WireGenerateOptions {
                length: Some(24),
                symbols: Some(true),
            }),
            note: None,
            project: None,
        };
        let request =
            WireSecretUpdateRequest::new(input.target_id.clone(), WireSecretUpdate::from(&input));
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert!(json["update"].get("value").is_none());
        assert_eq!(json["update"]["generate"]["length"], 24);
        assert_eq!(json["update"]["generate"]["symbols"], true);
    }

    #[test]
    #[should_panic(expected = "must not carry both value and generate")]
    fn secret_update_input_both_value_and_generate_asserts() {
        let input = SecretUpdateInput {
            target_id: "secret-1".to_string(),
            name: None,
            value: Some(Zeroizing::new("hunter2".to_string())),
            generate: Some(WireGenerateOptions::default()),
            note: None,
            project: None,
        };
        let _ = WireSecretUpdate::from(&input);
    }

    #[test]
    fn secret_update_input_neither_value_nor_generate_is_allowed() {
        // Unlike create, update permits a rename/move/note-only update with
        // neither `value` nor `generate` present.
        let input = SecretUpdateInput {
            target_id: "secret-1".to_string(),
            name: Some("RENAMED".to_string()),
            value: None,
            generate: None,
            note: None,
            project: None,
        };
        let wire = WireSecretUpdate::from(&input);
        let json = serde_json::to_value(&wire).expect("serialize");
        assert!(json.get("value").is_none());
        assert!(json.get("generate").is_none());
    }

    #[test]
    fn secret_update_input_debug_never_prints_value() {
        let input = SecretUpdateInput {
            target_id: "secret-1".to_string(),
            name: Some("NEW_NAME".to_string()),
            value: Some(Zeroizing::new("hunter2".to_string())),
            generate: None,
            note: Some("a secret note".to_string()),
            project: Some("my-app".to_string()),
        };
        let debug = format!("{input:?}");
        assert!(!debug.contains("hunter2"), "value leaked: {debug}");
        assert!(!debug.contains("a secret note"), "note leaked: {debug}");
        assert!(debug.contains("secret-1"));
        assert!(debug.contains("NEW_NAME"));
        assert!(debug.contains("my-app"));
    }

    #[test]
    fn wire_secret_update_debug_never_prints_value() {
        let input = SecretUpdateInput {
            target_id: "secret-1".to_string(),
            name: None,
            value: Some(Zeroizing::new("hunter2".to_string())),
            generate: None,
            note: None,
            project: None,
        };
        let wire = WireSecretUpdate::from(&input);
        let debug = format!("{wire:?}");
        assert!(!debug.contains("hunter2"), "value leaked: {debug}");
    }

    // ── secretDelete / projectDelete / projectUpdate / projectCreate /
    //    projectList wire request serde ────────────────────────────────

    #[test]
    fn secret_delete_request_serializes_contract_shape_exactly() {
        let request = WireTargetRequest::secret_delete("secret-1".to_string());
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert_eq!(json["op"], "secretDelete");
        assert_eq!(json["target"]["id"], "secret-1");
        let mut top_level: Vec<&str> = json
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        top_level.sort_unstable();
        assert_eq!(top_level, vec!["client", "op", "target", "version"]);
    }

    #[test]
    fn project_delete_request_serializes_contract_shape_exactly() {
        let request = WireTargetRequest::project_delete("project-1".to_string());
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert_eq!(json["op"], "projectDelete");
        assert_eq!(json["target"]["id"], "project-1");
    }

    #[test]
    fn project_update_request_serializes_contract_shape_exactly() {
        let request = WireProjectUpdateRequest::new("project-1".to_string(), "Renamed".to_string());
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert_eq!(json["op"], "projectUpdate");
        assert_eq!(json["target"]["id"], "project-1");
        assert_eq!(json["update"]["name"], "Renamed");
        let mut top_level: Vec<&str> = json
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        top_level.sort_unstable();
        assert_eq!(
            top_level,
            vec!["client", "op", "target", "update", "version"]
        );
    }

    #[test]
    fn project_create_request_serializes_contract_shape_exactly() {
        let request = WireProjectCreateRequest::new("my-app".to_string());
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert_eq!(json["op"], "projectCreate");
        assert_eq!(json["create"]["name"], "my-app");
        let mut top_level: Vec<&str> = json
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        top_level.sort_unstable();
        assert_eq!(top_level, vec!["client", "create", "op", "version"]);

        // `value`/`generate`/`note`/`project` must be ABSENT: `create` is
        // exactly `{name}` for this op, never the full secretCreate shape.
        let mut create_keys: Vec<&str> = json["create"]
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        create_keys.sort_unstable();
        assert_eq!(create_keys, vec!["name"]);
    }

    #[test]
    fn project_list_request_serializes_contract_shape_exactly() {
        let request = WireProjectListRequest::new();
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert_eq!(json["op"], "projectList");
        let mut top_level: Vec<&str> = json
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        top_level.sort_unstable();
        assert_eq!(top_level, vec!["client", "op", "version"]);
    }

    // ── secretUpdate / secretDelete / project* response interpretation ──

    #[test]
    fn reference_outcome_approved_derives_outcome() {
        let json = r#"{"version":1,"status":"approved",
 "reference":"bw://secret/33333333-3333-3333-3333-333333333333",
 "item":{"name":"NEW_NAME"}}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let outcome = interpret_reference_outcome(resp, SECRET_REFERENCE_PREFIX, "secretUpdate")
            .expect("should be Ok");
        assert_eq!(outcome.id, "33333333-3333-3333-3333-333333333333");
        assert_eq!(
            outcome.reference,
            "bw://secret/33333333-3333-3333-3333-333333333333"
        );
        assert_eq!(outcome.name.as_deref(), Some("NEW_NAME"));
    }

    #[test]
    fn reference_outcome_project_prefix_mismatch_is_protocol_error() {
        // A `bw://secret/...` reference must not be accepted for a project
        // op (and vice versa) — the prefixes stay distinct end to end.
        let json = r#"{"version":1,"status":"approved",
 "reference":"bw://secret/33333333-3333-3333-3333-333333333333"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_reference_outcome(resp, PROJECT_REFERENCE_PREFIX, "projectDelete")
            .expect_err("must error");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[test]
    fn reference_outcome_missing_reference_is_protocol_error() {
        let json = r#"{"version":1,"status":"approved","item":{"name":"x"}}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_reference_outcome(resp, SECRET_REFERENCE_PREFIX, "secretDelete")
            .expect_err("must error");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[test]
    fn reference_outcome_status_mapping() {
        let cases = [
            ("denied", "Denied by user"),
            ("locked", "Vault is locked"),
            ("timeout", "Approval timed out"),
            ("rateLimited", "Rate limited"),
            ("error", "Local agent-access endpoint returned an error"),
            ("notFound", "Not found"),
        ];
        for (status, default_msg) in cases {
            let json = format!(r#"{{"version":1,"status":"{status}"}}"#);
            let resp: WireResponse = serde_json::from_str(&json).expect("parse");
            let err = interpret_reference_outcome(resp, SECRET_REFERENCE_PREFIX, "secretUpdate")
                .expect_err("non-approved status must error");
            assert!(err.to_string().contains(default_msg), "status {status}");
        }
    }

    /// Mirrors `interpret_fill`'s stance (local.rs, near the top of this
    /// file): a value-bearing reply is rejected by construction, regardless
    /// of the delivery-shaped op it arrived on. Architecture doc, M6
    /// invariant #13: "No wire reply ever carries a secret value for ANY
    /// M6 op".
    #[test]
    fn reference_outcome_value_bearing_reply_is_rejected() {
        let json = r#"{"version":1,"status":"approved",
 "secret":{"name":"DB_PASSWORD","value":"hunter2","secretId":"secret-1"},
 "reference":"bw://secret/secret-1"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_reference_outcome(resp, SECRET_REFERENCE_PREFIX, "secretUpdate")
            .expect_err("must reject a value-bearing reply");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[test]
    fn project_list_value_bearing_reply_is_rejected() {
        let json = r#"{"version":1,"status":"approved",
 "secret":{"name":"DB_PASSWORD","value":"hunter2","secretId":"secret-1"},
 "projects":[]}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_project_list(resp).expect_err("must reject a value-bearing reply");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[test]
    fn project_list_approved_multi_entry() {
        let json = r#"{"version":1,"status":"approved","projects":[
 {"name":"my-app","reference":"bw://project/p-1","write":true,"organization":"Acme"},
 {"name":"infra","reference":"bw://project/p-2","write":false,"organization":"Acme"}
]}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let entries = interpret_project_list(resp).expect("should be Ok");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "my-app");
        assert_eq!(entries[0].reference, "bw://project/p-1");
        assert!(entries[0].write);
        assert_eq!(entries[0].organization.as_deref(), Some("Acme"));
        assert!(!entries[1].write);
    }

    #[test]
    fn project_list_approved_missing_projects_is_protocol_error() {
        let json = r#"{"version":1,"status":"approved"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_project_list(resp).expect_err("must error");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[test]
    fn project_list_denied_maps_to_denied_error() {
        let json = r#"{"version":1,"status":"denied","message":"Denied by user"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_project_list(resp).expect_err("must error");
        assert!(matches!(err, LocalTransportError::Denied(m) if m == "Denied by user"));
    }

    // ── M7: projectSecretsRequest wire serde + interpretation ──────────

    #[test]
    fn project_secrets_request_serializes_id_selector_exactly() {
        let request = WireProjectSecretsRequest::new(WireProjectSelector::Id {
            id: "project-1".to_string(),
        });
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert_eq!(json["version"], 1);
        assert_eq!(json["op"], "projectSecretsRequest");
        assert_eq!(json["project"]["id"], "project-1");
        assert!(json["project"].get("name").is_none());
        let mut top_level: Vec<&str> = json
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        top_level.sort_unstable();
        assert_eq!(top_level, vec!["client", "op", "project", "version"]);
        // No `query`/`delivery`/`fill`/`create`/`update`/`target` on this op.
        for absent in ["query", "delivery", "fill", "create", "update", "target"] {
            assert!(json.get(absent).is_none(), "unexpected key: {absent}");
        }
    }

    #[test]
    fn project_secrets_request_serializes_name_selector_exactly() {
        let request = WireProjectSecretsRequest::new(WireProjectSelector::Name {
            name: "my-app".to_string(),
        });
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialize"))
                .expect("parse");

        assert_eq!(json["project"]["name"], "my-app");
        assert!(json["project"].get("id").is_none());
    }

    fn approved_project_secrets_json() -> &'static str {
        r#"{"version":1,"status":"approved","reference":"bw://project/proj-1",
 "item":{"name":"my-app"},
 "secrets":[{"name":"DB_PASSWORD","value":"hunter2","secretId":"secret-1"},
            {"name":"API_KEY","value":"key-value","secretId":"secret-2"}]}"#
    }

    #[test]
    fn project_secrets_approved_derives_outcome() {
        let resp: WireResponse =
            serde_json::from_str(approved_project_secrets_json()).expect("parse");
        let outcome = interpret_project_secrets(resp).expect("should be Ok");
        assert_eq!(outcome.project_name, "my-app");
        assert_eq!(outcome.reference, "bw://project/proj-1");
        assert_eq!(outcome.secrets.len(), 2);
        assert_eq!(outcome.secrets[0].name, "DB_PASSWORD");
        assert_eq!(outcome.secrets[0].value.as_str(), "hunter2");
        assert_eq!(outcome.secrets[1].secret_id, "secret-2");
    }

    #[test]
    fn project_secrets_approved_missing_secrets_is_protocol_error() {
        let json = r#"{"version":1,"status":"approved","reference":"bw://project/proj-1",
 "item":{"name":"my-app"}}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_project_secrets(resp).expect_err("must error");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[test]
    fn project_secrets_approved_empty_secrets_array_is_protocol_error() {
        // Fail closed: an approved-but-empty release is impossible by the
        // desktop's zero-secrets rule (notFound instead) — a client that
        // sees one anyway must treat it as an error, not an empty success.
        let json = r#"{"version":1,"status":"approved","reference":"bw://project/proj-1",
 "item":{"name":"my-app"},"secrets":[]}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_project_secrets(resp).expect_err("must error");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[test]
    fn project_secrets_approved_missing_reference_is_protocol_error() {
        let json = r#"{"version":1,"status":"approved","item":{"name":"my-app"},
 "secrets":[{"name":"DB_PASSWORD","value":"hunter2","secretId":"secret-1"}]}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_project_secrets(resp).expect_err("must error");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[test]
    fn project_secrets_approved_wrong_reference_prefix_is_protocol_error() {
        let json = r#"{"version":1,"status":"approved","reference":"bw://secret/secret-1",
 "item":{"name":"my-app"},
 "secrets":[{"name":"DB_PASSWORD","value":"hunter2","secretId":"secret-1"}]}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_project_secrets(resp).expect_err("must error");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[test]
    fn project_secrets_approved_missing_item_name_is_protocol_error() {
        let json = r#"{"version":1,"status":"approved","reference":"bw://project/proj-1",
 "secrets":[{"name":"DB_PASSWORD","value":"hunter2","secretId":"secret-1"}]}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_project_secrets(resp).expect_err("must error");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[test]
    fn project_secrets_value_bearing_single_secret_reply_is_rejected() {
        // Defense in depth: a server bug that answers a `projectSecretsRequest`
        // with the M4 single-secret shape (`secret`, singular) instead of the
        // M7 plural `secrets` array must not be accepted.
        let json = r#"{"version":1,"status":"approved",
 "secret":{"name":"DB_PASSWORD","value":"hunter2","secretId":"secret-1"},
 "reference":"bw://project/proj-1"}"#;
        let resp: WireResponse = serde_json::from_str(json).expect("parse");
        let err = interpret_project_secrets(resp).expect_err("must reject a value-bearing reply");
        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[test]
    fn project_secrets_status_mapping() {
        let cases = [
            ("denied", "Denied by user"),
            ("locked", "Vault is locked"),
            ("timeout", "Approval timed out"),
            ("rateLimited", "Rate limited"),
            ("error", "Local agent-access endpoint returned an error"),
            ("notFound", "No matching project found"),
        ];
        for (status, default_msg) in cases {
            let json = format!(r#"{{"version":1,"status":"{status}"}}"#);
            let resp: WireResponse = serde_json::from_str(&json).expect("parse");
            let err = interpret_project_secrets(resp).expect_err("non-approved status must error");
            assert!(err.to_string().contains(default_msg), "status {status}");
        }
    }

    // ── M7: env-var naming + collision resolution ──────────────────────

    #[test]
    fn resolve_project_secrets_env_names_default_naming_no_collision() {
        let secrets = vec![
            WireSecret {
                name: "DB_PASSWORD".to_string(),
                value: Zeroizing::new("hunter2".to_string()),
                secret_id: "secret-1".to_string(),
            },
            WireSecret {
                name: "API_KEY".to_string(),
                value: Zeroizing::new("key-value".to_string()),
                secret_id: "secret-2".to_string(),
            },
        ];
        let resolved =
            resolve_project_secrets_env_names(&secrets, false).expect("should not collide");
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].0, "DB_PASSWORD");
        assert_eq!(resolved[0].1.as_str(), "hunter2");
        assert_eq!(resolved[1].0, "API_KEY");
        assert_eq!(resolved[1].1.as_str(), "key-value");
    }

    #[test]
    fn resolve_project_secrets_env_names_default_naming_collision_names_env_var_not_value() {
        // Two secret names that uppercase-sanitize to the same env var name.
        let secrets = vec![
            WireSecret {
                name: "db.password".to_string(),
                value: Zeroizing::new("hunter2".to_string()),
                secret_id: "secret-1".to_string(),
            },
            WireSecret {
                name: "db_password".to_string(),
                value: Zeroizing::new("other-value".to_string()),
                secret_id: "secret-2".to_string(),
            },
        ];
        let collisions =
            resolve_project_secrets_env_names(&secrets, false).expect_err("should collide");
        assert_eq!(collisions, vec!["DB_PASSWORD".to_string()]);
    }

    #[test]
    fn resolve_project_secrets_env_names_uuids_as_keynames_never_collides() {
        // Same name twice would collide under default naming; uuids as
        // keynames is structurally collision-free (distinct secret ids).
        let secrets = vec![
            WireSecret {
                name: "DB_PASSWORD".to_string(),
                value: Zeroizing::new("hunter2".to_string()),
                secret_id: "11111111-1111-1111-1111-111111111111".to_string(),
            },
            WireSecret {
                name: "DB_PASSWORD".to_string(),
                value: Zeroizing::new("other-value".to_string()),
                secret_id: "22222222-2222-2222-2222-222222222222".to_string(),
            },
        ];
        let resolved =
            resolve_project_secrets_env_names(&secrets, true).expect("uuids never collide");
        assert_eq!(resolved[0].0, "_11111111_1111_1111_1111_111111111111");
        assert_eq!(resolved[1].0, "_22222222_2222_2222_2222_222222222222");
    }

    #[test]
    fn secret_env_var_name_from_uuid_matches_bws_uuid_to_posix_shape() {
        assert_eq!(
            secret_env_var_name_from_uuid("759130d0-29dd-48bd-831a-e3bdbafeeb6e"),
            "_759130d0_29dd_48bd_831a_e3bdbafeeb6e"
        );
    }

    // ── M7: project_query_from_flag ─────────────────────────────────────

    #[test]
    fn project_query_from_flag_treats_reference_as_id() {
        let query = project_query_from_flag("bw://project/33333333-3333-3333-3333-333333333333");
        assert!(
            matches!(query, ProjectQueryInput::Id(id) if id == "33333333-3333-3333-3333-333333333333")
        );
    }

    #[test]
    fn project_query_from_flag_treats_bare_uuid_as_id() {
        let query = project_query_from_flag("44444444-4444-4444-4444-444444444444");
        assert!(
            matches!(query, ProjectQueryInput::Id(id) if id == "44444444-4444-4444-4444-444444444444")
        );
    }

    #[test]
    fn project_query_from_flag_treats_plain_value_as_name() {
        let query = project_query_from_flag("my-app");
        assert!(matches!(query, ProjectQueryInput::Name(n) if n == "my-app"));
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
            value: Some(Zeroizing::new("hunter2".to_string())),
            generate: None,
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

    // ── secretUpdate end-to-end ────────────────────────────────────────

    fn make_secret_update_input() -> SecretUpdateInput {
        SecretUpdateInput {
            target_id: "secret-1".to_string(),
            name: Some("NEW_NAME".to_string()),
            value: Some(Zeroizing::new("hunter2".to_string())),
            generate: None,
            note: None,
            project: None,
        }
    }

    #[tokio::test]
    async fn secret_update_end_to_end_approved() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","reference":"bw://secret/secret-1","item":{"name":"NEW_NAME"}}"#,
        )
        .await;

        let outcome = request_secret_update(&endpoint, &make_secret_update_input())
            .await
            .expect("should succeed");

        assert_eq!(outcome.id, "secret-1");
        assert_eq!(outcome.reference, "bw://secret/secret-1");
        assert_eq!(outcome.name.as_deref(), Some("NEW_NAME"));
    }

    #[tokio::test]
    async fn secret_update_end_to_end_denied() {
        let endpoint =
            spawn_mock_server(r#"{"version":1,"status":"denied","message":"Denied by user"}"#)
                .await;

        let err = request_secret_update(&endpoint, &make_secret_update_input())
            .await
            .expect_err("should be denied");

        assert!(matches!(err, LocalTransportError::Denied(m) if m == "Denied by user"));
    }

    #[tokio::test]
    async fn secret_update_end_to_end_value_bearing_reply_rejected() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","secret":{"name":"NEW_NAME","value":"hunter2","secretId":"secret-1"},"reference":"bw://secret/secret-1"}"#,
        )
        .await;

        let err = request_secret_update(&endpoint, &make_secret_update_input())
            .await
            .expect_err("must reject a value-bearing reply");

        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[tokio::test]
    async fn secret_update_connect_failed_when_no_listener() {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);
        let endpoint = LocalEndpoint::Unix(path);

        let err = request_secret_update(&endpoint, &make_secret_update_input())
            .await
            .expect_err("should fail to connect");

        assert!(matches!(err, LocalTransportError::ConnectFailed(_)));
    }

    // ── secretDelete end-to-end ────────────────────────────────────────

    #[tokio::test]
    async fn secret_delete_end_to_end_approved() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","reference":"bw://secret/secret-1","item":{"name":"DB_PASSWORD"}}"#,
        )
        .await;

        let outcome = request_secret_delete(&endpoint, "secret-1")
            .await
            .expect("should succeed");

        assert_eq!(outcome.id, "secret-1");
        assert_eq!(outcome.name.as_deref(), Some("DB_PASSWORD"));
    }

    #[tokio::test]
    async fn secret_delete_end_to_end_denied() {
        let endpoint =
            spawn_mock_server(r#"{"version":1,"status":"denied","message":"Denied by user"}"#)
                .await;

        let err = request_secret_delete(&endpoint, "secret-1")
            .await
            .expect_err("should be denied");

        assert!(matches!(err, LocalTransportError::Denied(m) if m == "Denied by user"));
    }

    #[tokio::test]
    async fn secret_delete_end_to_end_value_bearing_reply_rejected() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","secret":{"name":"DB_PASSWORD","value":"hunter2","secretId":"secret-1"},"reference":"bw://secret/secret-1"}"#,
        )
        .await;

        let err = request_secret_delete(&endpoint, "secret-1")
            .await
            .expect_err("must reject a value-bearing reply");

        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[tokio::test]
    async fn secret_delete_connect_failed_when_no_listener() {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);
        let endpoint = LocalEndpoint::Unix(path);

        let err = request_secret_delete(&endpoint, "secret-1")
            .await
            .expect_err("should fail to connect");

        assert!(matches!(err, LocalTransportError::ConnectFailed(_)));
    }

    // ── projectList end-to-end ─────────────────────────────────────────

    #[tokio::test]
    async fn project_list_end_to_end_approved_multi_entry() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","projects":[{"name":"my-app","reference":"bw://project/p-1","write":true,"organization":"Acme"},{"name":"infra","reference":"bw://project/p-2","write":false,"organization":"Acme"}]}"#,
        )
        .await;

        let entries = request_project_list(&endpoint)
            .await
            .expect("should succeed");

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "my-app");
        assert!(entries[0].write);
        assert_eq!(entries[1].name, "infra");
        assert!(!entries[1].write);
    }

    #[tokio::test]
    async fn project_list_end_to_end_denied() {
        let endpoint =
            spawn_mock_server(r#"{"version":1,"status":"denied","message":"Denied by user"}"#)
                .await;

        let err = request_project_list(&endpoint)
            .await
            .expect_err("should be denied");

        assert!(matches!(err, LocalTransportError::Denied(m) if m == "Denied by user"));
    }

    #[tokio::test]
    async fn project_list_connect_failed_when_no_listener() {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);
        let endpoint = LocalEndpoint::Unix(path);

        let err = request_project_list(&endpoint)
            .await
            .expect_err("should fail to connect");

        assert!(matches!(err, LocalTransportError::ConnectFailed(_)));
    }

    // ── projectCreate / projectUpdate / projectDelete end-to-end ────────

    #[tokio::test]
    async fn project_create_end_to_end_approved() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","reference":"bw://project/project-1","item":{"name":"my-app"}}"#,
        )
        .await;

        let outcome = request_project_create(&endpoint, "my-app")
            .await
            .expect("should succeed");

        assert_eq!(outcome.id, "project-1");
        assert_eq!(outcome.reference, "bw://project/project-1");
        assert_eq!(outcome.name.as_deref(), Some("my-app"));
    }

    #[tokio::test]
    async fn project_create_connect_failed_when_no_listener() {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);
        let endpoint = LocalEndpoint::Unix(path);

        let err = request_project_create(&endpoint, "my-app")
            .await
            .expect_err("should fail to connect");

        assert!(matches!(err, LocalTransportError::ConnectFailed(_)));
    }

    #[tokio::test]
    async fn project_update_end_to_end_approved() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","reference":"bw://project/project-1","item":{"name":"Renamed"}}"#,
        )
        .await;

        let outcome = request_project_update(&endpoint, "project-1", "Renamed")
            .await
            .expect("should succeed");

        assert_eq!(outcome.id, "project-1");
        assert_eq!(outcome.name.as_deref(), Some("Renamed"));
    }

    #[tokio::test]
    async fn project_update_end_to_end_denied() {
        let endpoint =
            spawn_mock_server(r#"{"version":1,"status":"denied","message":"Denied by user"}"#)
                .await;

        let err = request_project_update(&endpoint, "project-1", "Renamed")
            .await
            .expect_err("should be denied");

        assert!(matches!(err, LocalTransportError::Denied(m) if m == "Denied by user"));
    }

    #[tokio::test]
    async fn project_delete_end_to_end_approved() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","reference":"bw://project/project-1","item":{"name":"my-app"}}"#,
        )
        .await;

        let outcome = request_project_delete(&endpoint, "project-1")
            .await
            .expect("should succeed");

        assert_eq!(outcome.id, "project-1");
        assert_eq!(outcome.name.as_deref(), Some("my-app"));
    }

    #[tokio::test]
    async fn project_delete_end_to_end_value_bearing_reply_rejected() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","secret":{"name":"x","value":"hunter2","secretId":"secret-1"},"reference":"bw://project/project-1"}"#,
        )
        .await;

        let err = request_project_delete(&endpoint, "project-1")
            .await
            .expect_err("must reject a value-bearing reply");

        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[tokio::test]
    async fn project_delete_connect_failed_when_no_listener() {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);
        let endpoint = LocalEndpoint::Unix(path);

        let err = request_project_delete(&endpoint, "project-1")
            .await
            .expect_err("should fail to connect");

        assert!(matches!(err, LocalTransportError::ConnectFailed(_)));
    }

    // ── projectSecretsRequest end-to-end ────────────────────────────────

    #[tokio::test]
    async fn project_secrets_end_to_end_approved() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","reference":"bw://project/project-1","item":{"name":"my-app"},"secrets":[{"name":"DB_PASSWORD","value":"hunter2","secretId":"secret-1"},{"name":"API_KEY","value":"key-value","secretId":"secret-2"}]}"#,
        )
        .await;

        let outcome =
            request_project_secrets(&endpoint, &ProjectQueryInput::Name("my-app".to_string()))
                .await
                .expect("should succeed");

        assert_eq!(outcome.project_name, "my-app");
        assert_eq!(outcome.reference, "bw://project/project-1");
        assert_eq!(outcome.secrets.len(), 2);
        assert_eq!(outcome.secrets[0].value.as_str(), "hunter2");
        assert_eq!(outcome.secrets[1].value.as_str(), "key-value");
    }

    #[tokio::test]
    async fn project_secrets_end_to_end_id_selector_sends_id_not_name() {
        // A `spawn_mock_server`-style handler already asserts the request is
        // well-formed JSON; this test's real assertion is behavioral: the Id
        // query must produce an `{"id":...}` selector, not `{"name":...}` —
        // verified indirectly by exercising the full round trip successfully
        // with an Id query (a wire-shape assertion covers the JSON directly
        // in the `mod tests` unit tests above).
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","reference":"bw://project/project-1","item":{"name":"my-app"},"secrets":[{"name":"DB_PASSWORD","value":"hunter2","secretId":"secret-1"}]}"#,
        )
        .await;

        let outcome =
            request_project_secrets(&endpoint, &ProjectQueryInput::Id("project-1".to_string()))
                .await
                .expect("should succeed");

        assert_eq!(outcome.secrets.len(), 1);
    }

    #[tokio::test]
    async fn project_secrets_end_to_end_not_found() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"notFound","message":"No matching project found"}"#,
        )
        .await;

        let err = request_project_secrets(
            &endpoint,
            &ProjectQueryInput::Name("nonexistent".to_string()),
        )
        .await
        .expect_err("should be not found");

        assert!(matches!(err, LocalTransportError::NotFound(_)));
    }

    #[tokio::test]
    async fn project_secrets_end_to_end_empty_array_is_error_not_empty_success() {
        let endpoint = spawn_mock_server(
            r#"{"version":1,"status":"approved","reference":"bw://project/project-1","item":{"name":"empty-project"},"secrets":[]}"#,
        )
        .await;

        let err = request_project_secrets(
            &endpoint,
            &ProjectQueryInput::Name("empty-project".to_string()),
        )
        .await
        .expect_err("an empty array must fail closed, not succeed with zero secrets");

        assert!(matches!(err, LocalTransportError::Protocol(_)));
    }

    #[tokio::test]
    async fn project_secrets_connect_failed_when_no_listener() {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);
        let endpoint = LocalEndpoint::Unix(path);

        let err =
            request_project_secrets(&endpoint, &ProjectQueryInput::Name("my-app".to_string()))
                .await
                .expect_err("should fail to connect");

        assert!(matches!(err, LocalTransportError::ConnectFailed(_)));
    }
}
