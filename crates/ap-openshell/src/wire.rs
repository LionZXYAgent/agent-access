//! Local wire protocol v1, OpenShell ops (architecture §M8.4).
//!
//! Field order in every serialized struct is the §M8.4 key order; the golden
//! fixtures in `tests/fixtures/` are byte-compared against it.
//!
//! Nothing in this module logs, and no error type carries reply content:
//! `serde_json` error text can quote input, so parse errors are collapsed to a
//! detail-free [`ReplyError`].

use std::collections::HashSet;
use std::fmt;
use std::path::Path;
use std::time::Duration;

use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::digest::{is_valid_digest, policy_digest};
use crate::handle::{Field, Resource, is_lowercase_uuid};

/// Local protocol version. Unchanged by the OpenShell ops.
pub const PROTOCOL_VERSION: u32 = 1;
/// `op` of a credential resolve.
pub const OP_RESOLVE: &str = "openshellResolve";
/// `op` of the value-free liveness ping.
pub const OP_HELLO: &str = "openshellHello";
/// `client.name` this driver reports (diagnostic only).
pub const CLIENT_NAME: &str = "aac-openshell-driver";

/// Default approval deadline offered to desktop.
pub const DEFAULT_DEADLINE_MS: u32 = 25_000;
/// Desktop validator range for `deadlineMs` (architecture §M8.4, floor lowered to 2 s by §M8.18).
/// It is also aac's send floor: a request with less approval time than this left fails
/// `DEADLINE_EXCEEDED` without contacting desktop. Anything at or above it is sent, however
/// short — desktop can answer an identical retry at once from a carried or just-delivered
/// decision, and opens no new dialog with under 3 s left.
pub const MIN_DEADLINE_MS: u32 = 2_000;
pub const MAX_DEADLINE_MS: u32 = 28_000;
/// aac waits `deadlineMs + READ_SLACK_MS` for the reply.
pub const READ_SLACK_MS: u64 = 2_000;

/// Desktop's request-line cap.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Reply cap: 16 values of up to 16 KiB each plus framing fits comfortably.
pub const MAX_REPLY_BYTES: usize = 1024 * 1024;

pub const MAX_ENDPOINTS: usize = 64;
pub const MAX_TARGETS: usize = 16;
/// Desktop rejects a value larger than this.
pub const MAX_VALUE_BYTES: usize = 16_384;

/// `client` object (diagnostic only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

impl ClientInfo {
    /// The driver's own identity, with an explicit version (tests pin
    /// `0.0.0-fixture`).
    pub fn driver(version: &str) -> Self {
        Self {
            name: CLIENT_NAME.to_string(),
            version: version.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayRef {
    pub name: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRef {
    pub id: String,
    pub name: String,
    pub profile: String,
    pub workspace: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxRef {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

/// Where an endpoint came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EndpointSource {
    Profile,
    PolicyBinding,
}

impl EndpointSource {
    pub fn as_str(self) -> &'static str {
        match self {
            EndpointSource::Profile => "profile",
            EndpointSource::PolicyBinding => "policyBinding",
        }
    }
}

/// One endpoint a released credential can be sent to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub source: EndpointSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRef {
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisor_enabled: Option<bool>,
}

/// One requested credential. `credentialKey` is the env var name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireTarget {
    pub credential_key: String,
    pub resource: Resource,
    pub id: String,
    pub field: Field,
}

/// Body of an `openshellResolve` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveBody {
    pub deadline_ms: u32,
    pub gateway: GatewayRef,
    pub provider: ProviderRef,
    pub sandbox: SandboxRef,
    pub endpoints: Vec<Endpoint>,
    pub policy: PolicyRef,
    pub targets: Vec<WireTarget>,
}

/// `openshellResolve` request. Carries ids and gateway-reported context only,
/// never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveRequest {
    pub version: u32,
    pub op: String,
    pub openshell: ResolveBody,
    pub client: ClientInfo,
}

impl ResolveRequest {
    pub fn new(body: ResolveBody, client: ClientInfo) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            op: OP_RESOLVE.to_string(),
            openshell: body,
            client,
        }
    }

    /// One compact JSON line with a trailing `\n`.
    pub fn to_line(&self) -> Result<Vec<u8>, RequestError> {
        to_line(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloBody {
    pub gateway: GatewayRef,
}

/// `openshellHello`: value-free driver liveness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloRequest {
    pub version: u32,
    pub op: String,
    pub openshell: HelloBody,
    pub client: ClientInfo,
}

impl HelloRequest {
    pub fn new(gateway: GatewayRef, client: ClientInfo) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            op: OP_HELLO.to_string(),
            openshell: HelloBody { gateway },
            client,
        }
    }

    pub fn to_line(&self) -> Result<Vec<u8>, RequestError> {
        to_line(self)
    }
}

fn to_line<T: Serialize>(value: &T) -> Result<Vec<u8>, RequestError> {
    let mut line = serde_json::to_vec(value).map_err(|_| RequestError::Encode)?;
    line.push(b'\n');
    if line.len() > MAX_REQUEST_BYTES {
        return Err(RequestError::TooLarge);
    }
    Ok(line)
}

/// A request this driver refuses to emit (the desktop would reject it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    #[error("request could not be encoded")]
    Encode,
    #[error("request exceeds the local protocol line cap")]
    TooLarge,
    #[error("request field fails desktop validation: {0}")]
    Invalid(&'static str),
}

// ---------------------------------------------------------------------------
// Validation: mirrors desktop `validate_openshell_resolve` so aac only emits
// what passes it.
// ---------------------------------------------------------------------------

fn no_control(value: &str) -> bool {
    !value.chars().any(char::is_control)
}

fn bounded(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len()) && no_control(value)
}

/// `^[A-Za-z0-9._-]+$`, 1..=64 bytes.
pub fn is_valid_gateway_name(value: &str) -> bool {
    bounded(value, 1, 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `^[A-Za-z0-9._:-]+$`, 1..=128 bytes.
pub fn is_valid_object_id(value: &str) -> bool {
    bounded(value, 1, 128)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// `^[A-Za-z_][A-Za-z0-9_]{0,127}$`
pub fn is_valid_credential_key(value: &str) -> bool {
    let bytes = value.as_bytes();
    match bytes.split_first() {
        Some((first, rest)) => {
            (first.is_ascii_alphabetic() || *first == b'_')
                && rest.len() <= 127
                && rest.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
        }
        None => false,
    }
}

/// `^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`,
/// 1..=253 bytes. IPv6 literals never match.
pub fn is_valid_endpoint_host(value: &str) -> bool {
    if !(1..=253).contains(&value.len()) {
        return false;
    }
    let body = value.strip_prefix("*.").unwrap_or(value);
    !body.is_empty()
        && body.split('.').all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
                && bytes.first() != Some(&b'-')
                && bytes.last() != Some(&b'-')
        })
}

/// `https://` or `http://`, at most 256 bytes, no control characters.
pub fn is_valid_gateway_endpoint(value: &str) -> bool {
    bounded(value, 1, 256) && (value.starts_with("https://") || value.starts_with("http://"))
}

/// Full desktop-side validation of a resolve request, plus the aac-side
/// digest consistency check.
pub fn validate_resolve_request(request: &ResolveRequest) -> Result<(), RequestError> {
    use RequestError::Invalid;
    if request.version != PROTOCOL_VERSION || request.op != OP_RESOLVE {
        return Err(Invalid("version/op"));
    }
    let body = &request.openshell;
    if !(MIN_DEADLINE_MS..=MAX_DEADLINE_MS).contains(&body.deadline_ms) {
        return Err(Invalid("deadlineMs"));
    }
    if !is_valid_gateway_name(&body.gateway.name) {
        return Err(Invalid("gateway.name"));
    }
    if !is_valid_gateway_endpoint(&body.gateway.endpoint) {
        return Err(Invalid("gateway.endpoint"));
    }
    if !is_valid_object_id(&body.provider.id) {
        return Err(Invalid("provider.id"));
    }
    if !is_valid_object_id(&body.sandbox.id) {
        return Err(Invalid("sandbox.id"));
    }
    if !bounded(&body.provider.name, 1, 128) {
        return Err(Invalid("provider.name"));
    }
    if !bounded(&body.provider.profile, 0, 128) {
        return Err(Invalid("provider.profile"));
    }
    if !bounded(&body.provider.workspace, 0, 128) {
        return Err(Invalid("provider.workspace"));
    }
    if !bounded(&body.sandbox.name, 0, 128) {
        return Err(Invalid("sandbox.name"));
    }
    if let Some(image) = &body.sandbox.image {
        if !bounded(image, 0, 512) {
            return Err(Invalid("sandbox.image"));
        }
    }
    if body.endpoints.is_empty() {
        return Err(Invalid("openshell credential has no bound endpoints"));
    }
    if body.endpoints.len() > MAX_ENDPOINTS {
        return Err(Invalid("endpoints"));
    }
    let mut seen = HashSet::new();
    for endpoint in &body.endpoints {
        if !is_valid_endpoint_host(&endpoint.host) {
            return Err(Invalid("endpoints[].host"));
        }
        if endpoint.port == 0 {
            return Err(Invalid("endpoints[].port"));
        }
        if let Some(path) = &endpoint.path {
            if !bounded(path, 0, 512) {
                return Err(Invalid("endpoints[].path"));
            }
        }
        if !seen.insert((&endpoint.host, endpoint.port, &endpoint.path)) {
            return Err(Invalid("endpoints uniqueness"));
        }
    }
    if !is_valid_digest(&body.policy.digest) || body.policy.digest != policy_digest(&body.endpoints)
    {
        return Err(Invalid("policy.digest"));
    }
    if body.targets.is_empty() || body.targets.len() > MAX_TARGETS {
        return Err(Invalid("targets"));
    }
    let mut keys = HashSet::new();
    for target in &body.targets {
        if !is_valid_credential_key(&target.credential_key) {
            return Err(Invalid("targets[].credentialKey"));
        }
        if !keys.insert(target.credential_key.as_str()) {
            return Err(Invalid("targets[].credentialKey uniqueness"));
        }
        if !is_lowercase_uuid(&target.id) {
            return Err(Invalid("targets[].id"));
        }
        let field_ok = matches!(
            (target.resource, target.field),
            (Resource::Item, Field::Username)
                | (Resource::Item, Field::Password)
                | (Resource::Secret, Field::Value)
        );
        if !field_ok {
            return Err(Invalid("targets[].field"));
        }
    }
    if !bounded(&request.client.name, 1, 128) || !bounded(&request.client.version, 1, 128) {
        return Err(Invalid("client"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Replies
// ---------------------------------------------------------------------------

/// One released value. `Debug` prints the key only.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderValue {
    pub credential_key: String,
    pub value: Zeroizing<String>,
}

impl fmt::Debug for ProviderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderValue")
            .field("credential_key", &self.credential_key)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// How long the released values stay usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifetime {
    PerRequest { expires_at_ms: u64 },
    Ttl { expires_at_ms: u64 },
    SandboxLifetime,
}

impl Lifetime {
    pub fn expires_at_ms(self) -> Option<u64> {
        match self {
            Lifetime::PerRequest { expires_at_ms } | Lifetime::Ttl { expires_at_ms } => {
                Some(expires_at_ms)
            }
            Lifetime::SandboxLifetime => None,
        }
    }

    pub fn mode_str(self) -> &'static str {
        match self {
            Lifetime::PerRequest { .. } => "perRequest",
            Lifetime::Ttl { .. } => "ttl",
            Lifetime::SandboxLifetime => "sandboxLifetime",
        }
    }
}

/// An approved, all-or-nothing resolution. `Debug` prints keys only.
pub struct Resolution {
    pub lifetime: Lifetime,
    pub values: Vec<ProviderValue>,
}

impl fmt::Debug for Resolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resolution")
            .field("lifetime", &self.lifetime)
            .field(
                "values",
                &self
                    .values
                    .iter()
                    .map(|v| v.credential_key.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// The desktop's answer, after shape validation.
#[derive(Debug)]
pub enum DesktopReply {
    Approved(Resolution),
    Denied,
    NotFound,
    Locked,
    Timeout,
    RateLimited,
    Error,
}

/// The reply did not have the §M8.4 shape. Carries no detail by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed reply from Bitwarden desktop")]
pub struct ReplyError;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawLifetime {
    mode: String,
    #[serde(default)]
    expires_at_ms: Option<u64>,
}

#[derive(Deserialize)]
struct RawResolution {
    lifetime: RawLifetime,
    values: Vec<ProviderValue>,
}

#[derive(Deserialize)]
struct RawReply {
    version: u32,
    status: String,
    #[serde(default)]
    message: Option<IgnoredAny>,
    #[serde(default)]
    openshell: Option<RawResolution>,
    // Fields an approved OpenShell reply must never carry.
    #[serde(default)]
    credential: Option<IgnoredAny>,
    #[serde(default)]
    item: Option<IgnoredAny>,
    #[serde(default)]
    secret: Option<IgnoredAny>,
    #[serde(default)]
    reference: Option<IgnoredAny>,
}

/// Parse and shape-check one reply line (trailing `\n` optional).
pub fn parse_reply(line: &[u8]) -> Result<DesktopReply, ReplyError> {
    let raw: RawReply = serde_json::from_slice(line).map_err(|_| ReplyError)?;
    if raw.version != PROTOCOL_VERSION {
        return Err(ReplyError);
    }
    let simple = |reply: DesktopReply, raw: RawReply| {
        // A refusal never carries values.
        if raw.openshell.is_some() {
            Err(ReplyError)
        } else {
            Ok(reply)
        }
    };
    match raw.status.as_str() {
        "approved" => {
            if raw.message.is_some()
                || raw.credential.is_some()
                || raw.item.is_some()
                || raw.secret.is_some()
                || raw.reference.is_some()
            {
                return Err(ReplyError);
            }
            let resolution = raw.openshell.ok_or(ReplyError)?;
            let lifetime = match (
                resolution.lifetime.mode.as_str(),
                resolution.lifetime.expires_at_ms,
            ) {
                ("perRequest", Some(expires_at_ms)) => Lifetime::PerRequest { expires_at_ms },
                ("ttl", Some(expires_at_ms)) => Lifetime::Ttl { expires_at_ms },
                ("sandboxLifetime", None) => Lifetime::SandboxLifetime,
                _ => return Err(ReplyError),
            };
            Ok(DesktopReply::Approved(Resolution {
                lifetime,
                values: resolution.values,
            }))
        }
        "denied" => simple(DesktopReply::Denied, raw),
        "notFound" => simple(DesktopReply::NotFound, raw),
        "locked" => simple(DesktopReply::Locked, raw),
        "timeout" => simple(DesktopReply::Timeout, raw),
        "rateLimited" => simple(DesktopReply::RateLimited, raw),
        "error" => simple(DesktopReply::Error, raw),
        _ => Err(ReplyError),
    }
}

/// Fixed, value-free gRPC status messages.
pub mod messages {
    pub const DENIED: &str = "bitwarden: request denied in Bitwarden desktop";
    pub const TIMEOUT: &str = "bitwarden: approval timed out in Bitwarden desktop";
    pub const LOCKED: &str = "bitwarden: Bitwarden desktop is locked";
    pub const RATE_LIMITED: &str = "bitwarden: too many requests; try again later";
    pub const NOT_FOUND: &str = "bitwarden: a requested item or secret was not found";
    pub const ERROR: &str = "bitwarden: Bitwarden desktop refused the request";
    pub const UNAVAILABLE: &str =
        "Bitwarden desktop is not running or the OpenShell integration is off";
    pub const MALFORMED: &str = "bitwarden: malformed reply from Bitwarden desktop";
    pub const READ_TIMEOUT: &str = "bitwarden: no reply from Bitwarden desktop in time";
    pub const UNTRUSTED_SOCKET: &str =
        "bitwarden: the Bitwarden desktop socket is not a private socket owned by this user";
}

/// Map a non-approved reply onto the gRPC status for the **whole** batch.
/// Returns `None` for an approval.
pub fn refusal_status(reply: &DesktopReply) -> Option<tonic::Status> {
    use tonic::Status;
    match reply {
        DesktopReply::Approved(_) => None,
        DesktopReply::Denied => Some(Status::permission_denied(messages::DENIED)),
        DesktopReply::Timeout => Some(Status::deadline_exceeded(messages::TIMEOUT)),
        DesktopReply::Locked => Some(Status::unavailable(messages::LOCKED)),
        DesktopReply::RateLimited => Some(Status::resource_exhausted(messages::RATE_LIMITED)),
        DesktopReply::NotFound => Some(Status::failed_precondition(messages::NOT_FOUND)),
        DesktopReply::Error => Some(Status::failed_precondition(messages::ERROR)),
    }
}

// ---------------------------------------------------------------------------
// Transport: one connection per request, one JSON line each way.
// ---------------------------------------------------------------------------

/// Failure talking to the desktop socket. Carries no reply content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DesktopError {
    /// Missing socket, connection refused, or the connection broke.
    #[error("{}", messages::UNAVAILABLE)]
    Unavailable,
    /// No complete reply within the read timeout.
    #[error("{}", messages::READ_TIMEOUT)]
    ReadTimeout,
    /// The reply was not a valid §M8.4 reply (or exceeded the size cap).
    #[error("{}", messages::MALFORMED)]
    Malformed,
    /// The request itself would not pass desktop validation.
    #[error("bitwarden: request could not be built")]
    BadRequest,
    /// The socket file is not a 0600 socket owned by this uid, or the
    /// listening peer runs as another uid. Nothing was sent.
    #[error("{}", messages::UNTRUSTED_SOCKET)]
    UntrustedSocket,
}

impl DesktopError {
    pub fn to_status(self) -> tonic::Status {
        use tonic::Status;
        match self {
            DesktopError::Unavailable => Status::failed_precondition(messages::UNAVAILABLE),
            DesktopError::ReadTimeout => Status::deadline_exceeded(messages::READ_TIMEOUT),
            DesktopError::Malformed => Status::failed_precondition(messages::MALFORMED),
            DesktopError::BadRequest => Status::failed_precondition(self.to_string()),
            DesktopError::UntrustedSocket => {
                Status::failed_precondition(messages::UNTRUSTED_SOCKET)
            }
        }
    }
}

/// Read timeout for a resolve: `deadlineMs + 2000` ms (never the 120 s CLI
/// default).
pub fn read_timeout(deadline_ms: u32) -> Duration {
    Duration::from_millis(u64::from(deadline_ms) + READ_SLACK_MS)
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// The desktop socket must be a socket (not a symlink), owned by this uid,
/// with no group or other permission bits (the desktop binds it 0600).
#[cfg(unix)]
pub fn check_desktop_socket_file(socket_path: &Path) -> Result<(), DesktopError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::symlink_metadata(socket_path).map_err(|_| DesktopError::Unavailable)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != current_uid()
        || metadata.mode() & 0o077 != 0
    {
        return Err(DesktopError::UntrustedSocket);
    }
    Ok(())
}

/// Send one request line and read one reply line, all within `timeout`.
/// The reply buffer is zeroized on drop.
#[cfg(unix)]
pub async fn exchange(
    socket_path: &Path,
    line: &[u8],
    timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>, DesktopError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let round_trip = async {
        check_desktop_socket_file(socket_path)?;
        let mut stream = tokio::net::UnixStream::connect(socket_path)
            .await
            .map_err(|_| DesktopError::Unavailable)?;
        // The listener must run as this uid: a socket squatted by another
        // user never sees the request (which names vault item ids).
        if !stream
            .peer_cred()
            .is_ok_and(|cred| cred.uid() == current_uid())
        {
            return Err(DesktopError::UntrustedSocket);
        }
        stream
            .write_all(line)
            .await
            .map_err(|_| DesktopError::Unavailable)?;
        stream
            .flush()
            .await
            .map_err(|_| DesktopError::Unavailable)?;

        // Pre-size so the buffer never reallocates (a reallocation would
        // leave an un-zeroized copy of partial reply bytes behind).
        let mut reply = Zeroizing::new(Vec::with_capacity(MAX_REPLY_BYTES + 1));
        let mut chunk = Zeroizing::new([0u8; 4096]);
        loop {
            let read = stream
                .read(&mut chunk[..])
                .await
                .map_err(|_| DesktopError::Unavailable)?;
            if read == 0 {
                break;
            }
            let Some(bytes) = chunk.get(..read) else {
                return Err(DesktopError::Malformed);
            };
            if reply.len() + bytes.len() > MAX_REPLY_BYTES {
                return Err(DesktopError::Malformed);
            }
            reply.extend_from_slice(bytes);
            if let Some(newline) = reply.iter().position(|b| *b == b'\n') {
                // Anything after the first line is ignored (and zeroized).
                reply.truncate(newline);
                return Ok(reply);
            }
        }
        if reply.is_empty() {
            Err(DesktopError::Unavailable)
        } else {
            Ok(reply)
        }
    };

    tokio::time::timeout(timeout, round_trip)
        .await
        .map_err(|_| DesktopError::ReadTimeout)?
}

#[cfg(not(unix))]
pub async fn exchange(
    _socket_path: &Path,
    _line: &[u8],
    _timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>, DesktopError> {
    Err(DesktopError::Unavailable)
}

/// Validate, send and parse one `openshellResolve`.
pub async fn send_resolve(
    socket_path: &Path,
    request: &ResolveRequest,
) -> Result<DesktopReply, DesktopError> {
    validate_resolve_request(request).map_err(|_| DesktopError::BadRequest)?;
    let line = request.to_line().map_err(|_| DesktopError::BadRequest)?;
    let reply = exchange(
        socket_path,
        &line,
        read_timeout(request.openshell.deadline_ms),
    )
    .await?;
    parse_reply(&reply).map_err(|_| DesktopError::Malformed)
}

/// Send one `openshellHello`. The caller ignores any failure.
pub async fn send_hello(socket_path: &Path, request: &HelloRequest) -> Result<(), DesktopError> {
    let line = request.to_line().map_err(|_| DesktopError::BadRequest)?;
    let reply = exchange(socket_path, &line, Duration::from_secs(5)).await?;
    let raw: RawReply = serde_json::from_slice(&reply).map_err(|_| DesktopError::Malformed)?;
    if raw.version == PROTOCOL_VERSION && raw.status == "approved" && raw.openshell.is_none() {
        Ok(())
    } else {
        Err(DesktopError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_FIXTURE: &str = include_str!("../tests/fixtures/openshell-resolve.request.json");
    const HELLO_FIXTURE: &str = include_str!("../tests/fixtures/openshell-hello.request.json");
    const APPROVED_TTL: &str =
        include_str!("../tests/fixtures/openshell-resolve.approved-ttl.json");
    const APPROVED_SANDBOX: &str =
        include_str!("../tests/fixtures/openshell-resolve.approved-sandbox-lifetime.json");
    const DENIED: &str = include_str!("../tests/fixtures/openshell-resolve.denied.json");

    /// The §M8.4 example request, built field by field.
    pub(crate) fn fixture_request() -> ResolveRequest {
        ResolveRequest::new(
            ResolveBody {
                deadline_ms: 25_000,
                gateway: GatewayRef {
                    name: "openshell".into(),
                    endpoint: "https://127.0.0.1:17670".into(),
                },
                provider: ProviderRef {
                    id: "prov-7f3a".into(),
                    name: "gh-agent-1".into(),
                    profile: "github".into(),
                    workspace: "default".into(),
                },
                sandbox: SandboxRef {
                    id: "sbx-01J9Z6".into(),
                    name: "agent-1".into(),
                    image: Some("ghcr.io/example/agent:1.2".into()),
                },
                endpoints: vec![Endpoint {
                    host: "api.github.com".into(),
                    port: 443,
                    path: Some("/**".into()),
                    source: EndpointSource::Profile,
                }],
                policy: PolicyRef {
                    digest:
                        "sha256:998f40a71463c9250c9eaf7bcb560234fc838a2bf7592b260165f9b4af110020"
                            .into(),
                    advisor_enabled: Some(false),
                },
                targets: vec![
                    WireTarget {
                        credential_key: "GITHUB_TOKEN".into(),
                        resource: Resource::Item,
                        id: "3f1c2b9e-8a4d-4c7e-9b21-5d6f7a8b9c0d".into(),
                        field: Field::Password,
                    },
                    WireTarget {
                        credential_key: "DB_PASSWORD".into(),
                        resource: Resource::Secret,
                        id: "a7e2d4c1-6b3f-4e8a-9d10-2c5b6a7f8e9d".into(),
                        field: Field::Value,
                    },
                ],
            },
            ClientInfo::driver("0.0.0-fixture"),
        )
    }

    #[test]
    fn resolve_request_serializes_byte_equal_to_fixture() {
        let line = fixture_request().to_line().expect("encodes");
        assert_eq!(
            std::str::from_utf8(&line).expect("utf8"),
            REQUEST_FIXTURE,
            "key order / formatting drifted from §M8.11"
        );
        validate_resolve_request(&fixture_request()).expect("fixture passes validation");
    }

    #[test]
    fn hello_request_serializes_byte_equal_to_fixture() {
        let hello = HelloRequest::new(
            GatewayRef {
                name: "openshell".into(),
                endpoint: "https://127.0.0.1:17670".into(),
            },
            ClientInfo::driver("0.0.0-fixture"),
        );
        let line = hello.to_line().expect("encodes");
        assert_eq!(std::str::from_utf8(&line).expect("utf8"), HELLO_FIXTURE);
    }

    #[test]
    fn fixture_request_round_trips_through_serde() {
        let parsed: ResolveRequest = serde_json::from_str(REQUEST_FIXTURE).expect("parses");
        assert_eq!(parsed, fixture_request());
    }

    #[test]
    fn approved_ttl_fixture_parses() {
        let DesktopReply::Approved(resolution) =
            parse_reply(APPROVED_TTL.as_bytes()).expect("parses")
        else {
            panic!("expected approval");
        };
        assert_eq!(
            resolution.lifetime,
            Lifetime::Ttl {
                expires_at_ms: 1_791_234_567_890
            }
        );
        let keys: Vec<_> = resolution
            .values
            .iter()
            .map(|v| v.credential_key.as_str())
            .collect();
        assert_eq!(keys, ["GITHUB_TOKEN", "DB_PASSWORD"]);
        assert_eq!(resolution.values[0].value.as_str(), "fixture-password");
        assert_eq!(resolution.values[1].value.as_str(), "fixture-secret");
    }

    #[test]
    fn approved_sandbox_lifetime_fixture_parses() {
        let DesktopReply::Approved(resolution) =
            parse_reply(APPROVED_SANDBOX.as_bytes()).expect("parses")
        else {
            panic!("expected approval");
        };
        assert_eq!(resolution.lifetime, Lifetime::SandboxLifetime);
        assert_eq!(resolution.lifetime.expires_at_ms(), None);
        assert_eq!(resolution.values.len(), 2);
    }

    #[test]
    fn denied_fixture_maps_to_permission_denied() {
        let reply = parse_reply(DENIED.as_bytes()).expect("parses");
        assert!(matches!(reply, DesktopReply::Denied));
        let status = refusal_status(&reply).expect("refusal");
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn every_status_maps_per_the_table() {
        use tonic::Code;
        let table = [
            ("denied", Code::PermissionDenied),
            ("timeout", Code::DeadlineExceeded),
            ("locked", Code::Unavailable),
            ("rateLimited", Code::ResourceExhausted),
            ("notFound", Code::FailedPrecondition),
            ("error", Code::FailedPrecondition),
        ];
        for (status, code) in table {
            let line =
                format!(r#"{{"version":1,"status":"{status}","message":"desktop-text-xyz"}}"#);
            let reply = parse_reply(line.as_bytes()).expect("parses");
            let mapped = refusal_status(&reply).expect("refusal");
            assert_eq!(mapped.code(), code, "{status}");
            // The desktop's free-form message is never echoed into gRPC.
            assert!(!mapped.message().contains("desktop-text-xyz"));
        }
        assert_eq!(
            DesktopError::Unavailable.to_status().code(),
            Code::FailedPrecondition
        );
        assert_eq!(
            DesktopError::Unavailable.to_status().message(),
            "Bitwarden desktop is not running or the OpenShell integration is off"
        );
        assert_eq!(
            DesktopError::Malformed.to_status().code(),
            Code::FailedPrecondition
        );
    }

    #[test]
    fn malformed_replies_are_rejected() {
        let rejects = [
            "",
            "not json",
            r#"{"version":2,"status":"denied"}"#,
            r#"{"version":1,"status":"maybe"}"#,
            r#"{"version":1,"status":"approved"}"#,
            // approved + forbidden extras
            r#"{"version":1,"status":"approved","message":"x","openshell":{"lifetime":{"mode":"sandboxLifetime"},"values":[]}}"#,
            r#"{"version":1,"status":"approved","credential":{},"openshell":{"lifetime":{"mode":"sandboxLifetime"},"values":[]}}"#,
            r#"{"version":1,"status":"approved","reference":"bw://item/x","openshell":{"lifetime":{"mode":"sandboxLifetime"},"values":[]}}"#,
            // lifetime incoherence
            r#"{"version":1,"status":"approved","openshell":{"lifetime":{"mode":"ttl"},"values":[]}}"#,
            r#"{"version":1,"status":"approved","openshell":{"lifetime":{"mode":"perRequest"},"values":[]}}"#,
            r#"{"version":1,"status":"approved","openshell":{"lifetime":{"mode":"sandboxLifetime","expiresAtMs":5},"values":[]}}"#,
            r#"{"version":1,"status":"approved","openshell":{"lifetime":{"mode":"forever"},"values":[]}}"#,
            r#"{"version":1,"status":"approved","openshell":{"lifetime":{"mode":"ttl","expiresAtMs":1.5},"values":[]}}"#,
            r#"{"version":1,"status":"approved","openshell":{"lifetime":{"mode":"ttl","expiresAtMs":-1},"values":[]}}"#,
            // refusal carrying values
            r#"{"version":1,"status":"denied","openshell":{"lifetime":{"mode":"sandboxLifetime"},"values":[]}}"#,
        ];
        for line in rejects {
            assert!(parse_reply(line.as_bytes()).is_err(), "accepted: {line}");
        }
    }

    #[test]
    fn validator_rejects_each_contract_row() {
        type Mutate = fn(&mut ResolveRequest);
        let cases: Vec<(&str, Mutate)> = vec![
            ("deadline low", |r| r.openshell.deadline_ms = 1_999),
            ("deadline high", |r| r.openshell.deadline_ms = 28_001),
            ("gateway name chars", |r| {
                r.openshell.gateway.name = "a b".into()
            }),
            ("gateway name empty", |r| r.openshell.gateway.name.clear()),
            ("gateway name long", |r| {
                r.openshell.gateway.name = "a".repeat(65)
            }),
            ("endpoint scheme", |r| {
                r.openshell.gateway.endpoint = "ftp://x".into()
            }),
            ("endpoint long", |r| {
                r.openshell.gateway.endpoint = format!("https://{}", "a".repeat(250))
            }),
            ("provider id chars", |r| {
                r.openshell.provider.id = "a/b".into()
            }),
            ("sandbox id empty", |r| r.openshell.sandbox.id.clear()),
            ("provider name empty", |r| r.openshell.provider.name.clear()),
            ("provider name control", |r| {
                r.openshell.provider.name = "a\u{7}".into()
            }),
            ("sandbox name long", |r| {
                r.openshell.sandbox.name = "a".repeat(129)
            }),
            ("image long", |r| {
                r.openshell.sandbox.image = Some("a".repeat(513))
            }),
            ("workspace control", |r| {
                r.openshell.provider.workspace = "a\nb".into()
            }),
            ("no endpoints", |r| r.openshell.endpoints.clear()),
            ("uppercase host", |r| {
                r.openshell.endpoints[0].host = "API.github.com".into()
            }),
            ("ipv6 host", |r| {
                r.openshell.endpoints[0].host = "::1".into()
            }),
            ("port zero", |r| r.openshell.endpoints[0].port = 0),
            ("path long", |r| {
                r.openshell.endpoints[0].path = Some("/".repeat(513))
            }),
            ("duplicate endpoint", |r| {
                let dup = r.openshell.endpoints[0].clone();
                r.openshell.endpoints.push(dup);
            }),
            ("digest mismatch", |r| {
                r.openshell.policy.digest = format!("sha256:{}", "0".repeat(64))
            }),
            ("no targets", |r| r.openshell.targets.clear()),
            ("dup key", |r| {
                r.openshell.targets[1].credential_key = "GITHUB_TOKEN".into()
            }),
            ("bad key", |r| {
                r.openshell.targets[0].credential_key = "1ABC".into()
            }),
            ("bad uuid", |r| r.openshell.targets[0].id = "nope".into()),
            ("wrong field", |r| {
                r.openshell.targets[1].field = Field::Password
            }),
            ("wrong field item", |r| {
                r.openshell.targets[0].field = Field::Value
            }),
        ];
        for (name, mutate) in cases {
            let mut request = fixture_request();
            mutate(&mut request);
            assert!(
                validate_resolve_request(&request).is_err(),
                "validator accepted: {name}"
            );
        }
    }

    #[test]
    fn host_grammar() {
        for ok in ["api.github.com", "*.github.com", "a", "127.0.0.1", "a-b.c"] {
            assert!(is_valid_endpoint_host(ok), "{ok}");
        }
        for bad in [
            "",
            "**.github.com",
            "-a.com",
            "a-.com",
            "a..com",
            "a.com.",
            "[::1]",
            "a_b.com",
            "*.",
        ] {
            assert!(!is_valid_endpoint_host(bad), "{bad}");
        }
    }

    #[test]
    fn debug_of_value_types_contains_no_value() {
        let DesktopReply::Approved(resolution) =
            parse_reply(APPROVED_TTL.as_bytes()).expect("parses")
        else {
            panic!("expected approval");
        };
        let rendered = format!("{:?} {:?}", resolution.values[0], resolution);
        assert!(!rendered.contains("fixture-password"));
        assert!(!rendered.contains("fixture-secret"));
        let reply = DesktopReply::Approved(resolution);
        let rendered = format!("{reply:?}");
        assert!(!rendered.contains("fixture-"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn missing_socket_is_unavailable() {
        let path = std::env::temp_dir().join(format!("aos-missing-{}.sock", std::process::id()));
        let err = send_resolve(&path, &fixture_request())
            .await
            .expect_err("no socket");
        assert_eq!(err, DesktopError::Unavailable);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn non_private_desktop_socket_is_never_written_to() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("aos-squat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("desktop.sock");
        let listener = tokio::net::UnixListener::bind(&path).expect("bind");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        let err = send_resolve(&path, &fixture_request())
            .await
            .expect_err("refused");
        assert_eq!(err, DesktopError::UntrustedSocket);
        // Nothing connected, so nothing was sent.
        let accepted = tokio::time::timeout(Duration::from_millis(100), listener.accept()).await;
        assert!(accepted.is_err());

        // A regular file (or symlink) at the path is refused too.
        drop(listener);
        std::fs::remove_file(&path).expect("rm");
        std::fs::write(&path, "x").expect("write");
        assert_eq!(
            check_desktop_socket_file(&path),
            Err(DesktopError::UntrustedSocket)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
