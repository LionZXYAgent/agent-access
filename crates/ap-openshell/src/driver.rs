//! `CredentialDriver` gRPC implementation (architecture §M8.12).
//!
//! - `StoreCredential` validates and encodes a `bw://` reference: no I/O.
//! - `ResolveCredentials`: decode handles → single provider → context →
//!   one `openshellResolve` → map values back per `request_id` → set
//!   `expiration_time` → zeroize. Bounded at 27 s, or at the gateway's own
//!   `grpc-timeout` minus a margin when that is shorter (§M8.18); one at a
//!   time.
//!
//! Logging: `provider_id`, `sandbox_id`, status code and duration only.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;
use tokio::time::Instant;
use tonic::{Code, Request, Response, Status};
use zeroize::Zeroizing;

use crate::DesktopResolver;
use crate::context::{GatewayInfo, ProviderBatch, build_context, messages as ctx_messages};
use crate::gateway_config::GatewayConfigError;
use crate::handle::{parse_credential_handle, parse_store_value};
use crate::proto::openshell::credentials::v1::credential_driver_server::CredentialDriver;
use crate::proto::openshell::credentials::v1::{
    DeleteCredentialRequest, DeleteCredentialResponse, GetCredentialDriverCapabilitiesRequest,
    GetCredentialDriverCapabilitiesResponse, ListCredentialsRequest, ListCredentialsResponse,
    ResolveCredentialRequest, ResolveCredentialsRequest, ResolveCredentialsResponse,
    ResolvedCredential, StoreCredentialRequest, StoreCredentialResponse,
};
use crate::proto::openshell::extension::v1::{PeerMetadata, ProtocolVersion};
use crate::wire::{
    ClientInfo, DEFAULT_DEADLINE_MS, DesktopReply, GatewayRef, Lifetime, MAX_TARGETS,
    MAX_VALUE_BYTES, MIN_DEADLINE_MS, ResolveBody, ResolveRequest, WireTarget,
    is_valid_credential_key, messages as wire_messages, refusal_status,
};

/// Whole-call bound for `ResolveCredentials` (the gateway allows 30 s).
pub const DRIVER_DEADLINE: Duration = Duration::from_secs(27);
/// Kept free at the end of the caller's `grpc-timeout` for mapping the reply
/// and getting it back to the gateway (30 s − 3 s = the 27 s above).
pub const GRPC_DEADLINE_MARGIN: Duration = Duration::from_secs(3);
/// gRPC spec: at most 8 digits before the unit.
const GRPC_TIMEOUT_MAX_DIGITS: usize = 8;
/// OpenShell extension protocol major this driver implements.
pub const PROTOCOL_MAJOR: u32 = 1;
pub const PROTOCOL_MINOR: u32 = 0;
pub const CONTRACT_CAPABILITY: &str = "openshell.credentials.contract";
pub const IMPLEMENTATION_NAME: &str = "bitwarden-aac";
pub const BACKEND_KIND: &str = "bitwarden-desktop";

/// Upper bounds on a reply's `expiresAtMs` relative to now.
const PER_REQUEST_MAX_MS: u64 = 125_000;
const TTL_MAX_MS: u64 = 86_400_000 + 5_000;

pub const STORE_REJECTED: &str = "Bitwarden driver accepts only bw:// references";
pub const BAD_HANDLE: &str = "unrecognised Bitwarden handle";

/// Epoch-milliseconds clock (injectable for tests).
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    })
}

/// The gateway this driver serves and its read-only lookup client.
pub struct GatewayTarget<G> {
    pub gateway: GatewayRef,
    pub info: G,
}

pub struct BitwardenDriver<R, G> {
    resolver: R,
    gateway: Result<GatewayTarget<G>, GatewayConfigError>,
    deadline: Duration,
    clock: Clock,
    version: String,
    serial: Mutex<()>,
}

impl<R: DesktopResolver, G: GatewayInfo> BitwardenDriver<R, G> {
    pub fn new(resolver: R, gateway: Result<GatewayTarget<G>, GatewayConfigError>) -> Self {
        Self {
            resolver,
            gateway,
            deadline: DRIVER_DEADLINE,
            clock: system_clock(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            serial: Mutex::new(()),
        }
    }

    /// Test hook: pin the epoch clock.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Test hook: pin the reported `client.version`.
    pub fn with_client_version(mut self, version: &str) -> Self {
        self.version = version.to_string();
        self
    }

    /// Test hook: shorten the whole-call deadline.
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    async fn resolve_batch(
        &self,
        requests: Vec<ResolveCredentialRequest>,
        started: Instant,
        budget: Duration,
        sandbox_id: &mut String,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }

        // 1. Decode every handle; one bad handle fails the batch.
        let mut targets = Vec::with_capacity(requests.len());
        for request in &requests {
            let handle = request
                .handle
                .as_ref()
                .ok_or_else(|| Status::invalid_argument(BAD_HANDLE))?;
            let target = parse_credential_handle(handle)
                .map_err(|_| Status::invalid_argument(BAD_HANDLE))?;
            targets.push(target);
        }

        // Request ids must be usable for correlation.
        let mut ids = HashSet::new();
        if requests
            .iter()
            .any(|r| r.request_id.is_empty() || !ids.insert(r.request_id.as_str()))
        {
            return Err(Status::invalid_argument(
                "bitwarden: invalid request_id set",
            ));
        }

        // 2. Exactly one provider per batch.
        let first = &requests[0];
        let batch = ProviderBatch {
            provider_name: first.provider.clone(),
            provider_id: first.provider_id.clone(),
            workspace: first.workspace.clone(),
            handles: requests
                .iter()
                .filter_map(|r| {
                    r.handle
                        .as_ref()
                        .map(|h| (r.credential_key.clone(), h.handle.clone()))
                })
                .collect(),
        };
        if requests.iter().any(|r| {
            r.provider != batch.provider_name
                || r.provider_id != batch.provider_id
                || r.workspace != batch.workspace
        }) {
            return Err(Status::failed_precondition(ctx_messages::ATTRIBUTION));
        }

        // Credential keys become env var names and desktop map keys.
        if requests.len() > MAX_TARGETS {
            return Err(Status::failed_precondition(
                "bitwarden: too many credentials in one provider",
            ));
        }
        let mut keys = HashSet::new();
        if requests
            .iter()
            .any(|r| !is_valid_credential_key(&r.credential_key) || !keys.insert(&r.credential_key))
        {
            return Err(Status::failed_precondition(
                "bitwarden: unsupported credential key",
            ));
        }

        // 3. Build the gateway-reported context (fails closed).
        let target = self
            .gateway
            .as_ref()
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        let context = build_context(&target.info, &target.gateway, &batch)
            .await
            .map_err(|e| e.to_status())?;
        sandbox_id.clone_from(&context.sandbox.id);

        // Offer the desktop the default deadline, shrunk to what is left of
        // this call's budget (27 s, or the caller's grpc-timeout minus the
        // margin) after the mutex wait and the lookups. A short deadline is
        // still sent when it clears the floor: desktop may answer an
        // identical retry at once (§M8.18).
        let remaining_ms =
            u64::try_from(budget.saturating_sub(started.elapsed()).as_millis()).unwrap_or(0);
        let deadline_ms = remaining_ms
            .saturating_sub(1_000)
            .min(u64::from(DEFAULT_DEADLINE_MS));
        let deadline_ms = u32::try_from(deadline_ms).unwrap_or(0);
        if deadline_ms < MIN_DEADLINE_MS {
            return Err(Status::deadline_exceeded(
                "bitwarden: not enough time left to ask for approval",
            ));
        }

        // 4. One openshellResolve.
        let wire_targets: Vec<WireTarget> = requests
            .iter()
            .zip(&targets)
            .map(|(request, target)| WireTarget {
                credential_key: request.credential_key.clone(),
                resource: target.resource,
                id: target.id.clone(),
                field: target.field,
            })
            .collect();
        let request = ResolveRequest::new(
            ResolveBody {
                deadline_ms,
                gateway: context.gateway,
                provider: context.provider,
                sandbox: context.sandbox,
                endpoints: context.endpoints,
                policy: context.policy,
                targets: wire_targets,
            },
            ClientInfo::driver(&self.version),
        );
        let reply = self
            .resolver
            .resolve(&request)
            .await
            .map_err(|e| e.to_status())?;
        if let Some(status) = refusal_status(&reply) {
            return Err(status);
        }
        let DesktopReply::Approved(mut resolution) = reply else {
            return Err(Status::failed_precondition(wire_messages::MALFORMED));
        };

        // 5./6. Check the approval, then map values back to request ids.
        let malformed = || Status::failed_precondition(wire_messages::MALFORMED);
        if resolution.values.len() != requests.len()
            || resolution
                .values
                .iter()
                .zip(&requests)
                .any(|(value, request)| value.credential_key != request.credential_key)
        {
            return Err(malformed());
        }
        if resolution.values.iter().any(|v| {
            v.value.is_empty() || v.value.len() > MAX_VALUE_BYTES || v.value.contains('\0')
        }) {
            return Err(malformed());
        }
        let now = (self.clock)();
        let expiration_time = match resolution.lifetime {
            Lifetime::SandboxLifetime => None,
            Lifetime::PerRequest { expires_at_ms } | Lifetime::Ttl { expires_at_ms } => {
                let ceiling = match resolution.lifetime {
                    Lifetime::PerRequest { .. } => PER_REQUEST_MAX_MS,
                    _ => TTL_MAX_MS,
                };
                if expires_at_ms <= now || expires_at_ms > now.saturating_add(ceiling) {
                    return Err(Status::failed_precondition(
                        "bitwarden: approval lifetime is expired or incoherent",
                    ));
                }
                Some(timestamp_from_ms(expires_at_ms)?)
            }
        };

        let mut resolved = Vec::with_capacity(requests.len());
        for (request, value) in requests.iter().zip(resolution.values.iter_mut()) {
            // Move the value out; the emptied Zeroizing wrapper is dropped
            // with `resolution`. The proto String is handed to tonic.
            let secret = std::mem::take(&mut *value.value);
            resolved.push(ResolvedCredential {
                request_id: request.request_id.clone(),
                value: secret,
                expiration_time,
            });
        }
        // 7. Zeroize whatever is left of the reply.
        drop(resolution);
        Ok(resolved)
    }
}

/// The whole-call budget: the driver deadline, or the caller's `grpc-timeout`
/// minus [`GRPC_DEADLINE_MARGIN`] when that is shorter. A missing or
/// unparseable header leaves the driver deadline (tonic itself ignores an
/// unparseable one, so the call is still bounded by the 27 s).
///
/// OpenShell v0.1.2 always sends `grpc-timeout: 30S` on the driver call
/// (`credentials.rs:59,1484-1494`), so against it this stays 27 s; the
/// supervisor's 10 s startup cap reaches aac only as a cancellation, which
/// desktop detects as a hang-up (§M8.18).
pub fn call_budget(driver_deadline: Duration, metadata: &tonic::metadata::MetadataMap) -> Duration {
    metadata
        .get("grpc-timeout")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_grpc_timeout)
        .map_or(driver_deadline, |caller| {
            driver_deadline.min(caller.saturating_sub(GRPC_DEADLINE_MARGIN))
        })
}

/// Parses a gRPC `TimeoutValue TimeoutUnit` (`1-8 digits` + `H|M|S|m|u|n`).
fn parse_grpc_timeout(value: &str) -> Option<Duration> {
    let unit_at = value.len().checked_sub(1)?;
    let (digits, unit) = (value.get(..unit_at)?, value.get(unit_at..)?);
    if digits.is_empty()
        || digits.len() > GRPC_TIMEOUT_MAX_DIGITS
        || !digits.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let amount: u64 = digits.parse().ok()?;
    match unit {
        "H" => Some(Duration::from_secs(amount.checked_mul(3_600)?)),
        "M" => Some(Duration::from_secs(amount.checked_mul(60)?)),
        "S" => Some(Duration::from_secs(amount)),
        "m" => Some(Duration::from_millis(amount)),
        "u" => Some(Duration::from_micros(amount)),
        "n" => Some(Duration::from_nanos(amount)),
        _ => None,
    }
}

fn timestamp_from_ms(ms: u64) -> Result<prost_types::Timestamp, Status> {
    let seconds = i64::try_from(ms / 1_000)
        .map_err(|_| Status::failed_precondition("bitwarden: approval lifetime out of range"))?;
    let nanos = i32::try_from((ms % 1_000) * 1_000_000)
        .map_err(|_| Status::failed_precondition("bitwarden: approval lifetime out of range"))?;
    Ok(prost_types::Timestamp { seconds, nanos })
}

fn peer_metadata(version: &str) -> PeerMetadata {
    PeerMetadata {
        protocol_version: Some(ProtocolVersion {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
        }),
        implementation_name: IMPLEMENTATION_NAME.to_string(),
        implementation_version: version.to_string(),
        supported_capabilities: vec![CONTRACT_CAPABILITY.to_string()],
        required_capabilities: vec![CONTRACT_CAPABILITY.to_string()],
    }
}

/// Reject a gateway whose protocol major or required capabilities we can't
/// meet, or which does not offer the capability we require.
fn check_gateway_metadata(gateway: Option<&PeerMetadata>) -> Result<(), Status> {
    let gateway = gateway.ok_or_else(|| {
        Status::failed_precondition("bitwarden: gateway sent no protocol metadata")
    })?;
    let major = gateway.protocol_version.as_ref().map(|v| v.major);
    if major != Some(PROTOCOL_MAJOR) {
        return Err(Status::failed_precondition(
            "bitwarden: unsupported OpenShell extension protocol",
        ));
    }
    if !gateway
        .supported_capabilities
        .iter()
        .any(|c| c == CONTRACT_CAPABILITY)
        || gateway
            .required_capabilities
            .iter()
            .any(|c| c != CONTRACT_CAPABILITY)
    {
        return Err(Status::failed_precondition(
            "bitwarden: gateway capability requirements not met",
        ));
    }
    Ok(())
}

fn code_str(code: Code) -> &'static str {
    match code {
        Code::Ok => "ok",
        Code::InvalidArgument => "invalid_argument",
        Code::FailedPrecondition => "failed_precondition",
        Code::PermissionDenied => "permission_denied",
        Code::DeadlineExceeded => "deadline_exceeded",
        Code::Unavailable => "unavailable",
        Code::ResourceExhausted => "resource_exhausted",
        _ => "other",
    }
}

#[tonic::async_trait]
impl<R: DesktopResolver, G: GatewayInfo> CredentialDriver for BitwardenDriver<R, G> {
    async fn get_capabilities(
        &self,
        request: Request<GetCredentialDriverCapabilitiesRequest>,
    ) -> Result<Response<GetCredentialDriverCapabilitiesResponse>, Status> {
        check_gateway_metadata(request.get_ref().gateway.as_ref())?;
        Ok(Response::new(GetCredentialDriverCapabilitiesResponse {
            driver_name: crate::handle::DRIVER_NAME.to_string(),
            driver_version: self.version.clone(),
            backend_kind: BACKEND_KIND.to_string(),
            supports_list: false,
            supports_expires_at: true,
            extension: Some(peer_metadata(&self.version)),
        }))
    }

    async fn store_credential(
        &self,
        request: Request<StoreCredentialRequest>,
    ) -> Result<Response<StoreCredentialResponse>, Status> {
        // No I/O: validate the reference and encode the handle. The value is
        // a Bitwarden pointer, but it is still dropped zeroized in case a
        // user pasted a real secret by mistake.
        let request = request.into_inner();
        let value = Zeroizing::new(request.value);
        let target =
            parse_store_value(&value).map_err(|_| Status::invalid_argument(STORE_REJECTED))?;
        tracing::debug!(provider_id = %request.provider_id, "openshell store: handle encoded");
        Ok(Response::new(StoreCredentialResponse {
            handle: Some(target.to_credential_handle()),
        }))
    }

    async fn delete_credential(
        &self,
        _request: Request<DeleteCredentialRequest>,
    ) -> Result<Response<DeleteCredentialResponse>, Status> {
        // Nothing is stored on the Bitwarden side for a handle.
        Ok(Response::new(DeleteCredentialResponse {}))
    }

    async fn resolve_credentials(
        &self,
        request: Request<ResolveCredentialsRequest>,
    ) -> Result<Response<ResolveCredentialsResponse>, Status> {
        let started = Instant::now();
        let budget = call_budget(self.deadline, request.metadata());
        let requests = request.into_inner().credentials;
        let provider_id = requests
            .first()
            .map(|r| r.provider_id.clone())
            .unwrap_or_default();
        let mut sandbox_id = String::new();

        let outcome = tokio::time::timeout(budget, async {
            let _serial = self.serial.lock().await;
            self.resolve_batch(requests, started, budget, &mut sandbox_id)
                .await
        })
        .await
        .unwrap_or_else(|_| {
            Err(Status::deadline_exceeded(
                "bitwarden: resolve exceeded the driver deadline",
            ))
        });

        let code = outcome.as_ref().map_or_else(|s| s.code(), |_| Code::Ok);
        tracing::info!(
            provider_id = %provider_id,
            sandbox_id = %sandbox_id,
            code = code_str(code),
            duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "openshell resolve"
        );
        outcome.map(|credentials| Response::new(ResolveCredentialsResponse { credentials }))
    }

    async fn list_credentials(
        &self,
        _request: Request<ListCredentialsRequest>,
    ) -> Result<Response<ListCredentialsResponse>, Status> {
        Err(Status::unimplemented(
            "bitwarden: listing credentials is not supported",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::context::tests::{FakeGateway, gateway_ref};
    use crate::handle::parse_reference;
    use crate::proto::openshell::datamodel::v1::CredentialHandle;
    use crate::wire::{DesktopError, ProviderValue, Resolution, validate_resolve_request};

    const PINNED_NOW: u64 = 1_791_230_967_890;
    const ITEM: &str = "3f1c2b9e-8a4d-4c7e-9b21-5d6f7a8b9c0d";
    const SECRET: &str = "a7e2d4c1-6b3f-4e8a-9d10-2c5b6a7f8e9d";

    type Reply = fn(&ResolveRequest) -> Result<DesktopReply, DesktopError>;

    /// Mock desktop. Panics if called when `panic_on_call` is set.
    struct MockResolver {
        reply: Reply,
        delay: Option<Duration>,
        calls: Arc<AtomicUsize>,
        panic_on_call: bool,
    }

    impl MockResolver {
        fn new(reply: Reply) -> Self {
            Self {
                reply,
                delay: None,
                calls: Arc::new(AtomicUsize::new(0)),
                panic_on_call: false,
            }
        }
        fn panicking() -> Self {
            Self {
                panic_on_call: true,
                ..Self::new(|_| Err(DesktopError::Unavailable))
            }
        }
    }

    impl DesktopResolver for MockResolver {
        async fn resolve(&self, request: &ResolveRequest) -> Result<DesktopReply, DesktopError> {
            assert!(!self.panic_on_call, "desktop must not be contacted");
            self.calls.fetch_add(1, Ordering::SeqCst);
            validate_resolve_request(request).expect("driver emits only valid requests");
            if let Some(delay) = self.delay {
                tokio::time::sleep(delay).await;
            }
            (self.reply)(request)
        }
    }

    fn value(key: &str, v: &str) -> ProviderValue {
        ProviderValue {
            credential_key: key.into(),
            value: Zeroizing::new(v.into()),
        }
    }

    fn approve(lifetime: Lifetime) -> Result<DesktopReply, DesktopError> {
        Ok(DesktopReply::Approved(Resolution {
            lifetime,
            values: vec![
                value("GITHUB_TOKEN", "fixture-password"),
                value("DB_PASSWORD", "fixture-secret"),
            ],
        }))
    }

    fn driver(
        resolver: MockResolver,
        gateway: FakeGateway,
    ) -> BitwardenDriver<MockResolver, FakeGateway> {
        BitwardenDriver::new(
            resolver,
            Ok(GatewayTarget {
                gateway: gateway_ref(),
                info: gateway,
            }),
        )
        .with_clock(Arc::new(|| PINNED_NOW))
        .with_client_version("0.0.0-fixture")
    }

    fn handle(reference: &str) -> CredentialHandle {
        parse_reference(reference)
            .expect("valid")
            .to_credential_handle()
    }

    fn item(request_id: &str, key: &str, reference: &str) -> ResolveCredentialRequest {
        ResolveCredentialRequest {
            request_id: request_id.into(),
            provider: "gh-agent-1".into(),
            credential_key: key.into(),
            handle: Some(handle(reference)),
            workspace: "default".into(),
            provider_id: "prov-7f3a".into(),
        }
    }

    fn batch() -> ResolveCredentialsRequest {
        // Request ids deliberately not in target order to prove mapping.
        ResolveCredentialsRequest {
            credentials: vec![
                item(
                    "credential-1",
                    "GITHUB_TOKEN",
                    &format!("bw://item/{ITEM}#password"),
                ),
                item(
                    "credential-0",
                    "DB_PASSWORD",
                    &format!("bw://secret/{SECRET}"),
                ),
            ],
        }
    }

    async fn resolve(
        driver: &BitwardenDriver<MockResolver, FakeGateway>,
        request: ResolveCredentialsRequest,
    ) -> Result<ResolveCredentialsResponse, Status> {
        driver
            .resolve_credentials(Request::new(request))
            .await
            .map(Response::into_inner)
    }

    #[tokio::test]
    async fn every_request_id_is_answered_exactly_once() {
        let driver = driver(
            MockResolver::new(|_| {
                approve(Lifetime::Ttl {
                    expires_at_ms: 1_791_234_567_890,
                })
            }),
            FakeGateway::example(),
        );
        let response = resolve(&driver, batch()).await.expect("approved");
        assert_eq!(response.credentials.len(), 2);
        let by_id: std::collections::HashMap<_, _> = response
            .credentials
            .iter()
            .map(|c| (c.request_id.as_str(), c))
            .collect();
        assert_eq!(by_id.len(), 2);
        assert_eq!(by_id["credential-1"].value, "fixture-password");
        assert_eq!(by_id["credential-0"].value, "fixture-secret");
        let expected = prost_types::Timestamp {
            seconds: 1_791_234_567,
            nanos: 890_000_000,
        };
        for credential in &response.credentials {
            assert_eq!(credential.expiration_time, Some(expected));
        }
        // Debug of the response never shows values.
        let rendered = format!("{response:?}");
        assert!(!rendered.contains("fixture-"), "{rendered}");
    }

    #[tokio::test]
    async fn driver_emits_the_fixture_request() {
        fn check(request: &ResolveRequest) -> Result<DesktopReply, DesktopError> {
            let line = request.to_line().expect("encodes");
            assert_eq!(
                std::str::from_utf8(&line).expect("utf8"),
                include_str!("../tests/fixtures/openshell-resolve.request.json")
                    // The fixture shows advisorEnabled:false; the driver
                    // never claims false, so the key is omitted.
                    .replace(r#","advisorEnabled":false"#, "")
            );
            approve(Lifetime::SandboxLifetime)
        }
        let driver = driver(MockResolver::new(check), FakeGateway::example());
        let ordered = ResolveCredentialsRequest {
            credentials: vec![
                item(
                    "credential-0",
                    "GITHUB_TOKEN",
                    &format!("bw://item/{ITEM}#password"),
                ),
                item(
                    "credential-1",
                    "DB_PASSWORD",
                    &format!("bw://secret/{SECRET}"),
                ),
            ],
        };
        resolve(&driver, ordered).await.expect("approved");
    }

    #[tokio::test]
    async fn sandbox_lifetime_leaves_expiration_unset() {
        let driver = driver(
            MockResolver::new(|_| approve(Lifetime::SandboxLifetime)),
            FakeGateway::example(),
        );
        let response = resolve(&driver, batch()).await.expect("approved");
        assert!(
            response
                .credentials
                .iter()
                .all(|c| c.expiration_time.is_none())
        );
    }

    #[tokio::test]
    async fn per_request_lifetime_sets_expiration() {
        let driver = driver(
            MockResolver::new(|_| {
                approve(Lifetime::PerRequest {
                    expires_at_ms: PINNED_NOW + 120_000,
                })
            }),
            FakeGateway::example(),
        );
        let response = resolve(&driver, batch()).await.expect("approved");
        assert!(
            response
                .credentials
                .iter()
                .all(|c| c.expiration_time.is_some())
        );
    }

    #[tokio::test]
    async fn past_or_incoherent_expiry_fails() {
        let cases: [Reply; 4] = [
            |_| {
                approve(Lifetime::Ttl {
                    expires_at_ms: PINNED_NOW,
                })
            },
            |_| {
                approve(Lifetime::Ttl {
                    expires_at_ms: PINNED_NOW - 1,
                })
            },
            |_| {
                approve(Lifetime::PerRequest {
                    expires_at_ms: PINNED_NOW + 125_001,
                })
            },
            |_| {
                approve(Lifetime::Ttl {
                    expires_at_ms: PINNED_NOW + 86_405_001,
                })
            },
        ];
        for reply in cases {
            let driver = driver(MockResolver::new(reply), FakeGateway::example());
            let status = resolve(&driver, batch()).await.expect_err("refused");
            assert_eq!(status.code(), Code::FailedPrecondition);
            assert!(!status.message().contains("fixture-"));
        }
    }

    #[tokio::test]
    async fn value_set_mismatch_fails() {
        let cases: [Reply; 4] = [
            // missing
            |_| {
                Ok(DesktopReply::Approved(Resolution {
                    lifetime: Lifetime::SandboxLifetime,
                    values: vec![value("GITHUB_TOKEN", "x")],
                }))
            },
            // reordered
            |_| {
                Ok(DesktopReply::Approved(Resolution {
                    lifetime: Lifetime::SandboxLifetime,
                    values: vec![value("DB_PASSWORD", "x"), value("GITHUB_TOKEN", "y")],
                }))
            },
            // extra
            |_| {
                Ok(DesktopReply::Approved(Resolution {
                    lifetime: Lifetime::SandboxLifetime,
                    values: vec![
                        value("GITHUB_TOKEN", "x"),
                        value("DB_PASSWORD", "y"),
                        value("EXTRA", "z"),
                    ],
                }))
            },
            // empty value
            |_| {
                Ok(DesktopReply::Approved(Resolution {
                    lifetime: Lifetime::SandboxLifetime,
                    values: vec![value("GITHUB_TOKEN", ""), value("DB_PASSWORD", "y")],
                }))
            },
        ];
        for reply in cases {
            let driver = driver(MockResolver::new(reply), FakeGateway::example());
            let status = resolve(&driver, batch()).await.expect_err("refused");
            assert_eq!(status.code(), Code::FailedPrecondition);
        }
    }

    #[tokio::test]
    async fn desktop_denial_fails_the_whole_batch() {
        let driver = driver(
            MockResolver::new(|_| Ok(DesktopReply::Denied)),
            FakeGateway::example(),
        );
        let status = resolve(&driver, batch()).await.expect_err("denied");
        assert_eq!(status.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn missing_desktop_is_failed_precondition_with_fixed_text() {
        let driver = driver(
            MockResolver::new(|_| Err(DesktopError::Unavailable)),
            FakeGateway::example(),
        );
        let status = resolve(&driver, batch()).await.expect_err("down");
        assert_eq!(status.code(), Code::FailedPrecondition);
        assert_eq!(
            status.message(),
            "Bitwarden desktop is not running or the OpenShell integration is off"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn resolver_delay_over_27s_is_deadline_exceeded() {
        let mut resolver = MockResolver::new(|_| approve(Lifetime::SandboxLifetime));
        resolver.delay = Some(Duration::from_secs(28));
        let driver = driver(resolver, FakeGateway::example());
        let status = resolve(&driver, batch()).await.expect_err("too slow");
        assert_eq!(status.code(), Code::DeadlineExceeded);
    }

    fn with_grpc_timeout(
        request: ResolveCredentialsRequest,
        header: &str,
    ) -> Request<ResolveCredentialsRequest> {
        let mut request = Request::new(request);
        request
            .metadata_mut()
            .insert("grpc-timeout", header.parse().expect("ascii header value"));
        request
    }

    #[test]
    fn grpc_timeout_parsing_follows_the_spec() {
        assert_eq!(parse_grpc_timeout("30S"), Some(Duration::from_secs(30)));
        assert_eq!(
            parse_grpc_timeout("9900m"),
            Some(Duration::from_millis(9_900))
        );
        assert_eq!(parse_grpc_timeout("1M"), Some(Duration::from_secs(60)));
        assert_eq!(parse_grpc_timeout("2H"), Some(Duration::from_secs(7_200)));
        assert_eq!(parse_grpc_timeout("5000000u"), Some(Duration::from_secs(5)));
        assert_eq!(
            parse_grpc_timeout("99999999n"),
            Some(Duration::from_nanos(99_999_999))
        );
        for bad in [
            "",
            "S",
            "30",
            "30s",
            "123456789S",
            "-1S",
            "1.5S",
            "30 S",
            "３S",
        ] {
            assert_eq!(parse_grpc_timeout(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_budget_is_the_shorter_of_the_driver_deadline_and_the_callers_minus_margin() {
        let mut metadata = tonic::metadata::MetadataMap::new();
        assert_eq!(call_budget(DRIVER_DEADLINE, &metadata), DRIVER_DEADLINE);
        metadata.insert("grpc-timeout", "30S".parse().expect("ascii header value"));
        assert_eq!(call_budget(DRIVER_DEADLINE, &metadata), DRIVER_DEADLINE);
        metadata.insert("grpc-timeout", "10S".parse().expect("ascii header value"));
        assert_eq!(
            call_budget(DRIVER_DEADLINE, &metadata),
            Duration::from_secs(7)
        );
        metadata.insert("grpc-timeout", "2S".parse().expect("ascii header value"));
        assert_eq!(call_budget(DRIVER_DEADLINE, &metadata), Duration::ZERO);
        metadata.insert(
            "grpc-timeout",
            "garbage".parse().expect("ascii header value"),
        );
        assert_eq!(call_budget(DRIVER_DEADLINE, &metadata), DRIVER_DEADLINE);
        metadata.insert("grpc-timeout", "5M".parse().expect("ascii header value"));
        assert_eq!(call_budget(DRIVER_DEADLINE, &metadata), DRIVER_DEADLINE);
    }

    #[tokio::test]
    async fn a_short_caller_deadline_shrinks_the_offered_deadline() {
        fn check(request: &ResolveRequest) -> Result<DesktopReply, DesktopError> {
            // 10 s caller deadline − 3 s margin − 1 s reply slack, minus a little
            // for the (instant) fake lookups.
            let offered = request.openshell.deadline_ms;
            assert!((5_900..=6_000).contains(&offered), "offered {offered}");
            approve(Lifetime::SandboxLifetime)
        }
        let resolver = MockResolver::new(check);
        let calls = Arc::clone(&resolver.calls);
        let driver = driver(resolver, FakeGateway::example());
        driver
            .resolve_credentials(with_grpc_timeout(batch(), "10S"))
            .await
            .expect("approved");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_short_deadline_above_the_floor_is_still_sent() {
        fn check(request: &ResolveRequest) -> Result<DesktopReply, DesktopError> {
            let offered = request.openshell.deadline_ms;
            assert!(
                (MIN_DEADLINE_MS..=2_500).contains(&offered),
                "offered {offered}"
            );
            approve(Lifetime::SandboxLifetime)
        }
        let resolver = MockResolver::new(check);
        let calls = Arc::clone(&resolver.calls);
        let driver = driver(resolver, FakeGateway::example());
        // 6.5 s − 3 s margin − 1 s slack ≈ 2.5 s: short, but above the 2 s floor.
        driver
            .resolve_credentials(with_grpc_timeout(batch(), "6500m"))
            .await
            .expect("approved");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_deadline_below_the_floor_never_contacts_desktop() {
        let driver = driver(MockResolver::panicking(), FakeGateway::example());
        // 5.5 s − 3 s − 1 s = 1.5 s < 2 s floor.
        let status = driver
            .resolve_credentials(with_grpc_timeout(batch(), "5500m"))
            .await
            .expect_err("below the floor");
        assert_eq!(status.code(), Code::DeadlineExceeded);
    }

    #[tokio::test(start_paused = true)]
    async fn the_whole_call_is_bounded_by_the_callers_shorter_deadline() {
        let mut resolver = MockResolver::new(|_| approve(Lifetime::SandboxLifetime));
        resolver.delay = Some(Duration::from_secs(20));
        let driver = driver(resolver, FakeGateway::example());
        let started = Instant::now();
        let status = driver
            .resolve_credentials(with_grpc_timeout(batch(), "12S"))
            .await
            .expect_err("bounded at 9 s");
        assert_eq!(status.code(), Code::DeadlineExceeded);
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_secs(9) && waited < Duration::from_millis(9_100),
            "waited {waited:?}"
        );
    }

    #[tokio::test]
    async fn bad_handle_fails_the_whole_batch_without_desktop() {
        let driver = driver(MockResolver::panicking(), FakeGateway::example());
        let mut request = batch();
        request.credentials[1].handle = Some(CredentialHandle {
            driver: "bitwarden".into(),
            handle: "bw1:item:nope:password".into(),
            metadata: Default::default(),
        });
        let status = resolve(&driver, request).await.expect_err("bad");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), BAD_HANDLE);
    }

    #[tokio::test]
    async fn mixed_providers_fail_without_desktop() {
        let driver = driver(MockResolver::panicking(), FakeGateway::example());
        let mut request = batch();
        request.credentials[1].provider_id = "prov-other".into();
        let status = resolve(&driver, request).await.expect_err("mixed");
        assert_eq!(status.code(), Code::FailedPrecondition);
        assert_eq!(status.message(), ctx_messages::ATTRIBUTION);
    }

    #[tokio::test]
    async fn attribution_failure_never_contacts_desktop() {
        let mut gateway = FakeGateway::example();
        gateway.attachments.clear();
        let driver = driver(MockResolver::panicking(), gateway);
        let status = resolve(&driver, batch()).await.expect_err("unattributed");
        assert_eq!(status.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn unsupported_gateway_auth_never_contacts_desktop() {
        let driver: BitwardenDriver<MockResolver, FakeGateway> = BitwardenDriver::new(
            MockResolver::panicking(),
            Err(GatewayConfigError::UnsupportedAuth),
        );
        let status = resolve(&driver, batch()).await.expect_err("auth");
        assert_eq!(status.code(), Code::FailedPrecondition);
        assert!(status.message().contains("unsupported gateway auth mode"));
    }

    #[tokio::test]
    async fn store_credential_encodes_without_contacting_desktop() {
        let driver = driver(MockResolver::panicking(), FakeGateway::example());
        let response = driver
            .store_credential(Request::new(StoreCredentialRequest {
                value: format!("bw://item/{ITEM}#username"),
                ..Default::default()
            }))
            .await
            .expect("stored")
            .into_inner();
        let stored = response.handle.expect("handle");
        assert_eq!(stored.driver, "bitwarden");
        assert_eq!(stored.handle, format!("bw1:item:{ITEM}:username"));
        assert_eq!(
            stored.metadata.get("kind").map(String::as_str),
            Some("item")
        );
        assert_eq!(
            stored.metadata.get("field").map(String::as_str),
            Some("username")
        );
        let FakeGateway { calls, .. } = driver.gateway.expect("gateway").info;
        assert!(
            calls.lock().expect("lock").is_empty(),
            "store made a lookup"
        );
    }

    #[tokio::test]
    async fn store_credential_rejects_plain_values_without_echo() {
        let driver = driver(MockResolver::panicking(), FakeGateway::example());
        for value in ["ghp_realtokenvalue123", "", "bw://item/x#totp"] {
            let status = driver
                .store_credential(Request::new(StoreCredentialRequest {
                    value: value.into(),
                    ..Default::default()
                }))
                .await
                .expect_err("rejected");
            assert_eq!(status.code(), Code::InvalidArgument);
            assert_eq!(status.message(), STORE_REJECTED);
        }
    }

    #[tokio::test]
    async fn capabilities_advertise_expiry_support() {
        let driver = driver(MockResolver::panicking(), FakeGateway::example());
        let gateway = PeerMetadata {
            protocol_version: Some(ProtocolVersion { major: 1, minor: 0 }),
            implementation_name: "openshell/gateway".into(),
            implementation_version: "0.1.2".into(),
            supported_capabilities: vec![CONTRACT_CAPABILITY.into()],
            required_capabilities: vec![CONTRACT_CAPABILITY.into()],
        };
        let caps = driver
            .get_capabilities(Request::new(GetCredentialDriverCapabilitiesRequest {
                gateway: Some(gateway.clone()),
            }))
            .await
            .expect("caps")
            .into_inner();
        assert_eq!(caps.driver_name, "bitwarden");
        assert_eq!(caps.backend_kind, "bitwarden-desktop");
        assert!(caps.supports_expires_at);
        assert!(!caps.supports_list);
        let extension = caps.extension.expect("extension");
        assert_eq!(extension.implementation_name, "bitwarden-aac");
        assert_eq!(extension.protocol_version.map(|v| v.major), Some(1));

        let mut wrong_major = gateway.clone();
        wrong_major.protocol_version = Some(ProtocolVersion { major: 2, minor: 0 });
        let mut extra_requirement = gateway;
        extra_requirement
            .required_capabilities
            .push("openshell.credentials.something-new".into());
        for bad in [Some(wrong_major), Some(extra_requirement), None] {
            assert!(
                driver
                    .get_capabilities(Request::new(GetCredentialDriverCapabilitiesRequest {
                        gateway: bad,
                    }))
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn list_is_unimplemented_and_delete_is_noop() {
        let driver = driver(MockResolver::panicking(), FakeGateway::example());
        let status = driver
            .list_credentials(Request::new(ListCredentialsRequest {}))
            .await
            .expect_err("unimplemented");
        assert_eq!(status.code(), Code::Unimplemented);
        driver
            .delete_credential(Request::new(DeleteCredentialRequest::default()))
            .await
            .expect("noop");
    }

    #[tokio::test]
    async fn empty_batch_is_ok_without_desktop() {
        let driver = driver(MockResolver::panicking(), FakeGateway::example());
        let response = resolve(&driver, ResolveCredentialsRequest::default())
            .await
            .expect("empty");
        assert!(response.credentials.is_empty());
    }
}
