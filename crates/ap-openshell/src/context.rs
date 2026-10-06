//! Sandbox attribution and endpoint context (architecture §M8.5).
//!
//! `ResolveCredentialsRequest` carries no sandbox id, so aac derives it from
//! the gateway's read-only API and fails closed unless exactly one sandbox has
//! the provider attached. Every lookup is bounded at 3 s; any lookup error,
//! auth error or timeout fails closed the same way. aac makes no write RPC:
//! the vendored service subset does not even declare one.

use std::collections::HashSet;
use std::future::Future;
use std::time::Duration;

use tonic::Status;
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint as TonicEndpoint, Identity,
};

use crate::digest::policy_digest;
use crate::gateway_config::{GatewayAuth, GatewayConfig, GatewayConfigError};
use crate::proto::openshell::datamodel::v1::{Provider, WorkspaceSelector, workspace_selector};
use crate::proto::openshell::v1::open_shell_client::OpenShellClient;
use crate::proto::openshell::v1::{
    GetProviderProfileRequest, GetProviderRequest, GetSandboxPolicyStatusRequest,
    GetSandboxPolicyStatusResponse, ListSandboxProvidersRequest, ListSandboxProvidersResponse,
    ListSandboxesRequest, ListSandboxesResponse, NetworkEndpoint, ProviderProfile, Sandbox,
};
use crate::wire::{
    Endpoint, EndpointSource, GatewayRef, MAX_ENDPOINTS, PolicyRef, ProviderRef, SandboxRef,
    is_valid_endpoint_host, is_valid_object_id,
};

/// Per-lookup bound.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);
/// Pagination guard for list RPCs (pages per listing).
const MAX_PAGES: usize = 20;
/// Sandboxes beyond this are not scanned: attribution fails closed.
const MAX_SANDBOXES: usize = 1_000;
const DEFAULT_WORKSPACE: &str = "default";

/// Fixed, value-free status messages.
pub mod messages {
    pub const ATTRIBUTION: &str = "bitwarden: provider must be attached to exactly one sandbox";
    pub const NO_ENDPOINTS: &str = "bitwarden: openshell credential has no bound endpoints";
    pub const UNSUPPORTED_SHAPE: &str =
        "bitwarden: the gateway reported an endpoint or identity Bitwarden does not support";
    pub const HANDLE_MISMATCH: &str =
        "bitwarden: credential handles do not match the provider's stored handles";
}

/// The five read-only gateway lookups the driver needs.
pub trait GatewayInfo: Send + Sync + 'static {
    fn get_provider(
        &self,
        workspace: &str,
        name: &str,
    ) -> impl Future<Output = Result<Provider, Status>> + Send;

    fn list_sandboxes(
        &self,
        workspace: &str,
        page_token: &str,
    ) -> impl Future<Output = Result<ListSandboxesResponse, Status>> + Send;

    fn list_sandbox_providers(
        &self,
        workspace: &str,
        sandbox: &str,
        page_token: &str,
    ) -> impl Future<Output = Result<ListSandboxProvidersResponse, Status>> + Send;

    /// `profile_workspace` empty selects the platform scope.
    fn get_provider_profile(
        &self,
        profile_workspace: &str,
        id: &str,
    ) -> impl Future<Output = Result<ProviderProfile, Status>> + Send;

    fn get_sandbox_policy_status(
        &self,
        workspace: &str,
        sandbox: &str,
    ) -> impl Future<Output = Result<GetSandboxPolicyStatusResponse, Status>> + Send;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ContextError {
    /// 0 or ≥ 2 sandboxes, mixed providers, provider id mismatch.
    #[error("{}", messages::ATTRIBUTION)]
    Attribution,
    /// Lookup error, auth error or 3 s timeout.
    #[error("{}", messages::ATTRIBUTION)]
    Lookup,
    #[error("{}", messages::NO_ENDPOINTS)]
    NoEndpoints,
    /// Endpoint or identifier the desktop could not display honestly
    /// (IPv6 literal, `**` glob, empty host, port 0, > 64 entries, ...).
    #[error("{}", messages::UNSUPPORTED_SHAPE)]
    UnsupportedShape,
    /// A request's `(credential_key, handle)` is not what the gateway stores
    /// for this provider (defence in depth against a forged batch).
    #[error("{}", messages::HANDLE_MISMATCH)]
    HandleMismatch,
    #[error("{0}")]
    Gateway(GatewayConfigError),
}

impl ContextError {
    pub fn to_status(self) -> Status {
        Status::failed_precondition(self.to_string())
    }
}

/// Identity of one `ResolveCredentials` batch (all items share it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderBatch {
    pub provider_name: String,
    pub provider_id: String,
    pub workspace: String,
    /// `(credential_key, handle)` for every request in the batch. Handles are
    /// `bw1:` UUID references, never values.
    pub handles: Vec<(String, String)>,
}

/// Driver name the gateway records on handles this driver issued.
pub const DRIVER_NAME: &str = "bitwarden";

/// Defence in depth: when the gateway reports the provider's stored
/// credential handles, every requested `(credential_key, handle)` must be one
/// of them, owned by this driver. Whether `GetProvider` returns
/// `credential_handles` to API clients is unverified (§M8.15 U13); when the
/// map is empty the driver-socket peer check is the control.
fn handles_match(provider: &Provider, batch: &ProviderBatch) -> bool {
    if provider.credential_handles.is_empty() {
        return true;
    }
    batch.handles.iter().all(|(key, handle)| {
        provider
            .credential_handles
            .get(key)
            .is_some_and(|stored| stored.driver == DRIVER_NAME && stored.handle == *handle)
    })
}

/// Everything the desktop shows, minus the targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenShellContext {
    pub gateway: GatewayRef,
    pub provider: ProviderRef,
    pub sandbox: SandboxRef,
    pub endpoints: Vec<Endpoint>,
    pub policy: PolicyRef,
}

async fn lookup<T>(future: impl Future<Output = Result<T, Status>>) -> Result<T, ContextError> {
    match tokio::time::timeout(LOOKUP_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) | Err(_) => Err(ContextError::Lookup),
    }
}

fn bounded(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len()) && !value.chars().any(char::is_control)
}

/// Normalise one gateway endpoint into wire endpoints (one per port).
fn expand_endpoint(
    endpoint: &NetworkEndpoint,
    source: EndpointSource,
) -> Result<Vec<Endpoint>, ContextError> {
    let host = endpoint.host.to_ascii_lowercase();
    if !is_valid_endpoint_host(&host) {
        return Err(ContextError::UnsupportedShape);
    }
    let path = if endpoint.path.is_empty() {
        None
    } else if bounded(&endpoint.path, 1, 512) {
        Some(endpoint.path.clone())
    } else {
        return Err(ContextError::UnsupportedShape);
    };
    // Upstream: `ports` takes precedence over `port` when non-empty.
    let raw_ports: Vec<u32> = if endpoint.ports.is_empty() {
        vec![endpoint.port]
    } else {
        endpoint.ports.clone()
    };
    if raw_ports.len() > MAX_ENDPOINTS {
        return Err(ContextError::UnsupportedShape);
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for raw in raw_ports {
        let port = u16::try_from(raw)
            .ok()
            .filter(|p| *p != 0)
            .ok_or(ContextError::UnsupportedShape)?;
        if seen.insert(port) {
            out.push(Endpoint {
                host: host.clone(),
                port,
                path: path.clone(),
                source,
            });
        }
    }
    Ok(out)
}

/// Union of profile and policy-binding endpoints, deduplicated by
/// `(host, port, path)` with `profile` winning ties. Fails closed when empty,
/// over 64, or any entry has an unsupported shape.
pub fn merge_endpoints(
    profile: &[NetworkEndpoint],
    bound: &[NetworkEndpoint],
) -> Result<(Vec<Endpoint>, bool), ContextError> {
    let mut seen: HashSet<(String, u16, Option<String>)> = HashSet::new();
    let mut out = Vec::new();
    let mut advisor = false;
    for (endpoints, source) in [
        (profile, EndpointSource::Profile),
        (bound, EndpointSource::PolicyBinding),
    ] {
        let mut batch = Vec::new();
        for endpoint in endpoints {
            advisor |= endpoint.advisor_proposed;
            batch.extend(expand_endpoint(endpoint, source)?);
        }
        if source == EndpointSource::PolicyBinding {
            // Map iteration order upstream is unspecified: sort for stable output.
            batch.sort_by(|a, b| (&a.host, a.port, &a.path).cmp(&(&b.host, b.port, &b.path)));
        }
        for endpoint in batch {
            if seen.insert((endpoint.host.clone(), endpoint.port, endpoint.path.clone())) {
                out.push(endpoint);
            }
            if out.len() > MAX_ENDPOINTS {
                return Err(ContextError::UnsupportedShape);
            }
        }
    }
    if out.is_empty() {
        return Err(ContextError::NoEndpoints);
    }
    Ok((out, advisor))
}

fn object_id(provider: &Provider) -> Option<&str> {
    provider.metadata.as_ref().map(|m| m.id.as_str())
}

async fn sandbox_has_provider<G: GatewayInfo>(
    info: &G,
    workspace: &str,
    sandbox: &str,
    provider_id: &str,
) -> Result<bool, ContextError> {
    let mut page_token = String::new();
    for _ in 0..MAX_PAGES {
        let page = lookup(info.list_sandbox_providers(workspace, sandbox, &page_token)).await?;
        if page
            .providers
            .iter()
            .any(|p| object_id(p) == Some(provider_id))
        {
            return Ok(true);
        }
        if page.next_page_token.is_empty() {
            return Ok(false);
        }
        page_token = page.next_page_token;
    }
    // Too many pages to be sure: fail closed.
    Err(ContextError::Attribution)
}

/// Find the one sandbox that has `provider_id` attached.
async fn attributed_sandbox<G: GatewayInfo>(
    info: &G,
    workspace: &str,
    provider_id: &str,
) -> Result<Sandbox, ContextError> {
    let mut found: Option<Sandbox> = None;
    let mut scanned = 0usize;
    let mut page_token = String::new();
    for _ in 0..MAX_PAGES {
        let page = lookup(info.list_sandboxes(workspace, &page_token)).await?;
        for sandbox in page.sandboxes {
            scanned += 1;
            if scanned > MAX_SANDBOXES {
                return Err(ContextError::Attribution);
            }
            let name = sandbox
                .metadata
                .as_ref()
                .map(|m| m.name.clone())
                .unwrap_or_default();
            if name.is_empty() {
                return Err(ContextError::Attribution);
            }
            if sandbox_has_provider(info, workspace, &name, provider_id).await? {
                if found.is_some() {
                    return Err(ContextError::Attribution);
                }
                found = Some(sandbox);
            }
        }
        if page.next_page_token.is_empty() {
            return found.ok_or(ContextError::Attribution);
        }
        page_token = page.next_page_token;
    }
    Err(ContextError::Attribution)
}

/// Build the gateway-reported context for one batch, or fail closed.
pub async fn build_context<G: GatewayInfo>(
    info: &G,
    gateway: &GatewayRef,
    batch: &ProviderBatch,
) -> Result<OpenShellContext, ContextError> {
    if !is_valid_object_id(&batch.provider_id) || batch.provider_name.is_empty() {
        return Err(ContextError::Attribution);
    }
    let workspace = if batch.workspace.is_empty() {
        DEFAULT_WORKSPACE
    } else {
        batch.workspace.as_str()
    };

    let provider = lookup(info.get_provider(workspace, &batch.provider_name)).await?;
    if object_id(&provider) != Some(batch.provider_id.as_str()) {
        return Err(ContextError::Attribution);
    }
    if !handles_match(&provider, batch) {
        return Err(ContextError::HandleMismatch);
    }

    let sandbox = attributed_sandbox(info, workspace, &batch.provider_id).await?;
    let (sandbox_id, sandbox_name) = sandbox
        .metadata
        .as_ref()
        .map(|m| (m.id.clone(), m.name.clone()))
        .unwrap_or_default();

    let profile_endpoints = if provider.r#type.is_empty() {
        Vec::new()
    } else {
        lookup(info.get_provider_profile(&provider.profile_workspace, &provider.r#type))
            .await?
            .endpoints
    };

    let status = lookup(info.get_sandbox_policy_status(workspace, &sandbox_name)).await?;
    let bound_endpoints: Vec<NetworkEndpoint> = status
        .revision
        .and_then(|revision| revision.policy)
        .map(|policy| {
            policy
                .network_policies
                .into_values()
                .flat_map(|rule| rule.endpoints)
                .filter(|endpoint| {
                    endpoint
                        .credential_binding
                        .as_ref()
                        .is_some_and(|binding| binding.provider == batch.provider_name)
                })
                .collect()
        })
        .unwrap_or_default();

    let (endpoints, advisor_seen) = merge_endpoints(&profile_endpoints, &bound_endpoints)?;

    let image = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .map(|template| template.image.clone())
        .filter(|image| !image.is_empty());

    let context = OpenShellContext {
        gateway: gateway.clone(),
        provider: ProviderRef {
            id: batch.provider_id.clone(),
            name: batch.provider_name.clone(),
            profile: provider.r#type.clone(),
            workspace: batch.workspace.clone(),
        },
        sandbox: SandboxRef {
            id: sandbox_id,
            name: sandbox_name,
            image,
        },
        policy: PolicyRef {
            digest: policy_digest(&endpoints),
            // Only ever claim `true` from evidence; unknown stays absent and
            // the desktop shows it as if enabled.
            advisor_enabled: advisor_seen.then_some(true),
        },
        endpoints,
    };

    let identity_ok = is_valid_object_id(&context.sandbox.id)
        && bounded(&context.provider.name, 1, 128)
        && bounded(&context.provider.profile, 0, 128)
        && bounded(&context.provider.workspace, 0, 128)
        && bounded(&context.sandbox.name, 0, 128)
        && context
            .sandbox
            .image
            .as_deref()
            .is_none_or(|image| bounded(image, 0, 512));
    if !identity_ok {
        return Err(ContextError::UnsupportedShape);
    }
    Ok(context)
}

// ---------------------------------------------------------------------------
// tonic implementation
// ---------------------------------------------------------------------------

fn named(workspace: &str) -> Option<WorkspaceSelector> {
    Some(WorkspaceSelector {
        selection: Some(workspace_selector::Selection::Workspace(
            workspace.to_string(),
        )),
    })
}

/// Read-only gateway client over mTLS, or plaintext to loopback.
#[derive(Clone)]
pub struct TonicGatewayInfo {
    client: OpenShellClient<Channel>,
}

impl TonicGatewayInfo {
    /// Build a lazily connecting client; nothing is dialled until the first
    /// lookup.
    pub fn connect_lazy(config: &GatewayConfig) -> Result<Self, GatewayConfigError> {
        let mut endpoint = TonicEndpoint::from_shared(config.endpoint.clone())
            .map_err(|_| GatewayConfigError::MetadataInvalid)?
            .connect_timeout(LOOKUP_TIMEOUT)
            .timeout(LOOKUP_TIMEOUT);
        if let GatewayAuth::Mtls(material) = &config.auth {
            let tls = ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(&material.ca_pem))
                .identity(Identity::from_pem(
                    &material.cert_pem,
                    material.key_pem.as_slice(),
                ))
                .domain_name(config.host.clone());
            endpoint = endpoint
                .tls_config(tls)
                .map_err(|_| GatewayConfigError::MtlsMaterialUnreadable)?;
        }
        Ok(Self {
            client: OpenShellClient::new(endpoint.connect_lazy()),
        })
    }
}

impl GatewayInfo for TonicGatewayInfo {
    async fn get_provider(&self, workspace: &str, name: &str) -> Result<Provider, Status> {
        let response = self
            .client
            .clone()
            .get_provider(GetProviderRequest {
                workspace_scope: named(workspace),
                name: name.to_string(),
            })
            .await?
            .into_inner();
        response
            .provider
            .ok_or_else(|| Status::not_found("provider missing"))
    }

    async fn list_sandboxes(
        &self,
        workspace: &str,
        page_token: &str,
    ) -> Result<ListSandboxesResponse, Status> {
        Ok(self
            .client
            .clone()
            .list_sandboxes(ListSandboxesRequest {
                workspace_scope: named(workspace),
                page_size: 1000,
                page_token: page_token.to_string(),
                label_selector: String::new(),
            })
            .await?
            .into_inner())
    }

    async fn list_sandbox_providers(
        &self,
        workspace: &str,
        sandbox: &str,
        page_token: &str,
    ) -> Result<ListSandboxProvidersResponse, Status> {
        Ok(self
            .client
            .clone()
            .list_sandbox_providers(ListSandboxProvidersRequest {
                workspace_scope: named(workspace),
                sandbox: sandbox.to_string(),
                page_size: 1000,
                page_token: page_token.to_string(),
            })
            .await?
            .into_inner())
    }

    async fn get_provider_profile(
        &self,
        profile_workspace: &str,
        id: &str,
    ) -> Result<ProviderProfile, Status> {
        let response = self
            .client
            .clone()
            .get_provider_profile(GetProviderProfileRequest {
                workspace_scope: if profile_workspace.is_empty() {
                    None
                } else {
                    named(profile_workspace)
                },
                id: id.to_string(),
            })
            .await?
            .into_inner();
        response
            .profile
            .ok_or_else(|| Status::not_found("profile missing"))
    }

    async fn get_sandbox_policy_status(
        &self,
        workspace: &str,
        sandbox: &str,
    ) -> Result<GetSandboxPolicyStatusResponse, Status> {
        Ok(self
            .client
            .clone()
            .get_sandbox_policy_status(GetSandboxPolicyStatusRequest {
                workspace_scope: named(workspace),
                version: 0,
                global: false,
                sandbox: sandbox.to_string(),
            })
            .await?
            .into_inner())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;
    use crate::proto::openshell::datamodel::v1::{CredentialHandle, ObjectMeta};
    use crate::proto::openshell::v1::{
        NetworkCredentialBinding, NetworkPolicyRule, SandboxPolicy, SandboxPolicyRevision,
        SandboxSpec, SandboxTemplate,
    };

    pub(crate) fn endpoint(host: &str, port: u32, path: &str) -> NetworkEndpoint {
        NetworkEndpoint {
            host: host.into(),
            port,
            path: path.into(),
            ..Default::default()
        }
    }

    pub(crate) fn provider(id: &str, name: &str, profile: &str) -> Provider {
        Provider {
            metadata: Some(ObjectMeta {
                id: id.into(),
                name: name.into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            r#type: profile.into(),
            ..Default::default()
        }
    }

    pub(crate) fn sandbox(id: &str, name: &str, image: &str) -> Sandbox {
        Sandbox {
            metadata: Some(ObjectMeta {
                id: id.into(),
                name: name.into(),
                ..Default::default()
            }),
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    image: image.into(),
                }),
                providers: Vec::new(),
            }),
        }
    }

    /// In-memory gateway. `fail` makes every lookup error; `delay` sleeps.
    #[derive(Default)]
    pub(crate) struct FakeGateway {
        pub providers: HashMap<String, Provider>,
        pub sandboxes: Vec<Sandbox>,
        /// sandbox name -> attached providers
        pub attachments: HashMap<String, Vec<Provider>>,
        pub profiles: HashMap<String, ProviderProfile>,
        /// sandbox name -> policy rules
        pub policies: HashMap<String, Vec<NetworkPolicyRule>>,
        pub fail: bool,
        pub delay: Option<Duration>,
        pub calls: Mutex<Vec<String>>,
    }

    impl FakeGateway {
        /// The §M8.4 example: one sandbox `agent-1` with provider
        /// `gh-agent-1` (`prov-7f3a`, profile `github`).
        pub(crate) fn example() -> Self {
            let mut gateway = Self::default();
            let gh = provider("prov-7f3a", "gh-agent-1", "github");
            gateway.providers.insert("gh-agent-1".into(), gh.clone());
            gateway.sandboxes.push(sandbox(
                "sbx-01J9Z6",
                "agent-1",
                "ghcr.io/example/agent:1.2",
            ));
            gateway.sandboxes.push(sandbox("sbx-other", "other", ""));
            gateway.attachments.insert("agent-1".into(), vec![gh]);
            gateway.profiles.insert(
                "github".into(),
                ProviderProfile {
                    id: "github".into(),
                    endpoints: vec![endpoint("api.github.com", 443, "/**")],
                },
            );
            gateway
        }

        async fn gate(&self, call: &str) -> Result<(), Status> {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(call.to_string());
            }
            if let Some(delay) = self.delay {
                tokio::time::sleep(delay).await;
            }
            if self.fail {
                Err(Status::unauthenticated("nope"))
            } else {
                Ok(())
            }
        }
    }

    impl GatewayInfo for FakeGateway {
        async fn get_provider(&self, _workspace: &str, name: &str) -> Result<Provider, Status> {
            self.gate("GetProvider").await?;
            self.providers
                .get(name)
                .cloned()
                .ok_or_else(|| Status::not_found("x"))
        }

        async fn list_sandboxes(
            &self,
            _workspace: &str,
            _page_token: &str,
        ) -> Result<ListSandboxesResponse, Status> {
            self.gate("ListSandboxes").await?;
            Ok(ListSandboxesResponse {
                sandboxes: self.sandboxes.clone(),
                next_page_token: String::new(),
            })
        }

        async fn list_sandbox_providers(
            &self,
            _workspace: &str,
            sandbox: &str,
            _page_token: &str,
        ) -> Result<ListSandboxProvidersResponse, Status> {
            self.gate("ListSandboxProviders").await?;
            Ok(ListSandboxProvidersResponse {
                providers: self.attachments.get(sandbox).cloned().unwrap_or_default(),
                next_page_token: String::new(),
            })
        }

        async fn get_provider_profile(
            &self,
            _profile_workspace: &str,
            id: &str,
        ) -> Result<ProviderProfile, Status> {
            self.gate("GetProviderProfile").await?;
            self.profiles
                .get(id)
                .cloned()
                .ok_or_else(|| Status::not_found("x"))
        }

        async fn get_sandbox_policy_status(
            &self,
            _workspace: &str,
            sandbox: &str,
        ) -> Result<GetSandboxPolicyStatusResponse, Status> {
            self.gate("GetSandboxPolicyStatus").await?;
            let rules = self.policies.get(sandbox).cloned().unwrap_or_default();
            Ok(GetSandboxPolicyStatusResponse {
                revision: Some(SandboxPolicyRevision {
                    version: 1,
                    policy_hash: String::new(),
                    policy: Some(SandboxPolicy {
                        version: 1,
                        network_policies: rules
                            .into_iter()
                            .enumerate()
                            .map(|(i, rule)| (format!("rule{i}"), rule))
                            .collect(),
                    }),
                }),
                active_version: 1,
            })
        }
    }

    pub(crate) fn gateway_ref() -> GatewayRef {
        GatewayRef {
            name: "openshell".into(),
            endpoint: "https://127.0.0.1:17670".into(),
        }
    }

    pub(crate) fn batch() -> ProviderBatch {
        ProviderBatch {
            provider_name: "gh-agent-1".into(),
            provider_id: "prov-7f3a".into(),
            workspace: "default".into(),
            handles: vec![(
                "GITHUB_TOKEN".into(),
                "bw1:item:3f1c2b9e-8a4d-4c7e-9b21-5d6f7a8b9c0d:password".into(),
            )],
        }
    }

    fn stored_handle(driver: &str, handle: &str) -> CredentialHandle {
        CredentialHandle {
            driver: driver.into(),
            handle: handle.into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn stored_handles_must_match_the_batch() {
        let good = "bw1:item:3f1c2b9e-8a4d-4c7e-9b21-5d6f7a8b9c0d:password";
        let cases = [
            (vec![("GITHUB_TOKEN", "bitwarden", good)], true),
            (
                vec![
                    ("GITHUB_TOKEN", "bitwarden", good),
                    ("OTHER", "bitwarden", good),
                ],
                true,
            ),
            (
                vec![(
                    "GITHUB_TOKEN",
                    "bitwarden",
                    "bw1:item:00000000-0000-4000-8000-000000000000:password",
                )],
                false,
            ),
            (vec![("GITHUB_TOKEN", "other-driver", good)], false),
            (vec![("ANOTHER_KEY", "bitwarden", good)], false),
        ];
        for (stored, ok) in cases {
            let mut gateway = FakeGateway::example();
            let provider = gateway.providers.get_mut("gh-agent-1").expect("provider");
            provider.credential_handles = stored
                .iter()
                .map(|(k, d, h)| ((*k).to_string(), stored_handle(d, h)))
                .collect();
            let result = build_context(&gateway, &gateway_ref(), &batch()).await;
            if ok {
                assert!(result.is_ok(), "{stored:?}");
            } else {
                assert_eq!(result, Err(ContextError::HandleMismatch), "{stored:?}");
            }
        }
    }

    fn bound_rule(host: &str, provider: &str) -> NetworkPolicyRule {
        NetworkPolicyRule {
            name: "r".into(),
            endpoints: vec![NetworkEndpoint {
                credential_binding: Some(NetworkCredentialBinding {
                    provider: provider.into(),
                }),
                ..endpoint(host, 443, "")
            }],
        }
    }

    #[tokio::test]
    async fn exactly_one_sandbox_builds_the_example_context() {
        let context = build_context(&FakeGateway::example(), &gateway_ref(), &batch())
            .await
            .expect("context");
        assert_eq!(context.sandbox.id, "sbx-01J9Z6");
        assert_eq!(context.sandbox.name, "agent-1");
        assert_eq!(
            context.sandbox.image.as_deref(),
            Some("ghcr.io/example/agent:1.2")
        );
        assert_eq!(context.provider.profile, "github");
        assert_eq!(context.endpoints.len(), 1);
        assert_eq!(
            context.policy.digest,
            "sha256:998f40a71463c9250c9eaf7bcb560234fc838a2bf7592b260165f9b4af110020"
        );
        assert_eq!(context.policy.advisor_enabled, None);
    }

    #[tokio::test]
    async fn zero_attached_sandboxes_fail() {
        let mut gateway = FakeGateway::example();
        gateway.attachments.clear();
        assert_eq!(
            build_context(&gateway, &gateway_ref(), &batch()).await,
            Err(ContextError::Attribution)
        );
    }

    #[tokio::test]
    async fn two_attached_sandboxes_fail() {
        let mut gateway = FakeGateway::example();
        let gh = gateway.providers["gh-agent-1"].clone();
        gateway.attachments.insert("other".into(), vec![gh]);
        assert_eq!(
            build_context(&gateway, &gateway_ref(), &batch()).await,
            Err(ContextError::Attribution)
        );
    }

    #[tokio::test]
    async fn provider_id_mismatch_fails() {
        let mut gateway = FakeGateway::example();
        gateway.providers.insert(
            "gh-agent-1".into(),
            provider("prov-other", "gh-agent-1", "github"),
        );
        assert_eq!(
            build_context(&gateway, &gateway_ref(), &batch()).await,
            Err(ContextError::Attribution)
        );
    }

    #[tokio::test]
    async fn empty_endpoint_set_fails() {
        let mut gateway = FakeGateway::example();
        gateway.profiles.clear();
        gateway
            .providers
            .insert("gh-agent-1".into(), provider("prov-7f3a", "gh-agent-1", ""));
        assert_eq!(
            build_context(&gateway, &gateway_ref(), &batch()).await,
            Err(ContextError::NoEndpoints)
        );
    }

    #[tokio::test]
    async fn lookup_error_fails_closed() {
        let mut gateway = FakeGateway::example();
        gateway.fail = true;
        assert_eq!(
            build_context(&gateway, &gateway_ref(), &batch()).await,
            Err(ContextError::Lookup)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn lookup_timeout_fails_closed() {
        let mut gateway = FakeGateway::example();
        gateway.delay = Some(Duration::from_secs(4));
        assert_eq!(
            build_context(&gateway, &gateway_ref(), &batch()).await,
            Err(ContextError::Lookup)
        );
    }

    #[tokio::test]
    async fn policy_bindings_are_merged_with_profile_winning() {
        let mut gateway = FakeGateway::example();
        gateway.policies.insert(
            "agent-1".into(),
            vec![
                bound_rule("uploads.github.com", "gh-agent-1"),
                // Bound to someone else: ignored.
                bound_rule("evil.example.com", "other-provider"),
                // Same (host, port, path) as the profile entry: profile wins.
                NetworkPolicyRule {
                    name: "dup".into(),
                    endpoints: vec![NetworkEndpoint {
                        credential_binding: Some(NetworkCredentialBinding {
                            provider: "gh-agent-1".into(),
                        }),
                        ..endpoint("API.GITHUB.COM", 443, "/**")
                    }],
                },
            ],
        );
        let context = build_context(&gateway, &gateway_ref(), &batch())
            .await
            .expect("context");
        assert_eq!(context.endpoints.len(), 2);
        assert_eq!(context.endpoints[0].source, EndpointSource::Profile);
        assert_eq!(context.endpoints[1].host, "uploads.github.com");
        assert_eq!(context.endpoints[1].source, EndpointSource::PolicyBinding);
        assert_eq!(
            context.policy.digest,
            "sha256:f098164656d916d933b9ad3ea24ce0c43cc84aa04300528a4e2e6ec2844e582d"
        );
    }

    #[test]
    fn unsupported_endpoint_shapes_fail_closed() {
        for bad in [
            endpoint("::1", 443, ""),
            endpoint("[::1]", 443, ""),
            endpoint("**.github.com", 443, ""),
            endpoint("", 443, ""),
            endpoint("a.com", 0, ""),
            endpoint("a.com", 70_000, ""),
            endpoint("a.com", 443, "/\u{1}"),
        ] {
            assert_eq!(
                merge_endpoints(std::slice::from_ref(&bad), &[]),
                Err(ContextError::UnsupportedShape),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn multi_port_endpoints_expand_up_to_64() {
        let mut multi = endpoint("a.com", 0, "");
        multi.ports = vec![443, 8443, 443];
        let (merged, _) = merge_endpoints(&[multi], &[]).expect("expands");
        assert_eq!(
            merged.iter().map(|e| e.port).collect::<Vec<_>>(),
            [443, 8443]
        );
        let mut huge = endpoint("a.com", 0, "");
        huge.ports = (1..=65).collect();
        assert_eq!(
            merge_endpoints(&[huge], &[]),
            Err(ContextError::UnsupportedShape)
        );
    }

    #[test]
    fn advisor_proposed_endpoint_sets_the_flag() {
        let mut proposed = endpoint("a.com", 443, "");
        proposed.advisor_proposed = true;
        let (_, advisor) = merge_endpoints(&[proposed], &[]).expect("ok");
        assert!(advisor);
    }
}
