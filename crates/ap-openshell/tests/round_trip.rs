//! End-to-end seam test: an in-process tonic `CredentialDriver` client talks
//! to the real driver over a Unix socket; the driver talks to a fake desktop
//! over the real local-protocol client. Both wire lines are byte-checked
//! against the §M8.11 golden fixtures.

#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ap_openshell::driver::{BitwardenDriver, GatewayTarget};
use ap_openshell::handle::parse_reference;
use ap_openshell::proto::openshell::credentials::v1::credential_driver_client::CredentialDriverClient;
use ap_openshell::proto::openshell::credentials::v1::credential_driver_server::CredentialDriverServer;
use ap_openshell::proto::openshell::credentials::v1::{
    ResolveCredentialRequest, ResolveCredentialsRequest, StoreCredentialRequest,
};
use ap_openshell::proto::openshell::datamodel::v1::{ObjectMeta, Provider};
use ap_openshell::proto::openshell::v1::{
    GetSandboxPolicyStatusResponse, ListSandboxProvidersResponse, ListSandboxesResponse,
    NetworkEndpoint, ProviderProfile, Sandbox, SandboxSpec, SandboxTemplate,
};
use ap_openshell::wire::{self, ClientInfo, GatewayRef, HelloRequest};
use ap_openshell::{GatewayInfo, UdsDesktopResolver, bind_driver_socket, parent_only_incoming};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tonic::transport::{Channel, Endpoint, Server, Uri};
use tonic::{Code, Status};

const REQUEST_FIXTURE: &str = include_str!("fixtures/openshell-resolve.request.json");
const HELLO_FIXTURE: &str = include_str!("fixtures/openshell-hello.request.json");
const APPROVED_TTL: &str = include_str!("fixtures/openshell-resolve.approved-ttl.json");
const DENIED: &str = include_str!("fixtures/openshell-resolve.denied.json");
const PINNED_NOW: u64 = 1_791_230_967_890;
const ITEM: &str = "3f1c2b9e-8a4d-4c7e-9b21-5d6f7a8b9c0d";
const SECRET: &str = "a7e2d4c1-6b3f-4e8a-9d10-2c5b6a7f8e9d";

/// The §M8.4 example gateway: one sandbox with provider `gh-agent-1`.
struct ExampleGateway;

fn meta(id: &str, name: &str) -> Option<ObjectMeta> {
    Some(ObjectMeta {
        id: id.into(),
        name: name.into(),
        workspace: "default".into(),
        ..Default::default()
    })
}

fn gh_provider() -> Provider {
    Provider {
        metadata: meta("prov-7f3a", "gh-agent-1"),
        r#type: "github".into(),
        ..Default::default()
    }
}

impl GatewayInfo for ExampleGateway {
    async fn get_provider(&self, _workspace: &str, name: &str) -> Result<Provider, Status> {
        if name == "gh-agent-1" {
            Ok(gh_provider())
        } else {
            Err(Status::not_found("no"))
        }
    }

    async fn list_sandboxes(
        &self,
        _workspace: &str,
        _page_token: &str,
    ) -> Result<ListSandboxesResponse, Status> {
        Ok(ListSandboxesResponse {
            sandboxes: vec![Sandbox {
                metadata: meta("sbx-01J9Z6", "agent-1"),
                spec: Some(SandboxSpec {
                    template: Some(SandboxTemplate {
                        image: "ghcr.io/example/agent:1.2".into(),
                    }),
                    providers: vec!["gh-agent-1".into()],
                }),
            }],
            next_page_token: String::new(),
        })
    }

    async fn list_sandbox_providers(
        &self,
        _workspace: &str,
        sandbox: &str,
        _page_token: &str,
    ) -> Result<ListSandboxProvidersResponse, Status> {
        Ok(ListSandboxProvidersResponse {
            providers: if sandbox == "agent-1" {
                vec![gh_provider()]
            } else {
                Vec::new()
            },
            next_page_token: String::new(),
        })
    }

    async fn get_provider_profile(
        &self,
        _profile_workspace: &str,
        _id: &str,
    ) -> Result<ProviderProfile, Status> {
        Ok(ProviderProfile {
            id: "github".into(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".into(),
                port: 443,
                path: "/**".into(),
                ..Default::default()
            }],
        })
    }

    async fn get_sandbox_policy_status(
        &self,
        _workspace: &str,
        _sandbox: &str,
    ) -> Result<GetSandboxPolicyStatusResponse, Status> {
        Ok(GetSandboxPolicyStatusResponse::default())
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        // Short path: macOS caps sun_path at 104 bytes.
        let dir = std::env::temp_dir().join(format!("aos-rt-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Fake desktop: accepts one connection, returns the received line, replies
/// with `reply`.
fn fake_desktop(path: &Path, reply: &'static str) -> tokio::task::JoinHandle<String> {
    let listener = UnixListener::bind(path).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        // The real desktop binds its socket 0600; aac refuses anything else.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut line = String::new();
        BufReader::new(read).read_line(&mut line).await.unwrap();
        write.write_all(reply.as_bytes()).await.unwrap();
        write.flush().await.unwrap();
        line
    })
}

async fn start_driver(
    dir: &Path,
    desktop: PathBuf,
) -> (CredentialDriverClient<Channel>, tokio::task::JoinHandle<()>) {
    // The in-process client stands in for the spawning gateway.
    start_driver_for_peer(dir, desktop, i32::try_from(std::process::id()).unwrap()).await
}

async fn start_driver_for_peer(
    dir: &Path,
    desktop: PathBuf,
    expected_peer: i32,
) -> (CredentialDriverClient<Channel>, tokio::task::JoinHandle<()>) {
    let driver_socket = dir.join("driver.sock");
    let listener = bind_driver_socket(&driver_socket).unwrap();
    let driver = BitwardenDriver::new(
        UdsDesktopResolver {
            socket_path: desktop,
        },
        Ok(GatewayTarget {
            gateway: GatewayRef {
                name: "openshell".into(),
                endpoint: "https://127.0.0.1:17670".into(),
            },
            info: ExampleGateway,
        }),
    )
    .with_clock(Arc::new(|| PINNED_NOW))
    .with_client_version("0.0.0-fixture");

    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(CredentialDriverServer::new(driver))
            .serve_with_incoming(parent_only_incoming(listener, expected_peer))
            .await
            .unwrap();
    });

    let path = driver_socket.clone();
    let channel = Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector_lazy(tower::service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }));
    (CredentialDriverClient::new(channel), server)
}

async fn store(
    client: &mut CredentialDriverClient<Channel>,
    key: &str,
    reference: &str,
) -> Provider {
    // Mimic the gateway: StoreCredential returns the handle it persists.
    let handle = client
        .store_credential(StoreCredentialRequest {
            provider: "gh-agent-1".into(),
            credential_key: key.into(),
            value: reference.into(),
            workspace: "default".into(),
            provider_id: "prov-7f3a".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .handle
        .unwrap();
    assert_eq!(
        handle,
        parse_reference(reference).unwrap().to_credential_handle()
    );
    let mut provider = gh_provider();
    provider.credential_handles.insert(key.into(), handle);
    provider
}

fn resolve_request(handles: &HashMap<String, Provider>) -> ResolveCredentialsRequest {
    let mut credentials = Vec::new();
    for (index, key) in ["GITHUB_TOKEN", "DB_PASSWORD"].iter().enumerate() {
        credentials.push(ResolveCredentialRequest {
            request_id: format!("credential-{index}"),
            provider: "gh-agent-1".into(),
            credential_key: (*key).into(),
            handle: handles[*key].credential_handles.get(*key).cloned(),
            workspace: "default".into(),
            provider_id: "prov-7f3a".into(),
        });
    }
    ResolveCredentialsRequest { credentials }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_round_trip_with_ttl_approval() {
    let tmp = TempDir::new("ttl");
    let desktop_path = tmp.0.join("desktop.sock");
    let desktop = fake_desktop(&desktop_path, APPROVED_TTL);
    let (mut client, server) = start_driver(&tmp.0, desktop_path).await;

    let mut handles = HashMap::new();
    handles.insert(
        "GITHUB_TOKEN".to_string(),
        store(
            &mut client,
            "GITHUB_TOKEN",
            &format!("bw://item/{ITEM}#password"),
        )
        .await,
    );
    handles.insert(
        "DB_PASSWORD".to_string(),
        store(&mut client, "DB_PASSWORD", &format!("bw://secret/{SECRET}")).await,
    );

    let response = client
        .resolve_credentials(resolve_request(&handles))
        .await
        .unwrap()
        .into_inner();

    // Byte-level seam check: what reached the desktop is the golden request,
    // except that the driver never claims advisorEnabled:false (it omits the
    // key when unknown, which desktop shows as "may be on").
    let sent = desktop.await.unwrap();
    assert_eq!(
        sent,
        REQUEST_FIXTURE.replace(r#","advisorEnabled":false"#, "")
    );

    let by_id: HashMap<_, _> = response
        .credentials
        .iter()
        .map(|c| (c.request_id.clone(), c.clone()))
        .collect();
    assert_eq!(by_id.len(), 2);
    assert_eq!(by_id["credential-0"].value, "fixture-password");
    assert_eq!(by_id["credential-1"].value, "fixture-secret");
    for credential in by_id.values() {
        let ts = credential.expiration_time.unwrap();
        assert_eq!(
            u64::try_from(ts.seconds).unwrap() * 1000
                + u64::try_from(ts.nanos).unwrap() / 1_000_000,
            1_791_234_567_890
        );
    }
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_round_trip_with_denial() {
    let tmp = TempDir::new("deny");
    let desktop_path = tmp.0.join("desktop.sock");
    let desktop = fake_desktop(&desktop_path, DENIED);
    let (mut client, server) = start_driver(&tmp.0, desktop_path).await;
    let mut handles = HashMap::new();
    handles.insert(
        "GITHUB_TOKEN".to_string(),
        store(
            &mut client,
            "GITHUB_TOKEN",
            &format!("bw://item/{ITEM}#password"),
        )
        .await,
    );
    handles.insert(
        "DB_PASSWORD".to_string(),
        store(&mut client, "DB_PASSWORD", &format!("bw://secret/{SECRET}")).await,
    );
    let status = client
        .resolve_credentials(resolve_request(&handles))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied);
    desktop.await.unwrap();
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn desktop_off_is_failed_precondition() {
    let tmp = TempDir::new("off");
    let (mut client, server) = start_driver(&tmp.0, tmp.0.join("absent.sock")).await;
    let mut handles = HashMap::new();
    handles.insert(
        "GITHUB_TOKEN".to_string(),
        store(
            &mut client,
            "GITHUB_TOKEN",
            &format!("bw://item/{ITEM}#password"),
        )
        .await,
    );
    handles.insert(
        "DB_PASSWORD".to_string(),
        store(&mut client, "DB_PASSWORD", &format!("bw://secret/{SECRET}")).await,
    );
    let status = client
        .resolve_credentials(resolve_request(&handles))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(
        status.message(),
        "Bitwarden desktop is not running or the OpenShell integration is off"
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_process_other_than_the_gateway_is_never_served() {
    let tmp = TempDir::new("peer");
    let desktop_path = tmp.0.join("desktop.sock");
    // If the driver ever reached the desktop, this fake would approve.
    let _desktop = fake_desktop(&desktop_path, APPROVED_TTL);
    let not_me = i32::try_from(std::process::id()).unwrap() + 1;
    let (mut client, server) = start_driver_for_peer(&tmp.0, desktop_path, not_me).await;
    let status = client
        .store_credential(StoreCredentialRequest {
            value: format!("bw://item/{ITEM}#password"),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_ne!(status.code(), Code::Ok);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_rejects_plain_value_over_grpc() {
    let tmp = TempDir::new("store");
    let (mut client, server) = start_driver(&tmp.0, tmp.0.join("absent.sock")).await;
    let status = client
        .store_credential(StoreCredentialRequest {
            value: "ghp_plaintext_token_value".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(
        status.message(),
        "Bitwarden driver accepts only bw:// references"
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hello_line_is_byte_equal_to_fixture() {
    let tmp = TempDir::new("hello");
    let desktop_path = tmp.0.join("desktop.sock");
    let desktop = fake_desktop(&desktop_path, "{\"version\":1,\"status\":\"approved\"}\n");
    let hello = HelloRequest::new(
        GatewayRef {
            name: "openshell".into(),
            endpoint: "https://127.0.0.1:17670".into(),
        },
        ClientInfo::driver("0.0.0-fixture"),
    );
    tokio::time::timeout(
        Duration::from_secs(5),
        wire::send_hello(&desktop_path, &hello),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(desktop.await.unwrap(), HELLO_FIXTURE);
}
