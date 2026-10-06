//! Bitwarden credential driver for NVIDIA OpenShell gateways.
//!
//! `aac openshell-driver` is spawned by `openshell-gateway` (per the
//! `gateway.toml` snippet the desktop shows) and serves the OpenShell
//! `CredentialDriver` gRPC contract on a 0600 Unix socket. Every resolve is
//! forwarded as one `openshellResolve` line to the Bitwarden desktop's
//! OpenShell socket, where a human approves or denies it. See architecture
//! §M8 in the clients repo for the binding contract.
//!
//! Scope: transport and identity context only. No vault or Secrets Manager
//! logic lives here; the desktop resolves items and secrets.

use std::future::Future;
use std::path::PathBuf;

pub mod context;
pub mod digest;
pub mod driver;
pub mod gateway_config;
pub mod handle;
pub mod proto;
pub mod wire;

pub use context::{GatewayInfo, TonicGatewayInfo};
pub use driver::{BitwardenDriver, GatewayTarget};
pub use wire::{DesktopError, DesktopReply, ResolveRequest};

/// Default desktop OpenShell socket file name (in `$HOME`).
pub const DESKTOP_SOCKET_FILE: &str = ".bitwarden-agent-access-openshell.sock";

/// `aac openshell-driver` arguments.
#[derive(Debug, Clone, clap::Args)]
pub struct DriverArgs {
    /// OpenShell gateway name; selects `<config>/gateways/<name>/metadata.json`
    /// for aac's read-only lookups.
    #[arg(long)]
    pub gateway: String,

    /// Driver socket to bind (appended by `openshell-gateway`).
    #[arg(long)]
    pub bind_socket: PathBuf,

    /// Bitwarden desktop OpenShell socket. Defaults to
    /// `~/.bitwarden-agent-access-openshell.sock`.
    #[arg(long, env = "AAC_OPENSHELL_SOCKET")]
    pub desktop_socket: Option<PathBuf>,

    /// OpenShell client config directory. Defaults to
    /// `$XDG_CONFIG_HOME/openshell`, else `~/.config/openshell`.
    #[arg(long)]
    pub openshell_config_dir: Option<PathBuf>,
}

/// Fatal driver start-up errors. None of them carries secret material.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    #[error("openshell-driver is only supported on macOS and Linux")]
    UnsupportedPlatform,
    #[error("invalid gateway name")]
    InvalidGatewayName,
    #[error("HOME is not set; pass --desktop-socket")]
    NoHome,
    #[error("driver socket path has no parent directory")]
    NoSocketParent,
    #[error(
        "driver socket directory must be owned by the current user and not group- or world-writable"
    )]
    UnsafeSocketDirectory,
    #[error("openshell-driver must be started by openshell-gateway (gateway.toml `command`)")]
    NoGatewayParent,
    #[error("refusing to replace a non-socket file at the driver socket path")]
    NotASocket,
    #[error("driver socket I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("driver server failed: {0}")]
    Serve(#[from] tonic::transport::Error),
}

/// The desktop side of a resolve. The production implementation is
/// [`UdsDesktopResolver`]; tests substitute mocks.
pub trait DesktopResolver: Send + Sync + 'static {
    fn resolve(
        &self,
        request: &ResolveRequest,
    ) -> impl Future<Output = Result<DesktopReply, DesktopError>> + Send;
}

/// Talks to the desktop's OpenShell socket: one connection per request.
#[derive(Debug, Clone)]
pub struct UdsDesktopResolver {
    pub socket_path: PathBuf,
}

impl DesktopResolver for UdsDesktopResolver {
    async fn resolve(&self, request: &ResolveRequest) -> Result<DesktopReply, DesktopError> {
        wire::send_resolve(&self.socket_path, request).await
    }
}

/// Default desktop socket: `$HOME/.bitwarden-agent-access-openshell.sock`.
pub fn default_desktop_socket() -> Option<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    home.is_absolute().then(|| home.join(DESKTOP_SOCKET_FILE))
}

/// Check that `dir` is owned by the current uid and not group- or
/// world-writable.
#[cfg(unix)]
pub fn check_socket_directory(dir: &std::path::Path) -> Result<(), DriverError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(dir)?;
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        return Err(DriverError::UnsafeSocketDirectory);
    }
    Ok(())
}

/// Bind the driver socket: vetted parent directory, stale socket unlinked
/// (never a regular file), mode 0600 from the moment it exists.
#[cfg(unix)]
pub fn bind_driver_socket(path: &std::path::Path) -> Result<tokio::net::UnixListener, DriverError> {
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or(DriverError::NoSocketParent)?;
    check_socket_directory(parent)?;

    match std::fs::symlink_metadata(path) {
        Ok(existing) if existing.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => return Err(DriverError::NotASocket),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    // Bind inside a private 0700 staging directory, tighten the socket to
    // 0600, then rename it into place: no other user can reach the socket
    // while its mode is still the umask default. (A process-wide umask
    // change would race with other threads creating files.)
    let file_name = path.file_name().ok_or(DriverError::NoSocketParent)?;
    let staging = parent.join(format!(
        ".{}.staging-{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::DirBuilder::new().mode(0o700).create(&staging)?;
    let staged = staging.join("s");
    let result = (|| {
        let listener = tokio::net::UnixListener::bind(&staged)?;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&staged, path)?;
        Ok::<_, std::io::Error>(listener)
    })();
    let _ = std::fs::remove_dir_all(&staging);
    Ok(result?)
}

/// Whether a driver-socket peer is the process that spawned this driver:
/// same uid and exactly the expected pid. An expected pid of 0 or 1 (no real
/// parent, or reparented to init/launchd) matches nothing.
#[cfg(unix)]
pub fn peer_is_expected(peer_uid: u32, peer_pid: Option<i32>, uid: u32, expected_pid: i32) -> bool {
    expected_pid > 1 && peer_uid == uid && peer_pid == Some(expected_pid)
}

/// Driver-socket connections, filtered to the expected peer (the
/// `openshell-gateway` that spawned aac). Any other same-uid process that
/// connects is dropped before tonic sees the stream, so it can never receive
/// a released value. Accept errors pass through unchanged.
#[cfg(unix)]
pub fn parent_only_incoming(
    listener: tokio::net::UnixListener,
    expected_pid: i32,
) -> impl tokio_stream::Stream<Item = std::io::Result<tokio::net::UnixStream>> {
    use tokio_stream::StreamExt;
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    tokio_stream::wrappers::UnixListenerStream::new(listener).filter(move |conn| match conn {
        Ok(stream) => {
            let allowed = stream
                .peer_cred()
                .is_ok_and(|cred| peer_is_expected(cred.uid(), cred.pid(), uid, expected_pid));
            if !allowed {
                tracing::warn!("openshell driver: refused a connection from an unexpected process");
            }
            allowed
        }
        Err(_) => true,
    })
}

/// Run the driver until the gateway stops it.
#[cfg(unix)]
pub async fn run_driver(args: DriverArgs) -> Result<(), DriverError> {
    use proto::openshell::credentials::v1::credential_driver_server::CredentialDriverServer;

    if !gateway_config::is_safe_gateway_name(&args.gateway) {
        return Err(DriverError::InvalidGatewayName);
    }
    let desktop_socket = match args.desktop_socket.clone() {
        Some(path) => path,
        None => default_desktop_socket().ok_or(DriverError::NoHome)?,
    };

    // Gateway settings problems do not stop the driver: StoreCredential still
    // works, and every resolve fails closed with the reason.
    let gateway = gateway_config::config_dir(args.openshell_config_dir.as_deref())
        .ok_or(gateway_config::GatewayConfigError::NoConfigDir)
        .and_then(|dir| gateway_config::load(&dir, &args.gateway))
        .and_then(|config| {
            let info = TonicGatewayInfo::connect_lazy(&config)?;
            Ok(GatewayTarget {
                gateway: wire::GatewayRef {
                    name: config.name.clone(),
                    endpoint: config.endpoint.clone(),
                },
                info,
            })
        });
    if let Err(err) = &gateway {
        tracing::warn!(error = %err, "openshell driver: gateway lookups unavailable");
    }

    // Only the gateway that spawned aac may call the driver (§M8.5). Captured
    // once at start: if the gateway dies, aac is reparented and the captured
    // pid can no longer connect.
    // SAFETY: getppid has no preconditions and cannot fail.
    let expected_peer = unsafe { libc::getppid() };
    if expected_peer <= 1 {
        return Err(DriverError::NoGatewayParent);
    }

    let listener = bind_driver_socket(&args.bind_socket)?;

    // Value-free liveness ping, once; failures are ignored.
    if let Ok(target) = &gateway {
        let hello = wire::HelloRequest::new(
            target.gateway.clone(),
            wire::ClientInfo::driver(env!("CARGO_PKG_VERSION")),
        );
        let socket = desktop_socket.clone();
        tokio::spawn(async move {
            let _ = wire::send_hello(&socket, &hello).await;
        });
    }

    let driver = BitwardenDriver::new(
        UdsDesktopResolver {
            socket_path: desktop_socket,
        },
        gateway,
    );
    tracing::info!("openshell driver: serving");
    tonic::transport::Server::builder()
        .add_service(CredentialDriverServer::new(driver))
        .serve_with_incoming(parent_only_incoming(listener, expected_peer))
        .await?;
    Ok(())
}

/// Non-Unix platforms are not supported.
#[cfg(not(unix))]
pub async fn run_driver(_args: DriverArgs) -> Result<(), DriverError> {
    Err(DriverError::UnsupportedPlatform)
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("aos-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[tokio::test]
    async fn driver_socket_is_0600_and_replaces_stale_socket() {
        let dir = temp_dir("sock");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let path = dir.join("d.sock");
        let first = bind_driver_socket(&path).expect("binds");
        drop(first);
        // Stale socket file left behind: unlinked and re-bound.
        let listener = bind_driver_socket(&path).expect("rebinds");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // The renamed socket is reachable at its final path, and the staging
        // directory is gone.
        let (client, accepted) =
            tokio::join!(tokio::net::UnixStream::connect(&path), listener.accept());
        client.expect("connects");
        accepted.expect("accepts");
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("readdir")
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .collect();
        assert_eq!(leftovers, [std::ffi::OsString::from("d.sock")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn group_or_world_writable_parent_is_refused() {
        for mode in [0o777, 0o770, 0o722] {
            let dir = temp_dir(&format!("unsafe{mode:o}"));
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).expect("chmod");
            let err = bind_driver_socket(&dir.join("d.sock")).expect_err("refused");
            assert!(
                matches!(err, DriverError::UnsafeSocketDirectory),
                "{mode:o}"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[tokio::test]
    async fn regular_file_at_socket_path_is_not_deleted() {
        let dir = temp_dir("notsock");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let path = dir.join("d.sock");
        std::fs::write(&path, "keep me").expect("write");
        let err = bind_driver_socket(&path).expect_err("refused");
        assert!(matches!(err, DriverError::NotASocket));
        assert_eq!(
            std::fs::read_to_string(&path).expect("still there"),
            "keep me"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_must_be_the_spawning_process() {
        assert!(peer_is_expected(501, Some(4242), 501, 4242));
        // Another same-uid process.
        assert!(!peer_is_expected(501, Some(4243), 501, 4242));
        // Another uid with the right pid.
        assert!(!peer_is_expected(0, Some(4242), 501, 4242));
        // Pid unknown.
        assert!(!peer_is_expected(501, None, 501, 4242));
        // No real parent: nothing matches, not even init.
        assert!(!peer_is_expected(501, Some(1), 501, 1));
        assert!(!peer_is_expected(501, Some(0), 501, 0));
    }

    async fn rpc_reaches_server(expected_pid: i32, tag: &str) -> bool {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_stream::StreamExt;
        let dir = temp_dir(tag);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let path = dir.join("d.sock");
        let listener = bind_driver_socket(&path).expect("binds");
        let mut incoming = Box::pin(parent_only_incoming(listener, expected_pid));
        let server = tokio::spawn(async move {
            if let Some(Ok(mut stream)) = incoming.next().await {
                let _ = stream.write_all(b"ok").await;
            }
        });
        let mut client = tokio::net::UnixStream::connect(&path)
            .await
            .expect("connects");
        let mut buf = Vec::new();
        let read = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            client.read_to_end(&mut buf),
        )
        .await;
        server.abort();
        let _ = std::fs::remove_dir_all(&dir);
        matches!(read, Ok(Ok(_))) && buf == b"ok"
    }

    #[tokio::test]
    async fn only_the_expected_pid_is_served() {
        let me = i32::try_from(std::process::id()).expect("pid");
        assert!(rpc_reaches_server(me, "peerok").await);
        assert!(!rpc_reaches_server(me + 1, "peerbad").await);
    }

    #[tokio::test]
    async fn traversal_gateway_name_is_refused_at_start() {
        let err = run_driver(DriverArgs {
            gateway: "..".into(),
            bind_socket: PathBuf::from("/nonexistent/x.sock"),
            desktop_socket: None,
            openshell_config_dir: None,
        })
        .await
        .expect_err("refused");
        assert!(matches!(err, DriverError::InvalidGatewayName));
    }
}
