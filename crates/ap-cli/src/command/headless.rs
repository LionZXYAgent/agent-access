//! Headless `aac listen` (no TUI) with Telegram approvals.
//!
//! Runs the user-client side as a plain daemon: suitable for systemd, OpenRC,
//! containers, or any environment without a TTY. Status is written to stderr
//! via `tracing`; approvals go exclusively through Telegram.

use std::path::{Path, PathBuf};

use ap_client::{
    ConnectionStore, CredentialRequestReply, DefaultRelayClient, FingerprintVerificationReply,
    IdentityProvider, PskStore, UserClient, UserClientHandle, UserClientNotification,
    UserClientRequest,
};
use color_eyre::eyre::{Result, WrapErr, bail};
use tracing::{debug, info, warn};

use super::listen::PairingMode;
use crate::providers::{CredentialProvider, LookupResult, ProviderStatus};
use crate::storage::{FileConnectionCache, FileIdentityStorage, FilePskStore};
use crate::telegram::message::{ApprovalPrompt, DeviceLabel};
use crate::telegram::{CredentialGate, TelegramApprover};

/// Options for the headless listener.
pub(super) struct HeadlessOptions {
    pub relay_url: String,
    pub pairing_mode: PairingMode,
    pub connection_name: Option<String>,
    pub token_file: Option<PathBuf>,
}

/// Name used for the user-client identity / connection cache (shared with the TUI).
const STORAGE_NAME: &str = "user_client";

/// Write the pairing token to a file with owner-only permissions, or print it.
fn publish_token(kind: &str, token: &str, token_file: Option<&Path>) -> Result<()> {
    match token_file {
        Some(path) => {
            write_private_file(path, token)
                .wrap_err_with(|| format!("Failed to write token file {}", path.display()))?;
            info!("{kind} written to {}", path.display());
        }
        None => {
            // Printed (not logged) so it doesn't end up in structured log sinks by accident.
            println!("{kind}: {token}");
        }
    }
    Ok(())
}

#[cfg(unix)]
fn write_private_file(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    // Tighten pre-existing files too.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(contents.as_bytes())?;
    file.write_all(b"\n")
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, format!("{contents}\n"))
}

/// Resolves on Ctrl-C or SIGTERM.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn log_notification(notification: &UserClientNotification) {
    match notification {
        UserClientNotification::Listening {} => info!("Listening for requests"),
        UserClientNotification::HandshakeComplete {} => info!("Handshake complete"),
        UserClientNotification::FingerprintVerified {} => info!("New connection accepted"),
        UserClientNotification::FingerprintRejected { reason } => {
            warn!("Connection rejected: {reason}")
        }
        UserClientNotification::CredentialApproved {
            domain,
            credential_id,
        } => info!("Credential sent (domain {domain:?}, item {credential_id:?})"),
        UserClientNotification::CredentialDenied {
            domain,
            credential_id,
        } => info!("Credential denied (domain {domain:?}, item {credential_id:?})"),
        UserClientNotification::SessionRefreshed { fingerprint } => {
            info!("Known device reconnected: {}", fingerprint.to_hex())
        }
        UserClientNotification::ClientDisconnected {} => warn!("Disconnected from relay"),
        UserClientNotification::Reconnecting { attempt } => {
            warn!("Reconnecting to relay (attempt {attempt})")
        }
        UserClientNotification::Reconnected {} => info!("Reconnected to relay"),
        UserClientNotification::Error { message, context } => {
            warn!(
                "Error{}: {message}",
                context
                    .as_deref()
                    .map(|c| format!(" in {c}"))
                    .unwrap_or_default()
            )
        }
        other => debug!("{other:?}"),
    }
}

/// Look up the friendly connection name for a device (reloaded from disk, since
/// the client may have just stored a new connection).
async fn device_label(identity: ap_client::IdentityFingerprint) -> DeviceLabel {
    let name = match FileConnectionCache::load_or_create(STORAGE_NAME) {
        Ok(cache) => cache
            .list()
            .await
            .into_iter()
            .find(|c| c.fingerprint == identity)
            .and_then(|c| c.name),
        Err(_) => None,
    };
    DeviceLabel { name, identity }
}

fn deny() -> CredentialRequestReply {
    CredentialRequestReply {
        approved: false,
        credential: None,
        credential_id: None,
    }
}

/// Handle one request from the user client. Approval waits happen in spawned
/// tasks so several requests can be pending in Telegram at once.
async fn handle_request(
    request: UserClientRequest,
    provider: &dyn CredentialProvider,
    telegram: &TelegramApprover,
    connection_name: &Option<String>,
) {
    match request {
        UserClientRequest::VerifyFingerprint {
            fingerprint,
            identity,
            reply,
        } => {
            info!(
                "Pairing request from {} — asking via Telegram",
                identity.to_hex()
            );
            let prompt = ApprovalPrompt::Pairing {
                device: DeviceLabel {
                    name: connection_name.clone(),
                    identity,
                },
                handshake_fingerprint: fingerprint,
            };
            match telegram.request(&prompt, None).await {
                Ok(pending) => {
                    let name = connection_name.clone();
                    tokio::spawn(async move {
                        let approved = pending.decision.await.is_ok_and(|d| d.is_allowed());
                        let _ = reply.send(FingerprintVerificationReply { approved, name });
                    });
                }
                Err(e) => {
                    warn!("Could not send pairing prompt to Telegram ({e}); rejecting");
                    let _ = reply.send(FingerprintVerificationReply {
                        approved: false,
                        name: None,
                    });
                }
            }
        }
        UserClientRequest::CredentialRequest {
            query,
            identity,
            request_id,
            timestamp,
            reply,
        } => {
            let device = device_label(identity).await;
            info!(
                "Credential request {request_id} from {} for {query}",
                device.render()
            );
            match provider.lookup(&query) {
                LookupResult::Found(credential) => {
                    match telegram
                        .gate_credential(device, &query, &credential, &request_id, timestamp)
                        .await
                    {
                        Ok(CredentialGate::AutoApproved(grant)) => {
                            info!(
                                "Request {request_id} auto-approved under Telegram grant ({})",
                                grant.duration.label()
                            );
                            let credential_id = credential.credential_id.clone();
                            let _ = reply.send(CredentialRequestReply {
                                approved: true,
                                credential: Some(credential),
                                credential_id,
                            });
                        }
                        Ok(CredentialGate::Pending(pending)) => {
                            tokio::spawn(async move {
                                let decision = pending.decision.await;
                                let approved = decision.as_ref().is_ok_and(|d| d.is_allowed());
                                info!(
                                    "Request {request_id}: {}",
                                    match decision {
                                        Ok(d) => format!("{d:?}"),
                                        Err(_) => "cancelled".to_string(),
                                    }
                                );
                                let credential_id = credential.credential_id.clone();
                                let _ = reply.send(if approved {
                                    CredentialRequestReply {
                                        approved: true,
                                        credential: Some(credential),
                                        credential_id,
                                    }
                                } else {
                                    CredentialRequestReply {
                                        approved: false,
                                        credential: None,
                                        credential_id,
                                    }
                                });
                            });
                        }
                        Err(e) => {
                            warn!(
                                "Could not send approval prompt to Telegram ({e}); denying {request_id}"
                            );
                            let _ = reply.send(deny());
                        }
                    }
                }
                other => {
                    let reason = match other {
                        LookupResult::NotReady { message } => message,
                        _ => "no matching credential in the vault".to_string(),
                    };
                    // No decision needed, so nothing goes to Telegram; logged locally only.
                    warn!(
                        "Denied request {request_id} from {} for {query} without prompting: {reason}",
                        device.render()
                    );
                    let _ = reply.send(deny());
                }
            }
        }
    }
}

/// Run the headless listener until Ctrl-C / SIGTERM or relay failure.
pub(super) async fn run(
    opts: HeadlessOptions,
    provider: &mut dyn CredentialProvider,
    telegram: TelegramApprover,
) -> Result<()> {
    match provider.status() {
        ProviderStatus::Ready { user_info } => info!(
            "{} ready{}",
            provider.name(),
            user_info.map(|u| format!(" ({u})")).unwrap_or_default()
        ),
        ProviderStatus::Locked { .. } => warn!(
            "{} vault is locked — requests will be denied. Provide an unlocked session (e.g. BW_SESSION)",
            provider.name()
        ),
        ProviderStatus::Unavailable { reason } => warn!("{}: {reason}", provider.name()),
        ProviderStatus::NotInstalled { install_hint } => {
            warn!("{} not found. {install_hint}", provider.name())
        }
    }

    let identity_provider = FileIdentityStorage::load_or_generate(STORAGE_NAME)?;
    let our_fingerprint = identity_provider.fingerprint().await;
    let connection_store = FileConnectionCache::load_or_create(STORAGE_NAME)?;
    let cached = connection_store.list().await;

    let (psk_store, existing_psk_token): (Option<Box<dyn PskStore>>, Option<String>) =
        if matches!(opts.pairing_mode, PairingMode::ReusablePsk) {
            let store = FilePskStore::load_or_create(STORAGE_NAME)?;
            let token = PskStore::list(&store).await.first().map(|entry| {
                ap_client::PskToken::new(entry.psk.clone(), our_fingerprint).to_string()
            });
            (Some(Box::new(store)), token)
        } else {
            (None, None)
        };

    let UserClientHandle {
        client,
        mut notifications,
        mut requests,
    } = UserClient::connect(
        Box::new(identity_provider) as Box<dyn IdentityProvider>,
        Box::new(connection_store) as Box<dyn ConnectionStore>,
        Box::new(DefaultRelayClient::from_url(opts.relay_url.clone())),
        None,
        psk_store,
    )
    .await?;
    info!("Connected to relay {}", opts.relay_url);

    let token_file = opts.token_file.as_deref();
    match opts.pairing_mode {
        PairingMode::ReusablePsk => {
            let token = match existing_psk_token {
                Some(t) => t,
                None => {
                    client
                        .get_psk_token(opts.connection_name.clone(), true)
                        .await?
                }
            };
            publish_token("Reusable PSK token", &token, token_file)?;
        }
        PairingMode::EphemeralPsk if cached.is_empty() => {
            let token = client
                .get_psk_token(opts.connection_name.clone(), false)
                .await?;
            publish_token("PSK token", &token, token_file)?;
        }
        PairingMode::Rendezvous if cached.is_empty() => {
            let code = client
                .get_rendezvous_token(opts.connection_name.clone())
                .await?;
            publish_token(
                "Rendezvous code (valid 5 minutes, approve the pairing in Telegram)",
                code.as_str(),
                token_file,
            )?;
        }
        _ => {}
    }
    if !cached.is_empty() {
        info!(
            "Accepting requests from {} paired connection(s)",
            cached.len()
        );
    }

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("Shutting down");
                break;
            }
            notification = notifications.recv() => match notification {
                Some(n) => log_notification(&n),
                None => bail!("User client stopped (relay connection lost)"),
            },
            request = requests.recv() => match request {
                Some(r) => handle_request(r, &*provider, &telegram, &opts.connection_name).await,
                None => bail!("User client stopped (request channel closed)"),
            },
        }
    }
    drop(client);
    Ok(())
}
