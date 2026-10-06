//! Connect command implementation
//!
//! Handles the interactive session for connecting to a relay
//! and requesting credentials over a secure Noise Protocol channel.

use ap_client::{
    ClientError, ConnectionInfo, ConnectionMode, ConnectionStore, DefaultRelayClient,
    IdentityFingerprint, IdentityProvider, Psk, PskToken, RemoteClient,
    RemoteClientFingerprintReply, RemoteClientNotification, RemoteClientRequest,
};
use clap::Args;
use color_eyre::eyre::{Result, bail};
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures_util::StreamExt;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use tokio::sync::{mpsc, oneshot};
use tracing::info;

use super::output::{
    OutputFormat, emit_json_error, emit_json_reference, emit_json_secret_reference,
    emit_json_success, emit_text_credential, emit_text_reference, emit_text_secret_reference,
    exit_code_for_report,
};
use super::tui::{
    App, AppAction, MessageKind, Mode, init_terminal, restore_terminal, wait_for_keypress,
};
use super::util::{format_connect_notification, format_relative_time};
use crate::storage::{FileConnectionCache, FileIdentityStorage};
use crate::transport::local::{
    self, LocalEndpoint, LocalTransportError, ProjectQueryInput, ProjectSecretsOutcome,
    SecretOutcome, SecretQueryInput, WireDelivery, WireOutcome,
};
use ap_client::MemoryConnectionStore;

use super::DEFAULT_RELAY_URL;

/// Arguments for the connect command
#[derive(Args)]
#[command(after_help = "\
AUTOMATION / AGENT / LLM USE:
  For non-interactive (single-shot) credential retrieval:

    1. Request a credential:  aac connect --domain <DOMAIN> --output json

  The token can be passed via --token <TOKEN> or the AAC_TOKEN env var.
  If only one session is cached, it is used automatically.
  With multiple cached sessions, specify one with --session <HEX>.
  --session accepts a full 64-char hex fingerprint or any unique prefix.
  --output json returns structured JSON to stdout (status to stderr).
  Exit codes: 0=success, 1=error, 2=connection failed, 3=auth failed, 4=not found, 5=fingerprint mismatch")]
pub struct ConnectArgs {
    /// Relay server URL
    #[arg(long, default_value = DEFAULT_RELAY_URL)]
    pub relay_url: String,

    /// Token (rendezvous code or PSK token)
    #[arg(long, env = "AAC_TOKEN", conflicts_with = "session")]
    pub token: Option<String>,

    /// Session fingerprint to reconnect to (hex string or unique prefix)
    #[arg(long, conflicts_with = "token")]
    pub session: Option<String>,

    /// Don't save this connection for future use
    #[arg(long)]
    pub ephemeral_connection: bool,

    /// Require fingerprint verification on the connect side
    #[arg(long)]
    pub verify_fingerprint: bool,

    /// Domain to request credentials for (single-shot, non-interactive)
    #[arg(long, conflicts_with_all = ["id", "search", "secret"])]
    pub domain: Option<String>,

    /// Vault item ID to request credentials for (single-shot, non-interactive).
    /// Accepts a bare id or a `bw://item/<id>` reference.
    #[arg(long, conflicts_with_all = ["domain", "search", "secret"])]
    pub id: Option<String>,

    /// Free-text search for credentials (single-shot, non-interactive)
    #[arg(long, conflicts_with_all = ["domain", "id", "secret"])]
    pub search: Option<String>,

    /// Secrets Manager secret name or `bw://secret/<id>` reference
    /// (single-shot, non-interactive). Local transport only — there is no
    /// relay fallback for secrets. Always reference delivery: prints the
    /// `bw://secret/<id>` reference and the secret's name, never the value.
    #[arg(long, conflicts_with_all = ["domain", "id", "search"])]
    pub secret: Option<String>,

    /// Local agent-access endpoint to use instead of the platform default
    /// (unix socket path / windows pipe name). Forces the local transport:
    /// fails rather than falling back to the relay if unreachable.
    #[arg(long, env = "AAC_SOCKET")]
    pub socket: Option<String>,

    /// Timeout in seconds for credential response (default: 120)
    #[arg(long)]
    pub timeout: Option<u64>,

    /// Output format for single-shot mode
    #[arg(long, default_value = "text", value_enum)]
    pub output: OutputFormat,
}

impl ConnectArgs {
    /// Execute the connect command
    pub async fn run(self, log_rx: Option<super::tui_tracing::LogReceiver>) -> Result<()> {
        if let Some(secret) = self.secret {
            return run_single_shot_secret(secret, self.output, self.socket).await;
        }

        let query = match (&self.domain, &self.id, &self.search) {
            (Some(domain), _, _) => Some(ap_client::CredentialQuery::Domain(domain.clone())),
            (_, Some(id), _) => Some(ap_client::CredentialQuery::Id(
                local::strip_reference(id).to_string(),
            )),
            (_, _, Some(search)) => Some(ap_client::CredentialQuery::Search(search.clone())),
            _ => None,
        };

        if let Some(query) = query {
            run_single_shot(
                self.relay_url,
                self.token,
                self.session,
                self.ephemeral_connection,
                query,
                self.output,
                self.timeout,
                self.socket,
            )
            .await
        } else {
            run_interactive_session(
                self.relay_url,
                self.token,
                self.session,
                self.ephemeral_connection,
                self.verify_fingerprint,
                log_rx,
            )
            .await
        }
    }
}

const EPHEMERAL_MSG: &str = "Ephemeral connection (won't be saved)";

/// Token type parsed from user input
enum TokenType {
    Rendezvous(String),
    Psk {
        psk: Psk,
        fingerprint: IdentityFingerprint,
    },
}

/// Current phase of the connect command's interactive loop.
enum Phase {
    /// Choosing between new connection or cached connection.
    ConnectionSelect {
        sorted_connections: Vec<ConnectionInfo>,
    },
    /// Entering a token (rendezvous code or PSK).
    TokenInput,
    /// Handshake/pairing in progress (read-only, no input).
    Connecting,
    /// Fingerprint verification prompt.
    FingerprintConfirm,
    /// Connected — entering domains to request credentials.
    Connected,
}

/// Parse a token (rendezvous code or PSK token)
fn parse_token(token: &str) -> Result<TokenType> {
    if PskToken::looks_like_psk_token(token) {
        let parsed = PskToken::parse(token)
            .map_err(|e| color_eyre::eyre::eyre!("Invalid PSK token: {e}"))?;
        let (psk, fingerprint) = parsed.into_parts();
        Ok(TokenType::Psk { psk, fingerprint })
    } else {
        // Rendezvous code (9 chars)
        validate_rendezvous_code(token)?;
        Ok(TokenType::Rendezvous(token.to_string()))
    }
}

/// Build pick-list labels for session selection.
#[allow(clippy::string_slice)]
fn connection_pick_options(sorted_connections: &[ConnectionInfo]) -> Vec<String> {
    let mut options = vec!["New connection (enter token)".to_string()];
    for session in sorted_connections {
        let short_hex = hex::encode(session.fingerprint.0)
            .chars()
            .take(12)
            .collect::<String>();
        let relative_time = format_relative_time(session.last_connected_at);
        options.push(format!("Session {short_hex}  (last used: {relative_time})"));
    }
    options
}

/// Footer shown during session selection.
fn select_footer() -> Line<'static> {
    Line::from(vec![
        Span::raw(" ↑↓ navigate  "),
        Span::styled("Enter", Style::default().fg(Color::Cyan)),
        Span::raw(" select  "),
        Span::styled("Esc", Style::default().fg(Color::Cyan)),
        Span::raw(" quit"),
    ])
}

/// Footer shown during token input.
fn token_footer() -> Line<'static> {
    Line::from(vec![
        Span::raw(" Enter a rendezvous code or PSK token  "),
        Span::styled("/exit", Style::default().fg(Color::Cyan)),
        Span::raw(" quit  "),
        Span::raw("| PageUp/PageDown to scroll"),
    ])
}

/// Footer shown while connecting.
fn connecting_footer() -> Line<'static> {
    Line::from(vec![Span::styled(
        " Establishing secure connection...",
        Style::default().fg(Color::Yellow),
    )])
}

/// Footer shown during the credential loop.
fn domain_footer() -> Line<'static> {
    Line::from(vec![
        Span::raw(" Enter a domain to request credentials  "),
        Span::styled("/exit", Style::default().fg(Color::Cyan)),
        Span::raw(" quit  "),
        Span::raw("| PageUp/PageDown to scroll"),
    ])
}

/// Spawn a pairing task based on the connection mode.
///
/// Returns a `JoinHandle` that resolves when pairing completes (or fails).
fn spawn_pairing(
    client: &RemoteClient,
    mode: &ConnectionMode,
    verify_fingerprint: bool,
) -> tokio::task::JoinHandle<Result<(), ClientError>> {
    let c = client.clone();
    match mode.clone() {
        ConnectionMode::New { rendezvous_code } => tokio::spawn(async move {
            c.pair_with_handshake(rendezvous_code, verify_fingerprint)
                .await?;
            Ok(())
        }),
        ConnectionMode::NewPsk {
            psk,
            remote_fingerprint,
        } => tokio::spawn(async move {
            c.pair_with_psk(psk, remote_fingerprint).await?;
            Ok(())
        }),
        ConnectionMode::Existing { remote_fingerprint } => tokio::spawn(async move {
            c.load_cached_connection(remote_fingerprint).await?;
            Ok(())
        }),
    }
}

/// Run an interactive session for requesting credentials
async fn run_interactive_session(
    relay_url: String,
    token: Option<String>,
    session_fingerprint: Option<String>,
    ephemeral_connection: bool,
    verify_fingerprint: bool,
    mut log_rx: Option<super::tui_tracing::LogReceiver>,
) -> Result<()> {
    // Create identity provider and session store first
    let identity_provider: Box<dyn IdentityProvider> =
        Box::new(FileIdentityStorage::load_or_generate("remote_client")?);
    let connection_store: Box<dyn ConnectionStore> =
        Box::new(FileConnectionCache::load_or_create("remote_client")?);

    // Get cached connections from connection store
    let mut cached_connections = connection_store.list().await;

    // Determine if we can skip straight to connecting based on CLI flags
    let cli_connection_mode = if session_fingerprint.is_some() || token.is_some() {
        Some(resolve_connection_mode(
            token.as_deref(),
            session_fingerprint.as_deref(),
            &cached_connections,
        )?)
    } else {
        None
    };

    // Initialise the TUI before any user interaction
    let mut app = App::new();
    let mut term = init_terminal();
    let mut reader = EventStream::new();

    // Track deferred resources for interactive connection setup.
    // When CLI flags provide a connection mode these are consumed immediately;
    // otherwise they are consumed when the user picks a session or enters a token.
    let mut deferred_identity: Option<Box<dyn IdentityProvider>> = Some(identity_provider);
    let mut deferred_connection_store: Option<Box<dyn ConnectionStore>> = Some(connection_store);
    let deferred_relay_url = relay_url;

    let mut notification_rx: Option<mpsc::Receiver<RemoteClientNotification>> = None;
    let mut request_rx: Option<mpsc::Receiver<RemoteClientRequest>> = None;
    let mut client: Option<RemoteClient> = None;
    let mut pairing_task: Option<tokio::task::JoinHandle<Result<(), ClientError>>> = None;
    let mut pending_fp_reply: Option<oneshot::Sender<RemoteClientFingerprintReply>> = None;

    // Determine starting phase (and connect immediately for CLI-flag paths)
    let mut phase = if let Some(ref mode) = cli_connection_mode {
        // CLI flags provided — go straight to connecting
        if ephemeral_connection {
            app.push_msg(MessageKind::Info, EPHEMERAL_MSG);
        }
        app.input_title = " Domain ";
        app.footer = connecting_footer();

        match start_connection(
            deferred_identity.take().expect("identity consumed twice"),
            deferred_connection_store
                .take()
                .expect("connection store consumed twice"),
            &deferred_relay_url,
        )
        .await
        {
            Ok((nrx, rrx, c)) => {
                pairing_task = Some(spawn_pairing(&c, mode, verify_fingerprint));
                notification_rx = Some(nrx);
                request_rx = Some(rrx);
                client = Some(c);
            }
            Err(e) => {
                restore_terminal();
                bail!("Connection failed: {e}");
            }
        }

        Phase::Connecting
    } else if !cached_connections.is_empty() && !ephemeral_connection {
        // Cached sessions available — show pick list
        cached_connections.sort_by_key(|c| std::cmp::Reverse(c.last_connected_at));
        let sorted = cached_connections;
        let options = connection_pick_options(&sorted);
        app.set_mode(Mode::Pick {
            title: "Select connection".to_string(),
            options,
            selected: 0,
        });
        app.footer = select_footer();
        Phase::ConnectionSelect {
            sorted_connections: sorted,
        }
    } else {
        // No cached connections — prompt for token
        app.push_msg(
            MessageKind::Prompt,
            "Enter a token (rendezvous code or PSK token):",
        );
        app.input_title = " Token ";
        app.footer = token_footer();
        app.commands = &["/exit"];
        Phase::TokenInput
    };

    loop {
        term.draw(|frame| app.draw(frame))
            .map_err(|e| color_eyre::eyre::eyre!("TUI draw error: {}", e))?;

        // Build the select! dynamically depending on which channels exist
        tokio::select! {
            maybe_event = reader.next() => {
                if let Some(Ok(Event::Key(key))) = maybe_event {
                    if key.kind == KeyEventKind::Press {
                        if let Some(action) = app.handle_key(key) {
                            match (&phase, action) {
                                // ── Session selection (pick list) ──
                                (Phase::ConnectionSelect { .. }, AppAction::Picked(idx)) => {
                                    // Extract sorted_connections before replacing phase
                                    let sorted_connections = match &phase {
                                        Phase::ConnectionSelect { sorted_connections } => sorted_connections.clone(),
                                        _ => unreachable!(),
                                    };

                                    if idx == 0 {
                                        // New connection — prompt for token
                                        app.push_msg(MessageKind::Prompt, "Enter a token (rendezvous code or PSK token):");
                                        app.set_mode(Mode::TextInput);
                                        app.input_title = " Token ";
                                        app.footer = token_footer();
                                        app.commands = &["/exit"];
                                        phase = Phase::TokenInput;
                                    } else {
                                        let session = &sorted_connections[idx - 1];
                                        let mode = ConnectionMode::Existing {
                                            remote_fingerprint: session.fingerprint,
                                        };

                                        // Start connecting
                                        app.set_mode(Mode::TextInput);
                                        app.input_title = " Domain ";
                                        app.footer = connecting_footer();

                                        match start_connection(
                                            deferred_identity.take().expect("identity consumed twice"),
                                            deferred_connection_store.take().expect("connection store consumed twice"),
                                            &deferred_relay_url,
                                        ).await {
                                            Ok((nrx, rrx, c)) => {
                                                pairing_task = Some(spawn_pairing(&c, &mode, verify_fingerprint));
                                                notification_rx = Some(nrx);
                                                request_rx = Some(rrx);
                                                client = Some(c);
                                                app.commands = &[];
                                                phase = Phase::Connecting;
                                            }
                                            Err(e) => {
                                                app.push_msg(MessageKind::Error, format!("Connection failed: {e}"));
                                                app.push_msg(MessageKind::Info, "Press any key to exit");
                                                term.draw(|frame| app.draw(frame)).ok();
                                                wait_for_keypress(&mut reader).await;
                                                break;
                                            }
                                        }
                                    }
                                }

                                // ── Token input ──
                                (Phase::TokenInput, AppAction::Submit(text)) => {
                                    let lower = text.trim().to_lowercase();
                                    if lower == "/exit" {
                                        break;
                                    }

                                    let trimmed = text.trim();
                                    if trimmed.is_empty() {
                                        app.push_msg(MessageKind::Error, "Token is required");
                                        continue;
                                    }

                                    match parse_token(trimmed) {
                                        Ok(token_type) => {
                                            let mode = match token_type {
                                                TokenType::Rendezvous(code) => ConnectionMode::New {
                                                    rendezvous_code: code,
                                                },
                                                TokenType::Psk { psk, fingerprint } => ConnectionMode::NewPsk {
                                                    psk,
                                                    remote_fingerprint: fingerprint,
                                                },
                                            };

                                            app.input_title = " Domain ";
                                            app.footer = connecting_footer();

                                            match start_connection(
                                                deferred_identity.take().expect("identity consumed twice"),
                                                deferred_connection_store.take().expect("connection store consumed twice"),
                                                &deferred_relay_url,
                                            ).await {
                                                Ok((nrx, rrx, c)) => {
                                                    pairing_task = Some(spawn_pairing(&c, &mode, verify_fingerprint));
                                                    notification_rx = Some(nrx);
                                                    request_rx = Some(rrx);
                                                    client = Some(c);
                                                    app.commands = &[];
                                                    phase = Phase::Connecting;
                                                }
                                                Err(e) => {
                                                    app.push_msg(MessageKind::Error, format!("Connection failed: {e}"));
                                                    app.push_msg(MessageKind::Info, "Press any key to exit");
                                                    term.draw(|frame| app.draw(frame)).ok();
                                                    wait_for_keypress(&mut reader).await;
                                                    break;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            app.push_msg(MessageKind::Error, format!("{e}"));
                                        }
                                    }
                                }

                                // ── Connecting (ignore text input) ──
                                (Phase::Connecting, AppAction::Submit(_)) => {
                                    // Ignore — handshake in progress
                                }

                                // ── Fingerprint confirmation ──
                                (Phase::FingerprintConfirm, AppAction::Confirmed(approved)) => {
                                    if let Some(reply) = pending_fp_reply.take() {
                                        let _ = reply.send(RemoteClientFingerprintReply { approved });
                                    }
                                    if approved {
                                        app.push_msg(MessageKind::Success, "Fingerprint approved");
                                    } else {
                                        app.push_msg(MessageKind::Error, "Fingerprint rejected");
                                    }
                                    phase = Phase::Connecting;
                                    app.set_mode(Mode::TextInput);
                                    app.footer = connecting_footer();
                                }

                                // ── Connected — domain requests ──
                                (Phase::Connected, AppAction::Submit(text)) => {
                                    let lower = text.trim().to_lowercase();
                                    if lower == "/exit" {
                                        break;
                                    }
                                    let domain = text.trim().to_string();
                                    if domain.is_empty() {
                                        app.push_msg(MessageKind::Error, "Domain is required");
                                        continue;
                                    }

                                    app.push_msg(MessageKind::User, format!("Requesting: {domain}"));

                                    if let Some(ref c) = client {
                                        let query = ap_client::CredentialQuery::Domain(domain.clone());
                                        let mut cred_fut = std::pin::pin!(c.request_credential(&query, None));
                                        let mut user_cancelled = false;
                                        let cred_result = loop {
                                            term.draw(|frame| app.draw(frame))
                                                .map_err(|e| color_eyre::eyre::eyre!("TUI draw error: {}", e))?;
                                            tokio::select! {
                                                result = &mut cred_fut => {
                                                    break Some(result);
                                                }
                                                maybe_ev = reader.next() => {
                                                    if let Some(Ok(Event::Key(key))) = maybe_ev {
                                                        if key.kind == KeyEventKind::Press {
                                                            if let Some(AppAction::Quit) = app.handle_key(key) {
                                                                user_cancelled = true;
                                                                break None;
                                                            }
                                                        }
                                                    }
                                                }
                                                notification = async {
                                                    match notification_rx.as_mut() {
                                                        Some(rx) => rx.recv().await,
                                                        None => std::future::pending().await,
                                                    }
                                                } => {
                                                    if let Some(notification) = notification {
                                                        if let Some(msg) = format_connect_notification(&notification) {
                                                            app.push_rich(msg);
                                                        }
                                                    }
                                                }
                                            }
                                        };

                                        if user_cancelled {
                                            app.push_msg(MessageKind::Info, "Request cancelled");
                                        }

                                        match cred_result {
                                            Some(Ok(credential)) => {
                                                app.push_msg(MessageKind::Success, format!("Credential received for: {domain}"));
                                                if let Some(username) = &credential.username {
                                                    app.push_msg(MessageKind::Info, format!("  Username: {username}"));
                                                }
                                                if let Some(password) = &credential.password {
                                                    app.push_msg(MessageKind::Info, format!("  Password: {}", password.as_str()));
                                                }
                                                if let Some(totp) = &credential.totp {
                                                    app.push_msg(MessageKind::Info, format!("  TOTP: {totp}"));
                                                }
                                                if let Some(uri) = &credential.uri {
                                                    app.push_msg(MessageKind::Info, format!("  URI: {uri}"));
                                                }
                                                if let Some(id) = &credential.credential_id {
                                                    app.push_msg(MessageKind::Info, format!("  ID: {id}"));
                                                }
                                            }
                                            Some(Err(e)) => {
                                                app.push_msg(MessageKind::Error, format!("Failed to get credential: {e}"));
                                            }
                                            None => {}
                                        }
                                    }
                                }

                                // ── Global quit ──
                                (_, AppAction::Quit) => break,

                                // ── Catch-all ──
                                _ => {}
                            }
                        }
                    }
                }
            }

            // Handle pairing task completion
            result = async {
                match pairing_task.as_mut() {
                    Some(handle) => Some(handle.await),
                    None => std::future::pending::<Option<_>>().await,
                }
            } => {
                pairing_task = None;
                if let Some(result) = result {
                    match result {
                        Ok(Ok(())) => {
                            // Pairing succeeded — Ready notification will arrive via notification_rx
                        }
                        Ok(Err(e)) => {
                            app.push_msg(MessageKind::Error, format!("Connection failed: {e}"));
                            app.push_msg(MessageKind::Info, "Press any key to exit");
                            term.draw(|frame| app.draw(frame)).ok();
                            wait_for_keypress(&mut reader).await;
                            break;
                        }
                        Err(e) => {
                            app.push_msg(MessageKind::Error, format!("Connection task error: {e}"));
                            app.push_msg(MessageKind::Info, "Press any key to exit");
                            term.draw(|frame| app.draw(frame)).ok();
                            wait_for_keypress(&mut reader).await;
                            break;
                        }
                    }
                }
            }

            // Handle fingerprint verification requests
            request = async {
                match request_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(RemoteClientRequest::VerifyFingerprint { fingerprint, reply }) = request {
                    // Show fingerprint message
                    let notification = RemoteClientNotification::HandshakeFingerprint {
                        fingerprint: fingerprint.clone(),
                    };
                    if let Some(msg) = format_connect_notification(&notification) {
                        app.push_rich(msg);
                    }

                    // Store reply and switch to confirmation phase
                    pending_fp_reply = Some(reply);
                    phase = Phase::FingerprintConfirm;
                    app.set_mode(Mode::Confirm {
                        title: "Fingerprint Verification".to_string(),
                        description: Line::from("Do the fingerprints match?"),
                    });
                    app.footer = Line::from(
                        Span::styled(
                            " Compare the fingerprint above with the remote device",
                            Style::default().fg(Color::Yellow),
                        )
                    );
                }
            }

            // Handle remote client notifications
            notification = async {
                match notification_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match notification {
                    Some(notification) => {
                        // Transition to Connected on Ready
                        if matches!(notification, RemoteClientNotification::Ready { .. }) {
                            app.push_msg(MessageKind::Success, "Connection established");
                            if ephemeral_connection {
                                app.push_msg(MessageKind::Info, EPHEMERAL_MSG);
                            } else {
                                app.push_msg(MessageKind::Info, "Connection will be saved (use --ephemeral-connection to disable)");
                            }
                            app.input_title = " Domain ";
                            app.footer = domain_footer();
                            app.commands = &["/exit"];
                            phase = Phase::Connected;
                        }

                        if let Some(msg) = format_connect_notification(&notification) {
                            app.push_rich(msg);
                        }
                    }
                    None => {
                        app.push_msg(MessageKind::Error, "Connection closed by remote");
                        app.push_msg(MessageKind::Info, "Press any key to exit");
                        term.draw(|frame| app.draw(frame))
                            .map_err(|e| color_eyre::eyre::eyre!("TUI draw error: {}", e))?;
                        wait_for_keypress(&mut reader).await;
                        break;
                    }
                }
            }

            // Handle tracing log entries routed into the TUI
            log_entry = async {
                match log_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(entry) = log_entry {
                    super::tui_tracing::push_log_entry(&mut app, entry);
                }
            }
        }
    }

    restore_terminal();

    if let Some(c) = client {
        println!("Closing connection...");
        drop(c);
        println!("Connection closed. Goodbye!");
    }
    Ok(())
}

/// Run a single-shot credential request — no TUI, stdout/stderr only.
///
/// This is the agent/LLM-friendly code path. It never initializes ratatui,
/// prints structured output to stdout, status to stderr, and exits with a
/// well-defined exit code.
/// Connect to the relay, fetch a single credential, and return it.
///
/// Shared by `run_single_shot` and the `run` subcommand. Returns the
/// credential on success, or an error that the caller can format/handle.
pub(super) async fn fetch_credential(
    relay_url: &str,
    token: Option<&str>,
    session_fingerprint: Option<&str>,
    ephemeral_connection: bool,
    query: &ap_client::CredentialQuery,
    credential_timeout: Option<std::time::Duration>,
) -> Result<ap_client::CredentialData> {
    let identity_provider: Box<dyn IdentityProvider> =
        Box::new(FileIdentityStorage::load_or_generate("remote_client")?);

    let connection_store: Box<dyn ConnectionStore> = if ephemeral_connection {
        Box::new(MemoryConnectionStore::new())
    } else {
        Box::new(FileConnectionCache::load_or_create("remote_client")?)
    };

    let cached_connections = connection_store.list().await;
    let mode = resolve_connection_mode(token, session_fingerprint, &cached_connections)?;

    info!("Connecting to relay...");

    let (mut notification_rx, _request_rx, client) =
        start_connection(identity_provider, connection_store, relay_url).await?;

    // Drain notifications in background (prevents channel backpressure)
    tokio::spawn(async move { while notification_rx.recv().await.is_some() {} });

    // Start pairing (inline — single-shot mode never verifies fingerprints)
    match &mode {
        ConnectionMode::New { rendezvous_code } => {
            client
                .pair_with_handshake(rendezvous_code.clone(), false)
                .await
                .map_err(|e| color_eyre::eyre::eyre!("Pairing failed: {}", e))?;
        }
        ConnectionMode::NewPsk {
            psk,
            remote_fingerprint,
        } => {
            client
                .pair_with_psk(psk.clone(), *remote_fingerprint)
                .await
                .map_err(|e| color_eyre::eyre::eyre!("PSK pairing failed: {}", e))?;
        }
        ConnectionMode::Existing { remote_fingerprint } => {
            client
                .load_cached_connection(*remote_fingerprint)
                .await
                .map_err(|e| color_eyre::eyre::eyre!("Connection reconnection failed: {}", e))?;
        }
    }

    info!("Requesting credential for {query}");

    match client.request_credential(query, credential_timeout).await {
        Ok(credential) => {
            drop(client);
            Ok(credential)
        }
        Err(e) => {
            drop(client);
            Err(color_eyre::eyre::eyre!(e))
        }
    }
}

#[allow(clippy::too_many_arguments)]
/// Delivery mode for a dispatched credential request. Only meaningful for
/// the local transport (the relay path is unchanged this phase and always
/// returns a value-bearing credential).
#[derive(Debug, Clone, Copy)]
pub(super) enum Delivery {
    /// `aac run` — values are injected into the child process's env, never printed.
    Inject,
    /// `aac get`-style single-shot — never returns credential values locally.
    Reference,
}

impl From<Delivery> for WireDelivery {
    fn from(delivery: Delivery) -> Self {
        match delivery {
            Delivery::Inject => WireDelivery::Inject,
            Delivery::Reference => WireDelivery::Reference,
        }
    }
}

/// Outcome of a dispatched credential request.
#[derive(Debug)]
pub(super) enum CredentialOutcome {
    /// Value-bearing credential: always for the relay path, and for the
    /// local path when `delivery == Inject`.
    Credential(ap_client::CredentialData),
    /// Local-only, value-free response: an opaque item reference plus a
    /// display name/username. Never produced by the relay path.
    Reference {
        reference: String,
        item_name: Option<String>,
        item_username: Option<String>,
    },
}

/// Which transport a request should use, decided once per invocation.
enum Transport {
    /// Use the local endpoint. `forced` is `true` when the user explicitly
    /// requested it via `--socket`/`AAC_SOCKET`: on failure there, we must
    /// fail hard rather than silently falling back to the relay.
    Local {
        endpoint: LocalEndpoint,
        forced: bool,
    },
    /// Use the relay (unchanged pre-existing path).
    Relay,
}

/// Decide which transport to use for this request.
///
/// `--socket`/`AAC_SOCKET` (passed in as `socket_override`) forces the local
/// transport. Otherwise, the local transport is attempted opportunistically
/// against the platform default endpoint — connect failure there (no
/// listener, socket file missing, ...) is treated as "local unavailable"
/// and falls back to the relay. There is deliberately no separate
/// availability probe: the first (and only) connection attempt for a
/// request *is* the availability check, so a request is never dispatched
/// twice.
fn resolve_transport(socket_override: Option<&str>) -> Transport {
    if let Some(path) = socket_override {
        return Transport::Local {
            endpoint: LocalEndpoint::from_override(path),
            forced: true,
        };
    }
    match LocalEndpoint::default_endpoint() {
        Some(endpoint) => Transport::Local {
            endpoint,
            forced: false,
        },
        None => Transport::Relay,
    }
}

/// Map a local `approved`+`inject` credential into the shared
/// `CredentialData` shape used by the relay path. The local wire protocol
/// never includes `notes` or `domain`; `domain` is backfilled from the
/// query when it was a domain lookup so `--env domain` / `AAC_DOMAIN`
/// behave the same as on the relay path.
fn local_credential_to_data(
    credential: local::WireCredential,
    query: &ap_client::CredentialQuery,
) -> ap_client::CredentialData {
    ap_client::CredentialData {
        username: credential.username,
        password: credential.password,
        totp: credential.totp,
        uri: credential.uri,
        notes: None,
        credential_id: credential.credential_id,
        domain: match query {
            ap_client::CredentialQuery::Domain(d) => Some(d.clone()),
            ap_client::CredentialQuery::Id(_) | ap_client::CredentialQuery::Search(_) => None,
        },
    }
}

/// Dispatch a credential request through the local transport when
/// available/requested, falling back to the relay otherwise. Both `aac
/// [connect] --domain/--id/--search` and `aac run` go through this
/// function.
#[allow(clippy::too_many_arguments)]
pub(super) async fn fetch_credential_dispatch(
    relay_url: &str,
    token: Option<&str>,
    session_fingerprint: Option<&str>,
    ephemeral_connection: bool,
    query: &ap_client::CredentialQuery,
    credential_timeout: Option<std::time::Duration>,
    socket_override: Option<&str>,
    delivery: Delivery,
) -> Result<CredentialOutcome> {
    match resolve_transport(socket_override) {
        Transport::Local { endpoint, forced } => {
            match local::request_credential(&endpoint, query, delivery.into()).await {
                // Defense in depth: a local server that ignores `delivery`
                // and returns a value-bearing credential for a reference
                // request must not have those values printed. Mirrors the
                // guard in `command/mcp.rs`'s `run_find_logins` for the same
                // corner (Credential outcome for a Reference-mode request).
                Ok(WireOutcome::Credential(_)) if matches!(delivery, Delivery::Reference) => {
                    Err(color_eyre::eyre::eyre!(
                        "local agent-access endpoint returned a credential-bearing response for \
                         a reference request; refusing to print it"
                    ))
                }
                Ok(WireOutcome::Credential(credential)) => Ok(CredentialOutcome::Credential(
                    local_credential_to_data(credential, query),
                )),
                Ok(WireOutcome::Reference { reference, item }) => {
                    Ok(CredentialOutcome::Reference {
                        reference,
                        item_name: item.name,
                        item_username: item.username,
                    })
                }
                Err(LocalTransportError::ConnectFailed(reason)) if !forced => {
                    info!(
                        "Local agent-access endpoint unreachable ({reason}); falling back to relay"
                    );
                    let credential = fetch_credential(
                        relay_url,
                        token,
                        session_fingerprint,
                        ephemeral_connection,
                        query,
                        credential_timeout,
                    )
                    .await?;
                    Ok(CredentialOutcome::Credential(credential))
                }
                Err(e) => Err(color_eyre::eyre::eyre!(e)),
            }
        }
        Transport::Relay => {
            let credential = fetch_credential(
                relay_url,
                token,
                session_fingerprint,
                ephemeral_connection,
                query,
                credential_timeout,
            )
            .await?;
            Ok(CredentialOutcome::Credential(credential))
        }
    }
}

/// Outcome of a dispatched Secrets Manager secret request. Mirrors
/// [`CredentialOutcome`], but secrets are local-transport-only (architecture
/// doc, M4: "secrets never ride the relay") — there is no value-bearing
/// variant sourced from the relay.
#[derive(Debug)]
pub(super) enum SecretRequestOutcome {
    /// Value-bearing secret: only ever produced for `Delivery::Inject`.
    Secret(local::WireSecret),
    /// Value-free response: an opaque `bw://secret/<id>` reference plus the
    /// secret's name.
    Reference {
        reference: String,
        item_name: Option<String>,
    },
}

/// Dispatch a Secrets Manager secret request through the local transport.
///
/// Unlike [`fetch_credential_dispatch`], there is **no relay fallback**:
/// secrets are local-transport-only, per the architecture doc's M4 wire
/// protocol section ("Secrets never ride the relay"). If the local endpoint
/// can't be determined or reached, this returns a hard, clear error rather
/// than silently trying the relay — the caller should tell the user to run
/// the Bitwarden desktop app with Agent Access enabled.
pub(super) async fn fetch_secret_dispatch(
    query: &SecretQueryInput,
    socket_override: Option<&str>,
    delivery: Delivery,
) -> Result<SecretRequestOutcome> {
    let endpoint = match resolve_transport(socket_override) {
        Transport::Local { endpoint, .. } => endpoint,
        Transport::Relay => {
            bail!(
                "Could not determine the local Bitwarden agent-access endpoint. Secrets Manager \
                 secrets are only available through the local Bitwarden desktop app — make sure \
                 it is installed, running, unlocked, and Agent Access is enabled. There is no \
                 relay fallback for secrets."
            );
        }
    };

    match local::request_secret(&endpoint, query, delivery.into()).await {
        // Defense in depth: a local server that ignores `delivery:
        // "reference"` and returns a value-bearing secret anyway must not
        // have that value printed. Mirrors the equivalent credential guard
        // above.
        Ok(SecretOutcome::Secret(_)) if matches!(delivery, Delivery::Reference) => {
            Err(color_eyre::eyre::eyre!(
                "local agent-access endpoint returned a value-bearing response for a reference \
                 secret request; refusing to print it"
            ))
        }
        Ok(SecretOutcome::Secret(secret)) => Ok(SecretRequestOutcome::Secret(secret)),
        Ok(SecretOutcome::Reference {
            reference,
            item_name,
        }) => Ok(SecretRequestOutcome::Reference {
            reference,
            item_name,
        }),
        Err(LocalTransportError::ConnectFailed(_)) => Err(color_eyre::eyre::eyre!(
            "Could not reach the Bitwarden desktop app locally. Secrets Manager secrets require \
             the Bitwarden desktop app to be running, unlocked, and Agent Access enabled — there \
             is no relay fallback for secrets."
        )),
        Err(e) => Err(color_eyre::eyre::eyre!(e)),
    }
}

/// Dispatch a `projectSecretsRequest` through the local transport.
///
/// Sibling of [`fetch_secret_dispatch`] — same no-relay-fallback contract
/// (architecture doc, M7: "Never rides the relay"). Unlike
/// [`fetch_secret_dispatch`], there is no `Delivery` parameter: a project
/// secrets release is implicitly inject-only, with no reference form
/// (architecture doc: "there is no reference form — reference-shaped
/// discovery is find_secrets/list_projects"). Backs `aac run --project`
/// only; there is deliberately no single-shot print form for this op.
pub(super) async fn fetch_project_secrets_dispatch(
    query: &ProjectQueryInput,
    socket_override: Option<&str>,
) -> Result<ProjectSecretsOutcome> {
    let endpoint = match resolve_transport(socket_override) {
        Transport::Local { endpoint, .. } => endpoint,
        Transport::Relay => {
            bail!(
                "Could not determine the local Bitwarden agent-access endpoint. Secrets Manager \
                 project secrets are only available through the local Bitwarden desktop app — \
                 make sure it is installed, running, unlocked, and Agent Access is enabled. \
                 There is no relay fallback for secrets."
            );
        }
    };

    local::request_project_secrets(&endpoint, query)
        .await
        .map_err(|e| match e {
            LocalTransportError::ConnectFailed(_) => color_eyre::eyre::eyre!(
                "Could not reach the Bitwarden desktop app locally. Secrets Manager secrets \
                 require the Bitwarden desktop app to be running, unlocked, and Agent Access \
                 enabled — there is no relay fallback for secrets."
            ),
            other => color_eyre::eyre::eyre!(other),
        })
}

/// `aac connect --secret ...` / top-level `aac --secret ...` single-shot
/// path. Always reference delivery: prints the `bw://secret/<id>` reference
/// and the secret's name, never the value.
async fn run_single_shot_secret(
    secret: String,
    output: OutputFormat,
    socket_override: Option<String>,
) -> Result<()> {
    use super::output::{exit_code, exit_code_name};

    let query = local::secret_query_from_flag(&secret);

    match fetch_secret_dispatch(&query, socket_override.as_deref(), Delivery::Reference).await {
        Ok(SecretRequestOutcome::Reference {
            reference,
            item_name,
        }) => {
            match output {
                OutputFormat::Json => emit_json_secret_reference(&reference, item_name.as_deref()),
                OutputFormat::Text => emit_text_secret_reference(&reference, item_name.as_deref()),
            }
            std::process::exit(exit_code::SUCCESS);
        }
        // Unreachable in practice: `fetch_secret_dispatch` already converts
        // a value-bearing reply to a reference request into an `Err` above.
        // Handled explicitly anyway so this match stays exhaustive and safe
        // even if that guard is ever refactored.
        Ok(SecretRequestOutcome::Secret(_)) => {
            let msg = "local agent-access endpoint returned a value-bearing response for a \
                        reference secret request; refusing to print it";
            match output {
                OutputFormat::Json => emit_json_error(msg, "local_transport_error"),
                OutputFormat::Text => tracing::error!("{msg}"),
            }
            std::process::exit(exit_code::LOCAL_TRANSPORT_ERROR);
        }
        Err(e) => {
            let code = exit_code_for_report(&e);
            let msg = format!("{e}");
            match output {
                OutputFormat::Json => emit_json_error(&msg, exit_code_name(code)),
                OutputFormat::Text => tracing::error!("{msg}"),
            }
            std::process::exit(code);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_single_shot(
    relay_url: String,
    token: Option<String>,
    session_fingerprint: Option<String>,
    ephemeral_connection: bool,
    query: ap_client::CredentialQuery,
    output: OutputFormat,
    timeout_secs: Option<u64>,
    socket_override: Option<String>,
) -> Result<()> {
    use super::output::{exit_code, exit_code_name};

    let credential_timeout = timeout_secs.map(std::time::Duration::from_secs);
    match fetch_credential_dispatch(
        &relay_url,
        token.as_deref(),
        session_fingerprint.as_deref(),
        ephemeral_connection,
        &query,
        credential_timeout,
        socket_override.as_deref(),
        Delivery::Reference,
    )
    .await
    {
        Ok(CredentialOutcome::Credential(credential)) => {
            match output {
                OutputFormat::Json => emit_json_success(&credential),
                OutputFormat::Text => emit_text_credential(&credential),
            }
            std::process::exit(exit_code::SUCCESS);
        }
        Ok(CredentialOutcome::Reference {
            reference,
            item_name,
            item_username,
        }) => {
            match output {
                OutputFormat::Json => {
                    emit_json_reference(&reference, item_name.as_deref(), item_username.as_deref())
                }
                OutputFormat::Text => {
                    emit_text_reference(&reference, item_name.as_deref(), item_username.as_deref())
                }
            }
            std::process::exit(exit_code::SUCCESS);
        }
        Err(e) => {
            let code = exit_code_for_report(&e);
            let msg = format!("{e}");
            match output {
                OutputFormat::Json => emit_json_error(&msg, exit_code_name(code)),
                OutputFormat::Text => tracing::error!("{msg}"),
            }
            std::process::exit(code);
        }
    }
}

/// Connect to the relay and return the notification/request channels + client handle.
///
/// Does NOT start pairing — the caller drives pairing as a concurrent task
/// so fingerprint verification requests can be handled without deadlocking.
async fn start_connection(
    identity_provider: Box<dyn IdentityProvider>,
    connection_store: Box<dyn ConnectionStore>,
    relay_url: &str,
) -> Result<(
    mpsc::Receiver<RemoteClientNotification>,
    mpsc::Receiver<RemoteClientRequest>,
    RemoteClient,
)> {
    let relay_client = Box::new(DefaultRelayClient::from_url(relay_url.to_string()));

    let handle = RemoteClient::connect(identity_provider, connection_store, relay_client)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("Connection to relay failed: {}", e))?;

    Ok((handle.notifications, handle.requests, handle.client))
}

/// Validate that a rendezvous code has the correct format
fn validate_rendezvous_code(code: &str) -> Result<()> {
    if code.is_empty() {
        bail!("Rendezvous code is required");
    }

    // Remove optional hyphen for validation
    let code_normalized = code.replace('-', "");

    if code_normalized.len() != 9 {
        bail!("Rendezvous code must be 9 characters (e.g., ABCDEF123 or ABC-DEF-123)");
    }

    if !code_normalized.chars().all(|c| c.is_ascii_alphanumeric()) {
        bail!("Rendezvous code must contain only letters and numbers");
    }

    Ok(())
}

/// Resolve a connection hex prefix against cached connections.
///
/// Accepts a full 64-char hex fingerprint or any unique prefix (e.g. "a1b2c3").
/// Returns the matching fingerprint, or an error if the prefix is ambiguous or not found.
fn resolve_connection_prefix(
    prefix: &str,
    cached_connections: &[ConnectionInfo],
) -> Result<IdentityFingerprint> {
    let clean_prefix = prefix.replace(['-', ' ', ':'], "").to_lowercase();

    if clean_prefix.is_empty() {
        bail!("Connection prefix must not be empty");
    }

    if !clean_prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("Connection prefix must be a hex string");
    }

    let mut iter = cached_connections
        .iter()
        .filter(|s| hex::encode(s.fingerprint.0).starts_with(&clean_prefix))
        .map(|s| s.fingerprint);

    match (iter.next(), iter.next()) {
        (None, _) => bail!("No cached connection matches prefix: {prefix}"),
        (Some(fp), None) => Ok(fp),
        (Some(_), Some(_)) => {
            bail!("Ambiguous connection prefix '{prefix}' — provide more characters")
        }
    }
}

/// Determine the connection mode from CLI flags and cached connections.
///
/// Pure decision logic — returns `Ok(mode)` or an error message instead of
/// calling `std::process::exit`, making it testable from both the single-shot
/// and interactive code paths.
fn resolve_connection_mode(
    token: Option<&str>,
    session_fingerprint: Option<&str>,
    cached_connections: &[ConnectionInfo],
) -> Result<ConnectionMode> {
    if session_fingerprint.is_some() && token.is_some() {
        bail!("--session and --token are mutually exclusive")
    } else if let Some(session_hex) = session_fingerprint {
        let fingerprint = resolve_connection_prefix(session_hex, cached_connections)?;
        Ok(ConnectionMode::Existing {
            remote_fingerprint: fingerprint,
        })
    } else if let Some(code_or_token) = token {
        match parse_token(code_or_token)? {
            TokenType::Rendezvous(code) => Ok(ConnectionMode::New {
                rendezvous_code: code,
            }),
            TokenType::Psk { psk, fingerprint } => Ok(ConnectionMode::NewPsk {
                psk,
                remote_fingerprint: fingerprint,
            }),
        }
    } else if cached_connections.len() == 1 {
        Ok(ConnectionMode::Existing {
            remote_fingerprint: cached_connections[0].fingerprint,
        })
    } else if cached_connections.is_empty() {
        bail!("No cached connections found — provide --token to start a new connection")
    } else {
        bail!(
            "Multiple cached connections found — specify one with --session. \
             Use `aac connections list` to see available connections."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a fingerprint from hex string, stripping separators.
    #[allow(clippy::string_slice)]
    fn parse_fingerprint_hex(hex: &str) -> Result<IdentityFingerprint> {
        let clean_hex = hex.replace(['-', ' ', ':'], "");

        if clean_hex.len() != 64 {
            bail!("Fingerprint must be 64 hex characters (32 bytes)");
        }

        // SAFETY: clean_hex is validated to be 64 hex characters (ASCII only),
        // so indexing at i*2 boundaries is safe.
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            let byte_str = &clean_hex[i * 2..i * 2 + 2];
            bytes[i] = u8::from_str_radix(byte_str, 16)
                .map_err(|_| color_eyre::eyre::eyre!("Invalid hex string"))?;
        }

        Ok(IdentityFingerprint(bytes))
    }

    /// Helper: create an IdentityFingerprint from a repeating byte.
    fn fp(byte: u8) -> IdentityFingerprint {
        IdentityFingerprint([byte; 32])
    }

    /// Helper: build a minimal cached-session ConnectionInfo.
    fn connection(byte: u8) -> ConnectionInfo {
        ConnectionInfo {
            fingerprint: fp(byte),
            name: None,
            cached_at: 0,
            last_connected_at: 0,
            transport_state: None,
        }
    }

    // ── resolve_connection_mode ─────────────────────────────────────

    #[test]
    fn resolve_mode_single_cached_session_auto_selects() {
        let sessions = vec![connection(0xaa)];
        let mode = resolve_connection_mode(None, None, &sessions).expect("should succeed");
        assert!(matches!(
            mode,
            ConnectionMode::Existing {
                remote_fingerprint
            } if remote_fingerprint == fp(0xaa)
        ));
    }

    #[test]
    fn resolve_mode_no_cached_connections_errors() {
        let result = resolve_connection_mode(None, None, &[]);
        assert!(result.is_err());
        let msg = format!("{}", result.expect_err("should be an error"));
        assert!(msg.contains("No cached connections found"));
    }

    #[test]
    fn resolve_mode_multiple_cached_connections_errors() {
        let sessions = vec![connection(0xaa), connection(0xbb)];
        let result = resolve_connection_mode(None, None, &sessions);
        assert!(result.is_err());
        let msg = format!("{}", result.expect_err("should be an error"));
        assert!(msg.contains("Multiple cached connections found"));
    }

    #[test]
    fn resolve_mode_connection_prefix_selects_existing() {
        let sessions = vec![connection(0xaa), connection(0xbb)];
        let full = hex::encode([0xaa; 32]);
        let prefix: String = full.chars().take(8).collect(); // first 8 chars
        let mode = resolve_connection_mode(None, Some(&prefix), &sessions).expect("should succeed");
        assert!(matches!(
            mode,
            ConnectionMode::Existing {
                remote_fingerprint
            } if remote_fingerprint == fp(0xaa)
        ));
    }

    #[test]
    fn resolve_mode_rendezvous_token() {
        let mode = resolve_connection_mode(Some("ABC123DEF"), None, &[]).expect("should succeed");
        assert!(
            matches!(mode, ConnectionMode::New { rendezvous_code } if rendezvous_code == "ABC123DEF")
        );
    }

    #[test]
    fn resolve_mode_psk_token() {
        let psk_hex = "aa".repeat(32);
        let fp_hex = "bb".repeat(32);
        let token = format!("{psk_hex}_{fp_hex}");
        let mode = resolve_connection_mode(Some(&token), None, &[]).expect("should succeed");
        assert!(matches!(
            mode,
            ConnectionMode::NewPsk {
                remote_fingerprint, ..
            } if remote_fingerprint == fp(0xbb)
        ));
    }

    #[test]
    fn resolve_mode_token_takes_priority_over_single_cached() {
        let sessions = vec![connection(0xcc)];
        let mode =
            resolve_connection_mode(Some("XYZ789ABC"), None, &sessions).expect("should succeed");
        assert!(
            matches!(mode, ConnectionMode::New { rendezvous_code } if rendezvous_code == "XYZ789ABC")
        );
    }

    #[test]
    fn resolve_mode_session_and_token_both_provided_errors() {
        let sessions = vec![connection(0xaa), connection(0xbb)];
        let full = hex::encode([0xaa; 32]);
        let prefix: String = full.chars().take(8).collect();
        let result = resolve_connection_mode(Some("ABC123DEF"), Some(&prefix), &sessions);
        assert!(result.is_err());
        let msg = format!("{}", result.expect_err("should be an error"));
        assert!(msg.contains("mutually exclusive"));
    }

    // ── resolve_connection_prefix ──────────────────────────────────────

    #[test]
    fn prefix_exact_full_hex_match() {
        let sessions = vec![connection(0xaa)];
        let full_hex = hex::encode([0xaa; 32]);
        let result = resolve_connection_prefix(&full_hex, &sessions).expect("should match");
        assert_eq!(result, fp(0xaa));
    }

    #[test]
    fn prefix_unique_short_match() {
        let sessions = vec![connection(0xaa), connection(0xbb)];
        let result = resolve_connection_prefix("aa", &sessions).expect("should match");
        assert_eq!(result, fp(0xaa));
    }

    #[test]
    fn prefix_ambiguous_errors() {
        // 0xaa and 0xab both start with 'a'
        let sessions = vec![connection(0xaa), connection(0xab)];
        let result = resolve_connection_prefix("a", &sessions);
        assert!(result.is_err());
        let msg = format!("{}", result.expect_err("should be an error"));
        assert!(msg.contains("Ambiguous"));
    }

    #[test]
    fn prefix_no_match_errors() {
        let sessions = vec![connection(0xaa)];
        let result = resolve_connection_prefix("ff", &sessions);
        assert!(result.is_err());
        let msg = format!("{}", result.expect_err("should be an error"));
        assert!(msg.contains("No cached connection"));
    }

    #[test]
    fn prefix_empty_errors() {
        let sessions = vec![connection(0xaa)];
        let result = resolve_connection_prefix("", &sessions);
        assert!(result.is_err());
        let msg = format!("{}", result.expect_err("should be an error"));
        assert!(msg.contains("must not be empty"));
    }

    #[test]
    fn prefix_non_hex_errors() {
        let sessions = vec![connection(0xaa)];
        let result = resolve_connection_prefix("zzzz", &sessions);
        assert!(result.is_err());
        let msg = format!("{}", result.expect_err("should be an error"));
        assert!(msg.contains("hex string"));
    }

    #[test]
    fn prefix_strips_separators() {
        let sessions = vec![connection(0xaa)];
        // "aa:aa" should normalize to "aaaa" and match
        let result = resolve_connection_prefix("aa:aa", &sessions).expect("should match");
        assert_eq!(result, fp(0xaa));
    }

    // ── parse_token ─────────────────────────────────────────────────

    #[test]
    fn parse_token_rendezvous_code() {
        let result = parse_token("ABC123DEF").expect("should parse");
        assert!(matches!(result, TokenType::Rendezvous(code) if code == "ABC123DEF"));
    }

    #[test]
    fn parse_token_psk_token() {
        let psk_hex = "aa".repeat(32);
        let fp_hex = "bb".repeat(32);
        let token = format!("{psk_hex}_{fp_hex}");
        let result = parse_token(&token).expect("should parse");
        assert!(matches!(result, TokenType::Psk { .. }));
    }

    #[test]
    fn parse_token_invalid_psk_format() {
        // Has underscore but wrong length
        let result = parse_token("abc_def");
        assert!(result.is_err());
    }

    // ── validate_rendezvous_code ────────────────────────────────────

    #[test]
    fn rendezvous_valid_plain() {
        assert!(validate_rendezvous_code("ABCDEF123").is_ok());
    }

    #[test]
    fn rendezvous_valid_with_hyphens() {
        assert!(validate_rendezvous_code("ABC-DEF-123").is_ok());
    }

    #[test]
    fn rendezvous_empty_errors() {
        let result = validate_rendezvous_code("");
        assert!(result.is_err());
        let msg = format!("{}", result.expect_err("should be an error"));
        assert!(msg.contains("required"));
    }

    #[test]
    fn rendezvous_wrong_length_errors() {
        let result = validate_rendezvous_code("AB");
        assert!(result.is_err());
        let msg = format!("{}", result.expect_err("should be an error"));
        assert!(msg.contains("9 characters"));
    }

    #[test]
    fn rendezvous_non_alphanumeric_errors() {
        let result = validate_rendezvous_code("ABCDEF!@#");
        assert!(result.is_err());
        let msg = format!("{}", result.expect_err("should be an error"));
        assert!(msg.contains("letters and numbers"));
    }

    // ── parse_fingerprint_hex ───────────────────────────────────────

    #[test]
    fn fingerprint_valid_64_hex() {
        let hex_str = "aa".repeat(32);
        let result = parse_fingerprint_hex(&hex_str).expect("should parse");
        assert_eq!(result, fp(0xaa));
    }

    #[test]
    fn fingerprint_wrong_length_errors() {
        let result = parse_fingerprint_hex("aabb");
        assert!(result.is_err());
        let msg = format!("{}", result.expect_err("should be an error"));
        assert!(msg.contains("64 hex characters"));
    }

    #[test]
    fn fingerprint_strips_separators() {
        // 64 hex chars with colons between byte pairs
        let with_colons: String = (0..32).map(|_| "aa").collect::<Vec<_>>().join(":");
        let result = parse_fingerprint_hex(&with_colons).expect("should parse");
        assert_eq!(result, fp(0xaa));
    }

    // ── --secret CLI flag mutual exclusion (clap-level) ─────────────────

    fn try_parse(args: &[&str]) -> std::result::Result<ConnectArgs, clap::Error> {
        use clap::{Args as ClapArgs, FromArgMatches};
        let cmd = ConnectArgs::augment_args(clap::Command::new("connect"));
        let matches = cmd.try_get_matches_from(args)?;
        ConnectArgs::from_arg_matches(&matches)
    }

    /// `ConnectArgs` doesn't derive `Debug`, so `Result::expect_err` isn't
    /// available here either (see the equivalent helper in `run.rs`'s
    /// tests).
    fn expect_parse_error(args: &[&str]) -> clap::Error {
        match try_parse(args) {
            Ok(_) => panic!("expected a parse error for args: {args:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn secret_conflicts_with_domain() {
        let err = expect_parse_error(&[
            "connect",
            "--domain",
            "example.com",
            "--secret",
            "DB_PASSWORD",
        ]);
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn secret_conflicts_with_id() {
        let err = expect_parse_error(&["connect", "--id", "item-1", "--secret", "DB_PASSWORD"]);
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn secret_conflicts_with_search() {
        let err = expect_parse_error(&["connect", "--search", "bank", "--secret", "DB_PASSWORD"]);
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn domain_conflicts_with_secret() {
        // Symmetric check: declaring --secret first must conflict too.
        let err = expect_parse_error(&[
            "connect",
            "--secret",
            "DB_PASSWORD",
            "--domain",
            "example.com",
        ]);
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn secret_alone_parses_ok() {
        let parsed = try_parse(&["connect", "--secret", "DB_PASSWORD"]).expect("should parse");
        assert_eq!(parsed.secret.as_deref(), Some("DB_PASSWORD"));
        assert!(parsed.domain.is_none());
    }
}

// ── local-transport defense-in-depth guard (finding #2) ────────────────
//
// A local server that ignores `delivery:"reference"` and replies with a
// value-bearing credential anyway must never have those values surface
// through `fetch_credential_dispatch` — `run_single_shot` prints whatever it
// gets back for a `Reference`-delivery request. Mirrors the guard already
// covered for the sibling corner case (`Reference`-for-`Inject`) in
// `command/run.rs`, and for `Credential`-for-`Reference` in
// `command/mcp.rs`'s `run_find_logins`.
#[cfg(all(test, unix))]
mod local_transport_guard_tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    use super::*;

    fn unique_socket_path() -> String {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("/tmp/aac-connect-{}-{n}.sock", std::process::id() % 100_000)
    }

    /// Spawn a one-shot mock local-socket server (mirrors
    /// `transport::local`'s and `command::mcp`'s test helpers): accepts one
    /// connection, reads one request line, replies with the given canned
    /// response line.
    async fn spawn_mock_server(response_line: &'static str) -> String {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind mock socket");

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    match stream.read(&mut byte).await {
                        Ok(0) => break,
                        Ok(_) if byte[0] == b'\n' => break,
                        Ok(_) => buf.push(byte[0]),
                        Err(_) => break,
                    }
                }
                let _: serde_json::Value =
                    serde_json::from_slice(&buf).expect("mock received valid json");
                let mut out = response_line.as_bytes().to_vec();
                out.push(b'\n');
                let _ = stream.write_all(&out).await;
                let _ = stream.flush().await;
            }
        });

        tokio::task::yield_now().await;
        path
    }

    #[tokio::test]
    async fn reference_delivery_rejects_value_bearing_credential_reply() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"approved","credential":{"username":"u","password":"hunter2","totp":"654321","uri":"https://example.com","credentialId":"item-1"},"reference":"bw://item/item-1"}"#,
        )
        .await;

        let result = fetch_credential_dispatch(
            DEFAULT_RELAY_URL,
            None,
            None,
            true,
            &ap_client::CredentialQuery::Domain("example.com".to_string()),
            None,
            Some(&socket),
            Delivery::Reference,
        )
        .await;

        let err = result.expect_err("value-bearing credential for a reference request must error");
        let msg = format!("{err}");
        assert!(
            !msg.contains("hunter2"),
            "secret leaked into error message: {msg}"
        );
        assert!(msg.contains("credential-bearing"));
    }

    /// Sanity check: a proper reference reply (no `credential` field) for a
    /// reference-delivery request still succeeds normally — the guard above
    /// must not reject the legitimate case.
    #[tokio::test]
    async fn reference_delivery_accepts_reference_reply() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"approved","item":{"name":"Example","username":"u"},"reference":"bw://item/item-1"}"#,
        )
        .await;

        let outcome = fetch_credential_dispatch(
            DEFAULT_RELAY_URL,
            None,
            None,
            true,
            &ap_client::CredentialQuery::Domain("example.com".to_string()),
            None,
            Some(&socket),
            Delivery::Reference,
        )
        .await
        .expect("reference reply should succeed");

        assert!(matches!(outcome, CredentialOutcome::Reference { .. }));
    }

    /// Sanity check: `Inject`-delivery requests are unaffected by the
    /// reference-mode guard.
    #[tokio::test]
    async fn inject_delivery_still_accepts_credential_reply() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"approved","credential":{"username":"u","password":"p","totp":"123456","uri":"https://example.com","credentialId":"item-1"},"reference":"bw://item/item-1"}"#,
        )
        .await;

        let outcome = fetch_credential_dispatch(
            DEFAULT_RELAY_URL,
            None,
            None,
            true,
            &ap_client::CredentialQuery::Domain("example.com".to_string()),
            None,
            Some(&socket),
            Delivery::Inject,
        )
        .await
        .expect("inject reply should succeed");

        assert!(matches!(outcome, CredentialOutcome::Credential(_)));
    }

    // ── secretRequest dispatch / guards ─────────────────────────────────

    #[tokio::test]
    async fn secret_reference_delivery_rejects_value_bearing_reply() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"approved","secret":{"name":"DB_PASSWORD","value":"hunter2","secretId":"secret-1"},"reference":"bw://secret/secret-1"}"#,
        )
        .await;

        let result = fetch_secret_dispatch(
            &SecretQueryInput::Name("DB_PASSWORD".to_string()),
            Some(&socket),
            Delivery::Reference,
        )
        .await;

        let err = result.expect_err("value-bearing secret for a reference request must error");
        let msg = format!("{err}");
        assert!(
            !msg.contains("hunter2"),
            "secret leaked into error message: {msg}"
        );
        assert!(msg.contains("value-bearing"));
    }

    /// Sanity check: a proper reference reply (no `secret` field) for a
    /// reference-delivery request still succeeds normally.
    #[tokio::test]
    async fn secret_reference_delivery_accepts_reference_reply() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"approved","item":{"name":"DB_PASSWORD"},"reference":"bw://secret/secret-1"}"#,
        )
        .await;

        let outcome = fetch_secret_dispatch(
            &SecretQueryInput::Name("DB_PASSWORD".to_string()),
            Some(&socket),
            Delivery::Reference,
        )
        .await
        .expect("reference reply should succeed");

        assert!(matches!(outcome, SecretRequestOutcome::Reference { .. }));
    }

    /// Sanity check: `Inject`-delivery requests are unaffected by the
    /// reference-mode guard.
    #[tokio::test]
    async fn secret_inject_delivery_still_accepts_secret_reply() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"approved","secret":{"name":"DB_PASSWORD","value":"hunter2","secretId":"secret-1"},"reference":"bw://secret/secret-1"}"#,
        )
        .await;

        let outcome = fetch_secret_dispatch(
            &SecretQueryInput::Name("DB_PASSWORD".to_string()),
            Some(&socket),
            Delivery::Inject,
        )
        .await
        .expect("inject reply should succeed");

        assert!(matches!(outcome, SecretRequestOutcome::Secret(_)));
    }

    /// Secrets never ride the relay: a local `ConnectFailed` must surface as
    /// a hard error, never a silent relay fallback (unlike the credential
    /// path's `Err(LocalTransportError::ConnectFailed(reason)) if !forced`
    /// branch).
    #[tokio::test]
    async fn secret_connect_failed_does_not_fall_back_to_relay() {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);

        let result = fetch_secret_dispatch(
            &SecretQueryInput::Name("DB_PASSWORD".to_string()),
            Some(&path),
            Delivery::Reference,
        )
        .await;

        let err = result.expect_err("unreachable local endpoint must be a hard error");
        let msg = format!("{err}");
        assert!(
            msg.contains("no relay fallback") || msg.contains("Bitwarden desktop app"),
            "error should explain the desktop app is required: {msg}"
        );
    }
}
