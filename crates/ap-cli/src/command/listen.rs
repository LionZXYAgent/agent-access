//! Listen command implementation
//!
//! Handles the user-client (trusted device) mode for receiving and
//! approving connection requests from remote clients.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ap_client::{
    ConnectionInfo, ConnectionStore, CredentialData, CredentialRequestReply, DefaultRelayClient,
    FingerprintVerificationReply, IdentityProvider, PskStore, UserClient, UserClientNotification,
    UserClientRequest,
};
use ap_relay_protocol::IdentityFingerprint;
use clap::Args;
use color_eyre::eyre::Result;
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures_util::StreamExt;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use tokio::sync::{mpsc, oneshot};

use super::tui::{
    App, AppAction, CredentialApproval, Message, MessageKind, Mode, init_terminal,
    restore_terminal, wait_for_keypress,
};
use super::util::{format_listen_notification, format_relative_time, val_style};
use crate::providers::{CredentialProvider, LookupResult, ProviderStatus};
use crate::storage::{FileConnectionCache, FileIdentityStorage};
use crate::telegram::message::{DeviceLabel, Outcome};
use crate::telegram::{CredentialGate, Decision, PendingApproval, TelegramApprover, TelegramArgs};

use super::DEFAULT_RELAY_URL;

/// Slash commands available in idle mode.
const IDLE_COMMANDS: &[&str] = &["/pair [name]", "/unlock", "/exit"];

/// How new connections are authenticated.
pub(super) enum PairingMode {
    /// Rendezvous code (default) — 9-char alphanumeric code.
    Rendezvous,
    /// Ephemeral PSK — single-use, not persisted.
    EphemeralPsk,
    /// Reusable PSK — persisted to disk, survives restarts.
    ReusablePsk,
}

/// Caches credential approval decisions so repeated requests from the same
/// device for the same credential are auto-approved within a time window.
struct ApprovalCache {
    /// Maps (source identity, query string) -> (when approved, how long valid).
    approvals: HashMap<(IdentityFingerprint, String), (Instant, Duration)>,
}

impl ApprovalCache {
    fn new() -> Self {
        Self {
            approvals: HashMap::new(),
        }
    }

    /// Check whether a matching approval exists and has not expired.
    /// Also removes any expired entries to prevent unbounded growth.
    fn is_approved(
        &mut self,
        identity: &IdentityFingerprint,
        query: &ap_client::CredentialQuery,
    ) -> bool {
        self.approvals
            .retain(|_, (approved_at, duration)| approved_at.elapsed() < *duration);
        self.approvals.contains_key(&(*identity, query.to_string()))
    }

    /// Record an approval for the given identity and query.
    fn approve(
        &mut self,
        identity: IdentityFingerprint,
        query: &ap_client::CredentialQuery,
        minutes: u32,
    ) {
        self.approvals.insert(
            (identity, query.to_string()),
            (Instant::now(), Duration::from_secs(u64::from(minutes) * 60)),
        );
    }
}

/// Arguments for the listen command
#[derive(Args)]
#[command(after_help = "\
TELEGRAM APPROVAL:
  With --telegram, every credential request that needs approval is also sent to your
  Telegram chat with buttons: Allow once, Allow 15m, Allow 1h, Allow forever, Decline.
  In the TUI the first answer wins (terminal or Telegram). With --headless there is no
  TUI and Telegram is the only approver (suitable for systemd/OpenRC/containers).

  Timed grants auto-approve later requests from the same device for the same query and
  vault item until they expire. They are kept in memory only (cleared on restart) and can
  be revoked with the bot commands /grants and /revoke <n|all>.

  Required:  AAC_TELEGRAM_BOT_TOKEN (env) or --telegram-bot-token-file
             --telegram-owner-id (your numeric Telegram user id)

  Example (headless, reusable PSK, Bitwarden CLI unlocked via BW_SESSION):
    AAC_TELEGRAM_BOT_TOKEN_FILE=/etc/aac/bot-token AAC_TELEGRAM_OWNER_ID=123456789 \\
      aac listen --headless --telegram --reusable-psk --token-file /var/lib/aac/psk-token")]
pub struct ListenArgs {
    /// Relay server URL
    #[arg(long, default_value = DEFAULT_RELAY_URL)]
    pub relay_url: String,

    /// Use PSK (Pre-Shared Key) mode instead of rendezvous code
    #[arg(long, conflicts_with = "reusable_psk")]
    pub psk: bool,

    /// Use a reusable PSK that persists across restarts.
    /// The token is generated once and stored on disk. Subsequent runs
    /// reload the same token, allowing remote clients to connect
    /// repeatedly without re-pairing.
    #[arg(long, conflicts_with = "psk")]
    pub reusable_psk: bool,

    /// Credential provider to use
    #[arg(long, default_value = "bitwarden")]
    pub provider: String,

    /// Run without the interactive TUI (for services, containers, no TTY).
    /// Requires --telegram, which then handles all approvals
    #[arg(long, env = "AAC_HEADLESS", value_parser = clap::builder::BoolishValueParser::new())]
    pub headless: bool,

    /// Headless only: name to give a newly paired connection
    #[arg(long, requires = "headless", value_name = "NAME")]
    pub connection_name: Option<String>,

    /// Headless only: write the pairing token / rendezvous code to this file (mode 0600)
    /// instead of printing it to stdout
    #[arg(long, requires = "headless", value_name = "PATH")]
    pub token_file: Option<std::path::PathBuf>,

    #[command(flatten)]
    pub telegram: TelegramArgs,
}

impl ListenArgs {
    /// Execute the listen command
    pub async fn run(self, log_rx: Option<super::tui_tracing::LogReceiver>) -> Result<()> {
        if self.headless && !self.telegram.telegram {
            color_eyre::eyre::bail!(
                "--headless needs an approver: add --telegram (with a bot token and --telegram-owner-id)"
            );
        }
        let mut provider = crate::providers::create_provider(&self.provider)?;
        let pairing_mode = if self.reusable_psk {
            PairingMode::ReusablePsk
        } else if self.psk {
            PairingMode::EphemeralPsk
        } else {
            PairingMode::Rendezvous
        };
        // Start Telegram before the TUI takes over the terminal so config errors are visible.
        let telegram = self.telegram.start().await?;
        match telegram {
            Some(telegram) if self.headless => {
                super::headless::run(
                    super::headless::HeadlessOptions {
                        relay_url: self.relay_url,
                        pairing_mode,
                        connection_name: self.connection_name,
                        token_file: self.token_file,
                    },
                    &mut *provider,
                    telegram,
                )
                .await
            }
            telegram => {
                run_user_client_loop(
                    self.relay_url,
                    pairing_mode,
                    &mut *provider,
                    log_rx,
                    telegram,
                )
                .await
            }
        }
    }
}

/// Current phase of the listen command's interactive loop.
#[allow(clippy::large_enum_variant)]
enum Phase {
    /// Waiting for events; showing the idle menu.
    Idle,
    /// Fingerprint verification pending — carries the oneshot reply sender.
    FingerprintConfirm {
        reply: oneshot::Sender<FingerprintVerificationReply>,
    },
    /// Prompting user for a friendly device name after fingerprint approval.
    NameInput {
        reply: oneshot::Sender<FingerprintVerificationReply>,
    },
    /// Credential approval pending — carries the oneshot reply sender.
    CredentialApproval {
        query: ap_client::CredentialQuery,
        credential: CredentialData,
        identity: ap_relay_protocol::IdentityFingerprint,
        reply: oneshot::Sender<CredentialRequestReply>,
        /// Mirror of this prompt in Telegram (when `--telegram` is enabled).
        telegram: Option<PendingApproval>,
    },
    /// Waiting for the user to enter unlock input (password or session key).
    UnlockInput,
}

/// Whether the event loop exited normally or because `/pair` was requested.
enum EventLoopExit {
    Quit,
    NewConnection { name: Option<String> },
}

/// Map a [`ProviderStatus`] to TUI header spans and apply them.
fn apply_status_spans(app: &mut App, name: &str, status: &ProviderStatus) {
    let (spans, user_info) = match status {
        ProviderStatus::Ready { user_info } => (
            vec![
                Span::styled(format!("{name} "), Style::default().fg(Color::Green)),
                Span::styled(
                    "unlocked",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
            ],
            user_info.clone(),
        ),
        ProviderStatus::Locked { user_info, .. } => (
            vec![
                Span::styled(format!("{name} "), Style::default().fg(Color::Red)),
                Span::styled(
                    "locked",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" — type /unlock", Style::default().fg(Color::DarkGray)),
            ],
            user_info.clone(),
        ),
        ProviderStatus::Unavailable { reason } => (
            vec![
                Span::styled(format!("{name} "), Style::default().fg(Color::Red)),
                Span::styled(
                    reason.clone(),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
            ],
            None,
        ),
        ProviderStatus::NotInstalled { install_hint } => (
            vec![
                Span::styled(format!("{name} "), Style::default().fg(Color::Red)),
                Span::styled(
                    "not found",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" — {install_hint}"),
                    Style::default().fg(Color::DarkGray),
                ),
            ],
            None,
        ),
    };

    app.vault_status = Some(spans);
    if let Some(info) = user_info {
        app.account_name = Some(info);
    }
}

/// Reload the session list from disk (the client may have updated it).
async fn reload_connections() -> Vec<ConnectionInfo> {
    match FileConnectionCache::load_or_create("user_client") {
        Ok(cache) => cache.list().await,
        Err(_) => Vec::new(),
    }
}

/// Build session info messages for display in the TUI.
fn connection_info_messages(
    sessions: &[ConnectionInfo],
    pending_label: Option<&str>,
) -> Vec<Message> {
    let mut sorted = sessions.to_vec();
    sorted.sort_by(|a, b| b.last_connected_at.cmp(&a.last_connected_at));

    let mut msgs = vec![Message::rich(
        MessageKind::Listening,
        vec![Span::styled(
            "Listening for incoming requests from:",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )],
    )];
    for session in &sorted {
        let short_hex = hex::encode(session.fingerprint.0)
            .chars()
            .take(12)
            .collect::<String>();
        let created = format_relative_time(session.cached_at);
        let last_used = format_relative_time(session.last_connected_at);
        let mut spans = vec![Span::raw("  ")];
        if let Some(name) = &session.name {
            spans.push(Span::styled(
                name.clone(),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(
                format!(" ({short_hex})"),
                Style::default().fg(Color::DarkGray),
            ));
        } else {
            spans.push(Span::styled(
                short_hex,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        spans.push(Span::styled(
            format!("  created {created}, last used {last_used}"),
            Style::default().fg(Color::DarkGray),
        ));
        msgs.push(Message::rich(MessageKind::Info, spans));
    }
    if let Some(label) = pending_label {
        msgs.push(Message::new(MessageKind::Info, format!("  {label}")));
    }
    msgs
}

/// Set up the idle-mode footer for the TUI.
fn idle_footer() -> Line<'static> {
    Line::from(vec![
        Span::styled(" /pair", Style::default().fg(Color::Cyan)),
        Span::styled(" [name]", Style::default().fg(Color::DarkGray)),
        Span::raw(" session  "),
        Span::styled("/unlock", Style::default().fg(Color::Cyan)),
        Span::raw(" vault  "),
        Span::styled("/exit", Style::default().fg(Color::Cyan)),
        Span::raw(" quit  "),
        Span::raw("| PageUp/PageDown to scroll"),
    ])
}

/// Run the interactive event+prompt loop using the ratatui TUI.
///
/// Handles notifications and requests from the `UserClient`, credential lookups,
/// and user input in a single `select!` loop.
///
/// The TUI state (`app`, `term`, `reader`) is owned by the caller so that
/// it survives across `/pair` session restarts without flickering.
#[allow(clippy::too_many_arguments)]
async fn run_event_loop(
    app: &mut App,
    term: &mut ratatui::DefaultTerminal,
    reader: &mut EventStream,
    mut notification_rx: mpsc::Receiver<UserClientNotification>,
    mut request_rx: mpsc::Receiver<UserClientRequest>,
    sessions: &[ConnectionInfo],
    pending_connection_name: &Option<String>,
    provider: &mut dyn CredentialProvider,
    log_rx: &mut Option<super::tui_tracing::LogReceiver>,
    approval_cache: &mut ApprovalCache,
    telegram: Option<&TelegramApprover>,
) -> Result<EventLoopExit> {
    let mut phase = Phase::Idle;

    // Seed session info panel for this iteration
    app.set_connection_panel(connection_info_messages(sessions, None));
    app.enter_idle(idle_footer(), IDLE_COMMANDS);

    let mut tick_interval = tokio::time::interval(std::time::Duration::from_millis(150));

    let exit = loop {
        term.draw(|frame| app.draw(frame))
            .map_err(|e| color_eyre::eyre::eyre!("TUI draw error: {}", e))?;

        tokio::select! {
            _ = tick_interval.tick() => {
                app.tick();
                continue;
            }
            maybe_event = reader.next() => {
                if let Some(Ok(Event::Key(key))) = maybe_event {
                    if key.kind == KeyEventKind::Press {
                        if let Some(action) = app.handle_key(key) {
                            match (&phase, &action) {
                                // Idle commands
                                (Phase::Idle, AppAction::Submit(s)) if s.starts_with("/pair") => {
                                    let name = s.strip_prefix("/pair ")
                                        .map(|n| n.trim().to_string())
                                        .filter(|n| !n.is_empty());
                                    break EventLoopExit::NewConnection { name };
                                }
                                (Phase::Idle, AppAction::Submit(s)) if s == "/exit" => {
                                    break EventLoopExit::Quit;
                                }
                                (Phase::Idle, AppAction::Submit(s)) if s == "/unlock" => {
                                    phase = Phase::UnlockInput;
                                    app.set_mode(Mode::TextInput);
                                    app.password_mode = true;
                                    app.input_title = " Unlock ";
                                    app.commands = &[];
                                    app.footer = Line::from(Span::styled(
                                        " Type your master password or session key, then press Enter (empty to cancel)",
                                        Style::default().fg(Color::Yellow),
                                    ));
                                }

                                // Unlock input phase
                                (Phase::UnlockInput, AppAction::Submit(s)) => {
                                    if s.is_empty() {
                                        app.push_msg(MessageKind::Info, "Unlock cancelled");
                                        phase = Phase::Idle;
                                        app.enter_idle(idle_footer(), IDLE_COMMANDS);
                                    } else {
                                        let input = s.clone();
                                        app.push_msg(MessageKind::Status, "Unlocking vault...");
                                        // Force a redraw before the blocking call
                                        term.draw(|frame| app.draw(frame))
                                            .map_err(|e| color_eyre::eyre::eyre!("TUI draw error: {}", e))?;

                                        match provider.unlock(&input) {
                                            Ok(()) => {
                                                let status = provider.status();
                                                apply_status_spans(app, provider.name(), &status);
                                                app.push_msg(MessageKind::Success, "Vault unlocked successfully");
                                            }
                                            Err(e) => {
                                                app.push_msg(MessageKind::Error, format!("Unlock failed: {e}"));
                                            }
                                        }

                                        phase = Phase::Idle;
                                        app.enter_idle(idle_footer(), IDLE_COMMANDS);
                                    }
                                }

                                // Fingerprint confirmation
                                (Phase::FingerprintConfirm { .. }, AppAction::Confirmed(approved)) => {
                                    let approved = *approved;
                                    let old_phase = std::mem::replace(&mut phase, Phase::Idle);
                                    if let Phase::FingerprintConfirm { reply } = old_phase {
                                        if !approved {
                                            let _ = reply.send(FingerprintVerificationReply { approved: false, name: None });
                                            app.push_msg(MessageKind::Error, "Fingerprint rejected");
                                            app.enter_idle(idle_footer(), IDLE_COMMANDS);
                                        } else if let Some(name) = pending_connection_name.clone() {
                                            // Name was pre-set via /pair — send immediately
                                            let _ = reply.send(FingerprintVerificationReply { approved: true, name: Some(name) });
                                            app.push_msg(MessageKind::Success, "Fingerprint approved");
                                            app.enter_idle(idle_footer(), IDLE_COMMANDS);
                                        } else {
                                            // No name pre-set — prompt user for one
                                            app.push_msg(MessageKind::Success, "Fingerprint approved");
                                            phase = Phase::NameInput { reply };
                                            app.input_title = " Name this connection (Enter to skip) ";
                                            app.set_mode(Mode::TextInput);
                                            app.commands = &[];
                                            app.footer = Line::from(vec![
                                                Span::styled(
                                                    " Type a friendly name for this connection, or press Enter to skip",
                                                    Style::default().fg(Color::Yellow),
                                                ),
                                            ]);
                                        }
                                    }
                                }

                                // Name input after fingerprint approval
                                (Phase::NameInput { .. }, AppAction::Submit(text)) => {
                                    let name = if text.is_empty() { None } else { Some(text.clone()) };
                                    let old_phase = std::mem::replace(&mut phase, Phase::Idle);
                                    if let Phase::NameInput { reply } = old_phase {
                                        let _ = reply.send(FingerprintVerificationReply { approved: true, name });
                                    }
                                    app.enter_idle(idle_footer(), IDLE_COMMANDS);
                                }

                                // Credential approval
                                (Phase::CredentialApproval { .. }, AppAction::CredentialConfirmed(approval)) => {
                                    let old_phase = std::mem::replace(&mut phase, Phase::Idle);
                                    if let Phase::CredentialApproval { query, credential, identity, reply, telegram: tg_pending } = old_phase {
                                        let label = credential.domain.clone().unwrap_or_else(|| query.to_string());
                                        let cred_id = credential.credential_id.clone();
                                        // Answered locally first — update the Telegram mirror in the background.
                                        if let (Some(tg), Some(pending)) = (telegram, tg_pending) {
                                            let tg = tg.clone();
                                            let outcome = if matches!(approval, CredentialApproval::Deny) {
                                                Outcome::DeclinedLocally
                                            } else {
                                                Outcome::AllowedLocally
                                            };
                                            tokio::spawn(async move { tg.resolve_externally(&pending.id, outcome).await });
                                        }
                                        if matches!(approval, CredentialApproval::Deny) {
                                            let _ = reply.send(CredentialRequestReply {
                                                approved: false,
                                                credential: None,
                                                credential_id: cred_id,
                                            });
                                            app.push_msg(MessageKind::Error, format!("Credential denied for {label}"));
                                        } else {
                                            if let CredentialApproval::AutoApprove { minutes } = approval {
                                                let mins = *minutes;
                                                approval_cache.approve(identity, &query, mins);
                                                app.push_msg(MessageKind::Success, format!("Credential sent for {label} (auto-approving for {mins}m)"));
                                            } else {
                                                app.push_msg(MessageKind::Success, format!("Credential sent for {label}"));
                                            }
                                            let _ = reply.send(CredentialRequestReply {
                                                approved: true,
                                                credential: Some(credential),
                                                credential_id: cred_id,
                                            });
                                        }
                                    }
                                    app.enter_idle(idle_footer(), IDLE_COMMANDS);
                                }

                                (_, AppAction::Quit) => break EventLoopExit::Quit,
                                _ => {}
                            }
                        }
                    }
                }
            }

            // Handle notifications (fire-and-forget status updates)
            notification = notification_rx.recv() => {
                match notification {
                    Some(notification) => {
                        // Print the formatted notification message
                        if let Some(msg) = format_listen_notification(&notification) {
                            app.push_rich(msg);
                        }

                        // Handle phase transitions for informational events
                        match notification {
                            UserClientNotification::SessionRefreshed { .. }
                            | UserClientNotification::FingerprintVerified { .. } => {
                                // Session store was updated — reload from disk
                                let fresh = reload_connections().await;
                                app.set_connection_panel(connection_info_messages(&fresh, None));
                            }
                            _ => {}
                        }
                    }
                    None => {
                        // Notification channel closed — client event loop ended
                        app.push_msg(MessageKind::Error, "Connection closed");
                        app.push_msg(MessageKind::Info, "Press any key to exit");
                        term.draw(|frame| app.draw(frame))
                            .map_err(|e| color_eyre::eyre::eyre!("TUI draw error: {}", e))?;
                        wait_for_keypress(reader).await;
                        break EventLoopExit::Quit;
                    }
                }
            }

            // Handle requests (require caller action via oneshot reply)
            request = request_rx.recv() => {
                if let Some(request) = request {
                    match request {
                        UserClientRequest::VerifyFingerprint { fingerprint, reply, .. } => {
                            // Display the fingerprint
                            app.push_rich(Message::rich(
                                MessageKind::Prompt,
                                vec![
                                    Span::styled(
                                        "SECURITY VERIFICATION — Fingerprint: ",
                                        Style::default()
                                            .fg(Color::Magenta)
                                            .add_modifier(Modifier::BOLD),
                                    ),
                                    Span::styled(fingerprint, val_style()),
                                    Span::styled(
                                        " — Compare with remote device",
                                        Style::default().fg(Color::DarkGray),
                                    ),
                                ],
                            ));

                            // Enter confirmation phase
                            phase = Phase::FingerprintConfirm { reply };
                            app.commands = &[];
                            let description = match pending_connection_name {
                                Some(name) => Line::from(vec![
                                    Span::styled("Device: ", Style::default().fg(Color::DarkGray)),
                                    Span::styled(
                                        name.clone(),
                                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                                    ),
                                    Span::styled(" — Do the fingerprints match?", Style::default()),
                                ]),
                                None => Line::from("Do the fingerprints match?"),
                            };
                            app.set_mode(Mode::Confirm {
                                title: "Fingerprint Verification".to_string(),
                                description,
                            });
                            app.footer = Line::from(vec![
                                Span::styled(
                                    " Compare fingerprints with remote device — ",
                                    Style::default().fg(Color::Yellow),
                                ),
                                Span::styled(
                                    "[y]",
                                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                                ),
                                Span::styled(" approve  ", Style::default().fg(Color::Yellow)),
                                Span::styled(
                                    "[n]",
                                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                                ),
                                Span::styled(" reject", Style::default().fg(Color::Yellow)),
                            ]);
                        }
                        UserClientRequest::CredentialRequest { query, identity, request_id, timestamp, reply } => {
                            // Check auto-approval cache first
                            if approval_cache.is_approved(&identity, &query) {
                                match provider.lookup(&query) {
                                    LookupResult::Found(credential) => {
                                        let label = credential.domain.clone().unwrap_or_else(|| query.to_string());
                                        let cred_id = credential.credential_id.clone();
                                        let _ = reply.send(CredentialRequestReply {
                                            approved: true,
                                            credential: Some(credential),
                                            credential_id: cred_id,
                                        });
                                        app.push_msg(MessageKind::Success, format!("Auto-approved credential for {label}"));
                                    }
                                    _ => {
                                        let label = query.to_string();
                                        app.push_msg(MessageKind::Warning, format!("Auto-approve: credential not found for {label}, denying"));
                                        let _ = reply.send(CredentialRequestReply {
                                            approved: false,
                                            credential: None,
                                            credential_id: None,
                                        });
                                    }
                                }
                            } else {
                                // Display the request
                                app.push_rich(Message::rich(
                                    MessageKind::Prompt,
                                    vec![
                                        Span::styled("Credential request - ", Style::default().fg(Color::White)),
                                        Span::styled(query.to_string(), val_style()),
                                    ],
                                ));

                                match provider.lookup(&query) {
                                    LookupResult::Found(credential) => {
                                        let domain = credential.domain.clone().unwrap_or_else(|| query.to_string());
                                        let found_msg = format!(
                                            "Found: {} ({})",
                                            credential.username.as_deref().unwrap_or("no username"),
                                            credential.uri.as_deref().unwrap_or("no uri")
                                        );
                                        app.push_msg(MessageKind::Info, found_msg);
                                        app.commands = &[];
                                        // Reload from disk to pick up connections added after the event loop started.
                                        let fresh_connections = reload_connections().await;
                                        let device_label = fresh_connections
                                            .iter()
                                            .find(|s| s.fingerprint == identity)
                                            .map(|s| {
                                                s.name.clone().unwrap_or_else(|| {
                                                    hex::encode(s.fingerprint.0)
                                                        .chars()
                                                        .take(12)
                                                        .collect::<String>()
                                                })
                                            })
                                            .unwrap_or_else(|| "unknown device".to_string());
                                        // Mirror the prompt to Telegram (or auto-approve under a Telegram grant).
                                        let mut tg_pending = None;
                                        if let Some(tg) = telegram {
                                            let device = DeviceLabel {
                                                name: fresh_connections
                                                    .iter()
                                                    .find(|s| s.fingerprint == identity)
                                                    .and_then(|s| s.name.clone()),
                                                identity,
                                            };
                                            match tg.gate_credential(device, &query, &credential, &request_id, timestamp).await {
                                                Ok(CredentialGate::AutoApproved(grant)) => {
                                                    let cred_id = credential.credential_id.clone();
                                                    let _ = reply.send(CredentialRequestReply {
                                                        approved: true,
                                                        credential: Some(credential),
                                                        credential_id: cred_id,
                                                    });
                                                    app.push_msg(MessageKind::Success, format!(
                                                        "Auto-approved credential for {domain} (Telegram grant, {})",
                                                        grant.duration.label()
                                                    ));
                                                    app.enter_idle(idle_footer(), IDLE_COMMANDS);
                                                    continue;
                                                }
                                                Ok(CredentialGate::Pending(pending)) => {
                                                    app.push_msg(MessageKind::Info, "Approval request also sent to Telegram — first answer wins");
                                                    tg_pending = Some(pending);
                                                }
                                                Err(e) => {
                                                    app.push_msg(MessageKind::Warning, format!("Telegram unavailable ({e}) — approve locally"));
                                                }
                                            }
                                        }
                                        // A still-unanswered earlier prompt is replaced (and thereby denied, as
                                        // upstream does); make sure its Telegram mirror can't be pressed anymore.
                                        if let (Phase::CredentialApproval { telegram: Some(old), .. }, Some(tg)) =
                                            (std::mem::replace(&mut phase, Phase::Idle), telegram)
                                        {
                                            let tg = tg.clone();
                                            tokio::spawn(async move { tg.resolve_externally(&old.id, Outcome::Cancelled).await });
                                        }
                                        phase = Phase::CredentialApproval {
                                            query,
                                            credential,
                                            identity,
                                            reply,
                                            telegram: tg_pending,
                                        };
                                        app.set_mode(Mode::CredentialConfirm {
                                            title: format!("Send credential for {domain} to {device_label}?"),
                                            description: Line::from(""),
                                            auto_approve_minutes: 10,
                                        });
                                        app.footer = Line::from(
                                            Span::styled(
                                                " Press [y] approve  [a] approve + auto-approve  [n] deny",
                                                Style::default().fg(Color::Yellow),
                                            )
                                        );
                                    }
                                    result @ (LookupResult::NotReady { .. } | LookupResult::NotFound) => {
                                        let label = query.to_string();
                                        match result {
                                            LookupResult::NotReady { message } => {
                                                app.push_msg(MessageKind::Warning, format!("{message} — cannot look up credential for {label}"));
                                            }
                                            _ => {
                                                app.push_msg(MessageKind::Error, format!("No credential found in vault for {label}"));
                                            }
                                        }
                                        // Auto-deny: reply through the oneshot directly
                                        let _ = reply.send(CredentialRequestReply {
                                            approved: false,
                                            credential: None,
                                            credential_id: None,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Telegram answered (or timed out) the pending credential prompt
            decision = async {
                match &mut phase {
                    Phase::CredentialApproval { telegram: Some(pending), .. } => (&mut pending.decision).await,
                    _ => std::future::pending().await,
                }
            } => {
                let old_phase = std::mem::replace(&mut phase, Phase::Idle);
                if let Phase::CredentialApproval { query, credential, reply, .. } = old_phase {
                    let label = credential.domain.clone().unwrap_or_else(|| query.to_string());
                    let cred_id = credential.credential_id.clone();
                    let decision = decision.unwrap_or(Decision::Decline);
                    if decision.is_allowed() {
                        let _ = reply.send(CredentialRequestReply {
                            approved: true,
                            credential: Some(credential),
                            credential_id: cred_id,
                        });
                        let how = match decision {
                            Decision::AllowFor(d) => format!(" (grant for {})", d.label()),
                            _ => String::new(),
                        };
                        app.push_msg(MessageKind::Success, format!("Credential sent for {label} — approved via Telegram{how}"));
                    } else {
                        let _ = reply.send(CredentialRequestReply {
                            approved: false,
                            credential: None,
                            credential_id: cred_id,
                        });
                        let why = if decision == Decision::TimedOut { "approval timed out" } else { "declined via Telegram" };
                        app.push_msg(MessageKind::Error, format!("Credential denied for {label} — {why}"));
                    }
                }
                app.enter_idle(idle_footer(), IDLE_COMMANDS);
            }

            // Handle tracing log entries routed into the TUI
            log_entry = async {
                match log_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(entry) = log_entry {
                    super::tui_tracing::push_log_entry(app, entry);
                }
            }
        }
    };

    Ok(exit)
}

/// Run the user client interactive session
async fn run_user_client_loop(
    relay_url: String,
    pairing_mode: PairingMode,
    provider: &mut dyn CredentialProvider,
    mut log_rx: Option<super::tui_tracing::LogReceiver>,
    telegram: Option<TelegramApprover>,
) -> Result<()> {
    // First iteration: if cached sessions exist, listen on those immediately.
    // On `/pair`, we loop back and start a fresh rendezvous/psk session.
    let mut force_new_connection = false;
    let mut pending_connection_name: Option<String> = None;

    // Create TUI state once — it survives across `/pair` restarts.
    let mut app = App::new();
    app.client_label = "User client";

    // Show initial provider status (single status() call)
    let initial_status = provider.status();
    let name = provider.name();
    match &initial_status {
        ProviderStatus::Ready { .. } => {}
        ProviderStatus::Locked { .. } => {
            app.push_msg(
                MessageKind::Warning,
                format!("{name} vault is not unlocked — credential lookups will fail. Use /unlock"),
            );
        }
        ProviderStatus::Unavailable { reason } => {
            app.push_msg(MessageKind::Warning, format!("{name}: {reason}"));
        }
        ProviderStatus::NotInstalled { install_hint } => {
            app.push_msg(
                MessageKind::Warning,
                format!("{name} not found. {install_hint}"),
            );
        }
    }
    apply_status_spans(&mut app, name, &initial_status);
    let mut term = init_terminal();
    let mut reader = EventStream::new();
    let mut approval_cache = ApprovalCache::new();

    loop {
        let identity_provider = Box::new(FileIdentityStorage::load_or_generate("user_client")?);
        let connection_cache = FileConnectionCache::load_or_create("user_client")?;
        let connection_store = Box::new(connection_cache);
        let cached_connections = connection_store.list().await;

        let has_cached = !cached_connections.is_empty() && !force_new_connection;

        let relay_client = Box::new(DefaultRelayClient::from_url(relay_url.clone()));

        // Create PSK store when reusable PSK mode is enabled.
        // Check for existing stored PSKs before passing ownership to connect().
        let our_fingerprint = identity_provider.fingerprint().await;
        let (psk_store, existing_psk_token): (Option<Box<dyn PskStore>>, Option<String>) =
            if matches!(pairing_mode, PairingMode::ReusablePsk) {
                let store = crate::storage::FilePskStore::load_or_create("user_client")?;
                let stored = PskStore::list(&store).await;
                let token = stored.first().map(|entry| {
                    ap_client::PskToken::new(entry.psk.clone(), our_fingerprint).to_string()
                });
                (Some(Box::new(store)), token)
            } else {
                (None, None)
            };

        let handle = UserClient::connect(
            identity_provider as Box<dyn IdentityProvider>,
            connection_store as Box<dyn ConnectionStore>,
            relay_client,
            None,
            psk_store,
        )
        .await?;

        let client = handle.client;
        let notification_rx = handle.notifications;
        let request_rx = handle.requests;

        if matches!(pairing_mode, PairingMode::ReusablePsk) {
            let token = if let Some(token) = existing_psk_token {
                token
            } else {
                // No stored PSK — generate a new one (will be persisted by the client)
                let client_connection_name = pending_connection_name.clone();
                client.get_psk_token(client_connection_name, true).await?
            };

            app.push_rich(Message::rich(
                MessageKind::Prompt,
                vec![
                    Span::styled(
                        "REUSABLE PSK TOKEN: ",
                        Style::default()
                            .fg(Color::Magenta)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(token, val_style()),
                    Span::styled(
                        " — Reusable across restarts",
                        Style::default().fg(Color::DarkGray),
                    ),
                ],
            ));
            app.set_connection_panel(connection_info_messages(
                &cached_connections,
                Some("Reusable PSK  (accepting connections)"),
            ));
        } else if !has_cached {
            let client_connection_name = pending_connection_name.clone();
            if matches!(pairing_mode, PairingMode::EphemeralPsk) {
                let token = client.get_psk_token(client_connection_name, false).await?;
                app.push_rich(Message::rich(
                    MessageKind::Prompt,
                    vec![
                        Span::styled(
                            "PSK TOKEN: ",
                            Style::default()
                                .fg(Color::Magenta)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(token, val_style()),
                        Span::styled(
                            " — Share this token securely",
                            Style::default().fg(Color::DarkGray),
                        ),
                    ],
                ));
            } else {
                let code = client.get_rendezvous_token(client_connection_name).await?;
                app.push_rich(Message::rich(
                    MessageKind::Prompt,
                    vec![
                        Span::styled(
                            "RENDEZVOUS CODE: ",
                            Style::default()
                                .fg(Color::Magenta)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(code.as_str().to_string(), val_style()),
                        Span::styled(
                            " — Share this code with your remote device",
                            Style::default().fg(Color::DarkGray),
                        ),
                    ],
                ));
            }
            app.set_connection_panel(connection_info_messages(
                &cached_connections,
                Some("New session  (awaiting connection)"),
            ));
        }

        match run_event_loop(
            &mut app,
            &mut term,
            &mut reader,
            notification_rx,
            request_rx,
            &cached_connections,
            &pending_connection_name,
            provider,
            &mut log_rx,
            &mut approval_cache,
            telegram.as_ref(),
        )
        .await?
        {
            EventLoopExit::NewConnection { name } => {
                force_new_connection = true;
                pending_connection_name = name;
                // Drop the client handle — event loop shuts down when all handles are dropped
                drop(client);
                continue;
            }
            EventLoopExit::Quit => break,
        }
    }

    drop(reader);
    restore_terminal();
    println!("\nUser client session ended.");
    Ok(())
}
