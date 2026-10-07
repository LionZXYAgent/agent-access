//! Telegram approval backend for `aac listen`.
//!
//! Each approval prompt is sent to the owner's chat with inline buttons:
//! **Allow**, **Allow 15m**, **Allow 1h**, **Allow forever** and **Decline**
//! (pairing prompts only get Allow / Decline). Button presses and bot commands
//! arrive through `getUpdates` long polling (no webhook, no inbound port).
//!
//! Security properties:
//! - Callback data is `aac:<id>:<action>` where `<id>` is 128 bits from the OS
//!   CSPRNG, so callbacks cannot be guessed or forged for other requests.
//! - Only presses and commands from the configured owner user id, in the
//!   configured chat, are accepted. Other presses are answered with
//!   "not authorized" and leave the request pending.
//! - Each request is single-use: the first accepted press (or the timeout)
//!   removes it, and any replayed callback is answered as expired.
//! - Unanswered requests are automatically declined after the timeout.
//! - Messages are edited to show the final outcome and lose their buttons.
//! - Standing grants (15m / 1h / forever) are scoped to device + query +
//!   vault item, kept in memory only, and revocable via `/grants`, `/revoke`
//!   or the revoke buttons.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rand::RngCore;
use rand::rngs::OsRng;
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::api::{BotApi, CallbackQuery, InlineButton, Message, TelegramError};
use super::grants::{Grant, GrantDuration, GrantScope, GrantStore};
use super::message::{
    ApprovalPrompt, HELP_TEXT, Outcome, render_grant_list, render_outcome, render_prompt,
};
use super::now_secs;

/// Prefix for our callback data, so foreign callbacks are ignored cleanly.
const CALLBACK_PREFIX: &str = "aac";
/// Long-poll timeout passed to `getUpdates`.
const POLL_TIMEOUT: Duration = Duration::from_secs(25);
/// Maximum backoff between failed `getUpdates` calls.
const MAX_POLL_BACKOFF: Duration = Duration::from_secs(30);

/// Configuration for the Telegram approver.
#[derive(Debug, Clone)]
pub struct TelegramSettings {
    /// Telegram user id whose button presses are accepted.
    pub owner_id: i64,
    /// Chat the prompts are sent to. Usually the owner's private chat (same as `owner_id`).
    pub chat_id: i64,
    /// How long a prompt stays answerable before it is automatically declined.
    pub timeout: Duration,
}

/// The owner's decision for a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Allow this request only.
    Allow,
    /// Allow this request and create a standing grant.
    AllowFor(GrantDuration),
    Decline,
    TimedOut,
}

impl Decision {
    /// Whether the decision approves the request.
    pub fn is_allowed(self) -> bool {
        matches!(self, Decision::Allow | Decision::AllowFor(_))
    }
}

/// Grant information attached to a credential prompt, enabling the
/// "Allow 15m / 1h / forever" buttons.
#[derive(Debug, Clone)]
pub struct GrantRequest {
    pub scope: GrantScope,
    /// Display label for `/grants` (device + query + item, no secrets).
    pub label: String,
}

/// A prompt waiting for a decision.
pub struct PendingApproval {
    /// Opaque approval id (used to resolve the prompt from elsewhere).
    pub id: String,
    /// Resolves once with the owner's decision or `TimedOut`.
    pub decision: oneshot::Receiver<Decision>,
}

struct PendingEntry {
    reply: oneshot::Sender<Decision>,
    message_id: i64,
    text: String,
    grant: Option<GrantRequest>,
}

struct Inner {
    api: BotApi,
    settings: TelegramSettings,
    pending: Mutex<HashMap<String, PendingEntry>>,
    grants: Mutex<GrantStore>,
}

/// Cloneable handle to the Telegram approval backend.
#[derive(Clone)]
pub struct TelegramApprover {
    inner: Arc<Inner>,
}

/// What a button press asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Decide(Decision),
    RevokeGrant,
}

/// Parsed callback data.
#[derive(Debug, PartialEq, Eq)]
struct CallbackData<'a> {
    id: &'a str,
    action: Action,
}

fn parse_callback_data(data: &str) -> Option<CallbackData<'_>> {
    let mut parts = data.split(':');
    if parts.next()? != CALLBACK_PREFIX {
        return None;
    }
    let id = parts.next()?;
    let action = match parts.next()? {
        "a" => Action::Decide(Decision::Allow),
        "m15" => Action::Decide(Decision::AllowFor(GrantDuration::Minutes15)),
        "h1" => Action::Decide(Decision::AllowFor(GrantDuration::Hour1)),
        "f" => Action::Decide(Decision::AllowFor(GrantDuration::Forever)),
        "d" => Action::Decide(Decision::Decline),
        "r" => Action::RevokeGrant,
        _ => return None,
    };
    if parts.next().is_some() || id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(CallbackData { id, action })
}

fn new_random_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn button(text: &str, id: &str, action: &str) -> InlineButton {
    InlineButton {
        text: text.to_string(),
        callback_data: format!("{CALLBACK_PREFIX}:{id}:{action}"),
    }
}

/// Keyboard with a single revoke button for a grant.
fn revoke_keyboard(grant_id: &str) -> Vec<Vec<InlineButton>> {
    vec![vec![button("🗑 Revoke grant", grant_id, "r")]]
}

impl TelegramApprover {
    /// Validate the bot token with `getMe` and start the long-polling task.
    pub async fn start(
        api: BotApi,
        settings: TelegramSettings,
    ) -> Result<(Self, JoinHandle<()>), TelegramError> {
        let me = api.get_me().await?;
        info!(
            "Telegram approvals enabled via bot @{} (owner id {}, timeout {}s)",
            me.username.as_deref().unwrap_or("unknown"),
            settings.owner_id,
            settings.timeout.as_secs()
        );
        let approver = Self {
            inner: Arc::new(Inner {
                api,
                settings,
                pending: Mutex::new(HashMap::new()),
                grants: Mutex::new(GrantStore::new()),
            }),
        };
        let poller = approver.clone();
        let handle = tokio::spawn(async move { poller.poll_loop().await });
        Ok((approver, handle))
    }

    /// Return the active grant covering `scope`, if any.
    pub async fn find_grant(&self, scope: &GrantScope) -> Option<Grant> {
        self.inner
            .grants
            .lock()
            .await
            .find(scope, tokio::time::Instant::now())
    }

    /// Active grants (for display / tests).
    pub async fn list_grants(&self) -> Vec<Grant> {
        self.inner
            .grants
            .lock()
            .await
            .list(tokio::time::Instant::now())
    }

    /// Send an approval prompt and return a handle that resolves with the decision.
    ///
    /// With `grant = Some(..)` the prompt also offers "Allow 15m / 1h / forever".
    pub async fn request(
        &self,
        prompt: &ApprovalPrompt,
        grant: Option<GrantRequest>,
    ) -> Result<PendingApproval, TelegramError> {
        let id = new_random_id();
        let settings = &self.inner.settings;
        let text = render_prompt(prompt, settings.timeout.as_secs(), now_secs());
        let keyboard = if grant.is_some() {
            vec![
                vec![
                    button("✅ Allow once", &id, "a"),
                    button("❌ Decline", &id, "d"),
                ],
                vec![
                    button("Allow 15m", &id, "m15"),
                    button("Allow 1h", &id, "h1"),
                    button("Allow forever", &id, "f"),
                ],
            ]
        } else {
            vec![vec![
                button("✅ Allow", &id, "a"),
                button("❌ Decline", &id, "d"),
            ]]
        };

        // Hold the lock across send so a very fast press can't race the insert.
        let mut pending = self.inner.pending.lock().await;
        let message = self
            .inner
            .api
            .send_message(settings.chat_id, &text, Some(&keyboard))
            .await?;
        let (tx, rx) = oneshot::channel();
        pending.insert(
            id.clone(),
            PendingEntry {
                reply: tx,
                message_id: message.message_id,
                text,
                grant,
            },
        );
        drop(pending);
        debug!(
            "Telegram approval {id} sent (message {})",
            message.message_id
        );

        // Timeout task: auto-decline if still pending.
        let approver = self.clone();
        let timeout_id = id.clone();
        let timeout = settings.timeout;
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            approver
                .finish(&timeout_id, Decision::TimedOut, Outcome::TimedOut)
                .await;
        });

        Ok(PendingApproval { id, decision: rx })
    }

    /// Reply to an owner command, optionally with buttons. Errors are logged, not returned.
    async fn notify(&self, text: &str, keyboard: Option<&[Vec<InlineButton>]>) {
        if let Err(e) = self
            .inner
            .api
            .send_message(self.inner.settings.chat_id, text, keyboard)
            .await
        {
            warn!("Failed to send Telegram notification: {e}");
        }
    }

    /// Resolve a prompt from outside Telegram (e.g. the terminal UI answered first,
    /// or the request was cancelled). Edits the message to show `outcome`.
    /// No-op if the prompt was already resolved.
    pub async fn resolve_externally(&self, id: &str, outcome: Outcome) {
        let decision = match outcome {
            Outcome::AllowedLocally | Outcome::AllowedTelegram => Decision::Allow,
            Outcome::TimedOut => Decision::TimedOut,
            _ => Decision::Decline,
        };
        self.finish(id, decision, outcome).await;
    }

    /// Remove a pending entry (single-use), record a grant if requested, deliver the
    /// decision and edit the message. Returns `false` if the entry was not pending anymore.
    async fn finish(&self, id: &str, decision: Decision, outcome: Outcome) -> bool {
        let Some(entry) = self.inner.pending.lock().await.remove(id) else {
            return false;
        };

        let mut outcome = outcome;
        let mut keyboard = None;
        let mut decision = decision;
        if let Decision::AllowFor(duration) = decision {
            match entry.grant {
                Some(grant_req) => {
                    let grant = self.inner.grants.lock().await.insert(
                        new_random_id(),
                        grant_req.scope,
                        grant_req.label,
                        duration,
                        tokio::time::Instant::now(),
                        now_secs(),
                    );
                    info!("Telegram grant {} created ({})", grant.id, duration.label());
                    outcome = Outcome::AllowedWithGrant {
                        duration,
                        expires_epoch: grant.expires_epoch,
                    };
                    keyboard = Some(revoke_keyboard(&grant.id));
                }
                None => {
                    // Prompt didn't offer grants (e.g. pairing) — treat as a one-time allow.
                    decision = Decision::Allow;
                    outcome = Outcome::AllowedTelegram;
                }
            }
        }

        // Receiver may be gone (e.g. caller resolved locally) — that's fine.
        let _ = entry.reply.send(decision);
        let text = render_outcome(&entry.text, outcome, now_secs());
        if let Err(e) = self
            .inner
            .api
            .edit_message_text(
                self.inner.settings.chat_id,
                entry.message_id,
                &text,
                keyboard.as_deref(),
            )
            .await
        {
            warn!("Failed to update Telegram message for approval {id}: {e}");
        }
        info!("Telegram approval {id}: {outcome:?}");
        true
    }

    fn is_owner_in_chat(&self, user_id: Option<i64>, chat_id: Option<i64>) -> bool {
        let s = &self.inner.settings;
        user_id == Some(s.owner_id) && chat_id == Some(s.chat_id)
    }

    /// Handle one callback query from `getUpdates`.
    async fn handle_callback(&self, query: CallbackQuery) {
        let answer = |text: String| {
            let api = self.inner.api.clone();
            let cb_id = query.id.clone();
            async move {
                if let Err(e) = api.answer_callback_query(&cb_id, &text).await {
                    debug!("answerCallbackQuery failed: {e}");
                }
            }
        };

        let Some(data) = query.data.as_deref().and_then(parse_callback_data) else {
            answer("Unknown action".to_string()).await;
            return;
        };

        let chat_id = query.message.as_ref().map(|m| m.chat.id);
        if !self.is_owner_in_chat(Some(query.from.id), chat_id) {
            warn!(
                "Ignoring Telegram button press from unauthorized user id {} (chat {:?})",
                query.from.id, chat_id
            );
            answer("Not authorized".to_string()).await;
            return;
        }

        match data.action {
            Action::RevokeGrant => {
                let revoked = self.inner.grants.lock().await.revoke(data.id);
                match revoked {
                    Some(grant) => {
                        info!("Telegram grant {} revoked via button", grant.id);
                        answer("Grant revoked".to_string()).await;
                    }
                    None => {
                        answer("Grant already expired or revoked".to_string()).await;
                    }
                }
            }
            Action::Decide(decision) => {
                let outcome = match decision {
                    Decision::Allow => Outcome::AllowedTelegram,
                    _ => Outcome::DeclinedTelegram,
                };
                if self.finish(data.id, decision, outcome).await {
                    answer(match decision {
                        Decision::Allow => "Allowed".to_string(),
                        Decision::AllowFor(d) => format!("Allowed, grant for {}", d.label()),
                        _ => "Declined".to_string(),
                    })
                    .await;
                } else {
                    answer("This request has expired or was already handled".to_string()).await;
                }
            }
        }
    }

    /// Handle a text message (bot command) from `getUpdates`.
    async fn handle_message(&self, message: Message) {
        let user_id = message.from.as_ref().map(|u| u.id);
        if !self.is_owner_in_chat(user_id, Some(message.chat.id)) {
            debug!(
                "Ignoring Telegram message from user {:?} in chat {}",
                user_id, message.chat.id
            );
            return;
        }
        let Some(text) = message.text.as_deref() else {
            return;
        };
        let mut words = text.split_whitespace();
        // Commands may be addressed as /cmd@BotName in groups.
        let command = words
            .next()
            .unwrap_or_default()
            .split('@')
            .next()
            .unwrap_or_default();
        let arg = words.next();
        let now = tokio::time::Instant::now();

        match command {
            "/grants" => self.send_grant_list().await,
            "/revoke" => {
                let reply = match arg {
                    Some("all") => {
                        let n = self.inner.grants.lock().await.revoke_all(now);
                        info!("Telegram: revoked all grants ({n})");
                        format!("🗑 Revoked {n} grant(s).")
                    }
                    Some(n) => match n.trim_start_matches('#').parse::<usize>() {
                        Ok(index) if index >= 1 => {
                            let mut store = self.inner.grants.lock().await;
                            let target = store.list(now).get(index - 1).map(|g| g.id.clone());
                            match target.and_then(|id| store.revoke(&id)) {
                                Some(g) => {
                                    info!("Telegram grant {} revoked via /revoke", g.id);
                                    format!("🗑 Grant revoked: {}", g.label)
                                }
                                None => format!("No grant #{index}. Use /grants to list."),
                            }
                        }
                        _ => "Usage: /revoke <number> or /revoke all".to_string(),
                    },
                    None => "Usage: /revoke <number> or /revoke all".to_string(),
                };
                self.notify(&reply, None).await;
            }
            "/start" | "/help" => self.notify(HELP_TEXT, None).await,
            _ => {}
        }
    }

    async fn send_grant_list(&self) {
        let grants = self.list_grants().await;
        let text = render_grant_list(&grants);
        let keyboard: Vec<Vec<InlineButton>> = grants
            .iter()
            .enumerate()
            .map(|(i, g)| vec![button(&format!("🗑 Revoke #{}", i + 1), &g.id, "r")])
            .collect();
        let keyboard = (!keyboard.is_empty()).then_some(keyboard);
        self.notify(&text, keyboard.as_deref()).await;
    }

    /// Long-poll `getUpdates` forever, dispatching callback queries and commands.
    async fn poll_loop(self) {
        let mut offset: Option<i64> = None;
        let mut backoff = Duration::from_secs(1);
        loop {
            match self.inner.api.get_updates(offset, POLL_TIMEOUT).await {
                Ok(updates) => {
                    backoff = Duration::from_secs(1);
                    for update in updates {
                        offset = Some(update.update_id + 1);
                        if let Some(cb) = update.callback_query {
                            self.handle_callback(cb).await;
                        } else if let Some(msg) = update.message {
                            self.handle_message(msg).await;
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Telegram getUpdates failed: {e} (retrying in {}s)",
                        backoff.as_secs()
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_POLL_BACKOFF);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_ids_are_128_bit_hex_and_unique() {
        let a = new_random_id();
        let b = new_random_id();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
        // Fits Telegram's 64-byte callback_data limit with the longest action.
        assert!(format!("{CALLBACK_PREFIX}:{a}:m15").len() <= 64);
    }

    #[test]
    fn parse_callback_data_accepts_valid() {
        let id = "0123456789abcdef0123456789abcdef";
        let cases = [
            ("a", Action::Decide(Decision::Allow)),
            ("d", Action::Decide(Decision::Decline)),
            (
                "m15",
                Action::Decide(Decision::AllowFor(GrantDuration::Minutes15)),
            ),
            (
                "h1",
                Action::Decide(Decision::AllowFor(GrantDuration::Hour1)),
            ),
            (
                "f",
                Action::Decide(Decision::AllowFor(GrantDuration::Forever)),
            ),
            ("r", Action::RevokeGrant),
        ];
        for (code, action) in cases {
            assert_eq!(
                parse_callback_data(&format!("aac:{id}:{code}")),
                Some(CallbackData { id, action }),
                "code {code}"
            );
        }
    }

    #[test]
    fn parse_callback_data_rejects_invalid() {
        let id = "0123456789abcdef0123456789abcdef";
        for bad in [
            String::new(),
            format!("xyz:{id}:a"),
            format!("aac:{id}:x"),
            format!("aac:{id}:a:extra"),
            "aac:short:a".to_string(),
            format!("aac:{}:a", "z".repeat(32)),
            format!("aac:{id}"),
        ] {
            assert!(parse_callback_data(&bad).is_none(), "accepted {bad:?}");
        }
    }
}
