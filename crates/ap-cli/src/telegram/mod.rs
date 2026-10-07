//! Telegram approvals for `aac listen`.
//!
//! Opt-in with `--telegram`. When enabled, every credential request that
//! reaches the approval step is also sent to the owner's Telegram chat with
//! inline **Allow** / **Decline** buttons. In the interactive TUI the first
//! answer wins (terminal or Telegram); with `--headless` Telegram is the only
//! approver.
//!
//! The credential itself never goes through Telegram: an approval only
//! releases it over the existing end-to-end encrypted Agent Access channel.

mod api;
#[cfg(test)]
#[path = "tests.rs"]
mod approval_tests;
mod approver;
pub mod grants;
pub mod message;
#[cfg(test)]
mod mock;

use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use color_eyre::eyre::{Result, WrapErr, bail, eyre};
use secrecy::SecretString;

pub use api::BotApi;
pub use approver::{Decision, GrantRequest, PendingApproval, TelegramApprover, TelegramSettings};

use ap_client::{CredentialData, CredentialQuery};
use grants::{Grant, GrantScope};
use message::{ApprovalPrompt, CredentialSummary, DeviceLabel, render_query};

/// Result of passing a credential request through Telegram.
pub enum CredentialGate {
    /// A standing grant covers this request; it is approved without a prompt.
    /// Nothing is sent to Telegram (logged locally only).
    AutoApproved(Grant),
    /// A prompt was sent; await the decision.
    Pending(PendingApproval),
}

impl TelegramApprover {
    /// Check standing grants for a credential request, otherwise send an approval prompt.
    pub async fn gate_credential(
        &self,
        device: DeviceLabel,
        query: &CredentialQuery,
        credential: &CredentialData,
        request_id: &str,
        timestamp: u64,
    ) -> Result<CredentialGate, api::TelegramError> {
        let scope = GrantScope::new(device.identity, query, credential.credential_id.as_deref());
        let matched = CredentialSummary::from_credential(credential);

        if let Some(grant) = self.find_grant(&scope).await {
            // No Telegram message: the owner already decided. Record it locally only.
            tracing::info!(
                "Auto-approved request {} from {} for {} under grant {} ({}); no Telegram prompt",
                message::sanitize(request_id),
                device.render(),
                render_query(query),
                grant.id,
                grant.duration.label()
            );
            return Ok(CredentialGate::AutoApproved(grant));
        }

        let label = format!(
            "{} · {} → item {}",
            device.render(),
            render_query(query),
            message::sanitize(credential.credential_id.as_deref().unwrap_or("unknown"))
        );
        let prompt = ApprovalPrompt::Credential {
            device,
            query: query.clone(),
            matched,
            request_id: request_id.to_string(),
            timestamp,
        };
        let pending = self
            .request(&prompt, Some(GrantRequest { scope, label }))
            .await?;
        Ok(CredentialGate::Pending(pending))
    }
}

/// Seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Environment variable holding the bot token (alternative to `--telegram-bot-token-file`).
///
/// Deliberately not a CLI flag: command-line arguments are visible to other
/// users via `ps`.
pub const BOT_TOKEN_ENV: &str = "AAC_TELEGRAM_BOT_TOKEN";

/// Default Telegram Bot API endpoint.
const DEFAULT_API_URL: &str = "https://api.telegram.org";

/// Telegram approval options for `aac listen`.
#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Telegram approval")]
pub struct TelegramArgs {
    /// Send each credential request to Telegram with Allow / Decline buttons.
    /// The bot token is read from $AAC_TELEGRAM_BOT_TOKEN or --telegram-bot-token-file
    #[arg(long, env = "AAC_TELEGRAM", value_parser = clap::builder::BoolishValueParser::new())]
    pub telegram: bool,

    /// File containing the Telegram bot token (from @BotFather). Preferred over
    /// the AAC_TELEGRAM_BOT_TOKEN environment variable
    #[arg(long, env = "AAC_TELEGRAM_BOT_TOKEN_FILE", value_name = "PATH")]
    pub telegram_bot_token_file: Option<PathBuf>,

    /// Numeric Telegram user id of the owner. Only this user's button presses are accepted
    #[arg(long, env = "AAC_TELEGRAM_OWNER_ID", value_name = "USER_ID")]
    pub telegram_owner_id: Option<i64>,

    /// Chat to send prompts to [default: the owner's private chat]
    #[arg(long, env = "AAC_TELEGRAM_CHAT_ID", value_name = "CHAT_ID")]
    pub telegram_chat_id: Option<i64>,

    /// Seconds before an unanswered Telegram prompt is automatically declined.
    /// Keep below the requester's timeout (`aac connect/run --timeout`, default 120)
    #[arg(long, env = "AAC_TELEGRAM_TIMEOUT", default_value_t = 90, value_name = "SECONDS",
          value_parser = clap::value_parser!(u64).range(5..=3600))]
    pub telegram_timeout: u64,

    /// Telegram Bot API base URL (for a self-hosted Bot API server or testing)
    #[arg(long, env = "AAC_TELEGRAM_API_URL", default_value = DEFAULT_API_URL, value_name = "URL")]
    pub telegram_api_url: String,
}

/// Read the bot token from the configured file or the environment.
fn load_bot_token(file: Option<&PathBuf>) -> Result<SecretString> {
    let raw = if let Some(path) = file {
        std::fs::read_to_string(path).wrap_err_with(|| {
            format!("Failed to read Telegram bot token file {}", path.display())
        })?
    } else {
        match std::env::var(BOT_TOKEN_ENV) {
            Ok(v) => v,
            Err(_) => bail!(
                "--telegram needs a bot token: set {BOT_TOKEN_ENV} or pass --telegram-bot-token-file"
            ),
        }
    };
    let token = raw.trim();
    // Bot tokens look like `<digits>:<35 chars>`; keep the check loose but catch obvious mistakes.
    if token.is_empty() || !token.contains(':') {
        bail!("Telegram bot token is empty or malformed (expected `<bot id>:<secret>`)");
    }
    Ok(SecretString::from(token.to_string()))
}

impl TelegramArgs {
    /// Build the approver if `--telegram` was given. Validates the token with `getMe`
    /// and starts long polling in the background.
    pub async fn start(&self) -> Result<Option<TelegramApprover>> {
        if !self.telegram {
            return Ok(None);
        }
        let owner_id = self.telegram_owner_id.ok_or_else(|| {
            eyre!("--telegram needs --telegram-owner-id (or AAC_TELEGRAM_OWNER_ID)")
        })?;
        let token = load_bot_token(self.telegram_bot_token_file.as_ref())?;
        let api = BotApi::new(&self.telegram_api_url, token)?;
        let settings = TelegramSettings {
            owner_id,
            chat_id: self.telegram_chat_id.unwrap_or(owner_id),
            timeout: Duration::from_secs(self.telegram_timeout),
        };
        let (approver, _poller) = TelegramApprover::start(api, settings)
            .await
            .wrap_err("Failed to start Telegram approvals (check the bot token and network)")?;
        Ok(Some(approver))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn token_file_is_trimmed() {
        let dir = std::env::temp_dir().join(format!("aac-tg-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("token");
        std::fs::write(&path, "123456:ABCdef\n").expect("write");
        let token = load_bot_token(Some(&path)).expect("should load");
        assert_eq!(token.expose_secret(), "123456:ABCdef");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn malformed_token_rejected() {
        let dir = std::env::temp_dir().join(format!("aac-tg-test-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("token");
        std::fs::write(&path, "   \n").expect("write");
        let err = load_bot_token(Some(&path)).expect_err("should reject");
        assert!(err.to_string().contains("malformed"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
