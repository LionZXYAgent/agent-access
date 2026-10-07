//! Minimal Telegram Bot API client.
//!
//! Implements only the handful of methods the approval flow needs
//! (`getMe`, `getUpdates`, `sendMessage`, `editMessageText`,
//! `answerCallbackQuery`) using long polling, so no inbound port is required.
//!
//! The bot token is part of every request URL (`/bot<token>/<method>`). It is
//! held in a [`SecretString`] and never logged: transport errors are stripped
//! of their URL before being surfaced, and API errors only carry Telegram's
//! `description` field.

use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Extra time on top of the long-poll timeout before the HTTP request is abandoned.
const LONG_POLL_GRACE: Duration = Duration::from_secs(15);
/// Timeout for regular (non long-poll) API calls.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Errors returned by the Bot API client.
///
/// Messages never contain the bot token or the request URL.
#[derive(Debug, thiserror::Error)]
pub enum TelegramError {
    #[error("Telegram request failed: {0}")]
    Transport(String),
    #[error("Telegram API error {code}: {description}")]
    Api { code: i64, description: String },
    #[error("Unexpected Telegram response: {0}")]
    Decode(String),
}

impl From<reqwest::Error> for TelegramError {
    fn from(err: reqwest::Error) -> Self {
        // `without_url()` is essential: the URL contains the bot token.
        TelegramError::Transport(err.without_url().to_string())
    }
}

/// Generic Bot API response envelope.
#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    ok: bool,
    result: Option<T>,
    error_code: Option<i64>,
    description: Option<String>,
}

/// The subset of `User` we need.
#[derive(Debug, Clone, Deserialize)]
pub struct User {
    pub id: i64,
    #[serde(default)]
    pub username: Option<String>,
}

/// The subset of `Chat` we need.
#[derive(Debug, Clone, Deserialize)]
pub struct Chat {
    pub id: i64,
}

/// The subset of `Message` we need.
#[derive(Debug, Clone, Deserialize)]
pub struct Message {
    pub message_id: i64,
    pub chat: Chat,
    #[serde(default)]
    pub from: Option<User>,
    #[serde(default)]
    pub text: Option<String>,
}

/// The subset of `CallbackQuery` we need.
#[derive(Debug, Clone, Deserialize)]
pub struct CallbackQuery {
    pub id: String,
    pub from: User,
    #[serde(default)]
    pub message: Option<Message>,
    #[serde(default)]
    pub data: Option<String>,
}

/// The subset of `Update` we need (button presses and bot commands).
#[derive(Debug, Clone, Deserialize)]
pub struct Update {
    pub update_id: i64,
    #[serde(default)]
    pub callback_query: Option<CallbackQuery>,
    #[serde(default)]
    pub message: Option<Message>,
}

/// Inline keyboard button carrying callback data.
#[derive(Debug, Clone, Serialize)]
pub struct InlineButton {
    pub text: String,
    pub callback_data: String,
}

#[derive(Debug, Serialize)]
struct InlineKeyboardMarkup<'a> {
    inline_keyboard: &'a [Vec<InlineButton>],
}

fn attach_keyboard(
    body: &mut serde_json::Value,
    keyboard: Option<&[Vec<InlineButton>]>,
) -> Result<(), TelegramError> {
    if let Some(rows) = keyboard {
        body["reply_markup"] = serde_json::to_value(InlineKeyboardMarkup {
            inline_keyboard: rows,
        })
        .map_err(|e| TelegramError::Decode(e.to_string()))?;
    }
    Ok(())
}

/// Telegram Bot API client.
#[derive(Clone)]
pub struct BotApi {
    http: reqwest::Client,
    base_url: String,
    token: SecretString,
}

impl std::fmt::Debug for BotApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BotApi")
            .field("base_url", &self.base_url)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl BotApi {
    /// Create a client. `base_url` is normally `https://api.telegram.org`;
    /// tests and self-hosted Bot API servers can point it elsewhere.
    pub fn new(base_url: &str, token: SecretString) -> Result<Self, TelegramError> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("aac/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
        })
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        body: serde_json::Value,
        timeout: Duration,
    ) -> Result<T, TelegramError> {
        let url = format!(
            "{}/bot{}/{}",
            self.base_url,
            self.token.expose_secret(),
            method
        );
        let response = self
            .http
            .post(url)
            .timeout(timeout)
            .json(&body)
            .send()
            .await?;
        let status = response.status();
        let envelope: ApiResponse<T> = response.json().await.map_err(|e| {
            TelegramError::Decode(format!("{method} (HTTP {status}): {}", e.without_url()))
        })?;
        match (envelope.ok, envelope.result) {
            (true, Some(result)) => Ok(result),
            _ => Err(TelegramError::Api {
                code: envelope.error_code.unwrap_or(i64::from(status.as_u16())),
                description: envelope
                    .description
                    .unwrap_or_else(|| "no description".to_string()),
            }),
        }
    }

    /// `getMe` — validates the token and returns the bot user.
    pub async fn get_me(&self) -> Result<User, TelegramError> {
        self.call("getMe", serde_json::json!({}), REQUEST_TIMEOUT)
            .await
    }

    /// `getUpdates` long poll for button presses and messages (bot commands).
    pub async fn get_updates(
        &self,
        offset: Option<i64>,
        poll_timeout: Duration,
    ) -> Result<Vec<Update>, TelegramError> {
        let mut body = serde_json::json!({
            "timeout": poll_timeout.as_secs(),
            "allowed_updates": ["callback_query", "message"],
        });
        if let Some(offset) = offset {
            body["offset"] = serde_json::json!(offset);
        }
        self.call("getUpdates", body, poll_timeout + LONG_POLL_GRACE)
            .await
    }

    /// `sendMessage` as plain text (no parse mode, so untrusted text cannot inject markup).
    pub async fn send_message(
        &self,
        chat_id: i64,
        text: &str,
        keyboard: Option<&[Vec<InlineButton>]>,
    ) -> Result<Message, TelegramError> {
        let mut body = serde_json::json!({
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": true,
        });
        attach_keyboard(&mut body, keyboard)?;
        self.call("sendMessage", body, REQUEST_TIMEOUT).await
    }

    /// `editMessageText` — replaces the text and the inline keyboard
    /// (`None` removes all buttons).
    pub async fn edit_message_text(
        &self,
        chat_id: i64,
        message_id: i64,
        text: &str,
        keyboard: Option<&[Vec<InlineButton>]>,
    ) -> Result<(), TelegramError> {
        let mut body = serde_json::json!({
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
            "disable_web_page_preview": true,
        });
        attach_keyboard(&mut body, keyboard)?;
        // Result is the edited Message (or `true` for inline messages); we don't need it.
        let _: serde_json::Value = self.call("editMessageText", body, REQUEST_TIMEOUT).await?;
        Ok(())
    }

    /// `answerCallbackQuery` — stops the button spinner and shows a short toast.
    pub async fn answer_callback_query(
        &self,
        callback_query_id: &str,
        text: &str,
    ) -> Result<(), TelegramError> {
        let body = serde_json::json!({
            "callback_query_id": callback_query_id,
            "text": text,
        });
        let _: bool = self
            .call("answerCallbackQuery", body, REQUEST_TIMEOUT)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_token() {
        let api = BotApi::new(
            "https://api.telegram.org",
            SecretString::from("123456:SECRET-TOKEN".to_string()),
        )
        .expect("client should build");
        let dbg = format!("{api:?}");
        assert!(
            !dbg.contains("SECRET-TOKEN"),
            "token leaked in Debug: {dbg}"
        );
        assert!(dbg.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn transport_error_does_not_leak_token() {
        // Port 9 (discard) on localhost is almost certainly closed → connection refused.
        let api = BotApi::new(
            "http://127.0.0.1:9",
            SecretString::from("123456:SECRET-TOKEN".to_string()),
        )
        .expect("client should build");
        let err = api.get_me().await.expect_err("should fail to connect");
        let msg = err.to_string();
        assert!(
            !msg.contains("SECRET-TOKEN"),
            "token leaked in error: {msg}"
        );
        assert!(!msg.contains("/bot"), "URL leaked in error: {msg}");
    }
}
