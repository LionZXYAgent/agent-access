//! Telegram message text for approval prompts and outcomes.
//!
//! Everything here is pure formatting so it can be unit tested. Messages are
//! sent as plain text (no parse mode). They describe *what* is being requested
//! and *which* fields would be released, but never contain secret values:
//! no password, TOTP, notes, PSK, or session key ever reaches Telegram.

use ap_client::{CredentialData, CredentialQuery, IdentityFingerprint};

use super::grants::{Grant, GrantDuration};

/// Max characters of untrusted, requester-supplied text shown in a message.
const MAX_UNTRUSTED_LEN: usize = 200;

/// Describes the requesting device as shown to the owner.
#[derive(Debug, Clone)]
pub struct DeviceLabel {
    /// Friendly connection name, if the connection was named at pairing time.
    pub name: Option<String>,
    /// Stable identity fingerprint of the requesting device.
    pub identity: IdentityFingerprint,
}

impl DeviceLabel {
    /// Render as `name (short-hex)`.
    pub fn render(&self) -> String {
        let hex = self.identity.to_hex();
        let short: String = hex.chars().take(12).collect();
        match &self.name {
            Some(name) => format!("{} ({short})", sanitize(name)),
            None => format!("unnamed device ({short})"),
        }
    }
}

/// What the owner is asked to approve.
#[derive(Debug, Clone)]
pub enum ApprovalPrompt {
    /// A paired device requests a credential.
    Credential {
        device: DeviceLabel,
        query: CredentialQuery,
        /// The credential that would be released (only metadata is rendered).
        matched: CredentialSummary,
        request_id: String,
        /// Requester's timestamp (seconds since Unix epoch).
        timestamp: u64,
    },
    /// A new device is pairing via rendezvous code and its handshake
    /// fingerprint must be compared out-of-band.
    Pairing {
        device: DeviceLabel,
        handshake_fingerprint: String,
    },
}

/// Non-secret metadata about a matched credential.
#[derive(Debug, Clone, Default)]
pub struct CredentialSummary {
    pub domain: Option<String>,
    pub credential_id: Option<String>,
    pub fields: Vec<&'static str>,
}

impl CredentialSummary {
    /// Extract non-secret metadata from a credential.
    pub fn from_credential(credential: &CredentialData) -> Self {
        let mut fields = Vec::new();
        if credential.username.is_some() {
            fields.push("username");
        }
        if credential.password.is_some() {
            fields.push("password");
        }
        if credential.totp.is_some() {
            fields.push("totp");
        }
        if credential.uri.is_some() {
            fields.push("uri");
        }
        if credential.notes.is_some() {
            fields.push("notes");
        }
        Self {
            domain: credential.domain.clone(),
            credential_id: credential.credential_id.clone(),
            fields,
        }
    }
}

/// Final state of an approval, rendered into the edited message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    AllowedTelegram,
    /// Allowed via Telegram and a standing grant was created.
    AllowedWithGrant {
        duration: GrantDuration,
        expires_epoch: Option<u64>,
    },
    DeclinedTelegram,
    TimedOut,
    AllowedLocally,
    DeclinedLocally,
    Cancelled,
}

impl Outcome {
    fn render(self) -> String {
        match self {
            Outcome::AllowedTelegram => "✅ ALLOWED once via Telegram".to_string(),
            Outcome::AllowedWithGrant {
                duration,
                expires_epoch,
            } => match expires_epoch {
                Some(t) => format!(
                    "✅ ALLOWED via Telegram + grant for {} (until {})",
                    duration.label(),
                    format_utc(t)
                ),
                None => "✅ ALLOWED via Telegram + grant until revoked".to_string(),
            },
            Outcome::DeclinedTelegram => "❌ DECLINED via Telegram".to_string(),
            Outcome::TimedOut => "⏱ TIMED OUT, automatically declined".to_string(),
            Outcome::AllowedLocally => "✅ ALLOWED locally (terminal)".to_string(),
            Outcome::DeclinedLocally => "❌ DECLINED locally (terminal)".to_string(),
            Outcome::Cancelled => "🚫 CANCELLED, request no longer pending".to_string(),
        }
    }
}

/// Strip control characters and truncate untrusted text for display.
pub fn sanitize(input: &str) -> String {
    let cleaned: String = input
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if cleaned.chars().count() > MAX_UNTRUSTED_LEN {
        let truncated: String = cleaned.chars().take(MAX_UNTRUSTED_LEN).collect();
        format!("{truncated}…")
    } else {
        cleaned
    }
}

/// Render a query for display, e.g. `domain "github.com"`.
pub fn render_query(query: &CredentialQuery) -> String {
    match query {
        CredentialQuery::Domain(d) => format!("domain \"{}\"", sanitize(d)),
        CredentialQuery::Id(id) => format!("vault item id \"{}\"", sanitize(id)),
        CredentialQuery::Search(s) => format!("search \"{}\"", sanitize(s)),
    }
}

/// Format seconds since the Unix epoch as `YYYY-MM-DD HH:MM:SS UTC`.
pub fn format_utc(epoch_secs: u64) -> String {
    let days = epoch_secs / 86_400;
    let secs_of_day = epoch_secs % 86_400;
    let (h, m, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );

    // Civil-from-days (Howard Hinnant), valid for all dates after 1970.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);

    format!("{year:04}-{month:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

/// Render the approval prompt text.
pub fn render_prompt(prompt: &ApprovalPrompt, timeout_secs: u64, now_secs: u64) -> String {
    match prompt {
        ApprovalPrompt::Credential {
            device,
            query,
            matched,
            request_id,
            timestamp,
        } => {
            let fields = if matched.fields.is_empty() {
                "none".to_string()
            } else {
                matched.fields.join(", ")
            };
            let item = match (&matched.domain, &matched.credential_id) {
                (Some(d), Some(id)) => format!("{} (id {})", sanitize(d), sanitize(id)),
                (Some(d), None) => sanitize(d),
                (None, Some(id)) => format!("id {}", sanitize(id)),
                (None, None) => "unknown".to_string(),
            };
            format!(
                "🔐 Agent Access: credential request\n\
                 \n\
                 Device: {device}\n\
                 Identity: {identity}\n\
                 Requested: {query}\n\
                 Matched item: {item}\n\
                 Fields to release: {fields}\n\
                 Reason: not provided (Agent Access protocol v0 has no purpose field)\n\
                 Request ID: {request_id}\n\
                 Sent by device at: {sent}\n\
                 Received at: {now}\n\
                 \n\
                 Allow 15m / 1h / forever: also auto-approve this device + query + item, silently, until the \
                 grant expires or is revoked (/grants).\n\
                 Auto-declines in {timeout_secs}s if unanswered.",
                device = device.render(),
                identity = device.identity.to_hex(),
                query = render_query(query),
                request_id = sanitize(request_id),
                sent = format_utc(*timestamp),
                now = format_utc(now_secs),
            )
        }
        ApprovalPrompt::Pairing {
            device,
            handshake_fingerprint,
        } => format!(
            "🔗 Agent Access: new device pairing\n\
             \n\
             Device: {device}\n\
             Identity: {identity}\n\
             Handshake fingerprint: {fp}\n\
             Received at: {now}\n\
             \n\
             Only allow if this fingerprint matches the one shown on the remote device.\n\
             Auto-declines in {timeout_secs}s if unanswered.",
            device = device.render(),
            identity = device.identity.to_hex(),
            fp = sanitize(handshake_fingerprint),
            now = format_utc(now_secs),
        ),
    }
}

/// Render the final message text: the original prompt (minus the countdown
/// line) followed by the outcome.
pub fn render_outcome(prompt_text: &str, outcome: Outcome, now_secs: u64) -> String {
    let body = prompt_text
        .lines()
        .filter(|l| !l.starts_with("Auto-declines in") && !l.starts_with("Allow 15m / 1h"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "{}\n{} at {}",
        body.trim_end(),
        outcome.render(),
        format_utc(now_secs)
    )
}

/// Render the `/grants` listing.
pub fn render_grant_list(grants: &[Grant]) -> String {
    if grants.is_empty() {
        return "No active grants. Every request will ask for approval.".to_string();
    }
    let mut out = String::from("Active grants (in memory, cleared when aac listen restarts):\n");
    for (i, g) in grants.iter().enumerate() {
        let expiry = match g.expires_epoch {
            Some(t) => format!("until {}", format_utc(t)),
            None => "until revoked".to_string(),
        };
        out.push_str(&format!("\n#{} {} · {}", i + 1, g.label, expiry));
    }
    out.push_str("\n\nRevoke with the buttons below, /revoke <number>, or /revoke all.");
    out
}

/// Help text for `/start` and `/help`.
pub const HELP_TEXT: &str = "Agent Access approval bot\n\
\n\
Credential requests from paired agents appear here with buttons:\n\
• Allow: release this one request\n\
• Allow 15m / Allow 1h / Allow forever: release it and auto-approve later requests \
from the same device for the same query and vault item\n\
• Decline: refuse\n\
\n\
Commands:\n\
/grants: list active grants\n\
/revoke <number>: revoke one grant\n\
/revoke all: revoke every grant";

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::zeroize::Zeroizing;

    fn credential() -> CredentialData {
        CredentialData {
            username: Some("alice@example.com".into()),
            password: Some(Zeroizing::new("hunter2-SUPER-SECRET".to_string())),
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            uri: Some("https://user:pw-in-uri@example.com/login".into()),
            notes: Some("recovery codes: 1111-2222".into()),
            credential_id: Some("cred-1".into()),
            domain: Some("example.com".into()),
        }
    }

    fn device() -> DeviceLabel {
        DeviceLabel {
            name: Some("openclaw-worker".into()),
            identity: IdentityFingerprint([0xab; 32]),
        }
    }

    fn credential_prompt() -> ApprovalPrompt {
        ApprovalPrompt::Credential {
            device: device(),
            query: CredentialQuery::Domain("example.com".into()),
            matched: CredentialSummary::from_credential(&credential()),
            request_id: "req-123".into(),
            timestamp: 1_791_400_000,
        }
    }

    #[test]
    fn prompt_contains_request_details() {
        let text = render_prompt(&credential_prompt(), 90, 1_791_400_005);
        assert!(text.contains("openclaw-worker (abababababab)"));
        assert!(text.contains(&"ab".repeat(32)));
        assert!(text.contains("domain \"example.com\""));
        assert!(text.contains("example.com (id cred-1)"));
        assert!(text.contains("Fields to release: username, password, totp, uri, notes"));
        assert!(text.contains("Request ID: req-123"));
        assert!(text.contains("Auto-declines in 90s"));
        assert!(text.contains("UTC"));
    }

    #[test]
    fn prompt_never_contains_secret_values() {
        let text = render_prompt(&credential_prompt(), 90, 1_791_400_005);
        for secret in [
            "hunter2-SUPER-SECRET",
            "JBSWY3DPEHPK3PXP",
            "recovery codes",
            "pw-in-uri",
            "alice@example.com",
        ] {
            assert!(!text.contains(secret), "leaked {secret:?} in:\n{text}");
        }
        let outcome = render_outcome(&text, Outcome::AllowedTelegram, 1_791_400_010);
        assert!(!outcome.contains("hunter2-SUPER-SECRET"));
    }

    #[test]
    fn outcome_replaces_countdown() {
        let text = render_prompt(&credential_prompt(), 90, 1_791_400_005);
        let done = render_outcome(&text, Outcome::DeclinedTelegram, 1_791_400_010);
        assert!(!done.contains("Auto-declines"));
        assert!(done.contains("DECLINED via Telegram"));
        assert!(done.contains("Request ID: req-123"));
    }

    #[test]
    fn pairing_prompt_shows_fingerprint() {
        let prompt = ApprovalPrompt::Pairing {
            device: DeviceLabel {
                name: None,
                identity: IdentityFingerprint([0x01; 32]),
            },
            handshake_fingerprint: "a1b2c3".into(),
        };
        let text = render_prompt(&prompt, 60, 0);
        assert!(text.contains("Handshake fingerprint: a1b2c3"));
        assert!(text.contains("unnamed device (010101010101)"));
    }

    #[test]
    fn sanitize_strips_control_chars_and_truncates() {
        assert_eq!(sanitize("a\nb\tc"), "a b c");
        let long = "x".repeat(500);
        let out = sanitize(&long);
        assert_eq!(out.chars().count(), MAX_UNTRUSTED_LEN + 1);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn untrusted_query_cannot_forge_lines() {
        let prompt = ApprovalPrompt::Credential {
            device: device(),
            query: CredentialQuery::Domain("evil.com\nMatched item: trusted-item".into()),
            matched: CredentialSummary::default(),
            request_id: "r\nReason: trusted".into(),
            timestamp: 0,
        };
        let text = render_prompt(&prompt, 30, 0);
        assert!(!text.contains("\nMatched item: trusted-item"));
        assert!(!text.contains("\nReason: trusted"));
    }

    #[test]
    fn format_utc_known_values() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(format_utc(1_791_403_200), "2026-10-07 20:00:00 UTC");
    }
}
