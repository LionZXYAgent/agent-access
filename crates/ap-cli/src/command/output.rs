//! Output formatting for single-shot (non-interactive) mode
//!
//! Provides structured output for agent/LLM consumption: JSON or plain text,
//! with well-defined exit codes for programmatic error handling.

use ap_client::{ClientError, CredentialData};
use clap::ValueEnum;

use crate::transport::local::{self, LocalTransportError};

/// Output format for single-shot mode
#[derive(Clone, Debug, Default, ValueEnum)]
pub enum OutputFormat {
    /// Plain text key: value lines (default)
    #[default]
    Text,
    /// Single JSON object
    Json,
}

/// Process exit codes for programmatic consumption
pub mod exit_code {
    pub const SUCCESS: i32 = 0;
    pub const GENERAL_ERROR: i32 = 1;
    pub const CONNECTION_FAILED: i32 = 2;
    pub const AUTH_HANDSHAKE_FAILED: i32 = 3;
    pub const CREDENTIAL_NOT_FOUND: i32 = 4;
    pub const FINGERPRINT_MISMATCH: i32 = 5;
    /// Local transport: `status: "denied"` — the user declined the request.
    pub const LOCAL_DENIED: i32 = 6;
    /// Local transport: `status: "locked"` — the vault is locked.
    pub const LOCAL_LOCKED: i32 = 7;
    /// Local transport: `status: "timeout"` — server-side approval timed out
    /// (distinct from the client-side read timeout, which surfaces as
    /// `LOCAL_TRANSPORT_ERROR`).
    pub const LOCAL_APPROVAL_TIMEOUT: i32 = 8;
    /// Local transport: `status: "rateLimited"`.
    pub const LOCAL_RATE_LIMITED: i32 = 9;
    /// Local transport: connection, protocol, or `status: "error"` failure.
    pub const LOCAL_TRANSPORT_ERROR: i32 = 10;
    /// Local transport, `delivery: "fill"` only: `status: "originMismatch"`
    /// — the active browser tab's origin doesn't match any saved website
    /// for the requested login. Refused mechanically, no prompt shown.
    pub const LOCAL_ORIGIN_MISMATCH: i32 = 11;
    /// Local transport, `delivery: "fill"` only: `status: "noSafeTarget"`
    /// — the origin matched but no requested field has a safe fill target.
    pub const LOCAL_NO_SAFE_TARGET: i32 = 12;
}

/// Map a `ClientError` to the appropriate exit code
pub fn exit_code_for_error(err: &ClientError) -> i32 {
    match err {
        ClientError::ConnectionFailed(_) | ClientError::WebSocket(_) => {
            exit_code::CONNECTION_FAILED
        }
        ClientError::RelayAuthFailed(_)
        | ClientError::HandshakeFailed(_)
        | ClientError::NoiseProtocol(_)
        | ClientError::Timeout(_)
        | ClientError::InvalidPairingCode(_)
        | ClientError::RendezvousResolutionFailed(_)
        | ClientError::InvalidRendezvousCode(_) => exit_code::AUTH_HANDSHAKE_FAILED,
        ClientError::CredentialRequestFailed(_) | ClientError::SecureChannelNotEstablished => {
            exit_code::CREDENTIAL_NOT_FOUND
        }
        ClientError::FingerprintRejected => exit_code::FINGERPRINT_MISMATCH,
        _ => exit_code::GENERAL_ERROR,
    }
}

/// Map a `LocalTransportError` to the appropriate exit code.
///
/// `ConnectFailed` reuses `CONNECTION_FAILED` (the request never reached
/// the server, same class of failure as a relay connection failure); the
/// remaining status-derived variants get their own codes since they have
/// no relay-path equivalent. `NotFound` reuses `CREDENTIAL_NOT_FOUND` —
/// same meaning as the relay path's "no matching item".
pub fn exit_code_for_local_error(err: &LocalTransportError) -> i32 {
    match err {
        LocalTransportError::ConnectFailed(_) => exit_code::CONNECTION_FAILED,
        LocalTransportError::NotFound(_) => exit_code::CREDENTIAL_NOT_FOUND,
        LocalTransportError::Denied(_) => exit_code::LOCAL_DENIED,
        LocalTransportError::Locked(_) => exit_code::LOCAL_LOCKED,
        LocalTransportError::ServerTimeout(_) => exit_code::LOCAL_APPROVAL_TIMEOUT,
        LocalTransportError::RateLimited(_) => exit_code::LOCAL_RATE_LIMITED,
        LocalTransportError::ReadTimeout
        | LocalTransportError::ResponseTooLarge
        | LocalTransportError::Protocol(_)
        | LocalTransportError::UnsupportedVersion(_)
        | LocalTransportError::Io(_)
        | LocalTransportError::ServerError(_) => exit_code::LOCAL_TRANSPORT_ERROR,
        LocalTransportError::OriginMismatch { .. } => exit_code::LOCAL_ORIGIN_MISMATCH,
        LocalTransportError::NoSafeTarget { .. } => exit_code::LOCAL_NO_SAFE_TARGET,
    }
}

/// Map any error surfaced from [`super::connect::fetch_credential_dispatch`]
/// to an exit code, regardless of which transport produced it.
pub fn exit_code_for_report(err: &color_eyre::eyre::Report) -> i32 {
    if let Some(local_err) = err.downcast_ref::<LocalTransportError>() {
        exit_code_for_local_error(local_err)
    } else if let Some(client_err) = err.downcast_ref::<ClientError>() {
        exit_code_for_error(client_err)
    } else {
        exit_code::GENERAL_ERROR
    }
}

/// Print a successful credential result as JSON to stdout
pub fn emit_json_success(credential: &CredentialData) {
    let obj = serde_json::json!({
        "success": true,
        "credential": credential,
    });
    println!("{obj}");
}

/// Print a successful *reference* result (local transport, `delivery:
/// "reference"`) as JSON to stdout. Never includes credential values —
/// only the opaque `bw://item/<id>` reference and a display name/username.
pub fn emit_json_reference(reference: &str, item_name: Option<&str>, item_username: Option<&str>) {
    let obj = serde_json::json!({
        "success": true,
        "reference": reference,
        "item": {
            "name": item_name,
            "username": item_username,
        },
    });
    println!("{obj}");
}

/// Print a successful *secret reference* result (local transport, `delivery:
/// "reference"`, `secretRequest`) as JSON to stdout. Never includes the
/// secret value — only the opaque `bw://secret/<id>` reference and the
/// secret's name. Secrets have no analogue of a credential's `username`.
pub fn emit_json_secret_reference(reference: &str, name: Option<&str>) {
    let obj = serde_json::json!({
        "success": true,
        "reference": reference,
        "secret": {
            "name": name,
        },
    });
    println!("{obj}");
}

/// Print an error as JSON to stdout
pub fn emit_json_error(message: &str, code: &str) {
    let obj = serde_json::json!({
        "success": false,
        "error": {
            "message": message,
            "code": code,
        }
    });
    println!("{obj}");
}

/// Return the string code name for an exit code constant
pub fn exit_code_name(code: i32) -> &'static str {
    match code {
        exit_code::SUCCESS => "success",
        exit_code::CONNECTION_FAILED => "connection_failed",
        exit_code::AUTH_HANDSHAKE_FAILED => "auth_handshake_failed",
        exit_code::CREDENTIAL_NOT_FOUND => "credential_not_found",
        exit_code::FINGERPRINT_MISMATCH => "fingerprint_mismatch",
        exit_code::LOCAL_DENIED => "denied",
        exit_code::LOCAL_LOCKED => "locked",
        exit_code::LOCAL_APPROVAL_TIMEOUT => "approval_timeout",
        exit_code::LOCAL_RATE_LIMITED => "rate_limited",
        exit_code::LOCAL_TRANSPORT_ERROR => "local_transport_error",
        exit_code::LOCAL_ORIGIN_MISMATCH => "origin_mismatch",
        exit_code::LOCAL_NO_SAFE_TARGET => "no_safe_target",
        _ => "general_error",
    }
}

/// Print a credential result as plain text key: value lines to stdout
pub fn emit_text_credential(credential: &CredentialData) {
    if let Some(domain) = &credential.domain {
        println!("domain: {domain}");
    }
    if let Some(username) = &credential.username {
        println!("username: {username}");
    }
    if let Some(password) = &credential.password {
        println!("password: {}", password.as_str());
    }
    if let Some(totp) = &credential.totp {
        println!("totp: {totp}");
    }
    if let Some(uri) = &credential.uri {
        println!("uri: {uri}");
    }
    if let Some(notes) = &credential.notes {
        println!("notes: {notes}");
    }
    if let Some(credential_id) = &credential.credential_id {
        println!("credential_id: {credential_id}");
    }
}

/// Print a *reference* result (local transport, `delivery: "reference"`)
/// as plain text. Never prints credential values.
pub fn emit_text_reference(reference: &str, item_name: Option<&str>, item_username: Option<&str>) {
    println!("reference: {reference}");
    if let Some(name) = item_name {
        println!("name: {name}");
    }
    if let Some(username) = item_username {
        println!("username: {username}");
    }
}

/// Print a successful *secret reference* result (local transport, `delivery:
/// "reference"`, `secretRequest`) as plain text. Never prints the secret
/// value.
pub fn emit_text_secret_reference(reference: &str, name: Option<&str>) {
    println!("reference: {reference}");
    if let Some(name) = name {
        println!("name: {name}");
    }
}

// ── browser fill (architecture doc, M5) ──────────────────────────────────

/// Print a successful `fill_credential`/`aac fill` outcome as JSON to
/// stdout. Value-free by construction, like [`local::FillOutcome`] itself —
/// only status, origin, reference, item metadata, and per-field outcome
/// descriptors, never a value.
pub fn emit_json_fill(outcome: &local::FillOutcome) {
    let fields: Vec<serde_json::Value> = outcome
        .fields
        .iter()
        .map(|f| {
            serde_json::json!({
                "role": f.role,
                "status": f.status,
                "target": f.target,
                "reason": f.reason,
            })
        })
        .collect();
    let obj = serde_json::json!({
        "success": true,
        "status": outcome.status,
        "origin": outcome.origin,
        "reference": outcome.reference,
        "item": outcome.item.as_ref().map(|item| serde_json::json!({
            "name": item.name,
            "username": item.username,
        })),
        "reason": outcome.reason,
        "fields": fields,
    });
    println!("{obj}");
}

/// Print a successful `fill_credential`/`aac fill` outcome as plain text.
/// Never prints a credential value.
pub fn emit_text_fill(outcome: &local::FillOutcome) {
    println!("status: {}", outcome.status);
    if let Some(origin) = &outcome.origin {
        println!("origin: {origin}");
    }
    if let Some(reference) = &outcome.reference {
        println!("reference: {reference}");
    }
    if let Some(item) = &outcome.item {
        if let Some(name) = &item.name {
            println!("name: {name}");
        }
        if let Some(username) = &item.username {
            println!("username: {username}");
        }
    }
    if let Some(reason) = &outcome.reason {
        println!("reason: {reason}");
    }
    for field in &outcome.fields {
        let target = field.target.as_deref().unwrap_or("-");
        match &field.reason {
            Some(reason) => println!(
                "field: {} {} {} ({reason})",
                field.role, field.status, target
            ),
            None => println!("field: {} {} {}", field.role, field.status, target),
        }
    }
}

/// Print a successful `describe_fill_target`/`aac describe-fill-target`
/// result as JSON to stdout. Vault-free and value-free — a read-only
/// description of the active browser tab (architecture doc, M5 §4.2).
pub fn emit_json_describe_fill_target(target: &local::WireFillTarget) {
    let candidates: Vec<serde_json::Value> = target
        .candidates
        .iter()
        .map(|c| {
            serde_json::json!({
                "role": c.role,
                "target": c.target,
                "visible": c.visible,
                "frame": c.frame,
            })
        })
        .collect();
    let refusals: Vec<serde_json::Value> = target
        .refusals
        .iter()
        .map(|r| serde_json::json!({"role": r.role, "reason": r.reason}))
        .collect();
    let obj = serde_json::json!({
        "origin": target.origin,
        "formClass": target.form_class,
        "candidates": candidates,
        "refusals": refusals,
        "targetToken": target.target_token,
        "expiresInMs": target.expires_in_ms,
    });
    println!("{obj}");
}

/// Print a successful `describe_fill_target`/`aac describe-fill-target`
/// result as plain text.
pub fn emit_text_describe_fill_target(target: &local::WireFillTarget) {
    println!("origin: {}", target.origin);
    println!("formClass: {}", target.form_class);
    for c in &target.candidates {
        println!(
            "candidate: {} {} visible={} frame={}",
            c.role,
            c.target,
            c.visible,
            c.frame.as_deref().unwrap_or("-")
        );
    }
    for r in &target.refusals {
        println!("refusal: {} {}", r.role, r.reason);
    }
    if let Some(token) = &target.target_token {
        println!("targetToken: {token}");
    }
    if let Some(ms) = target.expires_in_ms {
        println!("expiresInMs: {ms}");
    }
}
