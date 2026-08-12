//! `aac mcp` — Model Context Protocol server over stdio.
//!
//! Exposes the local wire protocol (`crate::transport::local`) to MCP
//! clients (Claude Code, Cursor, ...) as two tools:
//!
//! - `find_logins` — `delivery: "reference"`. Never returns a secret value;
//!   only an item name, a username, and an opaque `bw://item/<id>`
//!   reference.
//! - `run_with_credential` — `delivery: "inject"`. Injects the credential
//!   into a child process's environment and scrubs it from the child's
//!   captured stdout/stderr using the same [`Redactor`] that `aac run`
//!   uses — reused here, not reimplemented.
//!
//! It also serves precomputed secret-scan findings as an MCP resource
//! (`bitwarden://scan/findings`) and as a read-only `get_secret_findings`
//! tool for clients that don't surface resources. The findings themselves
//! come from `.bitwarden/secret-findings.json`, an artifact produced by
//! `bws scan` (the Secrets Manager CLI, backed by the `bitwarden-scan`
//! engine crate in `sdk-sm`) — **this server contains no scanner and no
//! request it handles ever triggers a scan**; see `findings_artifact` for
//! the artifact's schema and `plans/secret-scanning.md` for the split.
//! Both the resource and the tool re-read the artifact from disk on every
//! call — there is no in-memory cache and so nothing to invalidate: served
//! data is always as fresh as the last completed `bws scan`, and no
//! server-initiated notification is needed (or offered) to signal a
//! change. The served artifact never contains a matched secret value, only
//! masked previews. "Never scanned" (no artifact yet), "scanned, zero
//! findings" (an artifact with an empty list), and "artifact unreadable"
//! are always distinguishable via an explicit `status` field, so an empty
//! findings list is never mistaken for an all-clear.
//!
//! Framing is newline-delimited JSON, as the MCP stdio transport specifies:
//! exactly one JSON-RPC 2.0 message per line, with no headers and no embedded
//! newlines in the body. (LSP-style `Content-Length` headers are a *different*
//! protocol's framing — MCP does not use them.) **Only JSON-RPC frames may ever
//! be written to stdout** — it is the protocol channel. This module never
//! writes anything else to the writer it is given, and `main.rs` routes all
//! `tracing` output to stderr specifically for this subcommand so a log line
//! can never land mid-frame on the real process stdout.
//!
//! Tool-level failures (desktop unreachable, denied, not found, locked,
//! timeout, ...) are reported as MCP tool results with `isError: true`, per
//! the MCP spec — they are not JSON-RPC protocol errors. Only malformed
//! JSON-RPC and unknown methods are protocol-level errors (`-32700`,
//! `-32601`, `-32602`). No credential value is ever placed in a tool result,
//! a protocol error, or a log line.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ap_client::CredentialQuery;
use clap::Args;
use color_eyre::eyre::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::sync::mpsc;

use super::findings_artifact;
use super::redact::Redactor;
use crate::transport::local::{
    self, FillInput, LocalEndpoint, LocalTransportError, SecretCreateInput, SecretOutcome,
    SecretQueryInput, WireDelivery, WireOutcome,
};
use zeroize::Zeroizing;

/// MCP protocol version this server speaks (the 2024-11-05 stdio spec
/// revision — the one JSON-RPC surface implemented here: `initialize`,
/// `notifications/initialized`, `tools/list`, `tools/call`).
const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

const SERVER_NAME: &str = "bitwarden-agent-access";

// JSON-RPC 2.0 reserved error codes used here.
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
// MCP-defined (not JSON-RPC-reserved) error code: "Resource not found", per
// the MCP resources spec.
const RESOURCE_NOT_FOUND: i64 = -32002;

/// The one resource this server exposes: precomputed secret-scan findings
/// (plan §2/§3), read fresh from disk on every request. Read-only — there
/// is no scan this server can trigger, and no subscribe/notify support,
/// since without an in-process producer there is no reliable change signal
/// to subscribe to.
const FINDINGS_URI: &str = "bitwarden://scan/findings";

/// Run `aac` as an MCP server over stdio.
#[derive(Args)]
pub struct McpArgs {
    /// Local agent-access endpoint to use instead of the platform default
    /// (unix socket path / windows pipe name). Every tool call opens a
    /// fresh connection to this endpoint — there is no relay fallback for
    /// MCP: the Bitwarden desktop app must be reachable locally.
    #[arg(long, env = "AAC_SOCKET")]
    pub socket: Option<String>,

    /// Repository root to scan for secret findings, used for the
    /// `bitwarden://scan/findings` resource and the `get_secret_findings`
    /// tool. Defaults to `git rev-parse --show-toplevel` from the current
    /// working directory — MCP clients don't always launch the server with
    /// cwd set to the project directory (Claude Desktop uses `/` or
    /// `$HOME`). If neither resolves to a git repository, the server never
    /// walks an arbitrary directory tree: it serves an explicit `no_repo`
    /// state instead.
    #[arg(long)]
    pub repo: Option<PathBuf>,
}

impl McpArgs {
    pub async fn run(self) -> Result<()> {
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();
        serve(BufReader::new(stdin), stdout, self.socket, self.repo).await;
        Ok(())
    }
}

// ── secret-scan serving context ─────────────────────────────────────────

/// Server context `serve` builds once at startup and threads through
/// `process_frame`/`handle_request`, in place of the old mutable
/// `ScanState`. Nothing here is ever mutated after construction: every
/// `resources/read` and `get_secret_findings` call re-reads the findings
/// artifact from disk (see [`build_envelope`]) rather than consulting an
/// in-memory cache, so there is nothing to keep in sync and no notification
/// mechanism is needed.
struct McpContext {
    /// Resolved once at startup: `--repo` if given, else `git rev-parse
    /// --show-toplevel` from the server's cwd, else `None` ("no_repo" — no
    /// directory tree is ever walked in that state, and none of this
    /// module's I/O touches an arbitrary path unprompted).
    repo_root: Option<PathBuf>,
}

type SharedContext = Arc<McpContext>;

/// Resolve the repo root findings are read relative to: `--repo` if given,
/// else `git rev-parse --show-toplevel` from the current working
/// directory. Tolerates git being absent, erroring, or the cwd not being
/// inside a repository — `None` in every such case, never a panic.
async fn resolve_repo_root(repo_override: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(path) = repo_override {
        return Some(path);
    }
    let output = tokio::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let trimmed = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

/// Build the context `serve` runs with. Resolving the repo root is the only
/// startup work: it never reads the findings artifact and never scans —
/// both happen fresh on demand, per request (see [`build_envelope`]).
async fn build_context(repo_override: Option<PathBuf>) -> McpContext {
    McpContext {
        repo_root: resolve_repo_root(repo_override).await,
    }
}

/// Told to the agent when `status` is `no_repo` or `never_scanned`: this
/// server never scans, so findings only ever come from running `bws scan`
/// (the Bitwarden Secrets Manager CLI) out of band.
const NO_REPO_HINT: &str = "No git repository was resolved for this MCP server (no --repo flag \
    was given, and `git rev-parse --show-toplevel` did not resolve one from the server's working \
    directory), so no findings artifact can be located. This server never scans on its own: run \
    `bws scan` (the Bitwarden Secrets Manager CLI) inside the target repository to produce \
    .bitwarden/secret-findings.json, then point this server at it with --repo.";

const NEVER_SCANNED_HINT: &str = "No findings artifact has been produced for this repository \
    yet. This server never scans on its own: run `bws scan` (the Bitwarden Secrets Manager CLI) \
    in the repo to produce .bitwarden/secret-findings.json.";

/// The `{status, repo_root, report, remediation, ...}` envelope served by
/// both `resources/read` and the `get_secret_findings` tool (plan §3).
/// Always an envelope, never the bare artifact — `status` is what lets a
/// consumer distinguish "never scanned" from "scanned, zero findings"
/// instead of reading an empty `findings` array as an all-clear. Reads the
/// artifact fresh from disk every call — no cache, so nothing here can ever
/// go stale relative to the last `bws scan`. Every status keeps `isError:
/// false` at the tool-result layer: these are data states, not protocol or
/// tool failures.
fn build_envelope(repo_root: Option<&Path>) -> Value {
    let Some(repo_root) = repo_root else {
        return json!({
            "status": "no_repo",
            "repo_root": Value::Null,
            "report": Value::Null,
            "remediation": remediation_json(),
            "hint": NO_REPO_HINT,
        });
    };

    match findings_artifact::load_artifact(repo_root) {
        Ok(None) => json!({
            "status": "never_scanned",
            "repo_root": repo_root.display().to_string(),
            "report": Value::Null,
            "remediation": remediation_json(),
            "hint": NEVER_SCANNED_HINT,
        }),
        Ok(Some(report)) => json!({
            "status": "ready",
            "repo_root": repo_root.display().to_string(),
            "report": serde_json::to_value(&report).unwrap_or(Value::Null),
            "remediation": remediation_json(),
        }),
        Err(e) => {
            tracing::warn!(
                "mcp: findings artifact at {} is not usable: {e}",
                repo_root.display()
            );
            json!({
                "status": "artifact_error",
                "repo_root": repo_root.display().to_string(),
                "report": Value::Null,
                "remediation": remediation_json(),
                // The error CLASS only — never file contents or the full
                // `Display` text, which could embed a path or JSON detail.
                "error": e.class(),
            })
        }
    }
}

/// Remediation guidance (plan §5). Worktree findings loop back through the
/// existing `create_secret`/`run_with_secret` tools; history findings
/// cannot be edited away — the secret is already distributed to every
/// clone, so the only correct action is rotating it at the provider.
fn remediation_json() -> Value {
    json!({
        "worktree": "Use create_secret to store the value in Bitwarden Secrets Manager, then \
            replace the literal with a bw://secret/<id> reference injected via run_with_secret.",
        "history": "The secret is already distributed to every clone: rotate it at the \
            provider. Do not attempt to rewrite git history.",
    })
}

/// Drive the JSON-RPC request/response loop until stdin closes. Never
/// returns an error — framing/IO failures are logged (to stderr, via
/// `tracing`) and end the loop, matching "exits when stdin closes."
///
/// `tools/call` is the one method that can block on a desktop approval for
/// up to ~60s (client read timeout 120s), so it alone is dispatched onto its
/// own `tokio::spawn` task; its eventual response is delivered back through
/// `tx`/`rx` instead of being written inline. Every other method
/// (`initialize`, `ping`, `tools/list`, ...) is cheap and answered inline.
/// Either way, only this loop ever touches `writer` — inline responses and
/// channel-delivered ones are written one at a time via the same `await`
/// point, so frames can never interleave on stdout, and a pending approval
/// never blocks answering a `ping` or a second concurrent `tools/call`.
async fn serve<R, W>(
    mut reader: R,
    mut writer: W,
    socket_override: Option<String>,
    repo_override: Option<PathBuf>,
) where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let socket_override = Arc::new(socket_override);
    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    // Holds this loop's own sender clone. Set to `None` once stdin closes so
    // that, once every spawned `tools/call` task finishes and drops its own
    // clone, `rx.recv()` observes the channel as closed and the loop can
    // exit instead of waiting forever on a response that will never come.
    let mut tx_holder = Some(tx);
    let mut stdin_open = true;

    // Resolving the repo root is the only startup work — fast (a single
    // `git rev-parse`, no file I/O), so it's fine to await inline here
    // before the loop starts. Nothing about the findings artifact is
    // touched yet: that happens fresh on every `resources/read` and
    // `get_secret_findings` call.
    let context: SharedContext = Arc::new(build_context(repo_override).await);

    loop {
        let response = tokio::select! {
            frame = read_frame(&mut reader), if stdin_open => {
                match frame {
                    Ok(Some(bytes)) => {
                        let tx = tx_holder.as_ref().expect("stdin_open implies tx_holder is Some");
                        process_frame(bytes, &socket_override, &context, tx).await
                    }
                    Ok(None) => {
                        stdin_open = false;
                        tx_holder = None;
                        continue;
                    }
                    Err(e) => {
                        tracing::error!("mcp: framing error, closing: {e}");
                        break;
                    }
                }
            }
            Some(response) = rx.recv() => Some(response),
            else => break,
        };

        if let Some(response) = response {
            if let Err(e) = write_frame(&mut writer, &response).await {
                tracing::error!("mcp: failed to write response, closing: {e}");
                break;
            }
        }
    }
}

/// Handle one already-read frame. Parse errors, malformed requests, and
/// every method other than `tools/call` are answered inline (`Some`).
/// `tools/call` is spawned onto its own task instead — its response arrives
/// later on `tx`, and this function returns `None` for it immediately so
/// the read loop can keep going without waiting on it.
async fn process_frame(
    bytes: Vec<u8>,
    socket_override: &Arc<Option<String>>,
    context: &SharedContext,
    tx: &mpsc::UnboundedSender<Value>,
) -> Option<Value> {
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return Some(make_error_response(Value::Null, PARSE_ERROR, "Parse error")),
    };

    let request: RpcRequest = match serde_json::from_value(value.clone()) {
        Ok(r) => r,
        Err(_) => {
            let id = value.get("id").cloned().unwrap_or(Value::Null);
            return Some(make_error_response(id, INVALID_REQUEST, "Invalid Request"));
        }
    };

    if request.method == "tools/call" {
        let tx = tx.clone();
        let socket_override = Arc::clone(socket_override);
        let context = Arc::clone(context);
        tokio::spawn(async move {
            if let Some(response) = handle_request(request, &socket_override, &context).await {
                // Receiver gone means the server is already shutting down;
                // there's nothing left to deliver the response to.
                let _ = tx.send(response);
            }
        });
        None
    } else {
        handle_request(request, socket_override, context).await
    }
}

// ── newline-delimited JSON framing ──────────────────────────────────────

/// Read one newline-delimited JSON message. Blank lines are skipped rather
/// than treated as messages, so a client that pads with extra newlines does
/// not provoke a spurious parse error. Returns `Ok(None)` on clean EOF
/// (stdin closed).
async fn read_frame<R: AsyncBufRead + Unpin>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(None);
        }
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed.as_bytes().to_vec()));
        }
    }
}

/// Write one newline-delimited JSON-RPC message. `serde_json::to_vec` never
/// emits a bare newline inside its output, so the trailing `\n` is
/// unambiguously the frame terminator.
async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, value: &Value) -> std::io::Result<()> {
    let mut body = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    body.push(b'\n');
    writer.write_all(&body).await?;
    writer.flush().await
}

// ── JSON-RPC request/response shapes ────────────────────────────────────

/// A parsed JSON-RPC request or notification. `id` is `None` for
/// notifications (no reply expected/allowed).
#[derive(Debug, Deserialize)]
struct RpcRequest {
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

fn make_result_response(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn make_error_response(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Dispatch one parsed request/notification. Returns `None` when no reply
/// should be sent (notifications, and unknown methods on a notification).
async fn handle_request(
    request: RpcRequest,
    socket_override: &Option<String>,
    context: &SharedContext,
) -> Option<Value> {
    let is_notification = request.id.is_none();
    let id = request.id.unwrap_or(Value::Null);

    match request.method.as_str() {
        "initialize" => Some(make_result_response(id, initialize_result())),
        "notifications/initialized" => None,
        // Liveness check: MCP clients may ping while a `tools/call` is
        // pending on a desktop approval (up to ~60s) — reply immediately
        // with an empty result rather than falling through to
        // METHOD_NOT_FOUND, so the client doesn't mistake a slow approval
        // for a dead server.
        "ping" => Some(make_result_response(id, json!({}))),
        // Best-effort: acknowledged as a no-op notification rather than
        // erroring. Actually aborting the in-flight `tools/call` task this
        // refers to would need a request-id -> task-handle map, which this
        // server doesn't keep; not erroring is the contract this satisfies.
        "notifications/cancelled" => None,
        "tools/list" => Some(make_result_response(id, tools_list_result())),
        "tools/call" => {
            let outcome = handle_tools_call(request.params, socket_override, context).await;
            if is_notification {
                None
            } else {
                Some(match outcome {
                    Ok(result) => make_result_response(id, result),
                    Err((code, message)) => make_error_response(id, code, &message),
                })
            }
        }
        "resources/list" => Some(make_result_response(id, resources_list_result())),
        "resources/read" => Some(match handle_resources_read(request.params, context) {
            Ok(result) => make_result_response(id, result),
            Err((code, message)) => make_error_response(id, code, &message),
        }),
        // No `resources/subscribe`/`resources/unsubscribe`: without an
        // in-process producer there is no reliable change signal to
        // subscribe to (see the module doc), so these fall through to the
        // same METHOD_NOT_FOUND as any other unknown method.
        _ if is_notification => None,
        _ => Some(make_error_response(
            id,
            METHOD_NOT_FOUND,
            "Method not found",
        )),
    }
}

/// Server-level guidance surfaced to the model by MCP clients (optional
/// `instructions` on `InitializeResult`, MCP 2024-11-05).
///
/// This is the right home for guidance that spans tools — routing between them
/// and the fact that approvals cost the user something. Per-tool "when to call
/// me" guidance belongs in each tool's own `description`; a preference for one
/// tool must never be written into a rival tool's description, where it reads
/// as scolding and drifts out of sync when either tool changes.
const SERVER_INSTRUCTIONS: &str = "\
This server reaches a Bitwarden vault the user controls. Most tools open an approval prompt in the \
Bitwarden desktop app, which the user must answer before the call returns — so each call costs them \
an interruption. Prefer one tool that does the whole job over a lookup followed by an action.

In particular, to log into a website in the user's browser, call `fill_credential` directly with the \
site's domain. It resolves the login itself, so `find_logins` beforehand is a second approval prompt \
that buys nothing — and unlike `fill_credential`, `find_logins` does release vault data to you (an \
item name and username). Look a login up first only when you genuinely need to show the user what \
matched, or to disambiguate between several accounts on one site.";

fn initialize_result() -> Value {
    json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")},
        "capabilities": {
            "tools": {},
            // Resources, but no `subscribe`/`listChanged`: there is no
            // in-process producer to raise a change notification from, so
            // the capability advertises only that resources exist.
            "resources": {},
        },
        "instructions": SERVER_INSTRUCTIONS,
    })
}

fn tools_list_result() -> Value {
    json!({"tools": [
        find_logins_tool_def(),
        run_with_credential_tool_def(),
        find_secrets_tool_def(),
        run_with_secret_tool_def(),
        create_secret_tool_def(),
        get_secret_findings_tool_def(),
        fill_credential_tool_def(),
        describe_fill_target_tool_def(),
    ]})
}

// ── resources (secret-scan findings) ────────────────────────────────────

fn resource_def() -> Value {
    json!({
        "uri": FINDINGS_URI,
        "name": "Secret scan findings",
        "mimeType": "application/json",
        "description": "Precomputed, deterministic secret-scan findings for this repository, \
            produced out of band by `bws scan` (the Bitwarden Secrets Manager CLI) and read \
            fresh from disk on every read of this resource — this server contains no scanner \
            and reading it never triggers a scan. Never contains a secret value: only file \
            locations, rule ids, and masked previews.",
    })
}

fn resources_list_result() -> Value {
    json!({"resources": [resource_def()]})
}

/// Pull `params.uri` out of a `resources/*` request. Missing/malformed
/// `params` (or a non-string/missing `uri`) is `INVALID_PARAMS`, per
/// JSON-RPC's "Invalid params" — distinct from an unknown-but-well-formed
/// `uri`, which is `RESOURCE_NOT_FOUND`.
fn extract_uri(params: Option<Value>) -> Result<String, (i64, String)> {
    let params = params.ok_or_else(|| (INVALID_PARAMS, "params.uri is required".to_string()))?;
    params
        .get("uri")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| (INVALID_PARAMS, "params.uri must be a string".to_string()))
}

fn unknown_resource_error(uri: &str) -> (i64, String) {
    (RESOURCE_NOT_FOUND, format!("Resource not found: {uri}"))
}

fn handle_resources_read(
    params: Option<Value>,
    context: &SharedContext,
) -> Result<Value, (i64, String)> {
    let uri = extract_uri(params)?;
    if uri != FINDINGS_URI {
        return Err(unknown_resource_error(&uri));
    }

    let envelope = build_envelope(context.repo_root.as_deref());

    Ok(json!({
        "contents": [{
            "uri": FINDINGS_URI,
            "mimeType": "application/json",
            "text": envelope.to_string(),
        }],
    }))
}

fn find_logins_tool_def() -> Value {
    json!({
        "name": "find_logins",
        "description": "Look up saved Bitwarden logins matching a domain or a free-text \
            search. Requires the user to approve this request in the Bitwarden desktop app, \
            which must be open and unlocked — the call fails if it isn't. Never returns a \
            password, TOTP code, or note: only an item name, a username, and an opaque \
            bw://item/<id> reference you can pass to run_with_credential. Call this when you \
            need to see which logins exist — to show the user what matched, or to pick between \
            several accounts on one site. It is not a required first step: run_with_credential \
            and fill_credential both accept a domain or name directly, and calling this first \
            adds an approval prompt and releases an item name and username you may not need.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Domain (e.g. \"github.com\") or free-text search, \
                        depending on queryType.",
                },
                "queryType": {
                    "type": "string",
                    "enum": ["domain", "search"],
                    "default": "domain",
                    "description": "How to interpret 'query'. Defaults to 'domain'.",
                },
            },
            "required": ["query"],
            "additionalProperties": false,
        },
    })
}

fn run_with_credential_tool_def() -> Value {
    json!({
        "name": "run_with_credential",
        "description": "Run a local command with a Bitwarden login injected into its \
            environment (AAC_USERNAME, AAC_PASSWORD, AAC_TOTP, AAC_URI). Requires the user to \
            approve this request in the Bitwarden desktop app, which must be open and unlocked \
            — the call fails if it isn't. The credential value is never returned to you: it is \
            injected only into the child process's environment, and any occurrence of the \
            password or TOTP is scrubbed from the command's captured stdout/stderr before being \
            returned. Provide exactly one of 'query' (a domain or search text) or 'reference' \
            (a bw://item/<id> value returned by find_logins).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Domain or free-text search identifying the login to \
                        inject. Mutually exclusive with 'reference'; exactly one is required.",
                },
                "reference": {
                    "type": "string",
                    "description": "A bw://item/<id> reference previously returned by \
                        find_logins. Mutually exclusive with 'query'; exactly one is required.",
                },
                "queryType": {
                    "type": "string",
                    "enum": ["domain", "search"],
                    "default": "domain",
                    "description": "How to interpret 'query' (ignored when 'reference' is \
                        used). Defaults to 'domain'.",
                },
                "command": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "description": "Command and arguments to execute, e.g. [\"psql\", \"-h\", \
                        \"localhost\", \"-U\", \"$AAC_USERNAME\"]. The credential is injected \
                        into this process's environment, not passed as an argument.",
                },
            },
            "required": ["command"],
            "additionalProperties": false,
        },
    })
}

fn find_secrets_tool_def() -> Value {
    json!({
        "name": "find_secrets",
        "description": "Look up Bitwarden Secrets Manager secrets matching a name or free-text \
            search. Requires the user to approve this request in the Bitwarden desktop app, \
            which must be open and unlocked — the call fails if it isn't. Never returns a \
            secret value: only a name and an opaque bw://secret/<id> reference you can pass to \
            run_with_secret.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Secret name or free-text search.",
                },
            },
            "required": ["query"],
            "additionalProperties": false,
        },
    })
}

fn run_with_secret_tool_def() -> Value {
    json!({
        "name": "run_with_secret",
        "description": "Run a local command with a Bitwarden Secrets Manager secret injected \
            into its environment. Requires the user to approve this request in the Bitwarden \
            desktop app, which must be open and unlocked — the call fails if it isn't. The \
            secret value is never returned to you: it is injected only into the child \
            process's environment, and any occurrence of it is scrubbed from the command's \
            captured stdout/stderr before being returned. Provide exactly one of 'name' (the \
            secret's name) or 'reference' (a bw://secret/<id> value returned by find_secrets).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Secret name to inject. Mutually exclusive with \
                        'reference'; exactly one is required.",
                },
                "reference": {
                    "type": "string",
                    "description": "A bw://secret/<id> reference previously returned by \
                        find_secrets. Mutually exclusive with 'name'; exactly one is required.",
                },
                "env": {
                    "type": "string",
                    "description": "Environment variable name the secret value is injected \
                        under. Defaults to the secret's own name, uppercased with every \
                        character outside [A-Z0-9_] replaced by '_' (and '_'-prefixed if it \
                        would otherwise start with a digit).",
                },
                "command": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "description": "Command and arguments to execute. The secret is injected \
                        into this process's environment, not passed as an argument.",
                },
            },
            "required": ["command"],
            "additionalProperties": false,
        },
    })
}

fn create_secret_tool_def() -> Value {
    json!({
        "name": "create_secret",
        "description": "Create a new Bitwarden Secrets Manager secret. The value you provide is \
            encrypted and stored in Bitwarden Secrets Manager — it is never included in this \
            tool's result or in any error message. Requires the user to approve this request in \
            the Bitwarden desktop app, which must be open and unlocked — the call fails if it \
            isn't. The returned reference can be used with run_with_secret to inject the value \
            into a command's environment. Use this to migrate hardcoded credentials or values \
            from a .env file into a managed secret instead of leaving them in plaintext.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name (key) for the new secret.",
                },
                "value": {
                    "type": "string",
                    "description": "Value to store. Encrypted before storage; never returned by \
                        this tool.",
                },
                "note": {
                    "type": "string",
                    "description": "Optional note stored alongside the secret.",
                },
                "project": {
                    "type": "string",
                    "description": "Optional project name hint. This is only a hint: the user \
                        always sees and can change the selected project in the approval dialog \
                        before the secret is created.",
                },
            },
            "required": ["name", "value"],
            "additionalProperties": false,
        },
    })
}

/// Compatibility path for MCP clients that don't surface resources (plan
/// §3). Description deliberately spells out every property an agent needs
/// to act correctly on a finding without the model having to infer it: the
/// scan is precomputed/deterministic/non-AI and runs elsewhere (`bws
/// scan`), this tool never runs one, provenance must be checked for
/// staleness, values are never included, and the two remediation paths
/// differ (migrate vs. rotate).
fn get_secret_findings_tool_def() -> Value {
    json!({
        "name": "get_secret_findings",
        "description": "Return precomputed secret-scan findings for this repository, read \
            fresh from the on-disk findings artifact on every call. Findings come from a \
            deterministic, rule-based scan — regex/entropy detectors, no AI and no guessing — \
            run out of band by `bws scan` (the Bitwarden Secrets Manager CLI); this server \
            contains no scanner, and this tool never triggers a scan itself, so calling it \
            repeatedly will not produce fresher results unless `bws scan` has run again in the \
            meantime. Every response carries provenance (generated_at, head_commit, dirty) that \
            you MUST check against the current repo state for staleness before acting on a \
            finding — the file may have already been fixed since the scan ran. Finding previews \
            are masked: the actual secret value is never included here, so read the file at the \
            finding's path:line if you need the literal. For a worktree finding, migrate it \
            with create_secret and replace the literal with a bw://secret/<id> reference \
            injected via run_with_secret. For a history finding, the secret is already \
            distributed to every clone of the repository, so the correct action is to rotate it \
            at the provider — do not attempt to rewrite git history.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": false,
        },
    })
}

// ── fill_credential / describe_fill_target (architecture doc, M5) ────────

fn fill_credential_tool_def() -> Value {
    json!({
        "name": "fill_credential",
        "description": "Fill a Bitwarden login into the active tab of the user's browser. \
            Requires the Bitwarden desktop app to be open and unlocked, the Bitwarden browser \
            extension to be installed and connected, and the user to approve this request. The \
            credential value is never returned to you and never passes through this tool — the \
            desktop app hands it directly to the browser extension, which fills the form. You \
            cannot choose which tab, origin, or field is filled: the extension fills its active \
            tab, refuses outright if that tab's origin does not match the login's saved URIs, \
            and refuses to write a password anywhere but a password input. Navigate to the \
            login page first, then call this — optionally calling describe_fill_target first to \
            see what would be filled. Provide exactly one of 'domain', 'name', or 'reference' \
            ('name' performs a free-text search). Call this directly with the site's domain \
            whenever the user wants to log into a website: it resolves the login itself, so \
            looking one up beforehand only adds a second approval prompt and releases vault \
            data this tool would not have released.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain (e.g. \"bitnotes.io\") identifying the login to \
                        fill. Mutually exclusive with 'name' and 'reference'; exactly one is \
                        required.",
                },
                "name": {
                    "type": "string",
                    "description": "Free-text search identifying the login to fill. Mutually \
                        exclusive with 'domain' and 'reference'; exactly one is required.",
                },
                "reference": {
                    "type": "string",
                    "description": "A bw://item/<id> reference previously returned by \
                        find_logins. Mutually exclusive with 'domain' and 'name'; exactly one \
                        is required.",
                },
                "fields": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["username", "password", "totp"]},
                    "description": "Which fields to fill. Defaults to every field present on \
                        the item that has a safe target on the page.",
                },
                "target_token": {
                    "type": "string",
                    "description": "A target_token from a prior describe_fill_target call, to \
                        guarantee this fill matches exactly the plan described there.",
                },
            },
            "additionalProperties": false,
        },
    })
}

fn describe_fill_target_tool_def() -> Value {
    json!({
        "name": "describe_fill_target",
        "description": "Describe the login form in the active tab of the user's browser: its \
            origin, which fields would be filled for which role, and why any field would be \
            skipped. Returns no vault data and no credential values, and requires no approval. \
            Use it before fill_credential to check the page is what you expect, and to handle \
            multi-step logins where the username and password are on separate pages. Returns a \
            target_token that fill_credential accepts to guarantee it fills exactly the plan \
            described here.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
    })
}

/// Dispatch a `tools/call`. `Err` is a genuine protocol-level problem
/// (malformed `params`/`name`, per JSON-RPC's `Invalid params`); everything
/// else — including every credential-lookup failure — becomes an `Ok` tool
/// result with `isError` set, per MCP's tool-result-vs-protocol-error split.
async fn handle_tools_call(
    params: Option<Value>,
    socket_override: &Option<String>,
    context: &SharedContext,
) -> Result<Value, (i64, String)> {
    let params =
        params.ok_or_else(|| (INVALID_PARAMS, "tools/call requires params".to_string()))?;
    let name = params.get("name").and_then(Value::as_str).ok_or_else(|| {
        (
            INVALID_PARAMS,
            "tools/call params.name must be a string".to_string(),
        )
    })?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let (text, is_error) = match name {
        "find_logins" => run_find_logins(arguments, socket_override).await,
        "run_with_credential" => run_with_credential_tool(arguments, socket_override).await,
        "find_secrets" => run_find_secrets(arguments, socket_override).await,
        "run_with_secret" => run_with_secret_tool(arguments, socket_override).await,
        "create_secret" => run_create_secret(arguments, socket_override).await,
        "get_secret_findings" => run_get_secret_findings(context),
        "fill_credential" => run_fill_credential(arguments, socket_override).await,
        "describe_fill_target" => run_describe_fill_target(socket_override).await,
        other => (format!("Unknown tool: {other}"), true),
    };

    Ok(json!({"content": [{"type": "text", "text": text}], "isError": is_error}))
}

// ── get_secret_findings ─────────────────────────────────────────────────

/// Run `get_secret_findings`. Returns `(text, isError)`; `text` is the same
/// JSON envelope `resources/read` serves, built fresh from whatever the
/// on-disk artifact currently contains. `isError` is always `false` — every
/// envelope status (`no_repo`/`never_scanned`/`artifact_error`/`ready`) is
/// data, not a tool failure. Reads `context.repo_root` and the artifact
/// file only: no socket use, no scan ever triggered.
fn run_get_secret_findings(context: &SharedContext) -> (String, bool) {
    let envelope = build_envelope(context.repo_root.as_deref());
    (envelope.to_string(), false)
}

// ── find_logins ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FindLoginsArgs {
    query: String,
    #[serde(default)]
    query_type: Option<String>,
}

/// Run `find_logins`. Returns `(text, isError)`; `text` is JSON-encoded on
/// success. Never places a secret value in `text`.
async fn run_find_logins(arguments: Value, socket_override: &Option<String>) -> (String, bool) {
    let args: FindLoginsArgs = match serde_json::from_value(arguments) {
        Ok(a) => a,
        Err(e) => return (format!("Invalid arguments for find_logins: {e}"), true),
    };
    if args.query.trim().is_empty() {
        return ("The 'query' argument must not be empty.".to_string(), true);
    }
    let query = match build_text_query(args.query, args.query_type.as_deref()) {
        Ok(q) => q,
        Err(msg) => return (msg, true),
    };

    let endpoint = match resolve_endpoint(socket_override) {
        Some(e) => e,
        None => return (LOCAL_UNAVAILABLE_MSG.to_string(), true),
    };

    match local::request_credential(&endpoint, &query, WireDelivery::Reference).await {
        Ok(WireOutcome::Reference { reference, item }) => {
            let entry =
                json!([{"name": item.name, "reference": reference, "username": item.username}]);
            (entry.to_string(), false)
        }
        Ok(WireOutcome::Credential(_)) => (
            "The local agent-access endpoint returned an unexpected credential-bearing \
             response for a reference request; refusing to relay it."
                .to_string(),
            true,
        ),
        Err(e) => (map_local_error_to_tool_message(&e), true),
    }
}

// ── run_with_credential ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunWithCredentialArgs {
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    reference: Option<String>,
    #[serde(default)]
    query_type: Option<String>,
    command: Vec<String>,
}

/// Run `run_with_credential`. Returns `(text, isError)`; `text` is
/// JSON-encoded `{exitCode, output: {stdout, stderr}}` on success. The
/// credential is injected into the child's environment only — it is never
/// placed in `text`, and any occurrence of it in the child's captured
/// output is scrubbed via [`Redactor`] before being returned.
async fn run_with_credential_tool(
    arguments: Value,
    socket_override: &Option<String>,
) -> (String, bool) {
    let args: RunWithCredentialArgs = match serde_json::from_value(arguments) {
        Ok(a) => a,
        Err(e) => {
            return (
                format!("Invalid arguments for run_with_credential: {e}"),
                true,
            );
        }
    };

    if args.command.is_empty() {
        return (
            "The 'command' argument must be a non-empty array.".to_string(),
            true,
        );
    }

    let query = match (args.query, args.reference) {
        (Some(_), Some(_)) => {
            return (
                "Provide exactly one of 'query' or 'reference', not both.".to_string(),
                true,
            );
        }
        (None, None) => {
            return (
                "Provide exactly one of 'query' or 'reference'.".to_string(),
                true,
            );
        }
        (Some(q), None) => {
            if q.trim().is_empty() {
                return ("The 'query' argument must not be empty.".to_string(), true);
            }
            match build_text_query(q, args.query_type.as_deref()) {
                Ok(q) => q,
                Err(msg) => return (msg, true),
            }
        }
        (None, Some(r)) => {
            let id = local::strip_reference(&r);
            if id.is_empty() {
                return (
                    "The 'reference' argument must not be empty.".to_string(),
                    true,
                );
            }
            CredentialQuery::Id(id.to_string())
        }
    };

    let endpoint = match resolve_endpoint(socket_override) {
        Some(e) => e,
        None => return (LOCAL_UNAVAILABLE_MSG.to_string(), true),
    };

    let credential = match local::request_credential(&endpoint, &query, WireDelivery::Inject).await
    {
        Ok(WireOutcome::Credential(credential)) => credential,
        Ok(WireOutcome::Reference { .. }) => {
            return (
                "The local agent-access endpoint returned a reference response for an inject \
                 request; refusing to run the command without an injected credential."
                    .to_string(),
                true,
            );
        }
        Err(e) => return (map_local_error_to_tool_message(&e), true),
    };

    let (env_vars, secret_values) = credential_env_and_secrets(&credential);

    let program = args.command[0].clone();
    let child_args = &args.command[1..];

    match run_child_captured(&program, child_args, &env_vars, secret_values).await {
        Ok((exit_code, stdout, stderr)) => {
            let result =
                json!({"exitCode": exit_code, "output": {"stdout": stdout, "stderr": stderr}});
            (result.to_string(), false)
        }
        Err(e) => (format!("Failed to run command '{program}': {e}"), true),
    }
}

/// Build the `AAC_*` env vars and the list of secret values to scrub from
/// child output, from a value-bearing local wire credential. Mirrors
/// `run.rs`'s `--env-all` field set, restricted to what the wire protocol
/// actually carries (no `notes`; `domain`/`credential_id` are non-secret
/// and not injected here since no tool argument asks for them).
fn credential_env_and_secrets(
    credential: &local::WireCredential,
) -> (HashMap<String, String>, Vec<String>) {
    let mut env_vars = HashMap::new();
    let mut secret_values = Vec::new();

    if let Some(username) = &credential.username {
        env_vars.insert("AAC_USERNAME".to_string(), username.clone());
    }
    if let Some(password) = &credential.password {
        let value = password.as_str().to_string();
        env_vars.insert("AAC_PASSWORD".to_string(), value.clone());
        if !value.is_empty() {
            secret_values.push(value);
        }
    }
    if let Some(totp) = &credential.totp {
        env_vars.insert("AAC_TOTP".to_string(), totp.clone());
        if !totp.is_empty() {
            secret_values.push(totp.clone());
        }
    }
    if let Some(uri) = &credential.uri {
        env_vars.insert("AAC_URI".to_string(), uri.clone());
    }

    (env_vars, secret_values)
}

// ── find_secrets ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct FindSecretsArgs {
    query: String,
}

/// Run `find_secrets`. Returns `(text, isError)`; `text` is JSON-encoded on
/// success. Never places a secret value in `text` — reference delivery
/// only, per the architecture doc's M4 invariant #1.
async fn run_find_secrets(arguments: Value, socket_override: &Option<String>) -> (String, bool) {
    let args: FindSecretsArgs = match serde_json::from_value(arguments) {
        Ok(a) => a,
        Err(e) => return (format!("Invalid arguments for find_secrets: {e}"), true),
    };
    if args.query.trim().is_empty() {
        return ("The 'query' argument must not be empty.".to_string(), true);
    }

    let endpoint = match resolve_endpoint(socket_override) {
        Some(e) => e,
        None => return (LOCAL_UNAVAILABLE_MSG.to_string(), true),
    };

    let query = SecretQueryInput::Search(args.query);
    match local::request_secret(&endpoint, &query, WireDelivery::Reference).await {
        Ok(SecretOutcome::Reference {
            reference,
            item_name,
        }) => {
            // `secretId` is derived client-side from the reference so agents
            // don't need to parse the `bw://secret/<id>` URI themselves.
            let secret_id = local::strip_secret_reference(&reference).to_string();
            let entry = json!([{
                "name": item_name,
                "reference": reference,
                "secretId": secret_id,
            }]);
            (entry.to_string(), false)
        }
        Ok(SecretOutcome::Secret(_)) => (
            "The local agent-access endpoint returned an unexpected value-bearing response for \
             a reference secret request; refusing to relay it."
                .to_string(),
            true,
        ),
        Err(e) => (map_local_error_to_tool_message(&e), true),
    }
}

// ── run_with_secret ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RunWithSecretArgs {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    reference: Option<String>,
    #[serde(default)]
    env: Option<String>,
    command: Vec<String>,
}

/// Run `run_with_secret`. Returns `(text, isError)`; `text` is JSON-encoded
/// `{exitCode, output: {stdout, stderr}}` on success. The secret is injected
/// into the child's environment only — it is never placed in `text`, and any
/// occurrence of it in the child's captured output is scrubbed via
/// [`Redactor`] before being returned.
async fn run_with_secret_tool(
    arguments: Value,
    socket_override: &Option<String>,
) -> (String, bool) {
    let args: RunWithSecretArgs = match serde_json::from_value(arguments) {
        Ok(a) => a,
        Err(e) => {
            return (format!("Invalid arguments for run_with_secret: {e}"), true);
        }
    };

    if args.command.is_empty() {
        return (
            "The 'command' argument must be a non-empty array.".to_string(),
            true,
        );
    }

    let query = match (args.name, args.reference) {
        (Some(_), Some(_)) => {
            return (
                "Provide exactly one of 'name' or 'reference', not both.".to_string(),
                true,
            );
        }
        (None, None) => {
            return (
                "Provide exactly one of 'name' or 'reference'.".to_string(),
                true,
            );
        }
        (Some(n), None) => {
            if n.trim().is_empty() {
                return ("The 'name' argument must not be empty.".to_string(), true);
            }
            SecretQueryInput::Name(n)
        }
        (None, Some(r)) => {
            let id = local::strip_secret_reference(&r);
            if id.is_empty() {
                return (
                    "The 'reference' argument must not be empty.".to_string(),
                    true,
                );
            }
            SecretQueryInput::Id(id.to_string())
        }
    };

    let endpoint = match resolve_endpoint(socket_override) {
        Some(e) => e,
        None => return (LOCAL_UNAVAILABLE_MSG.to_string(), true),
    };

    let secret = match local::request_secret(&endpoint, &query, WireDelivery::Inject).await {
        Ok(SecretOutcome::Secret(secret)) => secret,
        Ok(SecretOutcome::Reference { .. }) => {
            return (
                "The local agent-access endpoint returned a reference response for an inject \
                 request; refusing to run the command without an injected secret value."
                    .to_string(),
                true,
            );
        }
        Err(e) => return (map_local_error_to_tool_message(&e), true),
    };

    let (env_vars, secret_values) = secret_env_and_secrets(&secret, args.env.as_deref());

    let program = args.command[0].clone();
    let child_args = &args.command[1..];

    match run_child_captured(&program, child_args, &env_vars, secret_values).await {
        Ok((exit_code, stdout, stderr)) => {
            let result =
                json!({"exitCode": exit_code, "output": {"stdout": stdout, "stderr": stderr}});
            (result.to_string(), false)
        }
        Err(e) => (format!("Failed to run command '{program}': {e}"), true),
    }
}

/// Build the single env var + the scrub list for a value-bearing local wire
/// secret. `env_override` is the tool's `env` argument (`--secret-env`'s MCP
/// analogue); when absent, the env var name is derived from the secret's own
/// name via [`local::secret_env_var_name`].
fn secret_env_and_secrets(
    secret: &local::WireSecret,
    env_override: Option<&str>,
) -> (HashMap<String, String>, Vec<String>) {
    let env_name = env_override
        .map(str::to_string)
        .unwrap_or_else(|| local::secret_env_var_name(&secret.name));
    let value = secret.value.as_str().to_string();

    let mut env_vars = HashMap::new();
    env_vars.insert(env_name, value.clone());

    let secret_values = if value.is_empty() {
        Vec::new()
    } else {
        vec![value]
    };

    (env_vars, secret_values)
}

// ── create_secret ────────────────────────────────────────────────────────

/// `value` is `Zeroizing<String>` so the submitted secret value is scrubbed
/// from memory on drop, same as every other secret-value-bearing type in
/// this crate. Deliberately does not derive `Debug` — nothing in this module
/// ever needs to print a `CreateSecretArgs`, and not deriving it removes the
/// possibility of an accidental future `{:?}` leaking `value`.
#[derive(Deserialize)]
struct CreateSecretArgs {
    name: String,
    value: Zeroizing<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    project: Option<String>,
}

/// Run `create_secret`. Returns `(text, isError)`; `text` is JSON-encoded
/// `{secretId, reference, name}` on success. The submitted `value` is never
/// placed in `text` or in any error message — only `secretId`/`reference`/
/// `name` (the reference the desktop app returned, not the input) ever
/// appear in the result.
async fn run_create_secret(arguments: Value, socket_override: &Option<String>) -> (String, bool) {
    let args: CreateSecretArgs = match serde_json::from_value(arguments) {
        Ok(a) => a,
        Err(e) => return (format!("Invalid arguments for create_secret: {e}"), true),
    };
    if args.name.trim().is_empty() {
        return ("The 'name' argument must not be empty.".to_string(), true);
    }
    if args.value.as_str().is_empty() {
        return ("The 'value' argument must not be empty.".to_string(), true);
    }

    let endpoint = match resolve_endpoint(socket_override) {
        Some(e) => e,
        None => return (LOCAL_UNAVAILABLE_MSG.to_string(), true),
    };

    let input = SecretCreateInput {
        name: args.name,
        value: args.value,
        note: args.note,
        project: args.project,
    };

    match local::request_secret_create(&endpoint, &input).await {
        Ok(outcome) => {
            let result = json!({
                "secretId": outcome.secret_id,
                "reference": outcome.reference,
                "name": outcome.name,
            });
            (result.to_string(), false)
        }
        Err(e) => (map_local_error_to_tool_message(&e), true),
    }
}

// ── fill_credential / describe_fill_target ──────────────────────────────

// No `rename_all`: every field name here matches its inputSchema property
// verbatim (`target_token`, not `targetToken` — the task-facing schema is
// snake_case here, unlike `RunWithCredentialArgs`'s `queryType`).
#[derive(Debug, Deserialize)]
struct FillCredentialArgs {
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    reference: Option<String>,
    #[serde(default)]
    fields: Option<Vec<String>>,
    #[serde(default)]
    target_token: Option<String>,
}

/// Run `fill_credential`. Returns `(text, isError)`; `text` is JSON-encoded
/// on success. Never places a credential value in `text` — the value never
/// enters this process at all for `delivery: "fill"` (architecture doc, M5
/// §1): only status, origin, reference, item metadata, and per-field
/// outcome descriptors ever appear.
async fn run_fill_credential(arguments: Value, socket_override: &Option<String>) -> (String, bool) {
    let args: FillCredentialArgs = match serde_json::from_value(arguments) {
        Ok(a) => a,
        Err(e) => return (format!("Invalid arguments for fill_credential: {e}"), true),
    };

    let provided = [
        args.domain.is_some(),
        args.name.is_some(),
        args.reference.is_some(),
    ]
    .into_iter()
    .filter(|&present| present)
    .count();
    if provided != 1 {
        return (
            "Provide exactly one of 'domain', 'name', or 'reference'.".to_string(),
            true,
        );
    }

    let query = if let Some(domain) = args.domain {
        if domain.trim().is_empty() {
            return ("The 'domain' argument must not be empty.".to_string(), true);
        }
        CredentialQuery::Domain(domain)
    } else if let Some(name) = args.name {
        if name.trim().is_empty() {
            return ("The 'name' argument must not be empty.".to_string(), true);
        }
        // M5 §5: "name" queries map to the wire "search" query type.
        CredentialQuery::Search(name)
    } else {
        let reference = args
            .reference
            .expect("exactly one of domain/name/reference was checked present above");
        let id = local::strip_reference(&reference);
        if id.is_empty() {
            return (
                "The 'reference' argument must not be empty.".to_string(),
                true,
            );
        }
        CredentialQuery::Id(id.to_string())
    };

    let endpoint = match resolve_endpoint(socket_override) {
        Some(e) => e,
        None => return (LOCAL_UNAVAILABLE_MSG.to_string(), true),
    };

    let fill_input = FillInput {
        fields: args.fields,
        target_token: args.target_token,
    };

    match local::request_fill(&endpoint, &query, Some(fill_input)).await {
        Ok(outcome) => {
            let fields: Vec<Value> = outcome
                .fields
                .iter()
                .map(|f| {
                    json!({
                        "role": f.role,
                        "status": f.status,
                        "target": f.target,
                        "reason": f.reason,
                    })
                })
                .collect();
            let result = json!({
                "status": outcome.status,
                "origin": outcome.origin,
                "reference": outcome.reference,
                "item": outcome.item.as_ref().map(|item| json!({
                    "name": item.name,
                    "username": item.username,
                })),
                "reason": outcome.reason,
                "fields": fields,
            });
            (result.to_string(), false)
        }
        Err(e) => (map_local_error_to_tool_message(&e), true),
    }
}

/// Run `describe_fill_target`. Returns `(text, isError)`; `text` is
/// JSON-encoded on success. Vault-free, approval-free, value-free — a
/// read-only description of the active browser tab (architecture doc, M5
/// §4.2). Takes no arguments.
async fn run_describe_fill_target(socket_override: &Option<String>) -> (String, bool) {
    let endpoint = match resolve_endpoint(socket_override) {
        Some(e) => e,
        None => return (LOCAL_UNAVAILABLE_MSG.to_string(), true),
    };

    match local::request_describe_fill_target(&endpoint).await {
        Ok(target) => {
            let candidates: Vec<Value> = target
                .candidates
                .iter()
                .map(|c| {
                    json!({
                        "role": c.role,
                        "target": c.target,
                        "visible": c.visible,
                        "frame": c.frame,
                    })
                })
                .collect();
            let refusals: Vec<Value> = target
                .refusals
                .iter()
                .map(|r| json!({"role": r.role, "reason": r.reason}))
                .collect();
            let result = json!({
                "origin": target.origin,
                "formClass": target.form_class,
                "candidates": candidates,
                "refusals": refusals,
                "targetToken": target.target_token,
                "expiresInMs": target.expires_in_ms,
            });
            (result.to_string(), false)
        }
        Err(e) => (map_local_error_to_tool_message(&e), true),
    }
}

/// Spawn `program(args)` with `env_vars` injected (in addition to the
/// inherited environment, same as `run.rs`), capturing stdout/stderr
/// separately with every `secret_values` occurrence scrubbed via
/// [`Redactor`]. The child's real stdin is never connected — this
/// process's stdin is the JSON-RPC input stream and must not be shared.
async fn run_child_captured(
    program: &str,
    args: &[String],
    env_vars: &HashMap<String, String>,
    secret_values: Vec<String>,
) -> std::io::Result<(i32, String, String)> {
    let out_redactor = Redactor::new(secret_values.clone());
    let err_redactor = Redactor::new(secret_values);

    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .envs(env_vars)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn()?;
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");

    let out_task = tokio::spawn(pump_scrubbed_to_vec(stdout, out_redactor));
    let err_task = tokio::spawn(pump_scrubbed_to_vec(stderr, err_redactor));

    let status = child.wait().await?;

    let stdout_bytes = out_task.await.unwrap_or_default();
    let stderr_bytes = err_task.await.unwrap_or_default();

    Ok((
        status.code().unwrap_or(-1),
        String::from_utf8_lossy(&stdout_bytes).into_owned(),
        String::from_utf8_lossy(&stderr_bytes).into_owned(),
    ))
}

/// Cap on bytes collected per stream by [`pump_scrubbed_to_vec`]. A
/// model-chosen `run_with_credential` command (e.g. `["cat",
/// "/dev/urandom"]`) or a merely chatty build must not be able to grow the
/// tool result — and this server's memory — without bound. The stream is
/// still drained to EOF past the cap (just not retained) so the child never
/// deadlocks writing to a full pipe.
const MAX_CAPTURED_OUTPUT_BYTES: usize = 1024 * 1024; // 1 MiB

/// Truncation marker appended when a stream's captured output was cut off
/// at [`MAX_CAPTURED_OUTPUT_BYTES`].
fn truncation_marker() -> String {
    format!("\n...[truncated: exceeded {MAX_CAPTURED_OUTPUT_BYTES} bytes]")
}

/// Append `bytes` to `out` up to [`MAX_CAPTURED_OUTPUT_BYTES`], returning
/// `true` if any of `bytes` had to be dropped to stay under the cap.
fn append_capped(out: &mut Vec<u8>, bytes: &[u8]) -> bool {
    if out.len() >= MAX_CAPTURED_OUTPUT_BYTES {
        return !bytes.is_empty();
    }
    let remaining = MAX_CAPTURED_OUTPUT_BYTES - out.len();
    let take = remaining.min(bytes.len());
    out.extend_from_slice(&bytes[..take]);
    take < bytes.len()
}

/// Read `reader` to EOF in chunks, scrubbing via `redactor`, and return the
/// scrubbed bytes — capped at [`MAX_CAPTURED_OUTPUT_BYTES`], with a
/// truncation marker appended if the cap was hit. Same scrubbing algorithm
/// as `run.rs`'s `pump_scrubbed`, adapted to collect into a buffer (returned
/// in the tool result) instead of forwarding to inherited stdio (which `aac
/// mcp` does not have available — stdout is the JSON-RPC channel).
///
/// Every byte read is still fed through `redactor` regardless of the cap —
/// scrubbing must see the whole stream so a secret split across the cap
/// boundary (or anywhere else) is still matched — only what's *retained*
/// for the tool result is capped. The reader is drained to EOF even past
/// the cap: stopping early would leave the child writing into a full pipe
/// and deadlock it.
async fn pump_scrubbed_to_vec<R: AsyncRead + Unpin>(
    mut reader: R,
    mut redactor: Redactor,
) -> Vec<u8> {
    let mut buf = [0u8; 8192];
    let mut out = Vec::new();
    let mut truncated = false;
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let scrubbed = redactor.push(&buf[..n]);
                truncated |= append_capped(&mut out, &scrubbed);
            }
            Err(_) => break,
        }
    }
    let tail = redactor.finish();
    truncated |= append_capped(&mut out, &tail);

    if truncated {
        out.extend_from_slice(truncation_marker().as_bytes());
    }
    out
}

// ── shared helpers ────────────────────────────────────────────────────────

const LOCAL_UNAVAILABLE_MSG: &str = "Could not determine the local Bitwarden agent-access \
    endpoint. Make sure Bitwarden Desktop is installed and Agent Access is enabled.";

/// Build a Domain/Search `CredentialQuery` from free text and an optional
/// `queryType` ("domain" | "search", default "domain").
fn build_text_query(text: String, query_type: Option<&str>) -> Result<CredentialQuery, String> {
    match query_type {
        None | Some("domain") => Ok(CredentialQuery::Domain(text)),
        Some("search") => Ok(CredentialQuery::Search(text)),
        Some(other) => Err(format!(
            "Invalid queryType '{other}': expected 'domain' or 'search'."
        )),
    }
}

fn resolve_endpoint(socket_override: &Option<String>) -> Option<LocalEndpoint> {
    match socket_override {
        Some(path) => Some(LocalEndpoint::from_override(path)),
        None => LocalEndpoint::default_endpoint(),
    }
}

/// Map a [`LocalTransportError`] to a safe, human-readable tool-result
/// message. Never includes a credential value or a raw filesystem/socket
/// path — only the protocol's own free-form `message` field (which the
/// wire protocol contract guarantees never carries vault data) and a fixed
/// description of the failure class.
fn map_local_error_to_tool_message(err: &LocalTransportError) -> String {
    match err {
        LocalTransportError::ConnectFailed(_) => "Could not reach the Bitwarden desktop app \
            locally. Make sure Bitwarden Desktop is running, unlocked, and Agent Access is \
            enabled."
            .to_string(),
        LocalTransportError::Denied(msg) => {
            format!("Request denied in the Bitwarden desktop app: {msg}")
        }
        LocalTransportError::NotFound(msg) => format!("No matching login found: {msg}"),
        LocalTransportError::Locked(msg) => format!("Bitwarden vault is locked: {msg}"),
        LocalTransportError::ServerTimeout(msg) => format!("Approval request timed out: {msg}"),
        LocalTransportError::RateLimited(msg) => format!("Rate limited: {msg}"),
        LocalTransportError::ServerError(msg) => {
            format!("Bitwarden desktop app returned an error: {msg}")
        }
        LocalTransportError::ReadTimeout => {
            "Timed out waiting for a response from the Bitwarden desktop app.".to_string()
        }
        LocalTransportError::ResponseTooLarge => {
            "Received an unexpectedly large response from the Bitwarden desktop app.".to_string()
        }
        LocalTransportError::Protocol(_) | LocalTransportError::UnsupportedVersion(_) => {
            "Received a malformed response from the Bitwarden desktop app.".to_string()
        }
        LocalTransportError::Io(_) => {
            "I/O error communicating with the Bitwarden desktop app.".to_string()
        }
        LocalTransportError::OriginMismatch { origin, item_name } => {
            let item = item_name.as_deref().unwrap_or("the requested login");
            format!(
                "Refused: the active browser tab ({origin}) does not match any saved website \
                 for {item}. Navigate to the login page you want to fill first, then call this \
                 again — you cannot direct a fill to a different origin than the one you're on."
            )
        }
        LocalTransportError::NoSafeTarget { reason } => {
            format!(
                "Refused: no safe fill target on the page ({reason}). Call describe_fill_target \
                 to see what Bitwarden found on this page and why each field was or wasn't a \
                 safe target."
            )
        }
    }
}

/// Test-only constructor for [`RpcRequest`] — shared by `tests` and
/// `unix_integration_tests` (both are submodules of this module, but not of
/// each other, so the helper lives here rather than inside either one).
#[cfg(test)]
fn request(id: Option<Value>, method: &str, params: Option<Value>) -> RpcRequest {
    RpcRequest {
        id,
        method: method.to_string(),
        params,
    }
}

/// A path guaranteed not to resolve to a real repo, for `serve()` tests.
/// Keeps `serve()` in tests from shelling out a meaningful `git rev-parse`
/// against this crate's own working tree — `resolve_repo_root` just fails
/// fast (the path is used verbatim when `--repo`-equivalent is given) and
/// the context ends up `no_repo`... except an explicit override is never
/// `None`, so this is deliberately a path that can't exist, keeping
/// findings reads harmless (`load_artifact` sees a missing file, not a
/// real repo's).
#[cfg(test)]
fn no_repo_override() -> Option<PathBuf> {
    Some(PathBuf::from(
        "/nonexistent/aac-mcp-test-no-such-repo-3f9c1a",
    ))
}

/// Default test [`SharedContext`]: no repo resolved. What most tests want
/// — tests exercising the findings-serving surface build a context with an
/// explicit `repo_root` (and write artifact fixtures under it themselves).
#[cfg(test)]
fn test_context(repo_root: Option<PathBuf>) -> SharedContext {
    Arc::new(McpContext { repo_root })
}

/// A minimal, valid [`findings_artifact::ScanReport`] for tests that need
/// an on-disk artifact with actual finding data.
#[cfg(test)]
fn test_scan_report() -> findings_artifact::ScanReport {
    findings_artifact::ScanReport {
        schema_version: findings_artifact::SCHEMA_VERSION,
        generated_at: "2026-08-11T12:00:00Z".to_string(),
        repo_root: "/tmp/example".to_string(),
        head_commit: Some("abc123".to_string()),
        dirty: Some(false),
        scan_mode: "worktree".to_string(),
        truncated: false,
        findings: vec![findings_artifact::Finding {
            fingerprint: "fp-1".to_string(),
            rule_id: "aws-access-key-id".to_string(),
            severity: "high".to_string(),
            path: "src/config.ts".to_string(),
            line: 42,
            column: 18,
            preview: "AKIA****************".to_string(),
            origin: "worktree".to_string(),
            commit: None,
            author: None,
            first_seen: None,
        }],
    }
}

/// A directory under `std::env::temp_dir()` with a unique name, removed on
/// drop. This crate has no `tempfile` dependency (the scanning engine that
/// used it lives in `sdk-sm` now, alongside `bws scan`), so tests build
/// their own minimal fixture dir to write findings-artifact fixtures into.
#[cfg(test)]
struct TestRepoDir(PathBuf);

#[cfg(test)]
impl TestRepoDir {
    fn new(label: &str) -> Self {
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aac-mcp-test-repo-{label}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("creating fixture repo dir must succeed");
        TestRepoDir(path)
    }

    fn path(&self) -> PathBuf {
        self.0.clone()
    }

    /// Write `report` as the findings artifact under this fixture repo.
    fn write_artifact(&self, report: &findings_artifact::ScanReport) {
        let path = findings_artifact::artifact_path(&self.0);
        std::fs::create_dir_all(path.parent().expect("artifact path always has a parent"))
            .expect("mkdir must succeed");
        let contents = serde_json::to_string(report).expect("serializing test report succeeds");
        std::fs::write(&path, contents).expect("writing artifact fixture must succeed");
    }

    /// Write raw (possibly invalid) bytes as the findings artifact —
    /// for `artifact_error` fixtures a [`findings_artifact::ScanReport`]
    /// can't represent (malformed JSON, an unsupported schema version).
    fn write_raw_artifact(&self, contents: &str) {
        let path = findings_artifact::artifact_path(&self.0);
        std::fs::create_dir_all(path.parent().expect("artifact path always has a parent"))
            .expect("mkdir must succeed");
        std::fs::write(&path, contents).expect("writing raw artifact fixture must succeed");
    }
}

#[cfg(test)]
impl Drop for TestRepoDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── framing ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn frame_round_trip_preserves_json() {
        let value = json!({"jsonrpc": "2.0", "id": 7, "result": {"ok": true}});
        let mut out: Vec<u8> = Vec::new();
        write_frame(&mut out, &value).await.expect("write");

        let mut reader = BufReader::new(std::io::Cursor::new(out));
        let frame = read_frame(&mut reader)
            .await
            .expect("read")
            .expect("some frame");
        let parsed: Value = serde_json::from_slice(&frame).expect("valid json");
        assert_eq!(parsed, value);
    }

    #[tokio::test]
    async fn read_frame_returns_none_on_clean_eof() {
        let mut reader = BufReader::new(std::io::Cursor::new(Vec::<u8>::new()));
        let frame = read_frame(&mut reader).await.expect("no io error");
        assert!(frame.is_none());
    }

    /// The MCP stdio transport is newline-delimited JSON, not LSP-style
    /// `Content-Length` framing. Emitting headers here makes every spec
    /// -compliant client (Claude Code, Cursor, ...) hang on the handshake.
    #[tokio::test]
    async fn write_frame_emits_one_bare_json_line() {
        let mut out: Vec<u8> = Vec::new();
        write_frame(&mut out, &json!({"jsonrpc": "2.0", "id": 1}))
            .await
            .expect("write");

        let wire = String::from_utf8(out).expect("utf8");
        assert!(!wire.contains("Content-Length"), "wire was: {wire:?}");
        assert!(wire.starts_with('{'), "wire was: {wire:?}");
        assert!(wire.ends_with('\n'), "wire was: {wire:?}");
        assert_eq!(wire.matches('\n').count(), 1, "wire was: {wire:?}");
    }

    #[tokio::test]
    async fn read_frame_skips_blank_lines() {
        let mut reader = BufReader::new(std::io::Cursor::new(b"\n\r\n{\"id\":1}\n".to_vec()));
        let frame = read_frame(&mut reader)
            .await
            .expect("read")
            .expect("some frame");
        assert_eq!(frame, b"{\"id\":1}");
    }

    #[tokio::test]
    async fn read_frame_handles_consecutive_messages() {
        let mut reader = BufReader::new(std::io::Cursor::new(b"{\"id\":1}\n{\"id\":2}\n".to_vec()));
        for expected in [b"{\"id\":1}", b"{\"id\":2}"] {
            let frame = read_frame(&mut reader)
                .await
                .expect("read")
                .expect("some frame");
            assert_eq!(frame, expected);
        }
        assert!(read_frame(&mut reader).await.expect("read").is_none());
    }

    /// Build a raw newline-delimited message with an arbitrary body,
    /// including a deliberately invalid-JSON one — `write_frame` can't do
    /// this since it only ever serializes a valid `Value`.
    fn frame_bytes(body: &[u8]) -> Vec<u8> {
        let mut out = body.to_vec();
        out.push(b'\n');
        out
    }

    #[tokio::test]
    async fn malformed_json_body_yields_parse_error() {
        let mut reader = BufReader::new(std::io::Cursor::new(frame_bytes(b"{not json")));
        let mut out: Vec<u8> = Vec::new();
        serve(&mut reader, &mut out, None, no_repo_override()).await;

        let mut resp_reader = BufReader::new(std::io::Cursor::new(out));
        let frame = read_frame(&mut resp_reader)
            .await
            .expect("read")
            .expect("a response");
        let value: Value = serde_json::from_slice(&frame).expect("valid json");
        assert_eq!(value["error"]["code"], PARSE_ERROR);
        assert_eq!(value["id"], Value::Null);
    }

    // ── initialize / tools/list / unknown method ────────────────────────

    #[tokio::test]
    async fn initialize_returns_expected_shape() {
        let response = handle_request(
            request(Some(json!(1)), "initialize", None),
            &None,
            &test_context(None),
        )
        .await
        .expect("initialize replies");
        assert_eq!(response["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
        assert_eq!(response["result"]["serverInfo"]["name"], SERVER_NAME);
        assert!(response["result"]["capabilities"]["tools"].is_object());
        assert_eq!(response["id"], json!(1));
    }

    /// The optional `instructions` field (MCP 2024-11-05) is where cross-tool
    /// routing lives — notably steering browser fills straight to
    /// `fill_credential` instead of a `find_logins` lookup first, which would
    /// cost a second approval prompt and release vault data the fill path
    /// never releases.
    #[tokio::test]
    async fn initialize_carries_server_instructions() {
        let response = handle_request(
            request(Some(json!(1)), "initialize", None),
            &None,
            &test_context(None),
        )
        .await
        .expect("initialize replies");
        let instructions = response["result"]["instructions"]
            .as_str()
            .expect("instructions is a string");
        assert!(instructions.contains("fill_credential"));
        assert!(instructions.contains("find_logins"));
    }

    /// No `subscribe`/`listChanged`: there is no in-process producer to
    /// raise a change notification from, so the capability advertises only
    /// that the `resources/*` methods exist.
    #[tokio::test]
    async fn initialize_advertises_resources_capability_without_subscribe_or_list_changed() {
        let response = handle_request(
            request(Some(json!(1)), "initialize", None),
            &None,
            &test_context(None),
        )
        .await
        .expect("initialize replies");
        let resources = response["result"]["capabilities"]["resources"]
            .as_object()
            .expect("resources capability is an object");
        assert!(
            resources.is_empty(),
            "resources capability must not advertise subscribe/listChanged: {resources:?}"
        );
    }

    #[tokio::test]
    async fn notifications_initialized_gets_no_reply() {
        let response = handle_request(
            request(None, "notifications/initialized", None),
            &None,
            &test_context(None),
        )
        .await;
        assert!(response.is_none());
    }

    #[tokio::test]
    async fn tools_list_returns_all_tools_with_schemas() {
        let response = handle_request(
            request(Some(json!(2)), "tools/list", None),
            &None,
            &test_context(None),
        )
        .await
        .expect("tools/list replies");
        let tools = response["result"]["tools"].as_array().expect("tools array");
        assert_eq!(tools.len(), 8);
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"find_logins"));
        assert!(names.contains(&"run_with_credential"));
        assert!(names.contains(&"find_secrets"));
        assert!(names.contains(&"run_with_secret"));
        assert!(names.contains(&"create_secret"));
        assert!(names.contains(&"get_secret_findings"));
        assert!(names.contains(&"fill_credential"));
        assert!(names.contains(&"describe_fill_target"));
        for tool in tools {
            assert_eq!(tool["inputSchema"]["type"], "object");
        }
        // `get_secret_findings` and `describe_fill_target` don't gate on
        // desktop approval — every *other* tool does.
        for tool in tools.iter().filter(|t| {
            !matches!(
                t["name"].as_str(),
                Some("get_secret_findings" | "describe_fill_target")
            )
        }) {
            assert!(
                tool["description"]
                    .as_str()
                    .is_some_and(|d| d.contains("Bitwarden desktop")),
                "{} description missing desktop-approval language",
                tool["name"]
            );
        }
    }

    #[tokio::test]
    async fn secret_tools_descriptions_state_reference_only_and_approval() {
        let response = handle_request(
            request(Some(json!(2)), "tools/list", None),
            &None,
            &test_context(None),
        )
        .await
        .expect("tools/list replies");
        let tools = response["result"]["tools"].as_array().expect("tools array");

        let find_secrets = tools
            .iter()
            .find(|t| t["name"] == "find_secrets")
            .expect("find_secrets present");
        let desc = find_secrets["description"].as_str().expect("description");
        assert!(desc.contains("approve"), "find_secrets desc: {desc}");
        assert!(
            desc.contains("Never returns a secret value") || desc.contains("reference"),
            "find_secrets desc must state reference-only: {desc}"
        );

        let run_with_secret = tools
            .iter()
            .find(|t| t["name"] == "run_with_secret")
            .expect("run_with_secret present");
        let desc = run_with_secret["description"]
            .as_str()
            .expect("description");
        assert!(desc.contains("approve"), "run_with_secret desc: {desc}");
    }

    #[tokio::test]
    async fn create_secret_description_states_encryption_approval_and_run_with_secret() {
        let response = handle_request(
            request(Some(json!(2)), "tools/list", None),
            &None,
            &test_context(None),
        )
        .await
        .expect("tools/list replies");
        let tools = response["result"]["tools"].as_array().expect("tools array");

        let create_secret = tools
            .iter()
            .find(|t| t["name"] == "create_secret")
            .expect("create_secret present");
        let desc = create_secret["description"].as_str().expect("description");
        assert!(
            desc.contains("encrypted") && desc.contains("Secrets Manager"),
            "create_secret desc must state encryption + SM storage: {desc}"
        );
        assert!(desc.contains("approve"), "create_secret desc: {desc}");
        assert!(
            desc.contains("run_with_secret"),
            "create_secret desc must mention run_with_secret: {desc}"
        );
        assert!(
            desc.to_lowercase().contains(".env") || desc.to_lowercase().contains("hardcoded"),
            "create_secret desc must state the migrate-hardcoded-credentials use case: {desc}"
        );

        let schema = &create_secret["inputSchema"];
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        let required: Vec<&str> = schema["required"]
            .as_array()
            .expect("required array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(required, vec!["name", "value"]);
    }

    #[tokio::test]
    async fn ping_returns_empty_result() {
        let response = handle_request(
            request(Some(json!(9)), "ping", None),
            &None,
            &test_context(None),
        )
        .await
        .expect("ping replies");
        assert_eq!(response["result"], json!({}));
        assert_eq!(response["id"], json!(9));
        assert!(response.get("error").is_none());
    }

    #[tokio::test]
    async fn notifications_cancelled_gets_no_reply() {
        let response = handle_request(
            request(None, "notifications/cancelled", None),
            &None,
            &test_context(None),
        )
        .await;
        assert!(response.is_none());
    }

    #[tokio::test]
    async fn unknown_method_returns_method_not_found() {
        let response = handle_request(
            request(Some(json!(3)), "bogus/method", None),
            &None,
            &test_context(None),
        )
        .await
        .expect("errors still reply");
        assert_eq!(response["error"]["code"], METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn unknown_method_notification_gets_no_reply() {
        let response = handle_request(
            request(None, "bogus/method", None),
            &None,
            &test_context(None),
        )
        .await;
        assert!(response.is_none());
    }

    #[tokio::test]
    async fn tools_call_missing_name_is_invalid_params() {
        let response = handle_request(
            request(Some(json!(4)), "tools/call", Some(json!({"arguments": {}}))),
            &None,
            &test_context(None),
        )
        .await
        .expect("errors still reply");
        assert_eq!(response["error"]["code"], INVALID_PARAMS);
    }

    // ── resources/* ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn resources_list_returns_the_findings_resource() {
        let response = handle_request(
            request(Some(json!(10)), "resources/list", None),
            &None,
            &test_context(None),
        )
        .await
        .expect("resources/list replies");
        let resources = response["result"]["resources"]
            .as_array()
            .expect("resources array");
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0]["uri"], FINDINGS_URI);
        assert_eq!(resources[0]["mimeType"], "application/json");
        let desc = resources[0]["description"].as_str().expect("description");
        assert!(desc.contains("Precomputed"), "resource desc: {desc}");
        assert!(desc.contains("deterministic"), "resource desc: {desc}");
        assert!(
            desc.to_lowercase().contains("never contains"),
            "resource desc must state it never contains a secret value: {desc}"
        );
    }

    async fn read_findings(context: &SharedContext) -> Value {
        handle_request(
            request(
                Some(json!(11)),
                "resources/read",
                Some(json!({"uri": FINDINGS_URI})),
            ),
            &None,
            context,
        )
        .await
        .expect("resources/read replies")
    }

    fn envelope_text(response: &Value) -> Value {
        let text = response["result"]["contents"][0]["text"]
            .as_str()
            .expect("contents[0].text");
        serde_json::from_str(text).expect("envelope is valid json")
    }

    #[tokio::test]
    async fn resources_read_reports_no_repo() {
        let context = test_context(None);
        let envelope = envelope_text(&read_findings(&context).await);
        assert_eq!(envelope["status"], "no_repo");
        assert_eq!(envelope["repo_root"], Value::Null);
        assert_eq!(envelope["report"], Value::Null);
        assert!(
            envelope["hint"]
                .as_str()
                .is_some_and(|h| h.contains("bws scan")),
            "no_repo envelope must hint at running bws scan: {envelope}"
        );
    }

    #[tokio::test]
    async fn resources_read_reports_never_scanned_distinct_from_empty_findings() {
        let repo = TestRepoDir::new("never-scanned");
        let context = test_context(Some(repo.path()));
        let envelope = envelope_text(&read_findings(&context).await);
        assert_eq!(envelope["status"], "never_scanned");
        assert_eq!(
            envelope["report"],
            Value::Null,
            "never_scanned must not carry a report, so it can't be read as zero findings"
        );
        assert!(
            envelope["hint"]
                .as_str()
                .is_some_and(|h| h.contains("bws scan")),
            "never_scanned envelope must hint at running bws scan: {envelope}"
        );
    }

    #[tokio::test]
    async fn resources_read_reports_artifact_error_without_leaking_contents() {
        let repo = TestRepoDir::new("malformed");
        repo.write_raw_artifact("not json, and definitely not a secret value either");
        let context = test_context(Some(repo.path()));

        let envelope = envelope_text(&read_findings(&context).await);
        assert_eq!(envelope["status"], "artifact_error");
        assert_eq!(envelope["report"], Value::Null);
        let error = envelope["error"].as_str().expect("error class present");
        // Error is a short class name only — never the raw file contents.
        assert!(!error.contains("not json"));
        assert!(["unreadable", "malformed", "unsupported_schema_version"].contains(&error));
    }

    #[tokio::test]
    async fn resources_read_reports_ready_with_findings() {
        let repo = TestRepoDir::new("ready");
        repo.write_artifact(&test_scan_report());
        let context = test_context(Some(repo.path()));

        let envelope = envelope_text(&read_findings(&context).await);
        assert_eq!(envelope["status"], "ready");
        assert_eq!(envelope["repo_root"], repo.path().display().to_string());
        let findings = envelope["report"]["findings"].as_array().expect("findings");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["rule_id"], "aws-access-key-id");
        // Never the matched value — only a masked preview.
        assert!(!envelope.to_string().contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(envelope["remediation"]["worktree"].as_str().is_some());
        assert!(
            envelope["remediation"]["history"]
                .as_str()
                .expect("history remediation")
                .to_lowercase()
                .contains("rotate")
        );
    }

    /// The core freshness property: no in-memory cache, so a second read
    /// after the artifact changes on disk sees the new content — with no
    /// server restart, and without going through `resources/subscribe`
    /// (which doesn't exist in this model).
    #[tokio::test]
    async fn resources_read_is_fresh_on_every_call_with_no_server_restart() {
        let repo = TestRepoDir::new("freshness");
        let context = test_context(Some(repo.path()));

        let before = envelope_text(&read_findings(&context).await);
        assert_eq!(before["status"], "never_scanned");

        let mut first_report = test_scan_report();
        first_report.findings[0].rule_id = "aws-access-key-id".to_string();
        repo.write_artifact(&first_report);
        let first_read = envelope_text(&read_findings(&context).await);
        assert_eq!(first_read["status"], "ready");
        assert_eq!(
            first_read["report"]["findings"][0]["rule_id"],
            "aws-access-key-id"
        );

        let mut second_report = test_scan_report();
        second_report.findings[0].rule_id = "github-pat".to_string();
        second_report.findings[0].fingerprint = "fp-2".to_string();
        repo.write_artifact(&second_report);
        let second_read = envelope_text(&read_findings(&context).await);
        assert_eq!(second_read["status"], "ready");
        assert_eq!(
            second_read["report"]["findings"][0]["rule_id"], "github-pat",
            "a second read on the same context must see the overwritten artifact"
        );
    }

    #[tokio::test]
    async fn resources_read_unknown_uri_is_resource_not_found() {
        let response = handle_request(
            request(
                Some(json!(12)),
                "resources/read",
                Some(json!({"uri": "bitwarden://scan/nope"})),
            ),
            &None,
            &test_context(None),
        )
        .await
        .expect("resources/read replies");
        assert_eq!(response["error"]["code"], RESOURCE_NOT_FOUND);
    }

    #[tokio::test]
    async fn resources_read_missing_params_is_invalid_params() {
        let response = handle_request(
            request(Some(json!(13)), "resources/read", None),
            &None,
            &test_context(None),
        )
        .await
        .expect("resources/read replies");
        assert_eq!(response["error"]["code"], INVALID_PARAMS);
    }

    /// No `resources/subscribe` support: without an in-process producer
    /// there's no reliable change signal to subscribe to, so it's just
    /// another unknown method on the wire.
    #[tokio::test]
    async fn resources_subscribe_is_method_not_found() {
        let response = handle_request(
            request(
                Some(json!(14)),
                "resources/subscribe",
                Some(json!({"uri": FINDINGS_URI})),
            ),
            &None,
            &test_context(None),
        )
        .await
        .expect("errors still reply");
        assert_eq!(response["error"]["code"], METHOD_NOT_FOUND);
    }

    // ── get_secret_findings ─────────────────────────────────────────────

    #[tokio::test]
    async fn get_secret_findings_description_states_key_properties() {
        let response = handle_request(
            request(Some(json!(17)), "tools/list", None),
            &None,
            &test_context(None),
        )
        .await
        .expect("tools/list replies");
        let tools = response["result"]["tools"].as_array().expect("tools array");
        let tool = tools
            .iter()
            .find(|t| t["name"] == "get_secret_findings")
            .expect("get_secret_findings present");
        let desc = tool["description"].as_str().expect("description");
        assert!(desc.contains("rotate"), "desc: {desc}");
        assert!(
            desc.to_lowercase().contains("provenance") || desc.contains("generated_at"),
            "desc must mention provenance/staleness fields: {desc}"
        );
        assert!(
            desc.contains("never triggers a scan") || desc.contains("never trigger a scan"),
            "desc must state the tool never triggers a scan: {desc}"
        );

        let schema = &tool["inputSchema"];
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert!(
            schema["properties"]
                .as_object()
                .expect("properties")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn get_secret_findings_returns_never_scanned_envelope_when_no_artifact() {
        let repo = TestRepoDir::new("get-findings-never-scanned");
        let response = handle_request(
            request(
                Some(json!(18)),
                "tools/call",
                Some(json!({"name": "get_secret_findings", "arguments": {}})),
            ),
            &None,
            &test_context(Some(repo.path())),
        )
        .await
        .expect("tools/call replies");
        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let envelope: Value = serde_json::from_str(text).expect("valid json");
        assert_eq!(envelope["status"], "never_scanned");
    }

    #[tokio::test]
    async fn get_secret_findings_returns_no_repo_envelope_when_repo_unresolved() {
        let response = handle_request(
            request(
                Some(json!(20)),
                "tools/call",
                Some(json!({"name": "get_secret_findings", "arguments": {}})),
            ),
            &None,
            &test_context(None),
        )
        .await
        .expect("tools/call replies");
        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let envelope: Value = serde_json::from_str(text).expect("valid json");
        assert_eq!(envelope["status"], "no_repo");
    }

    #[tokio::test]
    async fn get_secret_findings_returns_report_when_ready() {
        let repo = TestRepoDir::new("get-findings-ready");
        repo.write_artifact(&test_scan_report());
        let context = test_context(Some(repo.path()));

        let response = handle_request(
            request(
                Some(json!(19)),
                "tools/call",
                Some(json!({"name": "get_secret_findings", "arguments": {}})),
            ),
            &None,
            &context,
        )
        .await
        .expect("tools/call replies");
        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let envelope: Value = serde_json::from_str(text).expect("valid json");
        assert_eq!(envelope["status"], "ready");
        assert_eq!(
            envelope["report"]["findings"][0]["rule_id"],
            "aws-access-key-id"
        );
    }

    // ── build_text_query ─────────────────────────────────────────────────

    #[test]
    fn build_text_query_defaults_to_domain() {
        let q = build_text_query("github.com".to_string(), None).expect("ok");
        assert!(matches!(q, CredentialQuery::Domain(d) if d == "github.com"));
    }

    #[test]
    fn build_text_query_search_variant() {
        let q = build_text_query("bank".to_string(), Some("search")).expect("ok");
        assert!(matches!(q, CredentialQuery::Search(s) if s == "bank"));
    }

    #[test]
    fn build_text_query_rejects_unknown_type() {
        let err = build_text_query("x".to_string(), Some("bogus")).expect_err("should error");
        assert!(err.contains("bogus"));
    }

    // ── pump_scrubbed_to_vec cap (finding #4) ───────────────────────────

    #[tokio::test]
    async fn pump_scrubbed_to_vec_caps_output_with_truncation_marker() {
        let data = vec![b'a'; MAX_CAPTURED_OUTPUT_BYTES + 100];
        let reader = std::io::Cursor::new(data);
        let redactor = Redactor::new(vec![]);

        let out = pump_scrubbed_to_vec(reader, redactor).await;

        let marker = truncation_marker();
        assert!(
            out.ends_with(marker.as_bytes()),
            "missing truncation marker in output of len {}",
            out.len()
        );
        let retained = &out[..out.len() - marker.len()];
        assert_eq!(
            retained.len(),
            MAX_CAPTURED_OUTPUT_BYTES,
            "retained bytes exceeded the cap"
        );
        assert!(retained.iter().all(|&b| b == b'a'));
    }

    #[tokio::test]
    async fn pump_scrubbed_to_vec_under_cap_has_no_truncation_marker() {
        let data = b"hello world".to_vec();
        let reader = std::io::Cursor::new(data.clone());
        let redactor = Redactor::new(vec![]);

        let out = pump_scrubbed_to_vec(reader, redactor).await;
        assert_eq!(out, data, "output must be untouched below the cap");
    }

    #[tokio::test]
    async fn pump_scrubbed_to_vec_still_scrubs_secrets_straddling_the_cap() {
        // The secret starts just before the cap boundary and ends just
        // after it. Scrubbing must see the whole stream regardless of what
        // gets retained afterward, so the raw secret must never appear in
        // the output even though its bytes sit right at the truncation
        // point.
        let mut data = vec![b'a'; MAX_CAPTURED_OUTPUT_BYTES - 5];
        data.extend_from_slice(b"hunter2 trailing filler past the cap boundary");
        let reader = std::io::Cursor::new(data);
        let redactor = Redactor::new(vec!["hunter2".to_string()]);

        let out = pump_scrubbed_to_vec(reader, redactor).await;
        let text = String::from_utf8_lossy(&out);
        assert!(!text.contains("hunter2"), "secret leaked: {text}");
    }
}

#[cfg(all(test, unix))]
mod unix_integration_tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use tokio::net::UnixListener;

    use super::*;

    fn unique_socket_path() -> String {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("/tmp/aac-mcp-{}-{n}.sock", std::process::id() % 100_000)
    }

    /// Spawn a one-shot mock local-socket server (mirrors
    /// `transport::local`'s test helper): accepts one connection, reads one
    /// request line, replies with the given canned response line.
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
                let _: Value = serde_json::from_slice(&buf).expect("mock received valid json");
                let mut out = response_line.as_bytes().to_vec();
                out.push(b'\n');
                let _ = stream.write_all(&out).await;
                let _ = stream.flush().await;
            }
        });

        tokio::task::yield_now().await;
        path
    }

    /// Shared by every credential/secret-tool test below — none of them
    /// exercise findings serving, so a fresh no-repo context is enough.
    async fn call_tool(socket: Option<String>, tool_name: &str, arguments: Value) -> Value {
        call_tool_with_context(socket, tool_name, arguments, &test_context(None)).await
    }

    async fn call_tool_with_context(
        socket: Option<String>,
        tool_name: &str,
        arguments: Value,
        context: &SharedContext,
    ) -> Value {
        handle_request(
            request(
                Some(json!(1)),
                "tools/call",
                Some(json!({"name": tool_name, "arguments": arguments})),
            ),
            &socket,
            context,
        )
        .await
        .expect("tools/call always replies")
    }

    #[tokio::test]
    async fn find_logins_returns_reference_not_secret() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"approved","item":{"name":"GitHub","username":"octocat"},"reference":"bw://item/item-1"}"#,
        )
        .await;

        let response = call_tool(Some(socket), "find_logins", json!({"query": "github.com"})).await;

        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let entries: Value = serde_json::from_str(text).expect("valid json list");
        assert_eq!(entries[0]["name"], "GitHub");
        assert_eq!(entries[0]["username"], "octocat");
        assert_eq!(entries[0]["reference"], "bw://item/item-1");
        assert!(!text.contains("password"));
    }

    #[tokio::test]
    async fn run_with_credential_scrubs_secret_from_child_output() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"approved","credential":{"username":"u","password":"hunter2","totp":"654321","uri":"https://example.com","credentialId":"item-1"},"reference":"bw://item/item-1"}"#,
        )
        .await;

        let response = call_tool(
            Some(socket),
            "run_with_credential",
            json!({"query": "example.com", "command": ["sh", "-c", "printf '%s' \"$AAC_PASSWORD\""]}),
        )
        .await;

        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let result: Value = serde_json::from_str(text).expect("valid json");
        assert_eq!(result["exitCode"], 0);
        let stdout = result["output"]["stdout"].as_str().expect("stdout");
        assert!(
            stdout.contains("[redacted:aac]"),
            "expected placeholder in: {stdout}"
        );
        assert!(!stdout.contains("hunter2"), "secret leaked in: {stdout}");
        assert!(
            !text.contains("hunter2"),
            "secret leaked in tool text: {text}"
        );
    }

    // ── find_secrets / run_with_secret ──────────────────────────────────

    #[tokio::test]
    async fn find_secrets_returns_reference_not_value() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"approved","item":{"name":"DB_PASSWORD"},"reference":"bw://secret/secret-1"}"#,
        )
        .await;

        let response = call_tool(
            Some(socket),
            "find_secrets",
            json!({"query": "DB_PASSWORD"}),
        )
        .await;

        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let entries: Value = serde_json::from_str(text).expect("valid json list");
        assert_eq!(entries[0]["name"], "DB_PASSWORD");
        assert_eq!(entries[0]["reference"], "bw://secret/secret-1");
        // The secret value must never appear anywhere in the tool output.
        assert!(!text.contains("hunter2"));
    }

    #[tokio::test]
    async fn find_secrets_denied_maps_to_is_error_tool_result() {
        let socket =
            spawn_mock_server(r#"{"version":1,"status":"denied","message":"Denied by user"}"#)
                .await;

        let response = call_tool(
            Some(socket),
            "find_secrets",
            json!({"query": "DB_PASSWORD"}),
        )
        .await;

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(text.to_lowercase().contains("denied"));
    }

    #[tokio::test]
    async fn run_with_secret_scrubs_value_from_child_output_and_never_returns_it() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"approved","secret":{"name":"DB_PASSWORD","value":"hunter2","secretId":"secret-1"},"reference":"bw://secret/secret-1"}"#,
        )
        .await;

        let response = call_tool(
            Some(socket),
            "run_with_secret",
            json!({"name": "DB_PASSWORD", "command": ["sh", "-c", "printf '%s' \"$DB_PASSWORD\""]}),
        )
        .await;

        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let result: Value = serde_json::from_str(text).expect("valid json");
        assert_eq!(result["exitCode"], 0);
        let stdout = result["output"]["stdout"].as_str().expect("stdout");
        assert!(
            stdout.contains("[redacted:aac]"),
            "expected placeholder in: {stdout}"
        );
        assert!(!stdout.contains("hunter2"), "secret leaked in: {stdout}");
        // The secret value must never appear anywhere in the tool result text.
        assert!(
            !text.contains("hunter2"),
            "secret leaked in tool text: {text}"
        );
    }

    #[tokio::test]
    async fn run_with_secret_default_env_var_name_derived_from_secret_name() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"approved","secret":{"name":"db.password!","value":"hunter2","secretId":"secret-1"},"reference":"bw://secret/secret-1"}"#,
        )
        .await;

        let response = call_tool(
            Some(socket),
            "run_with_secret",
            json!({"name": "db.password!", "command": ["sh", "-c", "env | grep -o '^[A-Z0-9_]*=' "]}),
        )
        .await;

        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let result: Value = serde_json::from_str(text).expect("valid json");
        let stdout = result["output"]["stdout"].as_str().expect("stdout");
        assert!(
            stdout.contains("DB_PASSWORD_="),
            "expected derived env var name DB_PASSWORD_ in: {stdout}"
        );
    }

    #[tokio::test]
    async fn run_with_secret_env_override_used_when_given() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"approved","secret":{"name":"DB_PASSWORD","value":"hunter2","secretId":"secret-1"},"reference":"bw://secret/secret-1"}"#,
        )
        .await;

        let response = call_tool(
            Some(socket),
            "run_with_secret",
            json!({"name": "DB_PASSWORD", "env": "MY_VAR", "command": ["sh", "-c", "printf '%s' \"$MY_VAR\""]}),
        )
        .await;

        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let result: Value = serde_json::from_str(text).expect("valid json");
        let stdout = result["output"]["stdout"].as_str().expect("stdout");
        assert!(stdout.contains("[redacted:aac]"), "stdout: {stdout}");
    }

    #[tokio::test]
    async fn run_with_secret_reference_reply_to_inject_request_is_rejected() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"approved","item":{"name":"DB_PASSWORD"},"reference":"bw://secret/secret-1"}"#,
        )
        .await;

        let response = call_tool(
            Some(socket),
            "run_with_secret",
            json!({"name": "DB_PASSWORD", "command": ["true"]}),
        )
        .await;

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(text.to_lowercase().contains("reference"));
    }

    #[tokio::test]
    async fn run_with_secret_requires_exactly_one_of_name_or_reference() {
        let response = call_tool(
            Some("/nonexistent".to_string()),
            "run_with_secret",
            json!({"command": ["true"]}),
        )
        .await;

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(text.contains("exactly one"));
    }

    #[tokio::test]
    async fn find_secrets_result_entries_carry_explicit_secret_id() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"approved","item":{"name":"DB_PASSWORD"},"reference":"bw://secret/secret-1"}"#,
        )
        .await;

        let response = call_tool(
            Some(socket),
            "find_secrets",
            json!({"query": "DB_PASSWORD"}),
        )
        .await;

        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let entries: Value = serde_json::from_str(text).expect("valid json list");
        assert_eq!(entries[0]["secretId"], "secret-1");
        assert_eq!(entries[0]["reference"], "bw://secret/secret-1");
    }

    // ── create_secret ────────────────────────────────────────────────

    #[tokio::test]
    async fn create_secret_happy_path_returns_secret_id_reference_and_name() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"approved","reference":"bw://secret/secret-1","item":{"name":"DB_PASSWORD"}}"#,
        )
        .await;

        let response = call_tool(
            Some(socket),
            "create_secret",
            json!({"name": "DB_PASSWORD", "value": "hunter2", "note": "prod db", "project": "my-app"}),
        )
        .await;

        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let result: Value = serde_json::from_str(text).expect("valid json");
        assert_eq!(result["secretId"], "secret-1");
        assert_eq!(result["reference"], "bw://secret/secret-1");
        assert_eq!(result["name"], "DB_PASSWORD");
        // The submitted value must never appear in the tool result.
        assert!(
            !text.contains("hunter2"),
            "value leaked in tool text: {text}"
        );
    }

    #[tokio::test]
    async fn create_secret_value_never_in_output_on_every_status() {
        let cases: &[(&str, &str)] = &[
            (
                "denied",
                r#"{"version":1,"status":"denied","message":"Denied by user"}"#,
            ),
            (
                "locked",
                r#"{"version":1,"status":"locked","message":"Vault is locked"}"#,
            ),
            (
                "error",
                r#"{"version":1,"status":"error","message":"boom"}"#,
            ),
            (
                "missing-reference",
                r#"{"version":1,"status":"approved","item":{"name":"DB_PASSWORD"}}"#,
            ),
        ];

        for (label, response_line) in cases {
            let socket = spawn_mock_server(response_line).await;
            let response = call_tool(
                Some(socket),
                "create_secret",
                json!({"name": "DB_PASSWORD", "value": "hunter2-super-secret"}),
            )
            .await;

            assert_eq!(
                response["result"]["isError"], true,
                "case {label} should be isError"
            );
            let text = response["result"]["content"][0]["text"]
                .as_str()
                .expect("text content");
            assert!(
                !text.contains("hunter2-super-secret"),
                "case {label}: value leaked in tool text: {text}"
            );
            assert!(
                !response.to_string().contains("hunter2-super-secret"),
                "case {label}: value leaked anywhere in response: {response}"
            );
        }
    }

    #[tokio::test]
    async fn create_secret_requires_non_empty_name_and_value() {
        let empty_name = call_tool(
            Some("/nonexistent".to_string()),
            "create_secret",
            json!({"name": "", "value": "hunter2"}),
        )
        .await;
        assert_eq!(empty_name["result"]["isError"], true);
        let text = empty_name["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(text.contains("'name'"));

        let empty_value = call_tool(
            Some("/nonexistent".to_string()),
            "create_secret",
            json!({"name": "DB_PASSWORD", "value": ""}),
        )
        .await;
        assert_eq!(empty_value["result"]["isError"], true);
        let text = empty_value["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(text.contains("'value'"));
    }

    #[tokio::test]
    async fn create_secret_missing_arguments_is_invalid_arguments_error() {
        let response = call_tool(
            Some("/nonexistent".to_string()),
            "create_secret",
            json!({"name": "DB_PASSWORD"}),
        )
        .await;
        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(text.contains("Invalid arguments"));
    }

    #[tokio::test]
    async fn create_secret_connect_failed_does_not_leak_socket_path() {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);

        let response = call_tool(
            Some(path.clone()),
            "create_secret",
            json!({"name": "DB_PASSWORD", "value": "hunter2"}),
        )
        .await;

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(!text.contains(&path), "raw socket path leaked");
        assert!(!text.contains("hunter2"), "value leaked");
    }

    #[tokio::test]
    async fn denied_maps_to_is_error_tool_result() {
        let socket =
            spawn_mock_server(r#"{"version":1,"status":"denied","message":"Denied by user"}"#)
                .await;

        let response =
            call_tool(Some(socket), "find_logins", json!({"query": "example.com"})).await;

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(text.to_lowercase().contains("denied"));
    }

    #[tokio::test]
    async fn not_found_maps_to_is_error_tool_result() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"notFound","message":"No matching item found"}"#,
        )
        .await;

        let response = call_tool(
            Some(socket),
            "run_with_credential",
            json!({"query": "nonexistent.example", "command": ["true"]}),
        )
        .await;

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(text.to_lowercase().contains("no matching login"));
    }

    #[tokio::test]
    async fn connect_failed_maps_to_is_error_without_leaking_path() {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);

        let response = call_tool(
            Some(path.clone()),
            "find_logins",
            json!({"query": "example.com"}),
        )
        .await;

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(
            !text.contains(&path),
            "raw socket path leaked into tool error text"
        );
    }

    // ── `serve` concurrency (finding #3) ────────────────────────────────

    /// Like `spawn_mock_server`, but holds the reply back until `release`
    /// fires — stands in for a desktop approval dialog the user hasn't
    /// answered yet.
    async fn spawn_delayed_mock_server(
        release: tokio::sync::oneshot::Receiver<()>,
        response_line: &'static str,
    ) -> String {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind mock socket");

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    match stream.read(&mut byte).await {
                        Ok(0) => return,
                        Ok(_) if byte[0] == b'\n' => break,
                        Ok(_) => buf.push(byte[0]),
                        Err(_) => return,
                    }
                }
                let _: Value = serde_json::from_slice(&buf).expect("mock received valid json");
                let _ = release.await;
                let mut out = response_line.as_bytes().to_vec();
                out.push(b'\n');
                let _ = stream.write_all(&out).await;
                let _ = stream.flush().await;
            }
        });

        tokio::task::yield_now().await;
        path
    }

    /// Like `spawn_mock_server`, but accepts connections in a loop and
    /// delays each reply by `delay` — stands in for the desktop app
    /// handling several pending approvals at once.
    async fn spawn_multi_delayed_mock_server(
        delay: std::time::Duration,
        response_line: &'static str,
    ) -> String {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind mock socket");

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut byte = [0u8; 1];
                    loop {
                        match stream.read(&mut byte).await {
                            Ok(0) => return,
                            Ok(_) if byte[0] == b'\n' => break,
                            Ok(_) => buf.push(byte[0]),
                            Err(_) => return,
                        }
                    }
                    let _: Value = serde_json::from_slice(&buf).expect("mock received valid json");
                    tokio::time::sleep(delay).await;
                    let mut out = response_line.as_bytes().to_vec();
                    out.push(b'\n');
                    let _ = stream.write_all(&out).await;
                    let _ = stream.flush().await;
                });
            }
        });

        tokio::task::yield_now().await;
        path
    }

    #[tokio::test]
    async fn ping_is_answered_while_a_tools_call_is_pending() {
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let socket = spawn_delayed_mock_server(
            release_rx,
            r#"{"version":1,"status":"approved","credential":{"username":"u","password":"p","totp":"123456","uri":"https://example.com","credentialId":"item-1"},"reference":"bw://item/item-1"}"#,
        )
        .await;

        let (mut client_in, server_in) = tokio::io::duplex(64 * 1024);
        let (server_out, client_out) = tokio::io::duplex(64 * 1024);
        let mut client_out = BufReader::new(client_out);

        let serve_task = tokio::spawn(serve(
            BufReader::new(server_in),
            server_out,
            Some(socket),
            no_repo_override(),
        ));

        write_frame(
            &mut client_in,
            &json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "run_with_credential",
                           "arguments": {"query": "example.com", "command": ["true"]}}
            }),
        )
        .await
        .expect("write tools/call frame");

        // Give the spawned tools/call task time to reach (and block on) the
        // mock server before sending the ping.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        write_frame(
            &mut client_in,
            &json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
        )
        .await
        .expect("write ping frame");

        let first = read_frame(&mut client_out)
            .await
            .expect("read io")
            .expect("a frame");
        let first: Value = serde_json::from_slice(&first).expect("valid json");
        assert_eq!(
            first["id"],
            json!(2),
            "ping must be answered before the pending tools/call completes"
        );
        assert_eq!(first["result"], json!({}));

        let _ = release_tx.send(());

        let second = read_frame(&mut client_out)
            .await
            .expect("read io")
            .expect("a frame");
        let second: Value = serde_json::from_slice(&second).expect("valid json");
        assert_eq!(second["id"], json!(1));
        assert_eq!(second["result"]["isError"], false);

        drop(client_in);
        let _ = serve_task.await;
    }

    #[tokio::test]
    async fn two_concurrent_tools_calls_do_not_serialize() {
        let socket = spawn_multi_delayed_mock_server(
            std::time::Duration::from_millis(200),
            r#"{"version":1,"status":"approved","item":{"name":"Example","username":"u"},"reference":"bw://item/item-1"}"#,
        )
        .await;

        let (mut client_in, server_in) = tokio::io::duplex(64 * 1024);
        let (server_out, client_out) = tokio::io::duplex(64 * 1024);
        let mut client_out = BufReader::new(client_out);

        let serve_task = tokio::spawn(serve(
            BufReader::new(server_in),
            server_out,
            Some(socket),
            no_repo_override(),
        ));

        let start = std::time::Instant::now();

        for id in [1, 2] {
            write_frame(
                &mut client_in,
                &json!({
                    "jsonrpc": "2.0", "id": id, "method": "tools/call",
                    "params": {"name": "find_logins", "arguments": {"query": "example.com"}}
                }),
            )
            .await
            .expect("write tools/call frame");
        }

        let mut ids_seen = Vec::new();
        for _ in 0..2 {
            let frame = read_frame(&mut client_out)
                .await
                .expect("read io")
                .expect("a frame");
            let value: Value = serde_json::from_slice(&frame).expect("valid json");
            ids_seen.push(value["id"].as_i64().expect("id"));
        }
        let elapsed = start.elapsed();

        ids_seen.sort_unstable();
        assert_eq!(ids_seen, vec![1, 2]);
        // Two sequential ~200ms calls would take ~400ms; concurrent
        // handling should land well under that (generous margin for CI
        // scheduling jitter).
        assert!(
            elapsed < std::time::Duration::from_millis(350),
            "calls appear to have serialized: took {elapsed:?}"
        );

        drop(client_in);
        let _ = serve_task.await;
    }

    // ── fill_credential / describe_fill_target ──────────────────────────

    #[tokio::test]
    async fn fill_credential_approved_filled_returns_value_free_result() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"approved","item":{"name":"bitnotes.io","username":"demo@bitnotes.io"},"reference":"bw://item/item-1","fill":{"status":"filled","origin":"https://bitnotes.io","fields":[{"role":"username","status":"filled","target":"input#email (login form)"},{"role":"password","status":"filled","target":"input[type=password]#pw"}]}}"#,
        )
        .await;

        let response = call_tool(
            Some(socket),
            "fill_credential",
            json!({"domain": "bitnotes.io"}),
        )
        .await;

        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let result: Value = serde_json::from_str(text).expect("valid json");
        assert_eq!(result["status"], "filled");
        assert_eq!(result["origin"], "https://bitnotes.io");
        assert_eq!(result["reference"], "bw://item/item-1");
        assert_eq!(result["item"]["name"], "bitnotes.io");
        assert_eq!(result["item"]["username"], "demo@bitnotes.io");
        assert_eq!(result["fields"][0]["role"], "username");
        assert_eq!(result["fields"][1]["role"], "password");
        // Never a credential value anywhere in the tool output.
        assert!(!text.contains("hunter2"));
    }

    #[tokio::test]
    async fn fill_credential_partial_reports_per_field_status() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"approved","item":{"name":"bitnotes.io"},"reference":"bw://item/item-1","fill":{"status":"partial","origin":"https://bitnotes.io","fields":[{"role":"username","status":"filled","target":"input#email"},{"role":"password","status":"skipped","reason":"no password field on page"}]}}"#,
        )
        .await;

        let response = call_tool(
            Some(socket),
            "fill_credential",
            json!({"domain": "bitnotes.io", "fields": ["username", "password"]}),
        )
        .await;

        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let result: Value = serde_json::from_str(text).expect("valid json");
        assert_eq!(result["status"], "partial");
        assert_eq!(result["fields"][1]["status"], "skipped");
        assert_eq!(result["fields"][1]["reason"], "no password field on page");
    }

    #[tokio::test]
    async fn fill_credential_origin_mismatch_names_origin_and_leaks_no_value() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"originMismatch","item":{"name":"bitnotes.io"},"fill":{"origin":"https://evil.example"}}"#,
        )
        .await;

        let response = call_tool(
            Some(socket),
            "fill_credential",
            json!({"domain": "bitnotes.io"}),
        )
        .await;

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(
            text.contains("https://evil.example"),
            "message should name the mismatched origin: {text}"
        );
        // The agent-facing message must never carry a credential value —
        // only the origin and the item name (both non-secret metadata).
        assert!(!text.contains("hunter2"));
    }

    #[tokio::test]
    async fn fill_credential_no_safe_target_passes_through_each_reason() {
        for reason in [
            "looks-like-registration",
            "ambiguous-target",
            "no-password-field",
            "hidden-field-only",
            "cross-origin-frame",
            "no-login-form",
        ] {
            let socket = spawn_mock_server(Box::leak(
                format!(r#"{{"version":1,"status":"noSafeTarget","message":"{reason}"}}"#)
                    .into_boxed_str(),
            ))
            .await;

            let response = call_tool(
                Some(socket),
                "fill_credential",
                json!({"domain": "bitnotes.io"}),
            )
            .await;

            assert_eq!(response["result"]["isError"], true);
            let text = response["result"]["content"][0]["text"]
                .as_str()
                .expect("text content");
            assert!(
                text.contains(reason),
                "reason {reason} missing from: {text}"
            );
        }
    }

    #[tokio::test]
    async fn fill_credential_rejects_zero_selectors() {
        let response = call_tool(
            Some("/nonexistent".to_string()),
            "fill_credential",
            json!({}),
        )
        .await;

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(text.contains("exactly one"));
    }

    #[tokio::test]
    async fn fill_credential_rejects_two_selectors() {
        let response = call_tool(
            Some("/nonexistent".to_string()),
            "fill_credential",
            json!({"domain": "bitnotes.io", "name": "bitnotes"}),
        )
        .await;

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(text.contains("exactly one"));
    }

    #[tokio::test]
    async fn describe_fill_target_round_trip_with_target_token() {
        let socket = spawn_mock_server(
            r#"{"version":1,"status":"approved","fillTarget":{"origin":"https://bitnotes.io","formClass":"login","candidates":[{"role":"username","target":"input#email","visible":true,"frame":"top"},{"role":"password","target":"input[type=password]#pw","visible":true,"frame":"top"}],"refusals":[],"targetToken":"ft_abc123","expiresInMs":30000}}"#,
        )
        .await;

        let response = call_tool(Some(socket), "describe_fill_target", json!({})).await;

        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let result: Value = serde_json::from_str(text).expect("valid json");
        assert_eq!(result["origin"], "https://bitnotes.io");
        assert_eq!(result["formClass"], "login");
        assert_eq!(result["candidates"][0]["role"], "username");
        assert_eq!(result["targetToken"], "ft_abc123");
        assert_eq!(result["expiresInMs"], 30000);
    }

    #[tokio::test]
    async fn fill_credential_passes_target_token_through_to_the_wire_request() {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind mock socket");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                match stream.read(&mut byte).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) if byte[0] == b'\n' => break,
                    Ok(_) => buf.push(byte[0]),
                }
            }
            let request: Value = serde_json::from_slice(&buf).expect("valid json request");

            let response = r#"{"version":1,"status":"approved","item":{"name":"bitnotes.io"},"reference":"bw://item/item-1","fill":{"status":"filled","origin":"https://bitnotes.io","fields":[]}}"#;
            let mut out = response.as_bytes().to_vec();
            out.push(b'\n');
            let _ = stream.write_all(&out).await;
            let _ = stream.flush().await;

            request
        });

        tokio::task::yield_now().await;

        let response = call_tool(
            Some(path),
            "fill_credential",
            json!({"domain": "bitnotes.io", "target_token": "ft_abc123"}),
        )
        .await;
        assert_eq!(response["result"]["isError"], false);

        let request = server.await.expect("server task");
        assert_eq!(request["op"], "credentialRequest");
        assert_eq!(request["delivery"], "fill");
        assert_eq!(request["fill"]["targetToken"], "ft_abc123");
    }
}
