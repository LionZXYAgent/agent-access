//! Run subcommand — fetch a credential and inject it as env vars into a child process
//!
//! Secrets never touch stdout or disk; they are passed exclusively through
//! the child process's environment.

use std::collections::HashMap;

use ap_client::CredentialData;
use clap::Args;
use color_eyre::eyre::{Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::DEFAULT_RELAY_URL;
use super::connect::{
    CredentialOutcome, Delivery, SecretRequestOutcome, fetch_credential_dispatch,
    fetch_secret_dispatch,
};
use super::output::{exit_code, exit_code_for_report};
use super::redact::Redactor;
use crate::transport::local;

/// All credential fields with their canonical name, `AAC_` env var key, and
/// whether the value is secret. Secret fields are what `--no-scrub`-less
/// `aac run` redacts from the child's stdout/stderr when they end up
/// injected into its environment; non-secret fields (username, uri,
/// domain, credential_id) are left alone.
const CREDENTIAL_FIELDS: &[(&str, &str, bool)] = &[
    ("username", "AAC_USERNAME", false),
    ("password", "AAC_PASSWORD", true),
    ("totp", "AAC_TOTP", true),
    ("uri", "AAC_URI", false),
    ("notes", "AAC_NOTES", true),
    ("domain", "AAC_DOMAIN", false),
    ("credential_id", "AAC_CREDENTIAL_ID", false),
];

/// Run a command with credentials injected as environment variables
#[derive(Args)]
#[command(after_help = "\
EXAMPLES:
  # Map specific fields to env vars:
  aac run --domain example.com --env DB_PASSWORD=password --env DB_USER=username -- psql

  # Inject all fields with AAC_ prefix:
  aac run --domain example.com --env-all -- deploy.sh

  # Combine defaults with custom overrides:
  aac run --domain example.com --env-all --env CUSTOM_PW=password -- deploy.sh

The token can be passed via --token <TOKEN> or the AAC_TOKEN env var.

VALID FIELDS: username, password, totp, uri, notes, domain, credential_id")]
pub struct RunArgs {
    /// Relay server URL
    #[arg(long, default_value = DEFAULT_RELAY_URL)]
    pub relay_url: String,

    /// Domain to request credentials for
    #[arg(long, conflicts_with_all = ["id", "search", "reference", "secret"])]
    pub domain: Option<String>,

    /// Vault item ID to request credentials for. Accepts a bare id or a
    /// `bw://item/<id>` reference.
    #[arg(long, conflicts_with_all = ["domain", "search", "reference", "secret"])]
    pub id: Option<String>,

    /// Free-text search for credentials
    #[arg(long, conflicts_with_all = ["domain", "id", "reference", "secret"])]
    pub search: Option<String>,

    /// Redeem a `bw://item/<id>` reference (e.g. one printed by a prior
    /// `aac connect --output json` reference response). Equivalent to
    /// `--id` with the `bw://item/` prefix stripped.
    #[arg(long = "ref", conflicts_with_all = ["domain", "id", "search", "secret"])]
    pub reference: Option<String>,

    /// Secrets Manager secret name or `bw://secret/<id>` reference to
    /// inject, instead of a vault credential. Local transport only — there
    /// is no relay fallback for secrets. The value is injected under
    /// --secret-env if given, else the secret's own name (uppercased and
    /// sanitized — see `local::secret_env_var_name`).
    #[arg(long, conflicts_with_all = ["domain", "id", "search", "reference", "env_mappings", "env_all"])]
    pub secret: Option<String>,

    /// Override the environment variable name the secret value is injected
    /// under (default: the secret's own name, uppercased and sanitized).
    /// Only meaningful together with --secret; validated at runtime rather
    /// than via clap's `requires` (which silently no-ops here: `secret`
    /// conflicts_with `domain`/`env_all`/etc., and clap skips a `requires`
    /// error when satisfying it would itself immediately trigger a
    /// conflicts_with error against an already-present arg).
    #[arg(long)]
    pub secret_env: Option<String>,

    /// Token (rendezvous code or PSK token)
    #[arg(long, env = "AAC_TOKEN", conflicts_with = "session")]
    pub token: Option<String>,

    /// Session fingerprint to reconnect to
    #[arg(long, conflicts_with = "token")]
    pub session: Option<String>,

    /// Don't save this connection for future use
    #[arg(long)]
    pub ephemeral_connection: bool,

    /// Local agent-access endpoint to use instead of the platform default
    /// (unix socket path / windows pipe name). Forces the local transport:
    /// fails rather than falling back to the relay if unreachable.
    #[arg(long, env = "AAC_SOCKET")]
    pub socket: Option<String>,

    /// Timeout in seconds for credential response (default: 120)
    #[arg(long)]
    pub timeout: Option<u64>,

    /// Map a credential field to an env var: VAR_NAME=field
    /// Valid fields: username, password, totp, uri, notes, domain, credential_id
    #[arg(long = "env", value_name = "VAR=FIELD")]
    pub env_mappings: Vec<String>,

    /// Inject all credential fields with AAC_ prefix
    #[arg(long = "env-all")]
    pub env_all: bool,

    /// Disable stdout/stderr scrubbing of secret values. Scrubbing is on by
    /// default; disabling it means the child's output is forwarded
    /// unmodified and may leak injected credential values.
    #[arg(long = "no-scrub")]
    pub no_scrub: bool,

    /// Command and arguments to run (after --)
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

/// Look up a credential field value by name
fn get_field<'a>(credential: &'a CredentialData, field: &str) -> Option<&'a str> {
    match field {
        "username" => credential.username.as_deref(),
        "password" => credential.password.as_deref().map(|x| x.as_str()),
        "totp" => credential.totp.as_deref(),
        "uri" => credential.uri.as_deref(),
        "notes" => credential.notes.as_deref(),
        "credential_id" => credential.credential_id.as_deref(),
        "domain" => credential.domain.as_deref(),
        _ => None,
    }
}

/// Build the environment variable map from credential data and mapping options.
fn build_env_vars(
    credential: &CredentialData,
    env_all: bool,
    explicit_mappings: &[(String, String)],
) -> HashMap<String, String> {
    let mut env_vars = HashMap::new();

    if env_all {
        for &(field_name, env_key, _secret) in CREDENTIAL_FIELDS {
            if let Some(value) = get_field(credential, field_name) {
                env_vars.insert(env_key.to_string(), value.to_string());
            }
        }
    }

    // Apply explicit mappings (override any --env-all defaults)
    for (var_name, field) in explicit_mappings {
        if let Some(value) = get_field(credential, field) {
            env_vars.insert(var_name.clone(), value.to_string());
        }
    }

    env_vars
}

/// Check whether a field name is valid.
fn is_valid_field(field: &str) -> bool {
    CREDENTIAL_FIELDS.iter().any(|&(name, _, _)| name == field)
}

/// Whether a credential field is secret-classified (drives output
/// scrubbing; may drive future policies too).
fn is_secret_field(field: &str) -> bool {
    CREDENTIAL_FIELDS
        .iter()
        .any(|&(name, _, secret)| name == field && secret)
}

/// Collect the raw values of every secret-classified field that actually
/// ended up injected into the child's environment (via `--env-all` and/or
/// explicit `--env` mappings). These are exactly the values `aac run`
/// scrubs from the child's stdout/stderr. Deduplicated; empty values are
/// dropped (an empty needle would match everywhere).
fn collect_secret_values(
    credential: &CredentialData,
    env_all: bool,
    explicit_mappings: &[(String, String)],
) -> Vec<String> {
    let mut values: Vec<String> = Vec::new();
    let mut push = |value: &str| {
        if !value.is_empty() && !values.iter().any(|v| v == value) {
            values.push(value.to_string());
        }
    };

    if env_all {
        for &(field_name, _, secret) in CREDENTIAL_FIELDS {
            if secret {
                if let Some(value) = get_field(credential, field_name) {
                    push(value);
                }
            }
        }
    }

    for (_, field) in explicit_mappings {
        if is_secret_field(field) {
            if let Some(value) = get_field(credential, field) {
                push(value);
            }
        }
    }

    values
}

impl RunArgs {
    pub async fn run(self) -> Result<()> {
        if self.secret_env.is_some() && self.secret.is_none() {
            bail!("--secret-env requires --secret");
        }

        if self.secret.is_some() {
            return run_secret(self).await;
        }

        // Validate that exactly one of --domain/--id/--search/--ref is provided
        let query = match (&self.domain, &self.id, &self.search, &self.reference) {
            (Some(domain), None, None, None) => ap_client::CredentialQuery::Domain(domain.clone()),
            (None, Some(id), None, None) => {
                ap_client::CredentialQuery::Id(local::strip_reference(id).to_string())
            }
            (None, None, Some(search), None) => ap_client::CredentialQuery::Search(search.clone()),
            (None, None, None, Some(reference)) => {
                ap_client::CredentialQuery::Id(local::strip_reference(reference).to_string())
            }
            (None, None, None, None) => {
                bail!("One of --domain, --id, --search, or --ref is required")
            }
            _ => unreachable!("clap conflicts_with_all prevents this"),
        };

        // Validate that at least one env mapping method is specified
        if !self.env_all && self.env_mappings.is_empty() {
            bail!("At least one of --env or --env-all is required");
        }

        // Parse and validate --env mappings up front
        let mut explicit_mappings: Vec<(String, String)> = Vec::new();
        for mapping in &self.env_mappings {
            let (var_name, field) = mapping.split_once('=').ok_or_else(|| {
                color_eyre::eyre::eyre!(
                    "Invalid --env format: '{mapping}' (expected VAR_NAME=field)"
                )
            })?;

            if var_name.is_empty() {
                bail!("Empty variable name in --env mapping: '{mapping}'");
            }

            let field_lower = field.to_lowercase();
            if !is_valid_field(&field_lower) {
                let valid: Vec<&str> = CREDENTIAL_FIELDS.iter().map(|&(name, _, _)| name).collect();
                bail!(
                    "Unknown credential field '{field}' in --env mapping. \
                     Valid fields: {}",
                    valid.join(", ")
                );
            }

            explicit_mappings.push((var_name.to_string(), field_lower));
        }

        // Fetch the credential — local transport when available/requested
        // (delivery: inject), relay otherwise. Never a Reference outcome:
        // `aac run` always asks for `Delivery::Inject`.
        let credential_timeout = self.timeout.map(std::time::Duration::from_secs);
        let outcome = match fetch_credential_dispatch(
            &self.relay_url,
            self.token.as_deref(),
            self.session.as_deref(),
            self.ephemeral_connection,
            &query,
            credential_timeout,
            self.socket.as_deref(),
            Delivery::Inject,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(e) => {
                let code = exit_code_for_report(&e);
                tracing::error!("{e}");
                std::process::exit(code);
            }
        };

        let credential = match outcome {
            CredentialOutcome::Credential(credential) => credential,
            CredentialOutcome::Reference { .. } => {
                // Defense in depth: a local server that ignores `delivery`
                // and returns a reference anyway must not silently run the
                // child with no credentials injected.
                bail!(
                    "local agent-access endpoint returned a reference response for an inject request"
                );
            }
        };

        let env_vars = build_env_vars(&credential, self.env_all, &explicit_mappings);

        if env_vars.is_empty() {
            tracing::warn!(
                "No credential fields matched — child process will run without injected env vars"
            );
        }

        if self.no_scrub {
            eprintln!(
                "warning: --no-scrub is set — the child process's stdout/stderr will NOT be \
                 redacted and may leak injected credential values"
            );
        }

        let secret_values = collect_secret_values(&credential, self.env_all, &explicit_mappings);

        // Spawn child process
        let program = self.command[0].clone();
        let args = self.command[1..].to_vec();

        let status = run_child(&program, &args, &env_vars, secret_values, self.no_scrub).await?;

        std::process::exit(status.code().unwrap_or(exit_code::GENERAL_ERROR));
    }
}

/// `aac run --secret ...` — Secrets Manager secret injected into the child
/// env, instead of a vault credential. Always `Delivery::Inject`;
/// local-transport-only (no relay fallback for secrets, per the
/// architecture doc's M4 wire protocol section). The env var name defaults
/// to the secret's own name (uppercased/sanitized via
/// `local::secret_env_var_name`) — `--secret-env` overrides it.
async fn run_secret(args: RunArgs) -> Result<()> {
    let secret_input = args
        .secret
        .as_deref()
        .expect("run_secret is only called when self.secret is Some");
    let query = local::secret_query_from_flag(secret_input);

    let outcome =
        match fetch_secret_dispatch(&query, args.socket.as_deref(), Delivery::Inject).await {
            Ok(outcome) => outcome,
            Err(e) => {
                let code = exit_code_for_report(&e);
                tracing::error!("{e}");
                std::process::exit(code);
            }
        };

    let secret = match outcome {
        SecretRequestOutcome::Secret(secret) => secret,
        SecretRequestOutcome::Reference { .. } => {
            // Defense in depth: a local server that ignores `delivery` and
            // returns a reference anyway must not silently run the child
            // with no secret injected.
            bail!(
                "local agent-access endpoint returned a reference response for an inject request"
            );
        }
    };

    let env_name = args
        .secret_env
        .clone()
        .unwrap_or_else(|| local::secret_env_var_name(&secret.name));

    let mut env_vars = HashMap::new();
    env_vars.insert(env_name, secret.value.as_str().to_string());

    if args.no_scrub {
        eprintln!(
            "warning: --no-scrub is set — the child process's stdout/stderr will NOT be \
             redacted and may leak the injected secret value"
        );
    }

    let secret_values = if secret.value.as_str().is_empty() {
        Vec::new()
    } else {
        vec![secret.value.as_str().to_string()]
    };

    let program = args.command[0].clone();
    let cmd_args = args.command[1..].to_vec();

    let status = run_child(&program, &cmd_args, &env_vars, secret_values, args.no_scrub).await?;

    std::process::exit(status.code().unwrap_or(exit_code::GENERAL_ERROR));
}

/// Spawn the child process and, unless `no_scrub` is set, pump its stdout
/// and stderr incrementally through a [`Redactor`] on the way to *our*
/// stdout/stderr — the child's exit code is preserved exactly either way.
async fn run_child(
    program: &str,
    args: &[String],
    env_vars: &HashMap<String, String>,
    secret_values: Vec<String>,
    no_scrub: bool,
) -> Result<std::process::ExitStatus> {
    let out_redactor = Redactor::new(secret_values.clone());
    let err_redactor = Redactor::new(secret_values);

    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args).envs(env_vars);

    if no_scrub || out_redactor.is_noop() {
        // Nothing to redact (or the user opted out) — inherit stdio directly,
        // same behavior/perf as before this change.
        let status = cmd
            .status()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("Failed to execute '{program}': {e}"))?;
        return Ok(status);
    }

    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to execute '{program}': {e}"))?;

    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");

    let out_task = tokio::spawn(pump_scrubbed(stdout, tokio::io::stdout(), out_redactor));
    let err_task = tokio::spawn(pump_scrubbed(stderr, tokio::io::stderr(), err_redactor));

    // Await the child concurrently with draining its pipes — piping both
    // streams and only reading them after `wait()` risks deadlock if the
    // child fills a pipe buffer before exiting.
    let status = child
        .wait()
        .await
        .map_err(|e| color_eyre::eyre::eyre!("Failed to wait on '{program}': {e}"))?;

    // The pipes are at EOF once the child has exited (or already were);
    // the pump tasks finish shortly after and flush any held-back tail.
    let _ = out_task.await;
    let _ = err_task.await;

    Ok(status)
}

/// Read `reader` to EOF in chunks, forwarding each chunk to `writer` after
/// passing it through `redactor`, then flush the redactor's held-back tail.
/// Never buffers the whole stream — output is forwarded incrementally.
async fn pump_scrubbed<R, W>(mut reader: R, mut writer: W, mut redactor: Redactor)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let out = redactor.push(&buf[..n]);
                if !out.is_empty() && writer.write_all(&out).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let tail = redactor.finish();
    if !tail.is_empty() {
        let _ = writer.write_all(&tail).await;
    }
    let _ = writer.flush().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_credential() -> CredentialData {
        CredentialData {
            username: Some("admin".to_string()),
            password: Some("s3cret".to_string().into()),
            totp: Some("123456".to_string()),
            uri: Some("https://example.com".to_string()),
            notes: None,
            credential_id: Some("item-uuid-123".to_string()),
            domain: Some("example.com".to_string()),
        }
    }

    #[test]
    fn get_field_returns_correct_values() {
        let cred = make_credential();
        assert_eq!(get_field(&cred, "username"), Some("admin"));
        assert_eq!(get_field(&cred, "password"), Some("s3cret"));
        assert_eq!(get_field(&cred, "totp"), Some("123456"));
        assert_eq!(get_field(&cred, "domain"), Some("example.com"));
        assert_eq!(get_field(&cred, "notes"), None);
        assert_eq!(get_field(&cred, "credential_id"), Some("item-uuid-123"));
        assert_eq!(get_field(&cred, "invalid"), None);
    }

    #[test]
    fn build_env_vars_with_env_all() {
        let cred = make_credential();
        let env_vars = build_env_vars(&cred, true, &[]);

        assert_eq!(env_vars.get("AAC_USERNAME").expect("username"), "admin");
        assert_eq!(env_vars.get("AAC_PASSWORD").expect("password"), "s3cret");
        assert_eq!(env_vars.get("AAC_TOTP").expect("totp"), "123456");
        assert_eq!(env_vars.get("AAC_URI").expect("uri"), "https://example.com");
        assert!(!env_vars.contains_key("AAC_NOTES"), "notes is None");
        assert_eq!(env_vars.get("AAC_DOMAIN").expect("domain"), "example.com");
        assert_eq!(
            env_vars.get("AAC_CREDENTIAL_ID").expect("credential_id"),
            "item-uuid-123"
        );
        assert_eq!(env_vars.len(), 6);
    }

    #[test]
    fn build_env_vars_with_explicit_mappings() {
        let cred = make_credential();
        let mappings = vec![
            ("DB_USER".to_string(), "username".to_string()),
            ("DB_PASS".to_string(), "password".to_string()),
        ];
        let env_vars = build_env_vars(&cred, false, &mappings);

        assert_eq!(env_vars.get("DB_USER").expect("DB_USER"), "admin");
        assert_eq!(env_vars.get("DB_PASS").expect("DB_PASS"), "s3cret");
        assert_eq!(env_vars.len(), 2);
    }

    #[test]
    fn build_env_vars_explicit_overrides_env_all() {
        let cred = make_credential();
        let mappings = vec![("AAC_USERNAME".to_string(), "password".to_string())];
        let env_vars = build_env_vars(&cred, true, &mappings);

        // Explicit mapping overrides the AAC_USERNAME from env_all
        assert_eq!(env_vars.get("AAC_USERNAME").expect("overridden"), "s3cret");
    }

    #[test]
    fn build_env_vars_env_all_empty_credential() {
        let cred = CredentialData {
            username: None,
            password: None,
            totp: None,
            uri: None,
            notes: None,
            credential_id: None,
            domain: Some("example.com".to_string()),
        };
        let env_vars = build_env_vars(&cred, true, &[]);

        assert_eq!(env_vars.len(), 1);
        assert_eq!(env_vars.get("AAC_DOMAIN").expect("domain"), "example.com");
    }

    #[test]
    fn is_valid_field_accepts_known_rejects_unknown() {
        assert!(is_valid_field("username"));
        assert!(is_valid_field("credential_id"));
        assert!(is_valid_field("domain"));
        assert!(!is_valid_field("bogus"));
        assert!(!is_valid_field(""));
    }

    // ── secrecy classification / collect_secret_values ────────────────

    #[test]
    fn is_secret_field_classifies_correctly() {
        assert!(is_secret_field("password"));
        assert!(is_secret_field("totp"));
        assert!(is_secret_field("notes"));
        assert!(!is_secret_field("username"));
        assert!(!is_secret_field("uri"));
        assert!(!is_secret_field("domain"));
        assert!(!is_secret_field("credential_id"));
        assert!(!is_secret_field("bogus"));
    }

    #[test]
    fn collect_secret_values_env_all_picks_only_secret_fields() {
        let cred = make_credential();
        let values = collect_secret_values(&cred, true, &[]);
        assert!(values.contains(&"s3cret".to_string()));
        assert!(values.contains(&"123456".to_string()));
        assert!(!values.contains(&"admin".to_string()));
        assert!(!values.contains(&"example.com".to_string()));
        assert!(!values.contains(&"item-uuid-123".to_string()));
    }

    #[test]
    fn collect_secret_values_explicit_mapping_of_secret_field() {
        let cred = make_credential();
        let mappings = vec![("DB_PASS".to_string(), "password".to_string())];
        let values = collect_secret_values(&cred, false, &mappings);
        assert_eq!(values, vec!["s3cret".to_string()]);
    }

    #[test]
    fn collect_secret_values_explicit_mapping_of_non_secret_field_excluded() {
        let cred = make_credential();
        let mappings = vec![("DB_USER".to_string(), "username".to_string())];
        let values = collect_secret_values(&cred, false, &mappings);
        assert!(values.is_empty());
    }

    #[test]
    fn collect_secret_values_deduplicates() {
        let cred = make_credential();
        let mappings = vec![
            ("PW1".to_string(), "password".to_string()),
            ("PW2".to_string(), "password".to_string()),
        ];
        let values = collect_secret_values(&cred, true, &mappings);
        assert_eq!(values.iter().filter(|v| *v == "s3cret").count(), 1);
    }

    #[test]
    fn collect_secret_values_skips_none_and_empty() {
        let cred = CredentialData {
            username: Some("admin".to_string()),
            password: None,
            totp: None,
            uri: None,
            notes: Some(String::new()),
            credential_id: None,
            domain: None,
        };
        let values = collect_secret_values(&cred, true, &[]);
        assert!(values.is_empty());
    }

    // ── --secret / --secret-env CLI flag mutual exclusion (clap-level) ──

    fn try_parse(args: &[&str]) -> std::result::Result<RunArgs, clap::Error> {
        use clap::{Args as ClapArgs, FromArgMatches};
        let cmd = RunArgs::augment_args(clap::Command::new("run"));
        let matches = cmd.try_get_matches_from(args)?;
        RunArgs::from_arg_matches(&matches)
    }

    /// Like `try_parse`, but for tests asserting a parse *failure* —
    /// `RunArgs` doesn't derive `Debug` (it's plain CLI args, but nothing
    /// depends on printing it), so `Result::expect_err` isn't available;
    /// this discards the `Ok` value manually instead.
    fn expect_parse_error(args: &[&str]) -> clap::Error {
        match try_parse(args) {
            Ok(_) => panic!("expected a parse error for args: {args:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn secret_conflicts_with_domain() {
        let err = expect_parse_error(&[
            "run",
            "--domain",
            "example.com",
            "--secret",
            "DB_PASSWORD",
            "--",
            "true",
        ]);
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn secret_conflicts_with_ref() {
        let err = expect_parse_error(&[
            "run",
            "--ref",
            "bw://item/item-1",
            "--secret",
            "DB_PASSWORD",
            "--",
            "true",
        ]);
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn secret_conflicts_with_env_all() {
        let err =
            expect_parse_error(&["run", "--secret", "DB_PASSWORD", "--env-all", "--", "true"]);
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn secret_conflicts_with_env_mapping() {
        let err = expect_parse_error(&[
            "run",
            "--secret",
            "DB_PASSWORD",
            "--env",
            "FOO=username",
            "--",
            "true",
        ]);
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    /// `--secret-env` without `--secret` can't be caught by clap's
    /// declarative `requires` here (see the doc comment on the field) —
    /// `RunArgs::run` enforces it itself at runtime instead.
    #[tokio::test]
    async fn secret_env_requires_secret_at_runtime() {
        let parsed = try_parse(&[
            "run",
            "--domain",
            "example.com",
            "--env-all",
            "--secret-env",
            "FOO",
            "--",
            "true",
        ])
        .expect("clap parse itself should succeed");

        let err = parsed
            .run()
            .await
            .expect_err("--secret-env without --secret must be rejected at runtime");
        assert!(format!("{err}").contains("--secret-env requires --secret"));
    }

    #[test]
    fn secret_alone_parses_ok() {
        let parsed =
            try_parse(&["run", "--secret", "DB_PASSWORD", "--", "true"]).expect("should parse");
        assert_eq!(parsed.secret.as_deref(), Some("DB_PASSWORD"));
        assert!(parsed.secret_env.is_none());
    }

    #[test]
    fn secret_with_secret_env_parses_ok() {
        let parsed = try_parse(&[
            "run",
            "--secret",
            "DB_PASSWORD",
            "--secret-env",
            "MY_VAR",
            "--",
            "true",
        ])
        .expect("should parse");
        assert_eq!(parsed.secret.as_deref(), Some("DB_PASSWORD"));
        assert_eq!(parsed.secret_env.as_deref(), Some("MY_VAR"));
    }
}
