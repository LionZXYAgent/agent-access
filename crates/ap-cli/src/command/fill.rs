//! `aac fill` / `aac describe-fill-target` — browser-fill delivery
//! (architecture doc, M5).
//!
//! Local-socket-only, like Secrets Manager secrets (`run.rs`'s
//! `--secret`): there is no relay fallback. Unlike secrets, this isn't a
//! policy choice about where a value may ride — the fill protocol
//! (`transport::local::request_fill`/`request_describe_fill_target`)
//! carries no value in the first place, so there's no relay path to reuse:
//! the credential moves desktop → extension over a channel this repo never
//! touches. If the local endpoint can't be reached, the correct behavior is
//! a clear error telling the user to run the Bitwarden desktop app, not a
//! silent fallback to a transport that can't do this at all.

use clap::Args;
use color_eyre::eyre::{Result, bail};

use super::output::{
    OutputFormat, emit_json_describe_fill_target, emit_json_error, emit_json_fill,
    emit_text_describe_fill_target, emit_text_fill, exit_code, exit_code_for_local_error,
    exit_code_name,
};
use crate::transport::local::{self, FillInput, LocalEndpoint};

/// Could not determine the local Bitwarden agent-access endpoint. Shared by
/// both subcommands here — fill has no relay fallback, so this is a hard
/// error either way.
const LOCAL_UNAVAILABLE_MSG: &str = "Could not determine the local Bitwarden agent-access \
    endpoint. Make sure Bitwarden Desktop is installed, running, unlocked, and Agent Access is \
    enabled. Browser fill has no relay fallback.";

/// Resolve the local endpoint: `--socket`/`AAC_SOCKET` if given, else the
/// platform default. Never falls back to the relay — fill is
/// local-socket-only (architecture doc, M5 §2).
fn resolve_local_endpoint(socket_override: Option<&str>) -> Option<LocalEndpoint> {
    match socket_override {
        Some(path) => Some(LocalEndpoint::from_override(path)),
        None => LocalEndpoint::default_endpoint(),
    }
}

/// Fill a Bitwarden login into the active tab of the user's browser.
#[derive(Args)]
#[command(after_help = "\
EXAMPLES:
  aac fill --domain bitnotes.io
  aac fill --domain bitnotes.io --fields username --fields password
  aac fill --ref bw://item/11111111-1111-1111-1111-111111111111 --target-token ft_...

The credential value is never returned to you and never enters this process: the Bitwarden \
desktop app resolves it and hands it directly to the browser extension, which fills the active \
tab. You cannot choose which tab, origin, or field is filled.")]
pub struct FillArgs {
    /// Domain identifying the login to fill (e.g. "bitnotes.io").
    #[arg(long, conflicts_with_all = ["name", "reference"])]
    pub domain: Option<String>,

    /// Free-text search identifying the login to fill.
    #[arg(long, conflicts_with_all = ["domain", "reference"])]
    pub name: Option<String>,

    /// A `bw://item/<id>` reference previously returned by `find_logins` /
    /// `aac fill --domain ... --output json`.
    #[arg(long = "ref", conflicts_with_all = ["domain", "name"])]
    pub reference: Option<String>,

    /// Which fields to fill (username, password, totp). Repeatable.
    /// Defaults to every field present on the item that has a safe target
    /// on the page.
    #[arg(long = "fields")]
    pub fields: Vec<String>,

    /// A `targetToken` from a prior `aac describe-fill-target` call, to
    /// guarantee this fill matches exactly the plan described there.
    #[arg(long = "target-token")]
    pub target_token: Option<String>,

    /// Local agent-access endpoint to use instead of the platform default
    /// (unix socket path / windows pipe name).
    #[arg(long, env = "AAC_SOCKET")]
    pub socket: Option<String>,

    /// Output format (text or json)
    #[arg(long, default_value = "text", value_enum)]
    pub output: OutputFormat,
}

impl FillArgs {
    pub async fn run(self) -> Result<()> {
        let query = match (&self.domain, &self.name, &self.reference) {
            (Some(domain), None, None) => ap_client::CredentialQuery::Domain(domain.clone()),
            (None, Some(name), None) => ap_client::CredentialQuery::Search(name.clone()),
            (None, None, Some(reference)) => {
                ap_client::CredentialQuery::Id(local::strip_reference(reference).to_string())
            }
            (None, None, None) => bail!("One of --domain, --name, or --ref is required"),
            _ => unreachable!("clap conflicts_with_all prevents this"),
        };

        let endpoint = match resolve_local_endpoint(self.socket.as_deref()) {
            Some(e) => e,
            None => {
                match self.output {
                    OutputFormat::Json => {
                        emit_json_error(LOCAL_UNAVAILABLE_MSG, "connection_failed")
                    }
                    OutputFormat::Text => tracing::error!("{LOCAL_UNAVAILABLE_MSG}"),
                }
                std::process::exit(exit_code::CONNECTION_FAILED);
            }
        };

        let fill_input = FillInput {
            fields: if self.fields.is_empty() {
                None
            } else {
                Some(self.fields.clone())
            },
            target_token: self.target_token.clone(),
        };

        match local::request_fill(&endpoint, &query, Some(fill_input)).await {
            Ok(outcome) => {
                match self.output {
                    OutputFormat::Json => emit_json_fill(&outcome),
                    OutputFormat::Text => emit_text_fill(&outcome),
                }
                std::process::exit(exit_code::SUCCESS);
            }
            Err(e) => {
                let code = exit_code_for_local_error(&e);
                let msg = format!("{e}");
                match self.output {
                    OutputFormat::Json => emit_json_error(&msg, exit_code_name(code)),
                    OutputFormat::Text => tracing::error!("{msg}"),
                }
                std::process::exit(code);
            }
        }
    }
}

/// Describe the login form in the active tab of the user's browser: no
/// vault access, no approval, no value.
#[derive(Args)]
pub struct DescribeFillTargetArgs {
    /// Local agent-access endpoint to use instead of the platform default
    /// (unix socket path / windows pipe name).
    #[arg(long, env = "AAC_SOCKET")]
    pub socket: Option<String>,

    /// Output format (text or json)
    #[arg(long, default_value = "text", value_enum)]
    pub output: OutputFormat,
}

impl DescribeFillTargetArgs {
    pub async fn run(self) -> Result<()> {
        let endpoint = match resolve_local_endpoint(self.socket.as_deref()) {
            Some(e) => e,
            None => {
                match self.output {
                    OutputFormat::Json => {
                        emit_json_error(LOCAL_UNAVAILABLE_MSG, "connection_failed")
                    }
                    OutputFormat::Text => tracing::error!("{LOCAL_UNAVAILABLE_MSG}"),
                }
                std::process::exit(exit_code::CONNECTION_FAILED);
            }
        };

        match local::request_describe_fill_target(&endpoint).await {
            Ok(target) => {
                match self.output {
                    OutputFormat::Json => emit_json_describe_fill_target(&target),
                    OutputFormat::Text => emit_text_describe_fill_target(&target),
                }
                std::process::exit(exit_code::SUCCESS);
            }
            Err(e) => {
                let code = exit_code_for_local_error(&e);
                let msg = format!("{e}");
                match self.output {
                    OutputFormat::Json => emit_json_error(&msg, exit_code_name(code)),
                    OutputFormat::Text => tracing::error!("{msg}"),
                }
                std::process::exit(code);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn try_parse_fill(args: &[&str]) -> std::result::Result<FillArgs, clap::Error> {
        use clap::{Args as ClapArgs, FromArgMatches};
        let cmd = FillArgs::augment_args(clap::Command::new("fill"));
        let matches = cmd.try_get_matches_from(args)?;
        FillArgs::from_arg_matches(&matches)
    }

    /// Like `try_parse_fill`, but for tests asserting a parse *failure* —
    /// `FillArgs` doesn't derive `Debug` (mirrors `RunArgs` in `run.rs`:
    /// plain CLI args, nothing depends on printing them), so
    /// `Result::expect_err` isn't available; this discards the `Ok` value
    /// manually instead.
    fn expect_parse_error(args: &[&str]) -> clap::Error {
        match try_parse_fill(args) {
            Ok(_) => panic!("expected a parse error for args: {args:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn domain_conflicts_with_name() {
        let err = expect_parse_error(&["fill", "--domain", "bitnotes.io", "--name", "bitnotes"]);
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn domain_conflicts_with_ref() {
        let err = expect_parse_error(&[
            "fill",
            "--domain",
            "bitnotes.io",
            "--ref",
            "bw://item/item-1",
        ]);
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn name_conflicts_with_ref() {
        let err = expect_parse_error(&["fill", "--name", "bitnotes", "--ref", "bw://item/item-1"]);
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn domain_alone_parses_ok() {
        let parsed = try_parse_fill(&["fill", "--domain", "bitnotes.io"]).expect("should parse");
        assert_eq!(parsed.domain.as_deref(), Some("bitnotes.io"));
        assert!(parsed.fields.is_empty());
        assert!(parsed.target_token.is_none());
    }

    #[test]
    fn fields_and_target_token_parse_ok() {
        let parsed = try_parse_fill(&[
            "fill",
            "--domain",
            "bitnotes.io",
            "--fields",
            "username",
            "--fields",
            "password",
            "--target-token",
            "ft_abc",
        ])
        .expect("should parse");
        assert_eq!(parsed.fields, vec!["username", "password"]);
        assert_eq!(parsed.target_token.as_deref(), Some("ft_abc"));
    }

    #[tokio::test]
    async fn no_selector_errors_at_runtime() {
        let parsed = try_parse_fill(&["fill"]).expect("clap parse itself should succeed");
        let err = parsed
            .run()
            .await
            .expect_err("one of --domain/--name/--ref is required");
        assert!(format!("{err}").contains("One of --domain, --name, or --ref is required"));
    }

    fn try_parse_describe(
        args: &[&str],
    ) -> std::result::Result<DescribeFillTargetArgs, clap::Error> {
        use clap::{Args as ClapArgs, FromArgMatches};
        let cmd = DescribeFillTargetArgs::augment_args(clap::Command::new("describe-fill-target"));
        let matches = cmd.try_get_matches_from(args)?;
        DescribeFillTargetArgs::from_arg_matches(&matches)
    }

    #[test]
    fn describe_fill_target_parses_with_no_args() {
        try_parse_describe(&["describe-fill-target"]).expect("should parse with no args");
    }
}
