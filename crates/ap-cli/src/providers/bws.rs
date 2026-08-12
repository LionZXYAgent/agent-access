//! Bitwarden Secrets Manager provider
//!
//! Uses the official `bitwarden` Rust crate (the Secrets Manager SDK) to look
//! up secrets in-process — this does **not** shell out to the `bws` CLI.

use std::{
    future::Future,
    str::FromStr,
    time::{Duration, Instant},
};

use ap_client::CredentialData;
use async_trait::async_trait;
use bitwarden::secrets_manager::{
    AccessToken, AccessTokenLoginRequest, ClientSettings, SecretsManagerClient,
    secrets::{SecretGetRequest, SecretIdentifiersRequest, SecretResponse},
};
use secrecy::{ExposeSecret, SecretString, zeroize::Zeroizing};
use tokio::sync::Mutex;
use uuid::Uuid;

use super::{CredentialProvider, CredentialQuery, LookupResult, ProviderStatus};

/// Upper bound on any single Secrets Manager API call.
///
/// The SDK builds its HTTP client without a timeout, so without this an
/// unreachable or black-holed `BWS_SERVER_URL` would hang `aac listen` before
/// the TUI is even initialised, and freeze the event loop — rendering and quit
/// included — on every subsequent lookup.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a fetched secret-identifier listing stays usable.
///
/// Listing identifiers fetches and decrypts every secret key in the
/// organization, so repeating it per lookup is expensive on large orgs. A miss
/// against a cached listing is always retried against a fresh one, so this
/// only ever saves work — it never turns a hit into a miss.
const IDENTIFIER_CACHE_TTL: Duration = Duration::from_secs(60);

/// A logged-in Secrets Manager session, cached so repeated lookups don't
/// re-authenticate against the API every time.
struct BwsSession {
    client: SecretsManagerClient,
    organization_id: Uuid,
    identifiers: Option<CachedIdentifiers>,
}

/// The id and key of one secret. Secret *values* are never cached.
#[derive(Clone)]
struct SecretIdentifier {
    id: Uuid,
    key: String,
}

/// A secret-identifier listing plus the instant it was fetched.
struct CachedIdentifiers {
    entries: Vec<SecretIdentifier>,
    fetched_at: Instant,
}

impl CachedIdentifiers {
    fn is_fresh(&self) -> bool {
        self.fetched_at.elapsed() < IDENTIFIER_CACHE_TTL
    }
}

/// Why a Secrets Manager lookup failed.
enum LookupError {
    /// The secret does not exist, or this machine account cannot read it.
    /// Reported to the user as "not found" rather than as a provider fault.
    Missing,
    /// Anything else — transport, timeout, auth, decryption.
    Unavailable(String),
}

/// Credential provider backed by the Bitwarden Secrets Manager SDK.
///
/// Unlike [`super::BitwardenProvider`] (which wraps the `bw` CLI), this talks
/// to the Secrets Manager API directly via the `bitwarden` crate — no
/// subprocess involved.
pub struct BwsProvider {
    access_token: Option<SecretString>,
    server_url: Option<String>,
    session: Mutex<Option<BwsSession>>,
}

impl BwsProvider {
    /// Create a new provider, reading `BWS_ACCESS_TOKEN` and `BWS_SERVER_URL`
    /// from the environment.
    pub fn new() -> Self {
        let access_token = std::env::var("BWS_ACCESS_TOKEN")
            .ok()
            .filter(|s| !s.is_empty())
            .map(SecretString::from);
        let server_url = std::env::var("BWS_SERVER_URL")
            .ok()
            .filter(|s| !s.is_empty());
        Self {
            access_token,
            server_url,
            session: Mutex::new(None),
        }
    }

    /// Ensure a logged-in session exists, authenticating if necessary.
    ///
    /// Returns the organization id on success. Errors are descriptive but
    /// never include the access token itself.
    async fn ensure_session(&self) -> Result<Uuid, String> {
        let mut guard = self.session.lock().await;
        if let Some(session) = guard.as_ref() {
            return Ok(session.organization_id);
        }

        let token = self
            .access_token
            .as_ref()
            .ok_or_else(|| "No Bitwarden Secrets Manager access token configured".to_string())?;

        let session = login(token.expose_secret(), self.server_url.as_deref()).await?;
        let organization_id = session.organization_id;
        *guard = Some(session);

        Ok(organization_id)
    }

    /// Fetch a single secret by id using the cached session's client.
    async fn get_secret(&self, id: Uuid) -> Result<SecretResponse, LookupError> {
        let guard = self.session.lock().await;
        let session = guard.as_ref().ok_or_else(|| {
            LookupError::Unavailable("Not logged in to Bitwarden Secrets Manager".to_string())
        })?;

        let result = with_timeout(
            "secret fetch",
            session.client.secrets().get(&SecretGetRequest { id }),
        )
        .await
        .map_err(LookupError::Unavailable)?;

        result.map_err(|e| {
            let message = e.to_string();
            if is_missing(&message) {
                LookupError::Missing
            } else {
                LookupError::Unavailable(format!("Failed to fetch secret: {message}"))
            }
        })
    }

    /// Secret identifiers (id + key, no values) for the organization.
    ///
    /// Returns the entries and whether they were served from cache, so the
    /// caller can distinguish a genuine miss from a stale one.
    async fn identifiers(
        &self,
        organization_id: Uuid,
        force_refresh: bool,
    ) -> Result<(Vec<SecretIdentifier>, bool), String> {
        let mut guard = self.session.lock().await;
        let session = guard
            .as_mut()
            .ok_or_else(|| "Not logged in to Bitwarden Secrets Manager".to_string())?;

        if !force_refresh {
            if let Some(cached) = session.identifiers.as_ref() {
                if cached.is_fresh() {
                    return Ok((cached.entries.clone(), true));
                }
            }
        }

        let response = with_timeout(
            "secret listing",
            session
                .client
                .secrets()
                .list(&SecretIdentifiersRequest { organization_id }),
        )
        .await?
        .map_err(|e| format!("Failed to list secrets: {e}"))?;

        let entries: Vec<SecretIdentifier> = response
            .data
            .into_iter()
            .map(|entry| SecretIdentifier {
                id: entry.id,
                key: entry.key,
            })
            .collect();

        session.identifiers = Some(CachedIdentifiers {
            entries: entries.clone(),
            fetched_at: Instant::now(),
        });

        Ok((entries, false))
    }

    /// Resolve a secret key to its identifier, refreshing a cached listing
    /// once before concluding the key genuinely doesn't exist.
    async fn resolve_key(
        &self,
        organization_id: Uuid,
        key: &str,
    ) -> Result<Option<SecretIdentifier>, String> {
        let (entries, from_cache) = self.identifiers(organization_id, false).await?;
        if let Some(entry) = find_by_key(&entries, key) {
            return Ok(Some(entry.clone()));
        }

        // A cached listing can be up to IDENTIFIER_CACHE_TTL stale, so a
        // secret created moments ago would otherwise report as not found.
        if !from_cache {
            return Ok(None);
        }

        let (entries, _) = self.identifiers(organization_id, true).await?;
        Ok(find_by_key(&entries, key).cloned())
    }
}

impl Default for BwsProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Run a Secrets Manager call under [`REQUEST_TIMEOUT`].
async fn with_timeout<F: Future>(what: &str, call: F) -> Result<F::Output, String> {
    tokio::time::timeout(REQUEST_TIMEOUT, call)
        .await
        .map_err(|_| {
            format!(
                "Bitwarden Secrets Manager {what} timed out after {}s",
                REQUEST_TIMEOUT.as_secs()
            )
        })
}

/// Authenticate against Secrets Manager and return the resulting session.
///
/// Takes the token as a parameter rather than reading it from a provider so
/// that a candidate token can be validated before it replaces a working one.
async fn login(access_token: &str, server_url: Option<&str>) -> Result<BwsSession, String> {
    // Validate the token format up front for a clear error before making any
    // network calls (login_access_token would otherwise fail less clearly).
    AccessToken::from_str(access_token)
        .map_err(|e| format!("Invalid Bitwarden Secrets Manager access token: {e}"))?;

    let settings = client_settings_for(server_url)?;
    let client = SecretsManagerClient::new(settings);

    with_timeout(
        "login",
        client.auth().login_access_token(&AccessTokenLoginRequest {
            access_token: access_token.to_string(),
            // Deliberate: no auth state cached on disk.
            state_file: None,
        }),
    )
    .await?
    .map_err(|e| format!("Bitwarden Secrets Manager login failed: {e}"))?;

    let organization_id: Uuid = client
        .get_access_token_organization()
        .ok_or_else(|| "Access token is not associated with an organization".to_string())?
        .into();

    Ok(BwsSession {
        client,
        organization_id,
        identifiers: None,
    })
}

/// Build [`ClientSettings`] from an optional Secrets Manager server URL.
///
/// Any trailing slash on `server_url` is trimmed before appending `/api` and
/// `/identity`. Returns `None` when no server URL is given, so the SDK falls
/// back to its bitwarden.com cloud defaults.
fn client_settings_for(server_url: Option<&str>) -> Result<Option<ClientSettings>, String> {
    let Some(server_url) = server_url else {
        return Ok(None);
    };
    let server_url = server_url.trim_end_matches('/');
    validate_server_url(server_url)?;

    Ok(Some(ClientSettings {
        identity_url: format!("{server_url}/identity"),
        api_url: format!("{server_url}/api"),
        ..Default::default()
    }))
}

/// Reject server URLs that would silently misbehave or leak the access token.
///
/// A bare host produces an unparseable URL once `/api` is appended and surfaces
/// as an opaque login failure, and plaintext `http` would put the access token
/// on the wire in the clear — the SDK's own https guard is compiled in for
/// release builds only. `http` stays allowed for loopback so self-hosted
/// development against a local server still works.
fn validate_server_url(server_url: &str) -> Result<(), String> {
    let Some((scheme, rest)) = server_url.split_once("://") else {
        return Err(format!(
            "BWS_SERVER_URL must be an absolute URL starting with 'https://' (got '{server_url}')"
        ));
    };

    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if host.is_empty() {
        return Err(format!("BWS_SERVER_URL has no host (got '{server_url}')"));
    }

    match scheme.to_ascii_lowercase().as_str() {
        "https" => Ok(()),
        "http" if is_loopback(host) => Ok(()),
        "http" => Err(format!(
            "BWS_SERVER_URL must use 'https://' — plaintext http would send the access token in the clear (got '{server_url}')"
        )),
        other => Err(format!(
            "BWS_SERVER_URL has unsupported scheme '{other}://' — expected 'https://'"
        )),
    }
}

/// Whether an authority component (host, optionally `:port`) is loopback.
fn is_loopback(host: &str) -> bool {
    let host = match host.strip_prefix('[') {
        // IPv6 literal: `[::1]` or `[::1]:8080`.
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => host.split(':').next().unwrap_or(host),
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Whether an SDK error message describes a secret that isn't readable.
///
/// A 404 means no such secret; a 403 means this machine account can't see it.
/// Both are reported as "not found" — the distinction isn't actionable, and
/// collapsing them avoids confirming that an inaccessible secret exists.
fn is_missing(message: &str) -> bool {
    matches!(http_status_from_error(message), Some(403 | 404))
}

/// Extract the HTTP status from an SDK error message, if it carries one.
///
/// The Secrets Manager SDK keeps its error enum in a private module, so the
/// status code isn't reachable by matching — the only public surface is the
/// `Display` text, which formats as
/// `Received error message from server: [404 Not Found] <body>`.
fn http_status_from_error(message: &str) -> Option<u16> {
    const MARKER: &str = "server: [";
    let start = message.find(MARKER)? + MARKER.len();
    let rest = message.get(start..)?;
    let digits = rest.find(|c: char| !c.is_ascii_digit())?;
    rest.get(..digits)?.parse().ok()
}

/// Find a secret identifier by key: exact match first, then case-insensitive.
///
/// Keys are not unique across projects, so an ambiguous key is logged — the
/// first match wins, and which one that is depends on API ordering.
fn find_by_key<'a>(entries: &'a [SecretIdentifier], key: &str) -> Option<&'a SecretIdentifier> {
    first_match(entries, key, |entry| entry.key == key)
        .or_else(|| first_match(entries, key, |entry| entry.key.eq_ignore_ascii_case(key)))
}

fn first_match<'a>(
    entries: &'a [SecretIdentifier],
    key: &str,
    predicate: impl Fn(&SecretIdentifier) -> bool,
) -> Option<&'a SecretIdentifier> {
    let mut hits = entries.iter().filter(|entry| predicate(entry));
    let first = hits.next()?;
    if hits.next().is_some() {
        tracing::warn!(
            key,
            "Multiple Secrets Manager secrets share this key; using the first match"
        );
    }
    Some(first)
}

/// Map raw Secrets Manager secret fields into [`CredentialData`].
///
/// Extracted as a pure function over plain values (rather than operating
/// directly on [`SecretResponse`]) so the mapping can be unit-tested without
/// constructing a full SDK response type.
fn map_secret_fields(
    id: Uuid,
    key: String,
    value: String,
    note: String,
    domain: Option<String>,
) -> CredentialData {
    CredentialData {
        username: Some(key),
        password: Some(Zeroizing::new(value)),
        totp: None,
        uri: None,
        notes: (!note.is_empty()).then_some(note),
        credential_id: Some(id.to_string()),
        domain,
    }
}

/// Map a [`SecretResponse`] into [`CredentialData`].
///
/// Consumes the response and moves `value` out of it rather than cloning:
/// `SecretResponse.value` is a plain `String`, so a clone would leave a second
/// plaintext copy of the secret behind on the heap when the response drops,
/// defeating the zeroizing copy handed to the caller.
fn credential_from_secret(secret: SecretResponse, domain: Option<String>) -> CredentialData {
    let SecretResponse {
        id,
        key,
        value,
        note,
        ..
    } = secret;
    map_secret_fields(id, key, value, note, domain)
}

/// Create a `BwsProvider` with explicit fields (for testing without touching
/// process environment variables).
#[cfg(test)]
impl BwsProvider {
    fn with_token(access_token: Option<SecretString>, server_url: Option<String>) -> Self {
        Self {
            access_token,
            server_url,
            session: Mutex::new(None),
        }
    }
}

#[async_trait]
impl CredentialProvider for BwsProvider {
    fn name(&self) -> &str {
        "Bitwarden Secrets Manager"
    }

    async fn status(&self) -> ProviderStatus {
        if self.access_token.is_none() {
            return ProviderStatus::Locked {
                prompt: "BWS access token".to_string(),
                user_info: None,
            };
        }

        match self.ensure_session().await {
            Ok(organization_id) => ProviderStatus::Ready {
                user_info: Some(format!("org {organization_id}")),
            },
            Err(reason) => ProviderStatus::Unavailable { reason },
        }
    }

    async fn unlock(&mut self, input: &str) -> Result<(), String> {
        // Prove the new token works *before* it replaces the current one: a
        // structurally valid but revoked token would otherwise discard a
        // working session and leave the provider unusable for the rest of the
        // process.
        let session = login(input, self.server_url.as_deref()).await?;

        self.access_token = Some(SecretString::from(input.to_string()));
        *self.session.lock().await = Some(session);

        Ok(())
    }

    async fn lookup(&self, query: &CredentialQuery) -> LookupResult {
        let organization_id = match self.ensure_session().await {
            Ok(id) => id,
            Err(message) => return LookupResult::NotReady { message },
        };

        let (id, domain) = match query {
            CredentialQuery::Id(s) => {
                let Ok(id) = Uuid::parse_str(s) else {
                    return LookupResult::NotFound;
                };
                (id, None)
            }
            CredentialQuery::Domain(s) | CredentialQuery::Search(s) => {
                let entry = match self.resolve_key(organization_id, s).await {
                    Ok(Some(entry)) => entry,
                    Ok(None) => return LookupResult::NotFound,
                    Err(message) => return LookupResult::NotReady { message },
                };
                let domain = matches!(query, CredentialQuery::Domain(_)).then(|| s.clone());
                (entry.id, domain)
            }
        };

        match self.get_secret(id).await {
            Ok(secret) => LookupResult::Found(credential_from_secret(secret, domain)),
            Err(LookupError::Missing) => LookupResult::NotFound,
            Err(LookupError::Unavailable(message)) => LookupResult::NotReady { message },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identifier(key: &str, id: Uuid) -> SecretIdentifier {
        SecretIdentifier {
            id,
            key: key.to_string(),
        }
    }

    // -- construction / name() -----------------------------------------

    #[test]
    fn name_is_bitwarden_secrets_manager() {
        let provider = BwsProvider::with_token(None, None);
        assert_eq!(provider.name(), "Bitwarden Secrets Manager");
    }

    #[test]
    fn provider_has_token_when_constructed_with_one() {
        let provider = BwsProvider::with_token(Some(SecretString::from("tok".to_string())), None);
        assert!(provider.access_token.is_some());
    }

    #[test]
    fn provider_has_no_token_when_constructed_without() {
        let provider = BwsProvider::with_token(None, None);
        assert!(provider.access_token.is_none());
    }

    // -- status() ---------------------------------------------------------

    #[tokio::test]
    async fn status_locked_when_no_token() {
        let provider = BwsProvider::with_token(None, None);
        assert!(matches!(
            provider.status().await,
            ProviderStatus::Locked { .. }
        ));
    }

    // -- unlock() ---------------------------------------------------------

    #[tokio::test]
    async fn unlock_keeps_existing_token_when_new_one_is_invalid() {
        let mut provider =
            BwsProvider::with_token(Some(SecretString::from("original".to_string())), None);

        let err = provider
            .unlock("not-a-valid-access-token")
            .await
            .expect_err("malformed token should be rejected");

        assert!(err.contains("Invalid Bitwarden Secrets Manager access token"));
        assert_eq!(
            provider
                .access_token
                .as_ref()
                .map(|t| t.expose_secret().to_string()),
            Some("original".to_string()),
            "a failed unlock must not clobber the working token"
        );
    }

    // -- client_settings_for() --------------------------------------------

    #[test]
    fn client_settings_none_when_no_server_url() {
        assert!(
            client_settings_for(None)
                .expect("no url is valid")
                .is_none()
        );
    }

    #[test]
    fn client_settings_trims_trailing_slash() {
        let settings = client_settings_for(Some("https://vault.example.com/"))
            .expect("should validate")
            .expect("should build settings");
        assert_eq!(settings.identity_url, "https://vault.example.com/identity");
        assert_eq!(settings.api_url, "https://vault.example.com/api");
    }

    #[test]
    fn client_settings_without_trailing_slash() {
        let settings = client_settings_for(Some("https://vault.example.com"))
            .expect("should validate")
            .expect("should build settings");
        assert_eq!(settings.identity_url, "https://vault.example.com/identity");
        assert_eq!(settings.api_url, "https://vault.example.com/api");
    }

    // -- validate_server_url() ---------------------------------------------

    #[test]
    fn server_url_rejects_bare_host() {
        let err = validate_server_url("vault.corp.example").expect_err("bare host is not a URL");
        assert!(err.contains("absolute URL"));
    }

    #[test]
    fn server_url_rejects_plaintext_http() {
        let err =
            validate_server_url("http://vault.corp.example").expect_err("http leaks the token");
        assert!(err.contains("https"));
    }

    #[test]
    fn server_url_rejects_unknown_scheme() {
        let err =
            validate_server_url("ftp://vault.corp.example").expect_err("ftp is not supported");
        assert!(err.contains("unsupported scheme"));
    }

    #[test]
    fn server_url_rejects_empty_host() {
        assert!(validate_server_url("https://").is_err());
    }

    #[test]
    fn server_url_accepts_https() {
        assert!(validate_server_url("https://vault.corp.example").is_ok());
    }

    #[test]
    fn server_url_allows_http_on_loopback() {
        assert!(validate_server_url("http://localhost:8080").is_ok());
        assert!(validate_server_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_server_url("http://[::1]:8080").is_ok());
        assert!(validate_server_url("http://localhost").is_ok());
    }

    #[test]
    fn server_url_scheme_is_case_insensitive() {
        assert!(validate_server_url("HTTPS://vault.corp.example").is_ok());
    }

    // -- http_status_from_error() ------------------------------------------

    #[test]
    fn parses_status_from_sdk_error_text() {
        let message = "Received error message from server: [404 Not Found] {\"message\":\"gone\"}";
        assert_eq!(http_status_from_error(message), Some(404));
        assert!(is_missing(message));
    }

    #[test]
    fn treats_forbidden_as_missing() {
        assert!(is_missing(
            "Received error message from server: [403 Forbidden] no access"
        ));
    }

    #[test]
    fn server_errors_are_not_missing() {
        assert!(!is_missing(
            "Received error message from server: [500 Internal Server Error] boom"
        ));
    }

    #[test]
    fn transport_errors_carry_no_status() {
        assert_eq!(
            http_status_from_error("error sending request for url (https://api.example.com)"),
            None
        );
        assert!(!is_missing("connection refused"));
    }

    // -- find_by_key() ------------------------------------------------------

    #[test]
    fn find_by_key_prefers_exact_match() {
        let entries = vec![
            identifier("DB_PASSWORD", Uuid::from_u128(1)),
            identifier("db_password", Uuid::from_u128(2)),
        ];
        let found = find_by_key(&entries, "db_password").expect("should match");
        assert_eq!(found.id, Uuid::from_u128(2));
    }

    #[test]
    fn find_by_key_falls_back_to_case_insensitive() {
        let entries = vec![identifier("DB_PASSWORD", Uuid::from_u128(1))];
        let found = find_by_key(&entries, "db_password").expect("should match");
        assert_eq!(found.id, Uuid::from_u128(1));
    }

    #[test]
    fn find_by_key_returns_none_when_absent() {
        let entries = vec![identifier("other", Uuid::from_u128(1))];
        assert!(find_by_key(&entries, "db_password").is_none());
    }

    #[test]
    fn find_by_key_picks_first_of_duplicate_keys() {
        let entries = vec![
            identifier("shared", Uuid::from_u128(1)),
            identifier("shared", Uuid::from_u128(2)),
        ];
        let found = find_by_key(&entries, "shared").expect("should match");
        assert_eq!(found.id, Uuid::from_u128(1));
    }

    // -- identifier cache ---------------------------------------------------

    #[test]
    fn cached_identifiers_expire() {
        let fresh = CachedIdentifiers {
            entries: Vec::new(),
            fetched_at: Instant::now(),
        };
        assert!(fresh.is_fresh());

        let stale = CachedIdentifiers {
            entries: Vec::new(),
            fetched_at: Instant::now()
                .checked_sub(IDENTIFIER_CACHE_TTL * 2)
                .expect("instant should be representable"),
        };
        assert!(!stale.is_fresh());
    }

    // -- map_secret_fields() -----------------------------------------------

    #[test]
    fn map_secret_fields_basic() {
        let id = Uuid::nil();
        let cred = map_secret_fields(
            id,
            "db-password".to_string(),
            "hunter2".to_string(),
            String::new(),
            None,
        );
        assert_eq!(cred.username.as_deref(), Some("db-password"));
        assert_eq!(
            cred.password.as_deref().map(String::as_str),
            Some("hunter2")
        );
        assert_eq!(cred.notes, None);
        assert_eq!(cred.credential_id, Some(id.to_string()));
        assert_eq!(cred.domain, None);
    }

    #[test]
    fn map_secret_fields_with_note_and_domain() {
        let id = Uuid::nil();
        let cred = map_secret_fields(
            id,
            "key".to_string(),
            "value".to_string(),
            "some note".to_string(),
            Some("example.com".to_string()),
        );
        assert_eq!(cred.notes.as_deref(), Some("some note"));
        assert_eq!(cred.domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn map_secret_fields_empty_note_omitted() {
        let cred = map_secret_fields(
            Uuid::nil(),
            "k".to_string(),
            "v".to_string(),
            String::new(),
            None,
        );
        assert!(cred.notes.is_none());
    }
}
