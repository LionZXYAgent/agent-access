//! Standing approvals ("grants") created from Telegram.
//!
//! A grant auto-approves later requests that match its **scope** until it
//! expires or is revoked. The scope is deliberately narrow:
//!
//! - the same requesting device (remote identity fingerprint), **and**
//! - the same query (e.g. `domain: github.com`, compared case-insensitively
//!   for domains), **and**
//! - the same matched vault item id (if the query later resolves to a
//!   different item, the owner is asked again).
//!
//! Grants live in memory only. They are cleared when `aac listen` restarts and
//! are never written to disk.

use std::time::Duration;

use ap_client::{CredentialQuery, IdentityFingerprint};
use tokio::time::Instant;

/// How long a grant lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantDuration {
    Minutes15,
    Hour1,
    /// Until revoked or `aac listen` restarts.
    Forever,
}

impl GrantDuration {
    /// Duration, or `None` for [`GrantDuration::Forever`].
    pub fn duration(self) -> Option<Duration> {
        match self {
            GrantDuration::Minutes15 => Some(Duration::from_secs(15 * 60)),
            GrantDuration::Hour1 => Some(Duration::from_secs(60 * 60)),
            GrantDuration::Forever => None,
        }
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            GrantDuration::Minutes15 => "15 minutes",
            GrantDuration::Hour1 => "1 hour",
            GrantDuration::Forever => "until revoked",
        }
    }
}

/// What a grant covers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GrantScope {
    pub identity: IdentityFingerprint,
    pub query: String,
    pub credential_id: Option<String>,
}

impl GrantScope {
    /// Build a scope from a request and the vault item it resolved to.
    pub fn new(
        identity: IdentityFingerprint,
        query: &CredentialQuery,
        credential_id: Option<&str>,
    ) -> Self {
        let query = match query {
            CredentialQuery::Domain(d) => format!("domain: {}", d.trim().to_lowercase()),
            other => other.to_string(),
        };
        Self {
            identity,
            query,
            credential_id: credential_id.map(str::to_string),
        }
    }
}

/// An active grant.
#[derive(Debug, Clone)]
pub struct Grant {
    /// Random id (used in revoke buttons).
    pub id: String,
    pub scope: GrantScope,
    /// Display label (device name + query), never contains secrets.
    pub label: String,
    pub duration: GrantDuration,
    /// Monotonic expiry; `None` = forever.
    pub expires_at: Option<Instant>,
    /// Wall-clock expiry for display (seconds since epoch); `None` = forever.
    pub expires_epoch: Option<u64>,
}

impl Grant {
    fn is_active(&self, now: Instant) -> bool {
        self.expires_at.is_none_or(|t| now < t)
    }
}

/// In-memory grant store. Not persisted.
#[derive(Debug, Default)]
pub struct GrantStore {
    grants: Vec<Grant>,
}

impl GrantStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn prune(&mut self, now: Instant) {
        self.grants.retain(|g| g.is_active(now));
    }

    /// Add a grant, replacing any existing grant with the same scope.
    pub fn insert(
        &mut self,
        id: String,
        scope: GrantScope,
        label: String,
        duration: GrantDuration,
        now: Instant,
        now_epoch: u64,
    ) -> Grant {
        self.prune(now);
        self.grants.retain(|g| g.scope != scope);
        let grant = Grant {
            id,
            scope,
            label,
            duration,
            expires_at: duration.duration().map(|d| now + d),
            expires_epoch: duration.duration().map(|d| now_epoch + d.as_secs()),
        };
        self.grants.push(grant.clone());
        grant
    }

    /// Find an active grant covering `scope`.
    pub fn find(&mut self, scope: &GrantScope, now: Instant) -> Option<Grant> {
        self.prune(now);
        self.grants.iter().find(|g| &g.scope == scope).cloned()
    }

    /// Active grants in creation order.
    pub fn list(&mut self, now: Instant) -> Vec<Grant> {
        self.prune(now);
        self.grants.clone()
    }

    /// Revoke one grant by id.
    pub fn revoke(&mut self, id: &str) -> Option<Grant> {
        let pos = self.grants.iter().position(|g| g.id == id)?;
        Some(self.grants.remove(pos))
    }

    /// Revoke everything; returns how many active grants were removed.
    pub fn revoke_all(&mut self, now: Instant) -> usize {
        self.prune(now);
        let n = self.grants.len();
        self.grants.clear();
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(id_byte: u8, domain: &str, item: &str) -> GrantScope {
        GrantScope::new(
            IdentityFingerprint([id_byte; 32]),
            &CredentialQuery::Domain(domain.to_string()),
            Some(item),
        )
    }

    fn add(store: &mut GrantStore, s: GrantScope, d: GrantDuration, now: Instant) -> Grant {
        store.insert(
            format!("g{}", store.grants.len()),
            s,
            "label".into(),
            d,
            now,
            1_000,
        )
    }

    #[test]
    fn grant_matches_same_scope_only() {
        let now = Instant::now();
        let mut store = GrantStore::new();
        add(
            &mut store,
            scope(1, "github.com", "item-1"),
            GrantDuration::Hour1,
            now,
        );

        assert!(store.find(&scope(1, "github.com", "item-1"), now).is_some());
        // Domain comparison is case-insensitive.
        assert!(store.find(&scope(1, "GitHub.com", "item-1"), now).is_some());
        // Other device.
        assert!(store.find(&scope(2, "github.com", "item-1"), now).is_none());
        // Other domain.
        assert!(store.find(&scope(1, "gitlab.com", "item-1"), now).is_none());
        // Same query resolved to a different vault item.
        assert!(store.find(&scope(1, "github.com", "item-2"), now).is_none());
        // Same item requested by id instead of domain is a different query.
        let by_id = GrantScope::new(
            IdentityFingerprint([1; 32]),
            &CredentialQuery::Id("item-1".into()),
            Some("item-1"),
        );
        assert!(store.find(&by_id, now).is_none());
    }

    #[test]
    fn timed_grants_expire() {
        let now = Instant::now();
        let mut store = GrantStore::new();
        add(
            &mut store,
            scope(1, "a.com", "i"),
            GrantDuration::Minutes15,
            now,
        );
        add(
            &mut store,
            scope(1, "b.com", "i"),
            GrantDuration::Hour1,
            now,
        );

        let t14 = now + Duration::from_secs(14 * 60 + 59);
        assert!(store.find(&scope(1, "a.com", "i"), t14).is_some());

        let t15 = now + Duration::from_secs(15 * 60);
        assert!(store.find(&scope(1, "a.com", "i"), t15).is_none());
        assert!(store.find(&scope(1, "b.com", "i"), t15).is_some());

        let t60 = now + Duration::from_secs(60 * 60);
        assert!(store.find(&scope(1, "b.com", "i"), t60).is_none());
        assert!(store.list(t60).is_empty());
    }

    #[test]
    fn forever_holds_until_revoked() {
        let now = Instant::now();
        let mut store = GrantStore::new();
        let g = add(
            &mut store,
            scope(1, "a.com", "i"),
            GrantDuration::Forever,
            now,
        );
        assert!(g.expires_at.is_none() && g.expires_epoch.is_none());

        let much_later = now + Duration::from_secs(365 * 24 * 3600);
        assert!(store.find(&scope(1, "a.com", "i"), much_later).is_some());

        assert!(store.revoke(&g.id).is_some());
        assert!(store.find(&scope(1, "a.com", "i"), much_later).is_none());
        // Revoking twice is a no-op.
        assert!(store.revoke(&g.id).is_none());
    }

    #[test]
    fn revoke_all_and_replace_same_scope() {
        let now = Instant::now();
        let mut store = GrantStore::new();
        add(
            &mut store,
            scope(1, "a.com", "i"),
            GrantDuration::Minutes15,
            now,
        );
        // Same scope again replaces rather than duplicates.
        add(
            &mut store,
            scope(1, "a.com", "i"),
            GrantDuration::Forever,
            now,
        );
        add(
            &mut store,
            scope(2, "b.com", "j"),
            GrantDuration::Hour1,
            now,
        );
        let list = store.list(now);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].duration, GrantDuration::Forever);

        assert_eq!(store.revoke_all(now), 2);
        assert!(store.list(now).is_empty());
    }
}
