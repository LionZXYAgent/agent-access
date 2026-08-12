//! Read-only mirror of the secret-scan findings artifact schema.
//!
//! The artifact (`.bitwarden/secret-findings.json`) is produced by `bws
//! scan` — the Secrets Manager CLI, backed by the `bitwarden-scan` crate in
//! `sdk-sm` — and owned by that repo. This module is a *reader* only: `aac`
//! does not scan and does not write this file. Because the schema is owned
//! elsewhere, deserialization here is deliberately tolerant of fields this
//! build doesn't recognize (e.g. `severity`/`scan_mode` are read as plain
//! strings, not closed enums) so a future producer-side addition doesn't
//! break an older `aac mcp`.
//!
//! Invariant carried over from the producer: the artifact never contains a
//! matched secret value, only a masked [`Finding::preview`].

use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

/// Schema version this reader understands. A `schema_version` other than
/// this is rejected outright rather than guessed at.
pub const SCHEMA_VERSION: u32 = 1;

/// Artifact location, relative to the repo root.
pub const ARTIFACT_RELATIVE_PATH: &str = ".bitwarden/secret-findings.json";

/// The findings artifact, as written by `bws scan`. Field shapes mirror the
/// producer's schema (`plans/secret-scanning.md` §2); `severity` and
/// `scan_mode` are read as plain strings rather than closed enums, since
/// this reader must not fail to parse a future value it doesn't yet know
/// about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    /// RFC3339, seconds precision.
    pub generated_at: String,
    pub repo_root: String,
    /// `None` outside a git repository.
    pub head_commit: Option<String>,
    /// `None` outside a git repository.
    pub dirty: Option<bool>,
    /// `"worktree" | "staged" | "history"`, tolerated as a plain string.
    pub scan_mode: String,
    /// `true` when the producer's finding cap was hit.
    pub truncated: bool,
    pub findings: Vec<Finding>,
}

/// One detected secret. Never carries the matched value itself — only
/// location, rule id, and a masked [`preview`](Finding::preview).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub fingerprint: String,
    pub rule_id: String,
    /// Tolerated as a plain string rather than a closed enum — see the
    /// module doc.
    pub severity: String,
    /// Root-relative path, forward slashes regardless of platform.
    pub path: String,
    /// 1-based line number.
    pub line: u64,
    /// 1-based column, counted in characters.
    pub column: u64,
    /// Masked preview of the matched text. Never the full value.
    pub preview: String,
    /// `"worktree"` or `"history"`.
    pub origin: String,
    /// History-mode only.
    pub commit: Option<String>,
    /// History-mode only.
    pub author: Option<String>,
    /// History-mode only.
    pub first_seen: Option<String>,
}

/// Errors reading the findings artifact. Never carries file contents — only
/// paths and error classes — since [`ArtifactError`]'s `Display` can end up
/// in a served envelope's `error` field.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("could not read the findings artifact at {}: {source}", path.display())]
    Unreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("the findings artifact at {} is not valid JSON: {source}", path.display())]
    Malformed {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error(
        "the findings artifact's schema_version {found} is not supported by this build (expected {expected})"
    )]
    UnsupportedSchemaVersion { found: u32, expected: u32 },
}

impl ArtifactError {
    /// A short, stable class name for this error — safe to place in a
    /// served envelope's `error` field. Never includes a path or file
    /// contents.
    pub fn class(&self) -> &'static str {
        match self {
            ArtifactError::Unreadable { .. } => "unreadable",
            ArtifactError::Malformed { .. } => "malformed",
            ArtifactError::UnsupportedSchemaVersion { .. } => "unsupported_schema_version",
        }
    }
}

/// `<root>/.bitwarden/secret-findings.json`.
pub fn artifact_path(root: &Path) -> PathBuf {
    root.join(ARTIFACT_RELATIVE_PATH)
}

/// Load the findings artifact from disk.
///
/// - `Ok(None)`: no artifact file — "never scanned" (run `bws scan`),
///   distinct from "scanned, zero findings" (an empty `findings` list
///   inside `Ok(Some(_))`).
/// - `Err`: file present but unreadable, malformed JSON, or an unsupported
///   `schema_version`.
pub fn load_artifact(root: &Path) -> Result<Option<ScanReport>, ArtifactError> {
    let path = artifact_path(root);
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(ArtifactError::Unreadable { path, source }),
    };

    let report: ScanReport =
        serde_json::from_str(&contents).map_err(|source| ArtifactError::Malformed {
            path: path.clone(),
            source,
        })?;
    if report.schema_version != SCHEMA_VERSION {
        return Err(ArtifactError::UnsupportedSchemaVersion {
            found: report.schema_version,
            expected: SCHEMA_VERSION,
        });
    }
    Ok(Some(report))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory under `std::env::temp_dir()` with a unique name,
    /// removed on drop. This crate has no `tempfile` dependency (the
    /// scanning engine that used it lives in `sdk-sm` now), so tests build
    /// their own minimal fixture dir.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aac-findings-artifact-test-{label}-{}-{n}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("creating fixture dir must succeed");
            TempDir(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sample_json() -> &'static str {
        r#"{
            "schema_version": 1,
            "generated_at": "2026-08-11T12:00:00Z",
            "repo_root": "/tmp/example",
            "head_commit": "abc123",
            "dirty": false,
            "scan_mode": "worktree",
            "truncated": false,
            "findings": [
                {
                    "fingerprint": "fp-1",
                    "rule_id": "aws-access-key-id",
                    "severity": "high",
                    "path": "src/config.ts",
                    "line": 42,
                    "column": 18,
                    "preview": "AKIA****************",
                    "origin": "worktree",
                    "commit": null,
                    "author": null,
                    "first_seen": null
                }
            ]
        }"#
    }

    fn write_artifact_fixture(root: &Path, contents: &str) {
        let path = artifact_path(root);
        fs::create_dir_all(path.parent().expect("artifact path always has a parent"))
            .expect("mkdir must succeed");
        fs::write(&path, contents).expect("writing fixture artifact must succeed");
    }

    #[test]
    fn round_trips_a_sample_artifact() {
        let dir = TempDir::new("round-trip");
        write_artifact_fixture(dir.path(), sample_json());

        let report = load_artifact(dir.path())
            .expect("load must succeed")
            .expect("artifact is present");
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.repo_root, "/tmp/example");
        assert_eq!(report.head_commit.as_deref(), Some("abc123"));
        assert_eq!(report.dirty, Some(false));
        assert_eq!(report.scan_mode, "worktree");
        assert!(!report.truncated);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "aws-access-key-id");
        assert_eq!(report.findings[0].severity, "high");
    }

    #[test]
    fn absent_artifact_is_ok_none() {
        let dir = TempDir::new("absent");
        let result = load_artifact(dir.path()).expect("absent artifact must not error");
        assert!(result.is_none());
    }

    #[test]
    fn unsupported_schema_version_is_an_error() {
        let dir = TempDir::new("bad-schema");
        write_artifact_fixture(
            dir.path(),
            r#"{"schema_version":999,"generated_at":"x","repo_root":"/","head_commit":null,
               "dirty":null,"scan_mode":"worktree","truncated":false,"findings":[]}"#,
        );

        let err = load_artifact(dir.path()).expect_err("schema_version 999 must error");
        assert!(matches!(
            err,
            ArtifactError::UnsupportedSchemaVersion {
                found: 999,
                expected: 1
            }
        ));
        assert_eq!(err.class(), "unsupported_schema_version");
    }

    #[test]
    fn malformed_json_is_an_error() {
        let dir = TempDir::new("malformed");
        write_artifact_fixture(dir.path(), "not json");

        let err = load_artifact(dir.path()).expect_err("malformed json must error");
        assert!(matches!(err, ArtifactError::Malformed { .. }));
        assert_eq!(err.class(), "malformed");
    }

    #[test]
    fn unknown_severity_string_is_tolerated() {
        let dir = TempDir::new("unknown-severity");
        write_artifact_fixture(
            dir.path(),
            r#"{
                "schema_version": 1,
                "generated_at": "2026-08-11T12:00:00Z",
                "repo_root": "/tmp/example",
                "head_commit": null,
                "dirty": null,
                "scan_mode": "worktree",
                "truncated": false,
                "findings": [
                    {
                        "fingerprint": "fp-1",
                        "rule_id": "some-future-rule",
                        "severity": "catastrophic",
                        "path": "a.txt",
                        "line": 1,
                        "column": 1,
                        "preview": "***",
                        "origin": "worktree",
                        "commit": null,
                        "author": null,
                        "first_seen": null
                    }
                ]
            }"#,
        );

        let report = load_artifact(dir.path())
            .expect("an unrecognized severity string must not fail to parse")
            .expect("artifact is present");
        assert_eq!(report.findings[0].severity, "catastrophic");
    }
}
