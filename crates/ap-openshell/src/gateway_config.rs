//! Gateway connection settings for aac's read-only lookups (architecture §M8.5).
//!
//! - `<cfg>` = `--openshell-config-dir`, else `$XDG_CONFIG_HOME/openshell`,
//!   else `~/.config/openshell`.
//! - `<cfg>/gateways/<name>/metadata.json` supplies `gateway_endpoint` and
//!   `auth_mode` only (at most 64 KiB is read).
//! - `auth_mode == "mtls"`: `https://` endpoint, client identity from
//!   `<cfg>/gateways/<name>/mtls/{ca.crt,tls.crt,tls.key}`. The key bytes live
//!   in `Zeroizing` and are never logged.
//! - `auth_mode == "plaintext"`: only an `http://` endpoint whose host is
//!   `127.0.0.1`, `::1` or `localhost`.
//! - Anything else (`cloudflare_jwt`, `oidc`, unknown, missing) fails closed
//!   with "unsupported gateway auth mode".

use std::ffi::OsString;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::wire::{is_valid_gateway_endpoint, is_valid_gateway_name};

const MAX_METADATA_BYTES: u64 = 64 * 1024;
const MAX_PEM_BYTES: u64 = 1024 * 1024;

/// User-facing refusal text for every auth problem.
pub const UNSUPPORTED_AUTH: &str = "unsupported gateway auth mode";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GatewayConfigError {
    #[error("invalid gateway name")]
    InvalidName,
    #[error("OpenShell config directory could not be determined")]
    NoConfigDir,
    #[error("{UNSUPPORTED_AUTH} (gateway metadata missing or unreadable)")]
    MetadataUnreadable,
    #[error("{UNSUPPORTED_AUTH} (gateway metadata invalid)")]
    MetadataInvalid,
    #[error("{UNSUPPORTED_AUTH}")]
    UnsupportedAuth,
    #[error("{UNSUPPORTED_AUTH} (plaintext is allowed only for a loopback gateway)")]
    PlaintextNotLoopback,
    #[error("{UNSUPPORTED_AUTH} (mTLS material missing or unreadable)")]
    MtlsMaterialUnreadable,
}

/// mTLS client material. `Debug` never prints the key.
pub struct MtlsMaterial {
    pub ca_pem: Vec<u8>,
    pub cert_pem: Vec<u8>,
    pub key_pem: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for MtlsMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MtlsMaterial")
            .field("ca_pem_bytes", &self.ca_pem.len())
            .field("cert_pem_bytes", &self.cert_pem.len())
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

#[derive(Debug)]
pub enum GatewayAuth {
    Mtls(MtlsMaterial),
    PlaintextLoopback,
}

#[derive(Debug)]
pub struct GatewayConfig {
    pub name: String,
    pub endpoint: String,
    /// Host part of `endpoint` (used as the TLS server name).
    pub host: String,
    pub auth: GatewayAuth,
}

#[derive(Deserialize)]
struct RawMetadata {
    #[serde(default)]
    gateway_endpoint: Option<String>,
    #[serde(default)]
    auth_mode: Option<String>,
}

/// A gateway name that is safe as a single path component.
pub fn is_safe_gateway_name(name: &str) -> bool {
    is_valid_gateway_name(name) && name != "." && name != ".."
}

/// Resolve `<cfg>`. Relative `XDG_CONFIG_HOME` values are ignored, per the
/// XDG spec.
pub fn config_dir_from(
    override_dir: Option<&Path>,
    xdg_config_home: Option<OsString>,
    home: Option<OsString>,
) -> Option<PathBuf> {
    if let Some(dir) = override_dir {
        return Some(dir.to_path_buf());
    }
    if let Some(xdg) = xdg_config_home.map(PathBuf::from) {
        if xdg.is_absolute() {
            return Some(xdg.join("openshell"));
        }
    }
    let home = home.map(PathBuf::from)?;
    home.is_absolute()
        .then(|| home.join(".config").join("openshell"))
}

/// Resolve `<cfg>` from the process environment.
pub fn config_dir(override_dir: Option<&Path>) -> Option<PathBuf> {
    config_dir_from(
        override_dir,
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

fn read_capped(path: &Path, cap: u64) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    file.take(cap + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > cap {
        return Err(std::io::Error::other("file exceeds size cap"));
    }
    Ok(buf)
}

fn read_secret_capped(path: &Path, cap: u64) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len > cap {
        return Err(std::io::Error::other("file exceeds size cap"));
    }
    // Pre-size so the read never reallocates and strands a key copy.
    let capacity = usize::try_from(len).unwrap_or(0) + 1;
    let mut buf = Zeroizing::new(Vec::with_capacity(capacity));
    file.take(cap + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > cap {
        return Err(std::io::Error::other("file exceeds size cap"));
    }
    Ok(buf)
}

/// Split `scheme://authority/...` and return `(scheme, host)`. Userinfo,
/// malformed brackets or stray colons yield `None`.
pub fn endpoint_scheme_and_host(endpoint: &str) -> Option<(&'static str, String)> {
    let (scheme, rest) = if let Some(rest) = endpoint.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = endpoint.strip_prefix("http://") {
        ("http", rest)
    } else {
        return None;
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..authority_end)?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let close = bracketed.find(']')?;
        let host = bracketed.get(..close)?;
        let after = bracketed.get(close + 1..)?;
        let port = if after.is_empty() {
            None
        } else {
            Some(after.strip_prefix(':')?)
        };
        (host, port)
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    if let Some(port) = port {
        if port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().is_err()
        {
            return None;
        }
    }
    Some((scheme, host.to_ascii_lowercase()))
}

pub fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "::1" | "localhost")
}

/// Load and vet the gateway settings. Never opens anything but
/// `metadata.json` and, for mTLS, the three PEM files.
pub fn load(config_dir: &Path, name: &str) -> Result<GatewayConfig, GatewayConfigError> {
    if !is_safe_gateway_name(name) {
        return Err(GatewayConfigError::InvalidName);
    }
    let gateway_dir = config_dir.join("gateways").join(name);
    let bytes = read_capped(&gateway_dir.join("metadata.json"), MAX_METADATA_BYTES)
        .map_err(|_| GatewayConfigError::MetadataUnreadable)?;
    let raw: RawMetadata =
        serde_json::from_slice(&bytes).map_err(|_| GatewayConfigError::MetadataInvalid)?;
    let endpoint = raw
        .gateway_endpoint
        .filter(|e| is_valid_gateway_endpoint(e))
        .ok_or(GatewayConfigError::MetadataInvalid)?;
    let (scheme, host) =
        endpoint_scheme_and_host(&endpoint).ok_or(GatewayConfigError::MetadataInvalid)?;

    let auth = match raw.auth_mode.as_deref() {
        Some("mtls") => {
            if scheme != "https" {
                return Err(GatewayConfigError::UnsupportedAuth);
            }
            let mtls = gateway_dir.join("mtls");
            let read = |file: &str| {
                read_capped(&mtls.join(file), MAX_PEM_BYTES)
                    .map_err(|_| GatewayConfigError::MtlsMaterialUnreadable)
            };
            let ca_pem = read("ca.crt")?;
            let cert_pem = read("tls.crt")?;
            let key_pem = read_secret_capped(&mtls.join("tls.key"), MAX_PEM_BYTES)
                .map_err(|_| GatewayConfigError::MtlsMaterialUnreadable)?;
            GatewayAuth::Mtls(MtlsMaterial {
                ca_pem,
                cert_pem,
                key_pem,
            })
        }
        Some("plaintext") => {
            if scheme != "http" || !is_loopback_host(&host) {
                return Err(GatewayConfigError::PlaintextNotLoopback);
            }
            GatewayAuth::PlaintextLoopback
        }
        _ => return Err(GatewayConfigError::UnsupportedAuth),
    };

    Ok(GatewayConfig {
        name: name.to_string(),
        endpoint,
        host,
        auth,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "aos-gwcfg-{tag}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).expect("mkdir");
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write_gateway(cfg: &Path, name: &str, metadata: &str, mtls: bool) {
        let dir = cfg.join("gateways").join(name);
        std::fs::create_dir_all(dir.join("mtls")).expect("mkdir");
        std::fs::write(dir.join("metadata.json"), metadata).expect("write");
        if mtls {
            std::fs::write(dir.join("mtls/ca.crt"), "CA").expect("write");
            std::fs::write(dir.join("mtls/tls.crt"), "CERT").expect("write");
            std::fs::write(dir.join("mtls/tls.key"), "KEY-SECRET-BYTES").expect("write");
        }
    }

    #[test]
    fn mtls_gateway_loads_material() {
        let tmp = TempDir::new("mtls");
        write_gateway(
            &tmp.0,
            "openshell",
            r#"{"name":"openshell","gateway_endpoint":"https://127.0.0.1:17670","auth_mode":"mtls"}"#,
            true,
        );
        let cfg = load(&tmp.0, "openshell").expect("loads");
        assert_eq!(cfg.endpoint, "https://127.0.0.1:17670");
        assert_eq!(cfg.host, "127.0.0.1");
        let GatewayAuth::Mtls(material) = &cfg.auth else {
            panic!("expected mtls");
        };
        assert_eq!(material.key_pem.as_slice(), b"KEY-SECRET-BYTES");
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("KEY-SECRET"), "{rendered}");
    }

    #[test]
    fn plaintext_only_on_loopback() {
        for (endpoint, ok) in [
            ("http://127.0.0.1:8080", true),
            ("http://localhost:8080", true),
            ("http://[::1]:8080", true),
            ("http://10.0.0.5:8080", false),
            ("http://gateway.example.com", false),
            ("http://127.0.0.1.evil.com", false),
            ("http://user@127.0.0.1:8080", false),
            ("https://127.0.0.1:8080", false),
        ] {
            let tmp = TempDir::new("plain");
            write_gateway(
                &tmp.0,
                "gw",
                &format!(r#"{{"gateway_endpoint":"{endpoint}","auth_mode":"plaintext"}}"#),
                false,
            );
            assert_eq!(load(&tmp.0, "gw").is_ok(), ok, "{endpoint}");
        }
    }

    #[test]
    fn unsupported_auth_modes_fail_closed() {
        for mode in [
            r#""cloudflare_jwt""#,
            r#""oidc""#,
            r#""bearer""#,
            r#""MTLS""#,
            "null",
        ] {
            let tmp = TempDir::new("auth");
            write_gateway(
                &tmp.0,
                "gw",
                &format!(r#"{{"gateway_endpoint":"https://127.0.0.1:1","auth_mode":{mode}}}"#),
                true,
            );
            let err = load(&tmp.0, "gw").expect_err(mode);
            assert!(err.to_string().contains(UNSUPPORTED_AUTH), "{mode}");
        }
        // auth_mode key missing entirely.
        let tmp = TempDir::new("missing");
        write_gateway(
            &tmp.0,
            "gw",
            r#"{"gateway_endpoint":"https://127.0.0.1:1"}"#,
            true,
        );
        assert_eq!(
            load(&tmp.0, "gw").expect_err("missing"),
            GatewayConfigError::UnsupportedAuth
        );
        // No metadata file at all.
        let tmp = TempDir::new("nofile");
        assert_eq!(
            load(&tmp.0, "gw").expect_err("no file"),
            GatewayConfigError::MetadataUnreadable
        );
    }

    #[test]
    fn mtls_without_material_fails() {
        let tmp = TempDir::new("nomat");
        write_gateway(
            &tmp.0,
            "gw",
            r#"{"gateway_endpoint":"https://127.0.0.1:1","auth_mode":"mtls"}"#,
            false,
        );
        assert_eq!(
            load(&tmp.0, "gw").expect_err("no material"),
            GatewayConfigError::MtlsMaterialUnreadable
        );
    }

    #[test]
    fn oversized_metadata_is_rejected() {
        let tmp = TempDir::new("big");
        let padding = "x".repeat(70 * 1024);
        write_gateway(
            &tmp.0,
            "gw",
            &format!(
                r#"{{"gateway_endpoint":"http://127.0.0.1:1","auth_mode":"plaintext","pad":"{padding}"}}"#
            ),
            false,
        );
        assert_eq!(
            load(&tmp.0, "gw").expect_err("too big"),
            GatewayConfigError::MetadataUnreadable
        );
    }

    #[test]
    fn traversal_names_are_rejected() {
        let tmp = TempDir::new("trav");
        for name in ["..", ".", "a/b", "", "a b"] {
            assert_eq!(
                load(&tmp.0, name).expect_err(name),
                GatewayConfigError::InvalidName
            );
        }
    }

    #[test]
    fn config_dir_resolution_order() {
        let over = PathBuf::from("/over");
        assert_eq!(
            config_dir_from(Some(&over), Some("/xdg".into()), Some("/home/u".into())),
            Some(over)
        );
        assert_eq!(
            config_dir_from(None, Some("/xdg".into()), Some("/home/u".into())),
            Some(PathBuf::from("/xdg/openshell"))
        );
        assert_eq!(
            config_dir_from(None, Some("relative".into()), Some("/home/u".into())),
            Some(PathBuf::from("/home/u/.config/openshell"))
        );
        assert_eq!(config_dir_from(None, None, None), None);
    }
}
