//! Bitwarden reference and handle grammar (architecture §M8.3).
//!
//! | Reference                    | Handle                       |
//! | ---------------------------- | ---------------------------- |
//! | `bw://item/<uuid>#username`  | `bw1:item:<uuid>:username`   |
//! | `bw://item/<uuid>#password`  | `bw1:item:<uuid>:password`   |
//! | `bw://secret/<uuid>`         | `bw1:secret:<uuid>:value`    |
//!
//! Only the UUID is case-normalised (uppercase hex is lowercased before
//! validation). Nothing else is normalised and anything else is rejected.
//! Error values never echo the input, a prefix of it, or its length.

use std::collections::HashMap;

use crate::proto::openshell::datamodel::v1::CredentialHandle;

/// Driver name registered in `gateway.toml` and carried in every handle.
pub const DRIVER_NAME: &str = "bitwarden";

const REFERENCE_PREFIX: &str = "bw://";
const HANDLE_PREFIX: &str = "bw1:";

/// Which Bitwarden resource a reference points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Resource {
    /// A vault login item.
    Item,
    /// A Secrets Manager secret.
    Secret,
}

impl Resource {
    /// Wire / handle spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Resource::Item => "item",
            Resource::Secret => "secret",
        }
    }
}

/// Which field of the resource is released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Field {
    Username,
    Password,
    Value,
}

impl Field {
    /// Wire / handle spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Field::Username => "username",
            Field::Password => "password",
            Field::Value => "value",
        }
    }
}

/// A validated Bitwarden target: resource kind, lowercase UUID, field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub resource: Resource,
    pub id: String,
    pub field: Field,
}

/// Input did not match the grammar. Deliberately carries no detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a valid Bitwarden reference or handle")]
pub struct GrammarError;

impl Target {
    /// The opaque handle stored in the gateway database.
    pub fn to_handle_string(&self) -> String {
        format!(
            "{HANDLE_PREFIX}{}:{}:{}",
            self.resource.as_str(),
            self.id,
            self.field.as_str()
        )
    }

    /// The full `CredentialHandle` returned by `StoreCredential`.
    pub fn to_credential_handle(&self) -> CredentialHandle {
        let mut metadata = HashMap::new();
        metadata.insert("kind".to_string(), self.resource.as_str().to_string());
        metadata.insert("field".to_string(), self.field.as_str().to_string());
        CredentialHandle {
            driver: DRIVER_NAME.to_string(),
            handle: self.to_handle_string(),
            metadata,
        }
    }
}

/// Parse a user-facing `bw://` reference.
pub fn parse_reference(input: &str) -> Result<Target, GrammarError> {
    let rest = input.strip_prefix(REFERENCE_PREFIX).ok_or(GrammarError)?;
    if let Some(rest) = rest.strip_prefix("item/") {
        let (uuid, fragment) = rest.split_once('#').ok_or(GrammarError)?;
        let field = match fragment {
            "username" => Field::Username,
            "password" => Field::Password,
            _ => return Err(GrammarError),
        };
        Ok(Target {
            resource: Resource::Item,
            id: normalise_uuid(uuid)?,
            field,
        })
    } else if let Some(uuid) = rest.strip_prefix("secret/") {
        Ok(Target {
            resource: Resource::Secret,
            id: normalise_uuid(uuid)?,
            field: Field::Value,
        })
    } else {
        Err(GrammarError)
    }
}

/// Parse a `bw1:` handle produced by [`Target::to_handle_string`].
pub fn parse_handle(input: &str) -> Result<Target, GrammarError> {
    let rest = input.strip_prefix(HANDLE_PREFIX).ok_or(GrammarError)?;
    let mut parts = rest.split(':');
    let (Some(kind), Some(uuid), Some(field), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(GrammarError);
    };
    // Handles are produced by this driver, always lowercase: no normalising.
    if !is_lowercase_uuid(uuid) {
        return Err(GrammarError);
    }
    let (resource, field) = match (kind, field) {
        ("item", "username") => (Resource::Item, Field::Username),
        ("item", "password") => (Resource::Item, Field::Password),
        ("secret", "value") => (Resource::Secret, Field::Value),
        _ => return Err(GrammarError),
    };
    Ok(Target {
        resource,
        id: uuid.to_string(),
        field,
    })
}

/// Parse a handle from the gateway, also checking the owning driver name.
pub fn parse_credential_handle(handle: &CredentialHandle) -> Result<Target, GrammarError> {
    if handle.driver != DRIVER_NAME {
        return Err(GrammarError);
    }
    parse_handle(&handle.handle)
}

/// `StoreCredential` input: a `bw://` reference, or (fallback U1) an already
/// encoded `bw1:` handle.
pub fn parse_store_value(input: &str) -> Result<Target, GrammarError> {
    parse_reference(input).or_else(|_| parse_handle(input))
}

fn normalise_uuid(candidate: &str) -> Result<String, GrammarError> {
    // Only ASCII hex letters are lowercased; anything non-ASCII fails below.
    let lowered = candidate.to_ascii_lowercase();
    if is_lowercase_uuid(&lowered) {
        Ok(lowered)
    } else {
        Err(GrammarError)
    }
}

/// `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
pub fn is_lowercase_uuid(candidate: &str) -> bool {
    let bytes = candidate.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    bytes.iter().enumerate().all(|(index, byte)| match index {
        8 | 13 | 18 | 23 => *byte == b'-',
        _ => matches!(byte, b'0'..=b'9' | b'a'..=b'f'),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "3f1c2b9e-8a4d-4c7e-9b21-5d6f7a8b9c0d";

    #[test]
    fn three_reference_forms_round_trip() {
        let cases = [
            (
                format!("bw://item/{UUID}#username"),
                format!("bw1:item:{UUID}:username"),
                Resource::Item,
                Field::Username,
            ),
            (
                format!("bw://item/{UUID}#password"),
                format!("bw1:item:{UUID}:password"),
                Resource::Item,
                Field::Password,
            ),
            (
                format!("bw://secret/{UUID}"),
                format!("bw1:secret:{UUID}:value"),
                Resource::Secret,
                Field::Value,
            ),
        ];
        for (reference, handle, resource, field) in cases {
            let target = parse_reference(&reference).expect("valid reference");
            assert_eq!(target.resource, resource);
            assert_eq!(target.field, field);
            assert_eq!(target.id, UUID);
            assert_eq!(target.to_handle_string(), handle);
            assert_eq!(parse_handle(&handle).expect("valid handle"), target);

            let credential_handle = target.to_credential_handle();
            assert_eq!(credential_handle.driver, "bitwarden");
            assert_eq!(credential_handle.handle, handle);
            assert_eq!(
                credential_handle.metadata.get("kind").map(String::as_str),
                Some(resource.as_str())
            );
            assert_eq!(
                credential_handle.metadata.get("field").map(String::as_str),
                Some(field.as_str())
            );
            assert_eq!(
                parse_credential_handle(&credential_handle).expect("own handle"),
                target
            );
        }
    }

    #[test]
    fn uppercase_uuid_is_lowercased_and_nothing_else_is() {
        let upper = UUID.to_ascii_uppercase();
        let target = parse_reference(&format!("bw://item/{upper}#password")).expect("upper uuid");
        assert_eq!(target.id, UUID);
        assert!(parse_reference(&format!("BW://item/{UUID}#password")).is_err());
        assert!(parse_reference(&format!("bw://ITEM/{UUID}#password")).is_err());
        assert!(parse_reference(&format!("bw://item/{UUID}#Password")).is_err());
        // Handles are never normalised.
        assert!(parse_handle(&format!("bw1:item:{upper}:password")).is_err());
    }

    #[test]
    fn rejects_everything_outside_the_grammar() {
        let rejects = [
            String::new(),
            "ghp_plaintexttoken".to_string(),
            "bw://".to_string(),
            format!("bw://item/{UUID}"),
            format!("bw://item/{UUID}#totp"),
            format!("bw://item/{UUID}#"),
            format!("bw://item/{UUID}#password?x=1"),
            format!("bw://item/{UUID}?x=1#password"),
            format!("bw://item/{UUID}#password "),
            format!(" bw://item/{UUID}#password"),
            format!("bw://item/{UUID}#password\n"),
            format!("bw://item/{UUID}#password#password"),
            format!("bw://secret/{UUID}#value"),
            format!("bw://secret/{UUID}/"),
            format!("bw://secret/{UUID}x"),
            "bw://secret/not-a-uuid".to_string(),
            "bw://secret/3f1c2b9e8a4d4c7e9b215d6f7a8b9c0d".to_string(),
            "bw://secret/3f1c2b9e-8a4d-4c7e-9b21-5d6f7a8b9c0g".to_string(),
            format!("bw://collection/{UUID}"),
            format!("bw1:item:{UUID}:totp"),
            format!("bw1:secret:{UUID}:password"),
            format!("bw1:item:{UUID}:password:extra"),
            format!("bw1:item:{UUID}"),
            format!("bw2:item:{UUID}:password"),
        ];
        for input in rejects {
            assert!(
                parse_reference(&input).is_err(),
                "reference accepted: {input:?}"
            );
            assert!(parse_handle(&input).is_err(), "handle accepted: {input:?}");
        }
    }

    #[test]
    fn store_value_accepts_reference_or_own_handle_only() {
        assert!(parse_store_value(&format!("bw://secret/{UUID}")).is_ok());
        assert!(parse_store_value(&format!("bw1:secret:{UUID}:value")).is_ok());
        assert!(parse_store_value("plain-secret-value").is_err());
    }

    #[test]
    fn foreign_driver_handle_is_rejected() {
        let mut handle = parse_reference(&format!("bw://secret/{UUID}"))
            .expect("valid")
            .to_credential_handle();
        handle.driver = "vault".into();
        assert!(parse_credential_handle(&handle).is_err());
    }

    #[test]
    fn grammar_error_text_is_constant() {
        let secret = "ghp_supersecretvalue";
        let err = parse_reference(secret).expect_err("rejected");
        let rendered = format!("{err} {err:?}");
        assert!(!rendered.contains("ghp_"));
        assert!(!rendered.contains(&secret.len().to_string()));
    }
}
