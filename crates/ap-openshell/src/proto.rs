//! Generated OpenShell protobuf/gRPC code (vendored protos, see `proto/NOTICE`).
//!
//! `build.rs` skips the derived `Debug` for every message that can carry a
//! secret value; the impls below print structure only, never a value.

#![allow(clippy::all, missing_docs)]

use std::fmt;

pub mod openshell {
    pub mod v1 {
        tonic::include_proto!("openshell.v1");
    }
    pub mod credentials {
        pub mod v1 {
            tonic::include_proto!("openshell.credentials.v1");
        }
    }
    pub mod extension {
        pub mod v1 {
            tonic::include_proto!("openshell.extension.v1");
        }
    }
    pub mod datamodel {
        pub mod v1 {
            tonic::include_proto!("openshell.datamodel.v1");
        }
    }
    pub mod options {
        pub mod v1 {
            tonic::include_proto!("openshell.options.v1");
        }
    }
}

use openshell::credentials::v1::{
    ResolveCredentialsResponse, ResolvedCredential, StoreCredentialRequest,
};
use openshell::datamodel::v1::Provider;

const REDACTED: &str = "<redacted>";

impl fmt::Debug for StoreCredentialRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreCredentialRequest")
            .field("provider", &self.provider)
            .field("credential_key", &self.credential_key)
            .field("value", &REDACTED)
            .field("existing_handle", &self.existing_handle)
            .field("workspace", &self.workspace)
            .field("provider_id", &self.provider_id)
            .field("object_id", &self.object_id)
            .finish()
    }
}

impl fmt::Debug for ResolvedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedCredential")
            .field("request_id", &self.request_id)
            .field("value", &REDACTED)
            .field("expiration_time", &self.expiration_time)
            .finish()
    }
}

impl fmt::Debug for ResolveCredentialsResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolveCredentialsResponse")
            .field("credentials", &self.credentials)
            .finish()
    }
}

impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let credential_keys: Vec<&String> = self.credentials.keys().collect();
        f.debug_struct("Provider")
            .field("metadata", &self.metadata)
            .field("type", &self.r#type)
            .field(
                "credentials",
                &format_args!("<{} redacted>", credential_keys.len()),
            )
            .field("config_keys", &self.config.keys().collect::<Vec<_>>())
            .field("profile_workspace", &self.profile_workspace)
            .field(
                "credential_handle_keys",
                &self.credential_handles.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_of_value_bearing_messages_contains_no_value() {
        let store = StoreCredentialRequest {
            value: "hunter2-store".into(),
            ..Default::default()
        };
        let resolved = ResolvedCredential {
            request_id: "credential-0".into(),
            value: "hunter2-resolved".into(),
            expiration_time: None,
        };
        let response = ResolveCredentialsResponse {
            credentials: vec![resolved.clone()],
        };
        let mut provider = Provider::default();
        provider
            .credentials
            .insert("TOKEN".into(), "hunter2-provider".into());
        provider.config.insert("k".into(), "config-value".into());

        for rendered in [
            format!("{store:?}"),
            format!("{resolved:?}"),
            format!("{response:?}"),
            format!("{provider:?}"),
        ] {
            assert!(!rendered.contains("hunter2"), "{rendered}");
            assert!(!rendered.contains("config-value"), "{rendered}");
        }
    }
}
