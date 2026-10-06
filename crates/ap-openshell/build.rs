//! Compiles the vendored OpenShell protos with `protox` (pure Rust, so no
//! system `protoc` is needed) and generates the tonic client/server code.
//!
//! Value-bearing messages get `skip_debug`; their redacting `Debug` impls are
//! hand-written in `src/proto.rs`. No message-level tracing is generated.

const PROTO_DIR: &str = "proto";

const PROTO_FILES: &[&str] = &[
    "proto/credential_driver.proto",
    "proto/datamodel.proto",
    "proto/extension.proto",
    "proto/options.proto",
    "proto/openshell.proto",
];

/// Messages that carry (or may carry) a secret value. Their derived `Debug`
/// would print it, so it is skipped and replaced by a redacting impl.
const SKIP_DEBUG: &[&str] = &[
    ".openshell.credentials.v1.StoreCredentialRequest",
    ".openshell.credentials.v1.ResolvedCredential",
    ".openshell.credentials.v1.ResolveCredentialsResponse",
    // `Provider.credentials` is a secret map upstream. The gateway API is not
    // expected to return it, but nothing here may ever print it.
    ".openshell.datamodel.v1.Provider",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for file in PROTO_FILES {
        println!("cargo:rerun-if-changed={file}");
    }

    let descriptors = protox::compile(
        ["proto/credential_driver.proto", "proto/openshell.proto"],
        [PROTO_DIR],
    )?;

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .skip_debug(SKIP_DEBUG.iter().copied())
        .compile_fds(descriptors)?;

    Ok(())
}
