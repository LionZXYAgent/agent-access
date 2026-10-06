//! `aac openshell-driver`: thin wrapper over `ap_openshell::run_driver`.
//!
//! Spawned by `openshell-gateway` per the `gateway.toml` snippet the
//! Bitwarden desktop shows; the gateway appends `--bind-socket <path>`.
//! All wire types and logic live in the `ap-openshell` crate. On non-Unix
//! platforms `run_driver` fails with "openshell-driver is only supported on
//! macOS and Linux".

use clap::Args;
use color_eyre::eyre::Result;

#[derive(Debug, Args)]
pub struct OpenShellDriverArgs {
    #[command(flatten)]
    inner: ap_openshell::DriverArgs,
}

impl OpenShellDriverArgs {
    pub async fn run(self) -> Result<()> {
        ap_openshell::run_driver(self.inner).await?;
        Ok(())
    }
}
