//! Transports for talking to a credential provider.
//!
//! `local` speaks the desktop app's local wire protocol (Unix domain socket /
//! Windows named pipe) directly from `ap-cli`, bypassing the Noise/relay
//! stack in `ap-client` entirely — the local endpoint is already a trusted,
//! same-machine channel, so the relay's end-to-end encryption layer would add
//! nothing here.

pub mod local;
