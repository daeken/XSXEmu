//! Reusable, host-independent XSXEmu components.

pub mod compute_metadata;
pub mod pipeline_library;
pub mod root_signature;
pub mod rpf9;
#[cfg(feature = "rpf9-retail")]
mod rpf9_crypto;
#[cfg(feature = "rpf9-retail")]
pub mod rpf9_retail;
