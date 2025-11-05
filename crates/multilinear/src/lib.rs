//! Multilinear extension implementation for cryptographic protocols.
//! 
//! This crate provides an implementation of multilinear extensions (MLEs),
//! which are fundamental building blocks for many cryptographic protocols
//! including zero-knowledge proofs and interactive proofs.

pub mod extension;
pub mod binary;

pub use extension::{MultilinearExtension, MLE};
pub use binary::dec_to_bin;

/// Re-export commonly used types
pub mod prelude {
    pub use super::extension::{MultilinearExtension, MLE};
    pub use super::binary::dec_to_bin;
} 