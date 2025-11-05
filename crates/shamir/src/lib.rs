//! Shamir secret sharing implementation for secure secret distribution.
//! 
//! This crate provides an implementation of Shamir's secret sharing scheme,
//! which allows a secret to be split into n shares such that any k shares
//! can reconstruct the secret, but any k-1 shares reveal no information.

pub mod scheme;
pub mod share;

pub use scheme::{ShamirScheme, ShareResult};
pub use share::{Share, ShareError};

/// Re-export commonly used types
pub mod prelude {
    pub use super::scheme::{ShamirScheme, ShareResult};
    pub use super::share::{Share, ShareError};
} 