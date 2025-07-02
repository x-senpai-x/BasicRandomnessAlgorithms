//! Core cryptographic primitives and utilities.
//! 
//! This crate provides fundamental building blocks for cryptographic algorithms
//! including error types, utility functions, and common mathematical operations.

pub mod error;
pub mod utils;

pub use error::{CryptoError, CryptoResult};
pub use utils::{extended_gcd, generate_random_prime,is_miller_rabin_passed, prime_factors};

/// Re-export commonly used types and functions
pub mod prelude {
    pub use super::error::{CryptoError, CryptoResult};
    pub use super::utils::{extended_gcd, generate_random_numbers,is_miller_rabin_passed, prime_factors,generate_random_prime};
} 