//! Sum-check protocol implementation for interactive proofs.
//! 
//! This crate provides an implementation of the sum-check protocol,
//! which is a fundamental building block for interactive proof systems
//! and zero-knowledge proofs.

pub mod protocol;
pub mod polynomial;

pub use protocol::{sum_check_protocol, SumCheckRoundMessage};
pub use polynomial::MultiVariatePolynomial;

/// Re-export commonly used types
pub mod prelude {
    pub use super::protocol::{sum_check_protocol, SumCheckRoundMessage};
    pub use super::polynomial::MultiVariatePolynomial;
} 