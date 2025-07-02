//! Finite field arithmetic for cryptographic operations.
//! 
//! This crate provides efficient implementations of finite field arithmetic
//! over prime fields, including addition, multiplication, division, and
//! exponentiation operations.

pub mod finite_field;
// pub mod ring;

pub use finite_field::FiniteField;
// pub use ring::Ring;

/// Re-export commonly used types
pub mod prelude {
    pub use super::finite_field::FiniteField;
    // pub use super::ring::Ring;
} 