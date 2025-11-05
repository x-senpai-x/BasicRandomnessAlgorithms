//! Polynomial arithmetic for cryptographic operations.
//! 
//! This crate provides efficient implementations of polynomial arithmetic
//! over finite fields, including evaluation, interpolation, and operations
//! on multivariate polynomials.

pub mod univariate;
pub mod multivariate;
pub mod interpolation;

pub use univariate::Polynomial;
pub use multivariate::MultiVariatePolynomial;
pub use interpolation::{Point, interpolate_monomial_basis, evaluate_polynomial, generate_delta};

/// Re-export commonly used types
pub mod prelude {
    pub use super::univariate::Polynomial;
    pub use super::multivariate::MultiVariatePolynomial;
    pub use super::interpolation::{Point, interpolate_monomial_basis, evaluate_polynomial, generate_delta};
} 