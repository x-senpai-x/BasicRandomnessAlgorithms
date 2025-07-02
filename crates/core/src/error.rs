//! Error types for cryptographic operations.

use thiserror::Error;

/// Represents errors that can occur in cryptographic operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Division by zero error
    #[error("Division by zero")]
    DivisionByZero,
    
    /// Invalid modulus error
    #[error("Invalid modulus: {0}")]
    InvalidModulus(u64),
    
    /// Element has no multiplicative inverse
    #[error("Element {0} has no multiplicative inverse modulo {1}")]
    NoInverse(u64, u64),
    
    /// Invalid polynomial degree
    #[error("Invalid polynomial degree: {0}")]
    InvalidDegree(usize),
    
    /// Invalid field element
    #[error("Invalid field element: {0}")]
    InvalidFieldElement(String),

    /// Invalid bit length
    #[error("Invalid bit length: {0}")]
    InvalidBitLength(u64),
    
    /// Matrix operation error
    #[error("Matrix operation error: {0}")]
    MatrixError(String),
    
    /// Interpolation error
    #[error("Interpolation error: {0}")]
    InterpolationError(String),
    
    /// FFT error
    #[error("FFT error: {0}")]
    FftError(String),
    
    /// Random number generation error
    #[error("Random number generation error: {0}")]
    RandomError(String),
}

/// Result type for cryptographic operations.
pub type CryptoResult<T> = Result<T, CryptoError>; 