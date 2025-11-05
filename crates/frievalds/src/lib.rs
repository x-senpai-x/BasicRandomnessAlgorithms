//! Frievalds algorithm implementation for matrix multiplication verification.
//! 
//! This crate provides an implementation of Frievalds algorithm,
//! which is a probabilistic algorithm for verifying matrix multiplication
//! without computing the full product.

pub mod algorithm;
pub mod matrix;

pub use algorithm::{frievalds_verify, FrievaldsResult};
pub use matrix::{Matrix, MatrixError};

/// Re-export commonly used types
pub mod prelude {
    pub use super::algorithm::{frievalds_verify, FrievaldsResult};
    pub use super::matrix::{Matrix, MatrixError};
} 