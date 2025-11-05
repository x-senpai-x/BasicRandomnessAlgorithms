//! Low-degree test implementation for polynomial verification.
//! 
//! This crate provides implementations of low-degree tests,
//! which are used to verify that a polynomial has degree at most d
//! by testing it at random points.

pub mod test;
pub mod protocol;

pub use test::{LowDegreeTest, TestResult};
pub use protocol::{low_degree_test_protocol, LowDegreeTestMessage};

/// Re-export commonly used types
pub mod prelude {
    pub use super::test::{LowDegreeTest, TestResult};
    pub use super::protocol::{low_degree_test_protocol, LowDegreeTestMessage};
} 