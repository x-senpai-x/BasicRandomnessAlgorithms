//! Fast Fourier Transform for cryptographic operations.
//! 
//! This crate provides efficient implementations of FFT algorithms
//! over finite fields, including polynomial multiplication and
//! evaluation.

pub mod fft;
pub mod polynomial_folding;

pub use fft::{fft, ifft, fft_in_place, ifft_in_place};
pub use polynomial_folding::fold_polynomial;

/// Re-export commonly used types
pub mod prelude {
    pub use super::fft::{fft, ifft, fft_in_place, ifft_in_place};
    pub use super::polynomial_folding::fold_polynomial;
} 