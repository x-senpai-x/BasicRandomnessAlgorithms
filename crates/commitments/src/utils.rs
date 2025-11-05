//! Utility functions for commitment schemes.
//!
//! This module provides helper functions for working with multiplicative
//! groups and generators in finite fields.

use crypto_core::{self, CryptoResult};
use rand::Rng;

/// Finds a generator of the multiplicative group modulo prime `p`.
///
/// A generator g of Z_p^* is an element such that the powers
/// g^1, g^2, ..., g^(p-1) produce all non-zero elements modulo p.
///
/// # Algorithm
/// For each candidate g in [2, p):
/// 1. For each prime factor q of (p-1), check if g^((p-1)/q) ≠ 1 (mod p)
/// 2. If all checks pass, g is a generator
///
/// # Arguments
/// * `p` - A prime number defining the field
///
/// # Returns
/// A generator of the multiplicative group Z_p^*, or an error if:
/// - `p` is not prime (verified using Miller-Rabin test)
/// - No generator found within 100 attempts (very unlikely for actual primes)
///
/// # Errors
/// Returns `CryptoError::NotPrime` if `p` fails the Miller-Rabin primality test.
/// Returns `CryptoError::NotFound` if no generator is found after 100 trials.
pub fn find_generator(p: u64) -> CryptoResult<u64> {
    if !crypto_core::is_miller_rabin_passed(p, 20) {
        return Err(crypto_core::CryptoError::NotPrime(p));
    }
    let order = p - 1;
    let factors = crypto_core::prime_factors(order);

    let mut rng = rand::rng();

    for _ in 0..100 {
        // Try up to 100 random candidates
        let g = rng.random_range(2..p); // avoid 0 and 1

        let mut is_generator = true;
        for &q in &factors {
            if mod_exp(g, order / q, p) == 1 {
                is_generator = false;
                break;
            }
        }

        if is_generator {
            return Ok(g);
        }
    }
    Err(crypto_core::CryptoError::NotFound(
        "Generator couldn't be found".to_string(),
    ))
}
/// Compute modular exponentiation: base^exp (mod modulus).
///
/// Uses the binary exponentiation algorithm (square-and-multiply) for
/// efficient computation. This runs in O(log exp) time.
///
/// # Algorithm
/// - Start with result = 1
/// - For each bit of the exponent (from least to most significant):
///   - If bit is 1, multiply result by current base
///   - Square the base for the next bit
///
/// # Arguments
/// * `base` - The base of the exponentiation
/// * `exp` - The exponent
/// * `modulus` - The modulus for reduction
///
/// # Returns
/// The value base^exp mod modulus
///
/// # Example
/// ```ignore
/// let result = mod_exp(2, 10, 1000); // 2^10 mod 1000 = 1024 mod 1000 = 24
/// ```
fn mod_exp(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1;
    base %= modulus;
    while exp > 0 {
        if exp % 2 == 1 {
            result = result * base % modulus;
        }
        base = base * base % modulus;
        exp /= 2;
    }
    result
}
