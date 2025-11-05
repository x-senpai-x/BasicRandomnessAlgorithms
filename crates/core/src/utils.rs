//! Utility functions for cryptographic operations.

use crate::error::{CryptoError, CryptoResult};
use rand::Rng;

/// Extended Euclidean algorithm implementation.
///
/// Returns (gcd, x, y) where gcd = ax + by
pub fn extended_gcd(a: i128, b: i128) -> (i128, i128, i128) {
    if b == 0 {
        (a, 1, 0)
    } else {
        let (gcd, x, y) = extended_gcd(b, a % b);
        (gcd, y, x - (a / b) * y)
    }
}
/// Check if a number is prime using Miller-Rabin primality test
pub fn generate_random_prime(bit_length: usize) -> CryptoResult<u64> {
    for _ in 0..1000 {
        let prime_candidate = get_low_level_prime(bit_length);
        if is_miller_rabin_passed(prime_candidate, 20) {
            return Ok(prime_candidate);
        }
    }
    Err(CryptoError::RandomError(
        "Failed to generate prime number".to_string(),
    ))
}

pub fn get_low_level_prime(bit_length: usize) -> u64 {
    let first_primes_list = [
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
        97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
        191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
        283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
    ];
    let mut rng = rand::rng();
    let min = 1u64 << (bit_length - 1);
    let max = (1u64 << bit_length) - 1;
    let mut pc = rng.random_range(min..=max);

    loop {
        let mut divisible = false;
        for divisor in first_primes_list {
            if pc % divisor == 0 && divisor.pow(2) <= pc {
                divisible = true;
                break;
            }
        }
        if divisible == false {
            break;
        }
        pc = rng.random_range(min..=max);
    }
    return pc;
}

/// Miller-Rabin primality test for probabilistic prime checking.
/// Returns true if the number passes the test (is probably prime).
pub fn is_miller_rabin_passed(n: u64, k: usize) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 || n == 3 {
        return true;
    }
    if n % 2 == 0 {
        return false;
    }
    let mut ec = n - 1;
    let mut max_divisions_by_two = 0;
    while ec % 2 == 0 {
        ec >>= 1;
        max_divisions_by_two += 1;
    }
    let mut rng = rand::rng();
    'outer: for _ in 0..k {
        let round_tester = rng.random_range(2..=n - 2);
        let mut x = mod_exp(round_tester, ec, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        for _ in 0..max_divisions_by_two - 1 {
            x = mod_exp(x, 2, n);
            if x == n - 1 {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

//     let sqrt_n = (n as f64).sqrt() as u64;
//     for i in (3..=sqrt_n).step_by(2) {
//         if n % i == 0 {
//             return false;
//         }
//     }
//     true
// }

//  Find prime factors of a number.
// Returns a vector of prime factors (not necessarily unique).
pub fn prime_factors(mut n: u64) -> Vec<u64> {
    let mut factors = Vec::new();

    // Handle 2 separately
    while n % 2 == 0 {
        factors.push(2);
        n /= 2;
    }

    // Check odd numbers up to sqrt(n)
    let sqrt_n = (n as f64).sqrt() as u64;
    for i in (3..=sqrt_n).step_by(2) {
        while n % i == 0 {
            factors.push(i);
            n /= i;
        }
    }

    // If n is still > 1, it's prime
    if n > 1 {
        factors.push(n);
    }

    factors
}

/// Generate a random prime number with specified bit length.
///
/// # Arguments
/// * `bit_length` - The desired bit length of the prime
///
/// # Returns
/// A random prime number with the specified bit length

/// Generate random numbers within a given range.
///
/// # Arguments
/// * `count` - Number of random numbers to generate
/// * `max` - Maximum value (exclusive)
///
/// # Returns
/// Vector of random numbers in [0, max)
pub fn generate_random_numbers(count: usize, max: u64) -> Vec<u64> {
    let mut rng = rand::rng();
    (0..count).map(|_| rng.random_range(0..max)).collect()
}

/// Convert decimal to binary representation.
///
/// # Arguments
/// * `decimal` - The decimal number to convert
/// * `bit_length` - The desired bit length of the output
///
/// # Returns
/// Binary representation as a vector of bits (least significant bit first)
pub fn decimal_to_binary(mut decimal: u64, bit_length: usize) -> Vec<u8> {
    let mut binary = Vec::with_capacity(bit_length);

    for _ in 0..bit_length {
        binary.push((decimal % 2) as u8);
        decimal /= 2;
    }

    binary
}

/// Convert binary representation to decimal.
///
/// # Arguments
/// * `binary` - Binary representation as a vector of bits
///
/// # Returns
/// The decimal value

/// Modular exponentiation: computes (base^exp) % modulus efficiently.
fn mod_exp(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base = base % modulus;
    while exp > 0 {
        if exp % 2 == 1 {
            result = result.wrapping_mul(base) % modulus;
        }
        exp >>= 1;
        base = base.wrapping_mul(base) % modulus;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extended_gcd() {
        let (gcd, x, y) = extended_gcd(48, 18);
        assert_eq!(gcd, 6);
        assert_eq!(48 * x + 18 * y, 6);
    }

    #[test]
    fn test_is_prime() {
        assert!(!is_miller_rabin_passed(0, 20));
        assert!(is_miller_rabin_passed(7, 20));
        assert!(!is_miller_rabin_passed(3122223, 20));
    }

    #[test]
    fn test_prime_factors() {
        assert_eq!(prime_factors(12), vec![2, 2, 3]);
        assert_eq!(prime_factors(15), vec![3, 5]);
        assert_eq!(prime_factors(17), vec![17]);
    }

    #[test]
    fn test_decimal_to_binary() {
        assert_eq!(decimal_to_binary(5, 4), vec![1, 0, 1, 0]);
        assert_eq!(decimal_to_binary(10, 5), vec![0, 1, 0, 1, 0]);
    }
}
