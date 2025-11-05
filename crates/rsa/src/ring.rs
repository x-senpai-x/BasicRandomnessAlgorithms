//! Ring arithmetic over composite moduli.
//!
//! This module provides a generic Ring structure for modular arithmetic over composite
//! moduli (not necessarily prime). This is useful for RSA and other cryptographic
//! protocols that work with composite numbers.

use crypto_core::utils::extended_gcd;
use rand::Rng;
use std::fmt::Display;

/// Simple primality test for small numbers.
///
/// # Arguments
/// * `n` - The number to check
///
/// # Returns
/// True if the number is prime, false otherwise
fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 {
        return true;
    }
    if n % 2 == 0 {
        return false;
    }
    let sqrt_n = (n as f64).sqrt() as u64;
    for i in (3..=sqrt_n).step_by(2) {
        if n % i == 0 {
            return false;
        }
    }
    true
}

/// Represents an element in a ring Z/nZ where n may be composite.
#[derive(Debug, Clone, Copy)]
pub struct Ring {
    /// The value of this ring element
    pub value: u64,
    /// The modulus of the ring
    pub modulus: u64,
}

impl Ring {
    /// Create a new ring element with value reduced modulo the modulus.
    ///
    /// # Arguments
    /// * `value` - The value to represent
    /// * `modulus` - The modulus of the ring
    ///
    /// # Returns
    /// A new ring element
    pub fn new(value: u64, modulus: u64) -> Self {
        Ring {
            value: value % modulus,
            modulus,
        }
    }

    /// Addition in the ring.
    ///
    /// # Arguments
    /// * `other` - The other ring element to add
    ///
    /// # Returns
    /// The sum of this and other
    ///
    /// # Panics
    /// Panics if the rings have different moduli
    pub fn add(&self, other: &Ring) -> Ring {
        assert_eq!(
            self.modulus, other.modulus,
            "Rings must have the same modulus"
        );
        Ring::new((self.value + other.value) % self.modulus, self.modulus)
    }

    /// Subtraction in the ring.
    ///
    /// # Arguments
    /// * `other` - The other ring element to subtract
    ///
    /// # Returns
    /// The difference of this and other
    ///
    /// # Panics
    /// Panics if the rings have different moduli
    pub fn sub(&self, other: &Ring) -> Ring {
        assert_eq!(
            self.modulus, other.modulus,
            "Rings must have the same modulus"
        );
        let result = if self.value < other.value {
            self.modulus - other.value + self.value
        } else {
            self.value - other.value
        };
        Ring::new(result % self.modulus, self.modulus)
    }

    /// Multiplication in the ring.
    ///
    /// # Arguments
    /// * `other` - The other ring element to multiply
    ///
    /// # Returns
    /// The product of this and other
    ///
    /// # Panics
    /// Panics if the rings have different moduli
    pub fn mul(&self, other: &Ring) -> Ring {
        assert_eq!(
            self.modulus, other.modulus,
            "Rings must have the same modulus"
        );
        let result = (self.value as u128) * (other.value as u128) % (self.modulus as u128);
        Ring::new(result as u64, self.modulus)
    }

    /// Check if this element has a multiplicative inverse.
    ///
    /// # Returns
    /// True if this element is invertible (coprime to modulus), false otherwise
    pub fn has_inverse(&self) -> bool {
        if self.value == 0 {
            return false;
        }
        let (gcd, _, _) = extended_gcd(self.value as i128, self.modulus as i128);
        gcd == 1
    }

    /// Calculate the multiplicative inverse if it exists.
    ///
    /// # Returns
    /// Some(inverse) if the inverse exists, None otherwise
    pub fn mod_inverse(&self) -> Option<u64> {
        if self.value == 0 {
            return None;
        }

        let (gcd, x, _) = extended_gcd(self.value as i128, self.modulus as i128);
        if gcd != 1 {
            return None; // Inverse doesn't exist if gcd != 1
        }

        // Make sure the result is positive and within the ring
        Some(((x % self.modulus as i128 + self.modulus as i128) % self.modulus as i128) as u64)
    }

    /// Division in the ring (only works if divisor has an inverse).
    ///
    /// # Arguments
    /// * `other` - The other ring element to divide by
    ///
    /// # Returns
    /// Some(quotient) if division is possible, None otherwise
    ///
    /// # Panics
    /// Panics if the rings have different moduli
    pub fn div(&self, other: &Ring) -> Option<Ring> {
        assert_eq!(
            self.modulus, other.modulus,
            "Rings must have the same modulus"
        );

        if other.value == 0 {
            return None; // Cannot divide by zero
        }

        match other.mod_inverse() {
            Some(inv) => {
                let result = (self.value as u128 * inv as u128) % (self.modulus as u128);
                Some(Ring::new(result as u64, self.modulus))
            }
            None => None, // Cannot divide when the divisor has no inverse
        }
    }

    /// Exponentiation using square-and-multiply algorithm (efficient).
    ///
    /// # Arguments
    /// * `n` - The exponent
    ///
    /// # Returns
    /// self^n in the ring
    pub fn pow(&self, n: u64) -> Ring {
        if n == 0 {
            return Ring::new(1, self.modulus);
        }

        let mut result = Ring::new(1, self.modulus);
        let mut base = *self;
        let mut exp = n;

        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(&base);
            }
            base = base.mul(&base);
            exp >>= 1;
        }

        result
    }

    /// Generate a random element in the ring.
    ///
    /// # Arguments
    /// * `modulus` - The modulus of the ring
    ///
    /// # Returns
    /// A random ring element
    pub fn random(modulus: u64) -> Ring {
        let mut rng = rand::rng();
        let value = rng.random_range(0..modulus);
        Ring::new(value, modulus)
    }

    /// Generate a random invertible element (for RSA purposes).
    ///
    /// # Arguments
    /// * `modulus` - The modulus of the ring
    ///
    /// # Returns
    /// A random invertible ring element
    pub fn random_invertible(modulus: u64) -> Ring {
        loop {
            let element = Self::random(modulus);
            if element.has_inverse() {
                return element;
            }
        }
    }

    /// Get the modulus of this ring.
    ///
    /// # Returns
    /// The modulus
    pub fn modulus(&self) -> u64 {
        self.modulus
    }

    /// Get the value of this ring element.
    ///
    /// # Returns
    /// The value
    pub fn value(&self) -> u64 {
        self.value
    }
}

impl Display for Ring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (mod {})", self.value, self.modulus)
    }
}

/// Generate a composite modulus (product of two primes) for RSA-like rings.
///
/// # Arguments
/// * `bit_size` - The bit size of the resulting modulus
///
/// # Returns
/// A tuple (p, q, n) where p and q are prime and n = p * q
pub fn generate_composite_modulus(bit_size: usize) -> (u64, u64, u64) {
    let mut rng = rand::rng();

    // Generate two distinct prime numbers
    let p = generate_prime_of_bitsize(bit_size / 2, &mut rng);
    let mut q = generate_prime_of_bitsize(bit_size / 2, &mut rng);

    // Ensure p and q are distinct
    while p == q {
        q = generate_prime_of_bitsize(bit_size / 2, &mut rng);
    }

    // Return the primes and their product
    (p, q, p * q)
}

/// Helper function to generate a prime of specified bit size.
///
/// # Arguments
/// * `bit_size` - The desired bit size
/// * `rng` - A random number generator
///
/// # Returns
/// A prime number with the specified bit size
pub fn generate_prime_of_bitsize(bit_size: usize, rng: &mut impl Rng) -> u64 {
    let min = 1u64 << (bit_size - 1);
    let max = (1u64 << bit_size) - 1;

    loop {
        let candidate = rng.random_range(min..=max);
        if is_prime(candidate) {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_creation() {
        let ring = Ring::new(15, 10);
        assert_eq!(ring.value(), 5); // 15 mod 10 = 5
        assert_eq!(ring.modulus(), 10);
    }

    #[test]
    fn test_ring_addition() {
        let a = Ring::new(7, 10);
        let b = Ring::new(5, 10);
        let sum = a.add(&b);
        assert_eq!(sum.value(), 2); // (7 + 5) mod 10 = 2
    }

    #[test]
    fn test_ring_subtraction() {
        let a = Ring::new(3, 10);
        let b = Ring::new(5, 10);
        let diff = a.sub(&b);
        assert_eq!(diff.value(), 8); // (3 - 5) mod 10 = 8
    }

    #[test]
    fn test_ring_multiplication() {
        let a = Ring::new(7, 10);
        let b = Ring::new(6, 10);
        let prod = a.mul(&b);
        assert_eq!(prod.value(), 2); // (7 * 6) mod 10 = 42 mod 10 = 2
    }

    #[test]
    fn test_ring_inverse() {
        let a = Ring::new(3, 10);
        let inv = a.mod_inverse();
        assert_eq!(inv, Some(7)); // 3 * 7 = 21 ≡ 1 (mod 10)

        let b = Ring::new(5, 10);
        assert!(b.mod_inverse().is_none()); // 5 has no inverse mod 10 (gcd(5,10) = 5)
    }

    #[test]
    fn test_ring_division() {
        let a = Ring::new(6, 7);
        let b = Ring::new(2, 7);
        let quot = a.div(&b).unwrap();
        assert_eq!(quot.value(), 3); // 6 / 2 = 3 in Z/7Z
    }

    #[test]
    fn test_ring_power() {
        let a = Ring::new(2, 10);
        let result = a.pow(3);
        assert_eq!(result.value(), 8); // 2^3 = 8

        let b = Ring::new(3, 10);
        let result2 = b.pow(2);
        assert_eq!(result2.value(), 9); // 3^2 = 9
    }

    #[test]
    fn test_has_inverse() {
        let a = Ring::new(3, 10);
        assert!(a.has_inverse()); // gcd(3, 10) = 1

        let b = Ring::new(5, 10);
        assert!(!b.has_inverse()); // gcd(5, 10) = 5
    }

    #[test]
    fn test_random_invertible() {
        let ring = Ring::random_invertible(17);
        assert!(ring.has_inverse());
        assert!(ring.value() > 0);
        assert!(ring.value() < 17);
    }

    #[test]
    fn test_generate_composite_modulus() {
        let (p, q, n) = generate_composite_modulus(16);
        assert_eq!(n, p * q);
        assert!(is_prime(p));
        assert!(is_prime(q));
        assert_ne!(p, q);
    }

    #[test]
    fn test_generate_prime_of_bitsize() {
        let mut rng = rand::rng();
        let prime = generate_prime_of_bitsize(8, &mut rng);
        assert!(is_prime(prime));
        assert!(prime >= 128); // 2^7
        assert!(prime < 256); // 2^8
    }
}
