//! Ring arithmetic for cryptographic operations.
//! 
//! This module provides implementations of arithmetic operations
//! in rings, particularly useful for RSA-like operations.

use std::fmt::{Display, Formatter};
use crypto_core::{CryptoError, CryptoResult, generate_random_prime};
use rand::Rng;

/// Represents an element in a ring with composite modulus.
/// 
/// This is particularly useful for RSA-like operations where
/// the modulus is the product of two primes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ring {
    /// The value of the ring element
    value: u64,
    /// The composite modulus defining the ring
    modulus: u64,
}

impl Ring {
    /// Create a new ring element.
    /// 
    /// # Arguments
    /// * `value` - The value of the element
    /// * `modulus` - The composite modulus defining the ring
    /// 
    /// # Returns
    /// A new ring element with the value reduced modulo the modulus
    pub fn new(value: u64, modulus: u64) -> CryptoResult<Self> {
        if modulus == 0 {
            return Err(CryptoError::InvalidModulus(0));
        }
        
        Ok(Self {
            value: value % modulus,
            modulus,
        })
    }
    
    /// Get the value of this ring element.
    pub fn value(&self) -> u64 {
        self.value
    }
    
    /// Get the modulus of this ring.
    pub fn modulus(&self) -> u64 {
        self.modulus
    }
    
    /// Add two ring elements.
    /// 
    /// # Arguments
    /// * `other` - The ring element to add
    /// 
    /// # Returns
    /// The sum of the two elements
    /// 
    /// # Errors
    /// Returns an error if the elements belong to different rings
    pub fn add(&self, other: &Self) -> CryptoResult<Self> {
        if self.modulus != other.modulus {
            return Err(CryptoError::MatrixError(
                "Cannot add elements from different rings".to_string()
            ));
        }
        
        let sum = (self.value + other.value) % self.modulus;
        Ok(Self::new(sum, self.modulus)?)
    }
    
    /// Subtract another ring element from this one.
    /// 
    /// # Arguments
    /// * `other` - The ring element to subtract
    /// 
    /// # Returns
    /// The difference of the two elements
    /// 
    /// # Errors
    /// Returns an error if the elements belong to different rings
    pub fn sub(&self, other: &Self) -> CryptoResult<Self> {
        if self.modulus != other.modulus {
            return Err(CryptoError::MatrixError(
                "Cannot subtract elements from different rings".to_string()
            ));
        }
        
        let diff = if self.value >= other.value {
            self.value - other.value
        } else {
            self.modulus - other.value + self.value
        };
        
        Ok(Self::new(diff, self.modulus)?)
    }
    
    /// Multiply this ring element by another.
    /// 
    /// # Arguments
    /// * `other` - The ring element to multiply by
    /// 
    /// # Returns
    /// The product of the two elements
    /// 
    /// # Errors
    /// Returns an error if the elements belong to different rings
    pub fn mul(&self, other: &Self) -> CryptoResult<Self> {
        if self.modulus != other.modulus {
            return Err(CryptoError::MatrixError(
                "Cannot multiply elements from different rings".to_string()
            ));
        }
        
        let product = ((self.value as u128) * (other.value as u128)) % (self.modulus as u128);
        Ok(Self::new(product as u64, self.modulus)?)
    }
    
    /// Check if this element has a multiplicative inverse.
    /// 
    /// # Returns
    /// True if the element has an inverse, false otherwise
    pub fn has_inverse(&self) -> bool {
        if self.value == 0 {
            return false;
        }
        
        let (gcd, _, _) = crypto_core::extended_gcd(self.value as i128, self.modulus as i128);
        gcd == 1
    }
    
    /// Compute the multiplicative inverse of this element.
    /// 
    /// # Returns
    /// The multiplicative inverse if it exists
    /// 
    /// # Errors
    /// Returns an error if the element has no inverse
    pub fn inverse(&self) -> CryptoResult<u64> {
        if self.value == 0 {
            return Err(CryptoError::DivisionByZero);
        }
        
        let (gcd, x, _) = crypto_core::extended_gcd(self.value as i128, self.modulus as i128);
        
        if gcd != 1 {
            return Err(CryptoError::NoInverse(self.value, self.modulus));
        }
        
        let inv = ((x % self.modulus as i128 + self.modulus as i128) % self.modulus as i128) as u64;
        Ok(inv)
    }
    
    /// Divide this ring element by another.
    /// 
    /// # Arguments
    /// * `other` - The ring element to divide by
    /// 
    /// # Returns
    /// The quotient of the division
    /// 
    /// # Errors
    /// Returns an error if the divisor has no inverse or if the elements belong to different rings
    pub fn div(&self, other: &Self) -> CryptoResult<Self> {
        if self.modulus != other.modulus {
            return Err(CryptoError::MatrixError(
                "Cannot divide elements from different rings".to_string()
            ));
        }
        
        let inv = other.inverse()?;
        let quotient = ((self.value as u128) * (inv as u128)) % (self.modulus as u128);
        Ok(Self::new(quotient as u64, self.modulus)?)
    }
    
    /// Raise this ring element to a power.
    /// 
    /// # Arguments
    /// * `exponent` - The exponent to raise to
    /// 
    /// # Returns
    /// The result of the exponentiation
    pub fn pow(&self, mut exponent: u64) -> CryptoResult<Self> {
        if exponent == 0 {
            return Ok(Self::new(1, self.modulus)?);
        }
        
        let mut base = *self;
        let mut result = Self::new(1, self.modulus)?;
        
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = result.mul(&base)?;
            }
            base = base.mul(&base)?;
            exponent >>= 1;
        }
        
        Ok(result)
    }
    
    /// Generate a random ring element.
    /// 
    /// # Arguments
    /// * `modulus` - The composite modulus defining the ring
    /// 
    /// # Returns
    /// A random ring element
    pub fn random(modulus: u64) -> CryptoResult<Self> {
        let mut rng = rand::thread_rng();
        let value = rng.gen_range(0..modulus);
        Self::new(value, modulus)
    }
    
    /// Generate a random invertible ring element.
    /// 
    /// # Arguments
    /// * `modulus` - The composite modulus defining the ring
    /// 
    /// # Returns
    /// A random invertible ring element
    pub fn random_invertible(modulus: u64) -> CryptoResult<Self> {
        let mut rng = rand::thread_rng();
        
        for _ in 0..1000 {
            let value = rng.gen_range(1..modulus);
            let element = Self::new(value, modulus)?;
            if element.has_inverse() {
                return Ok(element);
            }
        }
        
        Err(CryptoError::RandomError("Failed to generate invertible element".to_string()))
    }
}

impl Display for Ring {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (mod {})", self.value, self.modulus)
    }
}

impl std::ops::Add for Ring {
    type Output = CryptoResult<Self>;
    
    fn add(self, other: Self) -> Self::Output {
        self.add(&other)
    }
}

impl std::ops::Sub for Ring {
    type Output = CryptoResult<Self>;
    
    fn sub(self, other: Self) -> Self::Output {
        self.sub(&other)
    }
}

impl std::ops::Mul for Ring {
    type Output = CryptoResult<Self>;
    
    fn mul(self, other: Self) -> Self::Output {
        self.mul(&other)
    }
}

impl std::ops::Div for Ring {
    type Output = CryptoResult<Self>;
    
    fn div(self, other: Self) -> Self::Output {
        self.div(&other)
    }
}

/// Generate a composite modulus for RSA-like operations.
/// 
/// # Arguments
/// * `bit_size` - The desired bit size of the composite modulus
/// 
/// # Returns
/// A tuple of (p, q, n) where p and q are primes and n = p * q
pub fn generate_composite_modulus(bit_size: usize) -> CryptoResult<(u64, u64, u64)> {
    if bit_size < 2 {
        return Err(CryptoError::InvalidModulus(0));
    }
    
    let mut rng = rand::thread_rng();
    let half_bits = bit_size / 2;
    
    // Generate two distinct prime numbers
    let p = generate_prime_of_bitsize(half_bits, &mut rng)?;
    let mut q = generate_prime_of_bitsize(half_bits, &mut rng)?;
    
    // Ensure p and q are distinct
    while p == q {
        q = generate_prime_of_bitsize(half_bits, &mut rng)?;
    }
    
    let n = p * q;
    Ok((p, q, n))
}

/// Generate a prime number of specified bit size.
/// 
/// # Arguments
/// * `bit_size` - The desired bit size of the prime
/// * `rng` - Random number generator
/// 
/// # Returns
/// A prime number with the specified bit size
fn generate_prime_of_bitsize(bit_size: usize, rng: &mut impl Rng) -> CryptoResult<u64> {
    if bit_size == 0 || bit_size > 64 {
        return Err(CryptoError::InvalidModulus(0));
    }
    
    let min = 1u64 << (bit_size - 1);
    let max = (1u64 << bit_size) - 1;
    
    // Try a reasonable number of attempts
    for _ in 0..1000 {
        let candidate = rng.gen_range(min..=max);
        if crypto_core::is_prime(candidate) {
            return Ok(candidate);
        }
    }
    
    Err(CryptoError::RandomError("Failed to generate prime number".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_creation() {
        let ring = Ring::new(5, 15).unwrap();
        assert_eq!(ring.value(), 5);
        assert_eq!(ring.modulus(), 15);
    }

    #[test]
    fn test_ring_arithmetic() {
        let a = Ring::new(7, 15).unwrap();
        let b = Ring::new(3, 15).unwrap();
        
        assert_eq!(a.add(&b).unwrap().value(), 10); // 7 + 3 = 10 (mod 15)
        assert_eq!(a.sub(&b).unwrap().value(), 4);  // 7 - 3 = 4 (mod 15)
        assert_eq!(a.mul(&b).unwrap().value(), 6);  // 7 * 3 = 21 ≡ 6 (mod 15)
    }

    #[test]
    fn test_ring_power() {
        let ring = Ring::new(2, 15).unwrap();
        assert_eq!(ring.pow(4).unwrap().value(), 1); // 2^4 = 16 ≡ 1 (mod 15)
    }

    #[test]
    fn test_ring_inverse() {
        let ring = Ring::new(7, 15).unwrap();
        assert!(ring.has_inverse());
        let inv = ring.inverse().unwrap();
        assert_eq!((ring.value * inv) % ring.modulus, 1);
    }

    #[test]
    fn test_composite_modulus_generation() {
        let (p, q, n) = generate_composite_modulus(16).unwrap();
        assert!(crypto_core::is_prime(p));
        assert!(crypto_core::is_prime(q));
        assert_eq!(n, p * q);
        assert_ne!(p, q);
    }
} 