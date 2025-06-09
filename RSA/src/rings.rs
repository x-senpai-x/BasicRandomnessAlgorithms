use rand::{Rng, rng};
use rs_encoding::{prime_field::FiniteField,utils::{extended_gcd,is_prime}};
use std::{fmt::Display, u64};

// Define a generic Ring structure to represent elements in a ring
#[derive(Debug, Clone, Copy)]
pub struct Ring {
    pub value: u64,
    pub modulus: u64
}

// Generate a composite modulus (product of two primes) for RSA-like rings
pub fn generate_composite_modulus(bit_size: usize) -> (u64, u64, u64) {
    let mut rng = rng();
    
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

// Helper function to generate a prime of specified bit size
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

impl Ring {
    // Create a new ring element with value reduced modulo the modulus
    pub fn new(value: u64, modulus: u64) -> Ring {
        Ring { value: value % modulus, modulus }
    }
    
    // Addition in the ring
    pub fn add(&self, other: &Ring) -> Ring {
        assert_eq!(self.modulus, other.modulus, "Rings must have the same modulus");
        Ring::new((self.value + other.value) % self.modulus, self.modulus)
    }
    
    // Subtraction in the ring
    pub fn sub(&self, other: &Ring) -> Ring {
        assert_eq!(self.modulus, other.modulus, "Rings must have the same modulus");
        let result = if self.value < other.value {
            self.modulus - other.value + self.value
        } else {
            self.value - other.value
        };
        Ring::new(result % self.modulus, self.modulus)
    }
    
    // Multiplication in the ring
    pub fn mul(&self, other: &Ring) -> Ring {
        assert_eq!(self.modulus, other.modulus, "Rings must have the same modulus");
        let result = (self.value as u128) * (other.value as u128) % (self.modulus as u128);
        Ring::new(result as u64, self.modulus)
    }
    
    // Check if this element has a multiplicative inverse
    pub fn has_inverse(&self) -> bool {
        if self.value == 0 {
            return false;
        }
        let (gcd, _, _) = extended_gcd(self.value as i128, self.modulus as i128);
        gcd == 1
    }
    
    // Calculate the multiplicative inverse if it exists
    pub fn mod_inverse(&self) -> Option<u64> {
        if self.value == 0 {
            return None;
        }
        
        let (gcd, x, _) = extended_gcd(self.value as i128, self.modulus as i128);
        if gcd != 1 {
            return None;  // Inverse doesn't exist if gcd != 1
        }
        
        // Make sure the result is positive and within the ring
        Some(((x % self.modulus as i128 + self.modulus as i128) % self.modulus as i128) as u64)
    }
    
    // Division in the ring (only works if divisor has an inverse)
    pub fn div(&self, other: &Ring) -> Option<Ring> {
        assert_eq!(self.modulus, other.modulus, "Rings must have the same modulus");
        
        if other.value == 0 {
            return None; // Cannot divide by zero
        }
        
        match other.mod_inverse() {
            Some(inv) => {
                let result = (self.value as u128 * inv as u128) % (self.modulus as u128);
                Some(Ring::new(result as u64, self.modulus))
            },
            None => None  // Cannot divide when the divisor has no inverse
        }
    }
    
    // Exponentiation using square-and-multiply algorithm (efficient)
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
    
    // Generate a random element in the ring
    pub fn random(modulus: u64) -> Ring {
        let mut rng = rng();
        let value = rng.random_range(0..modulus);
        Ring::new(value, modulus)
    }
    
    // Generate a random invertible element (for RSA purposes)
    pub fn random_invertible(modulus: u64) -> Ring {
        loop {
            let element = Self::random(modulus);
            if element.has_inverse() {
                return element;
            }
        }
    }
    
    // Get the modulus
    pub fn modulus(&self) -> u64 {
        self.modulus
    }
}
