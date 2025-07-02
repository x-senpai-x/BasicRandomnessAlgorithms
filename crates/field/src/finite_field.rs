//! Finite field arithmetic over prime fields.
//! 
//! This module provides efficient implementations of arithmetic operations
//! in finite fields of prime order.

use std::fmt::{Display, Formatter};
use crypto_core::prelude::*;
// use crypto_core::{CryptoError, CryptoResult,generate_random_prime};
use rand::Rng;

/// Represents an element in a finite field of prime order.
/// 
/// The field is defined by a prime modulus p, and all arithmetic
/// operations are performed modulo p.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiniteField {
    /// The value of the field element
    value: u64,
    /// The prime modulus defining the field
    modulus: u64,
}

impl FiniteField {
    /// Create a new finite field element.
    /// 
    /// # Arguments
    /// * `value` - The value of the element
    /// * `modulus` - The prime modulus defining the field
    /// 
    /// # Returns
    /// A new finite field element with the value reduced modulo the modulus
    pub fn new(value: u64, modulus: u64) -> CryptoResult<Self> {
        if modulus == 0 {
            return Err(CryptoError::InvalidModulus(0));
        }
        
        Ok(Self {
            value: value % modulus,
            modulus,
        })
    }
    
    /// Create a new finite field element with a random prime modulus.
    /// 
    /// # Arguments
    /// * `value` - The value of the element
    /// 
    /// # Returns
    /// A new finite field element with a randomly generated prime modulus
    pub fn new_with_random_modulus(value: u64) -> CryptoResult<Self> {
        let modulus = generate_random_prime(32)?; // 32-bit prime
        Self::new(value, modulus)
    }
    
    /// Get the value of this field element.
    pub fn value(&self) -> u64 {
        self.value
    }
    
    /// Get the modulus of this field.
    pub fn modulus(&self) -> u64 {
        self.modulus
    }
    
    /// Add two field elements.
    /// 
    /// # Arguments
    /// * `other` - The field element to add
    /// 
    /// # Returns
    /// The sum of the two elements
    /// 
    /// # Errors
    /// Returns an error if the elements belong to different fields
    pub fn add(&self, other: &Self) -> CryptoResult<Self> {
        if self.modulus != other.modulus {
            return Err(CryptoError::InvalidFieldElement(
                "Cannot add elements from different fields".to_string()
            ));
        }
        let sum = (self.value + other.value) % self.modulus;
        Ok(Self::new(sum, self.modulus)?)
    }
    
    /// Subtract another field element from this one.
    /// 
    /// # Arguments
    /// * `other` - The field element to subtract
    /// 
    /// # Returns
    /// The difference of the two elements
    /// 
    /// # Errors
    /// Returns an error if the elements belong to different fields
    pub fn sub(&self, other: &Self) -> CryptoResult<Self> {
        if self.modulus != other.modulus {
            return Err(CryptoError::InvalidFieldElement(
                "Cannot subtract elements from different fields".to_string()
            ));
        }
        
        let diff = if self.value >= other.value {
            self.value - other.value
        } else {
            self.modulus - other.value + self.value
        };
        
        Ok(Self::new(diff, self.modulus)?)
    }
    
    /// Multiply this field element by another.
    /// 
    /// # Arguments
    /// * `other` - The field element to multiply by
    /// 
    /// # Returns
    /// The product of the two elements
    /// 
    /// # Errors
    /// Returns an error if the elements belong to different fields
    pub fn mul(&self, other: &Self) -> CryptoResult<Self> {
        if self.modulus != other.modulus {
            return Err(CryptoError::InvalidFieldElement(
                "Cannot multiply elements from different fields".to_string()
            ));
        }
        
        let product = ((self.value as u128) * (other.value as u128)) % (self.modulus as u128);
        Ok(Self::new(product as u64, self.modulus)?)
    }
    
    /// Multiply this field element by a binary value (0 or 1).
    /// 
    /// # Arguments
    /// * `bit` - The binary value to multiply by
    /// 
    /// # Returns
    /// The product (0 if bit is 0, self if bit is 1)
    pub fn mul_binary(&self, bit: u8) -> CryptoResult<Self> {
        match bit {
            0 => Ok(Self::new(0, self.modulus)?),
            1 => Ok(*self),
            _ => Err(CryptoError::InvalidFieldElement(
                "Binary multiplication only supports 0 and 1".to_string()
            )),
        }
    }
    
    /// Compute the multiplicative inverse of this element.
    /// 
    /// # Returns
    /// The multiplicative inverse if it exists
    /// 
    /// # Errors
    /// Returns an error if the element is zero (no inverse exists)
    pub fn inverse(&self) -> CryptoResult<Self> {
        if self.value == 0 {
            return Err(CryptoError::DivisionByZero);
        }
        
        let inv = self.mod_inverse()?;
        Ok(Self::new(inv, self.modulus)?)
    }
    
    /// Divide this field element by another.
    /// 
    /// # Arguments
    /// * `other` - The field element to divide by
    /// 
    /// # Returns
    /// The quotient of the division
    /// 
    /// # Errors
    /// Returns an error if the divisor is zero or if the elements belong to different fields
    pub fn div(&self, other: &Self) -> CryptoResult<Self> {
        if other.value == 0 {
            return Err(CryptoError::DivisionByZero);
        }
        
        if self.modulus != other.modulus {
            return Err(CryptoError::InvalidFieldElement(
                "Cannot divide elements from different fields".to_string()
            ));
        }
        
        let inv = other.mod_inverse()?;
        let quotient = ((self.value as u128) * (inv as u128)) % (self.modulus as u128);
        Ok(Self::new(quotient as u64, self.modulus)?)
    }
    
    /// Raise this field element to a power.
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
            if exponent % 2 == 1 {
                result = result.mul(&base)?;
            }
            base = base.mul(&base)?;
            exponent /= 2;
        }
        
        Ok(result)
    }
    
    /// Generate a random field element.
    /// 
    /// # Arguments
    /// * `modulus` - The prime modulus defining the field
    /// 
    /// # Returns
    /// A random field element
    pub fn random(modulus: u64) -> CryptoResult<Self> {
        let mut rng = rand::rng();
        let value = rng.random_range(0..modulus);
        Self::new(value, modulus)
    }
    
    /// Generate a random non-zero field element.
    /// 
    /// # Arguments
    /// * `modulus` - The prime modulus defining the field
    /// 
    /// # Returns
    /// A random non-zero field element
    pub fn random_nonzero(modulus: u64) -> CryptoResult<Self> {
        let mut rng = rand::rng();
        let value = rng.random_range(1..modulus);
        Self::new(value, modulus)
    }
    
    /// Generate a vector of random field elements.
    /// 
    /// # Arguments
    /// * `count` - Number of elements to generate
    /// * `modulus` - The prime modulus defining the field
    /// 
    /// # Returns
    /// A vector of random field elements
    pub fn random_vector(count: usize, modulus: u64) -> CryptoResult<Vec<Self>> {
        let values = generate_random_numbers(count, modulus);
        values.into_iter().map(|v| Self::new(v, modulus)).collect()
    }
    
    /// Generate the boolean hypercube in this field.
    /// 
    /// # Arguments
    /// * `dimension` - The dimension of the hypercube
    /// 
    /// # Returns
    /// A vector of vectors representing the boolean hypercube
    pub fn boolean_hypercube(&self, dimension: usize) -> Vec<Vec<Self>> {
        let mut cube = Vec::new();
        for i in 0..(1 << dimension) {
            let mut point = Vec::with_capacity(dimension);
            for j in 0..dimension {
                let bit = ((i >> (dimension - 1 - j)) & 1) as u64;
                point.push(Self::new(bit, self.modulus).unwrap());
            }
            cube.push(point);
        }
        cube
    }
    
    /// Generate the multiplicative group of this field.
    /// 
    /// # Returns
    /// A vector containing all non-zero field elements
    pub fn multiplicative_group(&self) -> Vec<Self> {
        (1..self.modulus).map(|i| Self::new(i, self.modulus).unwrap()).collect()
    }
    
    /// Find a generator of a multiplicative subgroup of given order.
    /// 
    /// # Arguments
    /// * `order` - The order of the subgroup
    /// 
    /// # Returns
    /// A generator of the subgroup if it exists
    pub fn find_generator(&self, order: u64) -> Option<Self> {
        if (self.modulus - 1) % order != 0 {
            return None;
        }
        
        let factors = crypto_core::prime_factors(order);
        
        for gen in 2..self.modulus {
            let generator = Self::new(gen, self.modulus).unwrap();
            if generator.pow(order).unwrap().value != 1 {
                continue;
            }
            
            let mut is_generator = true;
            for &factor in &factors {
                if generator.pow(order / factor).unwrap().value == 1 {
                    is_generator = false;
                    break;
                }
            }
            
            if is_generator {
                return Some(generator);
            }
        }
        
        None
    }
    
    /// Generate a multiplicative subgroup of given order.
    /// 
    /// # Arguments
    /// * `order` - The order of the subgroup
    /// 
    /// # Returns
    /// A vector containing the elements of the subgroup
    pub fn multiplicative_subgroup(&self, order: u64) -> Option<Vec<Self>> {
        let generator = self.find_generator(order)?;
        let mut subgroup = vec![Self::new(1, self.modulus).unwrap(); order as usize];
        
        for i in 1..order as usize {
            subgroup[i] = subgroup[i - 1].mul(&generator).unwrap();
        }
        
        Some(subgroup)
    }
    
    /// Compute the modular inverse using extended Euclidean algorithm.
    fn mod_inverse(&self) -> CryptoResult<u64> {
        let (gcd, x, _) = crypto_core::extended_gcd(self.value as i128, self.modulus as i128);
        
        if gcd != 1 {
            return Err(CryptoError::NoInverse(self.value, self.modulus));
        }
        
        let inv = ((x % self.modulus as i128 + self.modulus as i128) % self.modulus as i128) as u64;
        Ok(inv)
    }
}

impl Display for FiniteField {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (mod {})", self.value, self.modulus)
    }
}
//Operator overloading 
impl std::ops::Add for FiniteField {
    type Output = CryptoResult<Self>;
    
    fn add(self, other: Self) -> Self::Output {
        FiniteField::add(&self, &other)
    }
}

impl std::ops::Sub for FiniteField {
    type Output = CryptoResult<Self>;
    
    fn sub(self, other: Self) -> Self::Output {
        FiniteField::sub(&self, &other)
    }
}

impl std::ops::Mul for FiniteField {
    type Output = CryptoResult<Self>;
    
    fn mul(self, other: Self) -> Self::Output {
        FiniteField::mul(&self, &other)
    }
}

impl std::ops::Div for FiniteField {
    type Output = CryptoResult<Self>;
    
    fn div(self, other: Self) -> Self::Output {
        FiniteField::div(&self, &other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finite_field_creation() {
        let field = FiniteField::new(5, 7).unwrap();
        assert_eq!(field.value(), 5);
        assert_eq!(field.modulus(), 7);
    }

    #[test]
    fn test_finite_field_arithmetic() {
        let a = FiniteField::new(5, 7).unwrap();
        let b = FiniteField::new(3, 7).unwrap();
        
        assert_eq!(a.add(&b).unwrap().value(), 1); // 5 + 3 = 8 ≡ 1 (mod 7)
        assert_eq!(a.sub(&b).unwrap().value(), 2); // 5 - 3 = 2 (mod 7)
        assert_eq!(a.mul(&b).unwrap().value(), 1); // 5 * 3 = 15 ≡ 1 (mod 7)
        assert_eq!(a.div(&b).unwrap().value(), 4); // 5 / 3 = 5 * 3^(-1) = 5 * 5 = 25 ≡ 4 (mod 7)
    }

    #[test]
    fn test_finite_field_power() {
        let field = FiniteField::new(2, 7).unwrap();
        assert_eq!(field.pow(3).unwrap().value(), 1); // 2^3 = 8 ≡ 1 (mod 7)
    }

    #[test]
    fn test_finite_field_inverse() {
        let field = FiniteField::new(3, 7).unwrap();
        let inv = field.inverse().unwrap();
        assert_eq!(inv.value(), 5); // 3 * 5 = 15 ≡ 1 (mod 7)
    }

    #[test]
    fn test_boolean_hypercube() {
        let field = FiniteField::new(0, 7).unwrap();
        let cube = field.boolean_hypercube(2);
        assert_eq!(cube.len(), 4);
        assert_eq!(cube[0], vec![FiniteField::new(0, 7).unwrap(), FiniteField::new(0, 7).unwrap()]);
        assert_eq!(cube[1], vec![FiniteField::new(0, 7).unwrap(), FiniteField::new(1, 7).unwrap()]);
        assert_eq!(cube[2], vec![FiniteField::new(1, 7).unwrap(), FiniteField::new(0, 7).unwrap()]);
        assert_eq!(cube[3], vec![FiniteField::new(1, 7).unwrap(), FiniteField::new(1, 7).unwrap()]);
    }
    #[test]
    fn test_multiplication_large_numbers() {
        let modulus = 17;
        let a = FiniteField::new(u64::MAX - 2, modulus).unwrap();
        let b = FiniteField::new(u64::MAX - 1, modulus).unwrap();
        let result = (a*b).unwrap();
        assert_eq!(
        result.value,
            (((u64::MAX - 2) as u128) * ((u64::MAX - 1) as u128) % (modulus as u128)) as u64
        );
    }    
} 