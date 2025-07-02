//! Univariate polynomial arithmetic over finite fields.
//! 
//! This module provides efficient implementations of arithmetic operations
//! on univariate polynomials over finite fields.

use std::fmt::{Display, Formatter};
use crypto_core::{CryptoError, CryptoResult};
use crypto_field::FiniteField;

/// Represents a univariate polynomial over a finite field.
/// 
/// The polynomial is stored as a vector of coefficients in ascending order
/// of degree: a₀ + a₁x + a₂x² + ... + aₙxⁿ
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial {
    /// Coefficients in ascending order of degree
    coefficients: Vec<FiniteField>,
}

impl Polynomial {
    /// Create a new polynomial from coefficients.
    /// 
    /// # Arguments
    /// * `coefficients` - Vector of coefficients in ascending order of degree
    /// 
    /// # Returns
    /// A new polynomial
    pub fn new(coefficients: Vec<FiniteField>) -> CryptoResult<Self> {
        if coefficients.is_empty() {
            return Err(CryptoError::InvalidDegree(0));
        }
        
        // Ensure all coefficients have the same modulus
        let modulus = coefficients[0].modulus();
        for coeff in &coefficients {
            if coeff.modulus() != modulus {
                return Err(CryptoError::InvalidFieldElement(
                    "All coefficients must belong to the same field".to_string()
                ));
            }
        }
        
        Ok(Self { coefficients })
    }
    
    /// Create a zero polynomial of given degree.
    /// 
    /// # Arguments
    /// * `degree` - The degree of the polynomial
    /// * `modulus` - The modulus of the field
    /// 
    /// # Returns
    /// A zero polynomial of the specified degree
    pub fn zero(degree: usize, modulus: u64) -> CryptoResult<Self> {
        if degree == 0 {
            return Err(CryptoError::InvalidDegree(0));
        }
        
        let coefficients = vec![FiniteField::new(0, modulus)?; degree + 1];
        Self::new(coefficients)
    }
    
    /// Get the coefficients of this polynomial.
    pub fn coefficients(&self) -> &[FiniteField] {
        &self.coefficients
    }
    
    /// Get the degree of this polynomial.
    pub fn degree(&self) -> usize {
        self.coefficients.len() - 1
    }
    
    /// Get the modulus of the field this polynomial is defined over.
    pub fn modulus(&self) -> u64 {
        self.coefficients[0].modulus()
    }
    
    /// Evaluate the polynomial at a given point.
    /// 
    /// # Arguments
    /// * `point` - The point to evaluate at
    /// 
    /// # Returns
    /// The value of the polynomial at the given point
    pub fn evaluate(&self, point: &FiniteField) -> CryptoResult<FiniteField> {
        if point.modulus() != self.modulus() {
            return Err(CryptoError::InvalidFieldElement(
                "Point must belong to the same field as the polynomial".to_string()
            ));
        }
        
        let mut result = self.coefficients[0];
        let mut power = FiniteField::new(1, self.modulus())?;
        
        for i in 1..self.coefficients.len() {
            power = power.mul(point)?;
            result = result.add(&self.coefficients[i].mul(&power)?)?;
        }
        
        Ok(result)
    }
    
    /// Add another polynomial to this one.
    /// 
    /// # Arguments
    /// * `other` - The polynomial to add
    /// 
    /// # Returns
    /// The sum of the two polynomials
    /// 
    /// # Errors
    /// Returns an error if the polynomials are over different fields
    pub fn add(&self, other: &Self) -> CryptoResult<Self> {
        if self.modulus() != other.modulus() {
            return Err(CryptoError::InvalidFieldElement(
                "Cannot add polynomials over different fields".to_string()
            ));
        }
        
        let max_len = std::cmp::max(self.coefficients.len(), other.coefficients.len());
        let mut result_coeffs = Vec::with_capacity(max_len);
        
        for i in 0..max_len {
            let coeff1 = if i < self.coefficients.len() {
                self.coefficients[i]
            } else {
                FiniteField::new(0, self.modulus())?
            };
            
            let coeff2 = if i < other.coefficients.len() {
                other.coefficients[i]
            } else {
                FiniteField::new(0, other.modulus())?
            };
            
            result_coeffs.push(coeff1.add(&coeff2)?);
        }
        
        Self::new(result_coeffs)
    }
    
    /// Multiply this polynomial by another.
    /// 
    /// # Arguments
    /// * `other` - The polynomial to multiply by
    /// 
    /// # Returns
    /// The product of the two polynomials
    /// 
    /// # Errors
    /// Returns an error if the polynomials are over different fields
    pub fn mul(&self, other: &Self) -> CryptoResult<Self> {
        if self.modulus() != other.modulus() {
            return Err(CryptoError::InvalidFieldElement(
                "Cannot multiply polynomials over different fields".to_string()
            ));
        }
        
        let result_degree = self.degree() + other.degree();
        let mut result_coeffs = vec![FiniteField::new(0, self.modulus())?; result_degree + 1];
        
        for i in 0..self.coefficients.len() {
            for j in 0..other.coefficients.len() {
                let product = self.coefficients[i].mul(&other.coefficients[j])?;
                result_coeffs[i + j] = result_coeffs[i + j].add(&product)?;
            }
        }
        
        Self::new(result_coeffs)
    }
    
    /// Multiply this polynomial by a scalar.
    /// 
    /// # Arguments
    /// * `scalar` - The scalar to multiply by
    /// 
    /// # Returns
    /// The polynomial multiplied by the scalar
    /// 
    /// # Errors
    /// Returns an error if the scalar belongs to a different field
    pub fn scalar_mul(&self, scalar: &FiniteField) -> CryptoResult<Self> {
        if scalar.modulus() != self.modulus() {
            return Err(CryptoError::InvalidFieldElement(
                "Scalar must belong to the same field as the polynomial".to_string()
            ));
        }
        
        let result_coeffs: CryptoResult<Vec<_>> = self.coefficients
            .iter()
            .map(|coeff| coeff.mul(scalar))
            .collect();
        
        Self::new(result_coeffs?)
    }
    
    /// Compute the derivative of this polynomial.
    /// 
    /// # Returns
    /// The derivative polynomial
    pub fn derivative(&self) -> CryptoResult<Self> {
        if self.coefficients.len() <= 1 {
            return Self::zero(0, self.modulus());
        }
        
        let mut deriv_coeffs = Vec::with_capacity(self.coefficients.len() - 1);
        
        for (i, coeff) in self.coefficients.iter().skip(1).enumerate() {
            let degree = i + 1;
            let deriv_coeff = coeff.mul(&FiniteField::new(degree as u64, self.modulus())?)?;
            deriv_coeffs.push(deriv_coeff);
        }
        
        Self::new(deriv_coeffs)
    }
    
    /// Check if this polynomial is the zero polynomial.
    pub fn is_zero(&self) -> bool {
        self.coefficients.iter().all(|coeff| coeff.value() == 0)
    }
    
    /// Remove leading zero coefficients to normalize the polynomial.
    pub fn normalize(&mut self) {
        while self.coefficients.len() > 1 && self.coefficients.last().unwrap().value() == 0 {
            self.coefficients.pop();
        }
    }
}

impl Display for Polynomial {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.is_zero() {
            return write!(f, "0");
        }
        
        let mut terms = Vec::new();
        
        for (i, coeff) in self.coefficients.iter().enumerate() {
            if coeff.value() == 0 {
                continue;
            }
            
            let term = if i == 0 {
                format!("{}", coeff)
            } else if i == 1 {
                if coeff.value() == 1 {
                    "x".to_string()
                } else {
                    format!("{}x", coeff)
                }
            } else {
                if coeff.value() == 1 {
                    format!("x^{}", i)
                } else {
                    format!("{}x^{}", coeff, i)
                }
            };
            
            terms.push(term);
        }
        
        if terms.is_empty() {
            write!(f, "0")
        } else {
            write!(f, "{}", terms.join(" + "))
        }
    }
}

impl std::ops::Add for Polynomial {
    type Output = CryptoResult<Self>;
    
    fn add(self, other: Self) -> Self::Output {
        Polynomial::add(&self,&other)
    }
}

impl std::ops::Mul for Polynomial {
    type Output = CryptoResult<Self>;
    
    fn mul(self, other: Self) -> Self::Output {
        Polynomial::mul(&self,&other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_creation() {
        let coeffs = vec![
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(2, 7).unwrap(),
            FiniteField::new(3, 7).unwrap(),
        ];
        let poly = Polynomial::new(coeffs).unwrap();
        assert_eq!(poly.degree(), 2);
        assert_eq!(poly.modulus(), 7);
    }

    #[test]
    fn test_polynomial_evaluation() {
        let coeffs = vec![
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(2, 7).unwrap(),
            FiniteField::new(1, 7).unwrap(),
        ];
        let poly = Polynomial::new(coeffs).unwrap();
        let point = FiniteField::new(2, 7).unwrap();
        let result = poly.evaluate(&point).unwrap();
        assert_eq!(result.value(), 1); // 1 + 2*2 + 1*4 = 1 + 4 + 4 = 9 ≡ 2 (mod 7)
    }

    #[test]
    fn test_polynomial_addition() {
        let coeffs1 = vec![
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(2, 7).unwrap(),
        ];
        let coeffs2 = vec![
            FiniteField::new(3, 7).unwrap(),
            FiniteField::new(4, 7).unwrap(),
        ];
        let poly1 = Polynomial::new(coeffs1).unwrap();
        let poly2 = Polynomial::new(coeffs2).unwrap();
        let sum = poly1.add(&poly2).unwrap();
        assert_eq!(sum.coefficients()[0].value(), 4); // 1 + 3 = 4
        assert_eq!(sum.coefficients()[1].value(), 6); // 2 + 4 = 6
    }

    #[test]
    fn test_polynomial_multiplication() {
        let coeffs1 = vec![
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(1, 7).unwrap(),
        ];
        let coeffs2 = vec![
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(1, 7).unwrap(),
        ];
        let poly1 = Polynomial::new(coeffs1).unwrap();
        let poly2 = Polynomial::new(coeffs2).unwrap();
        let product = poly1.mul(&poly2).unwrap();
        assert_eq!(product.coefficients()[0].value(), 1); // 1 * 1 = 1
        assert_eq!(product.coefficients()[1].value(), 2); // 1 * 1 + 1 * 1 = 2
        assert_eq!(product.coefficients()[2].value(), 1); // 1 * 1 = 1
    }
} 