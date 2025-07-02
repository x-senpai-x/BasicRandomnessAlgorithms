//! Multivariate polynomial arithmetic over finite fields.
//! 
//! This module provides implementations of arithmetic operations
//! on multivariate polynomials over finite fields.

use crypto_core::{CryptoError, CryptoResult};
use crypto_field::FiniteField;

/// Represents a term in a multivariate polynomial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Term {
    /// The coefficient of the term
    pub coefficient: FiniteField,
    /// The degrees of each variable (e.g., [2, 1, 0] means x₁²x₂)
    pub degrees: Vec<usize>,
}

impl Term {
    /// Create a new term.
    /// 
    /// # Arguments
    /// * `coefficient` - The coefficient of the term
    /// * `degrees` - The degrees of each variable
    /// 
    /// # Returns
    /// A new term
    pub fn new(coefficient: FiniteField, degrees: Vec<usize>) -> Self {
        Self { coefficient, degrees }
    }
    
    /// Get the total degree of this term.
    pub fn total_degree(&self) -> usize {
        self.degrees.iter().sum()
    }
    
    /// Get the degree of a specific variable.
    /// 
    /// # Arguments
    /// * `variable` - The index of the variable(0,1,2,...)
    /// 
    /// # Returns
    /// The degree of the specified variable
    pub fn degree_of_variable(&self, variable: usize) -> usize {
        if variable < self.degrees.len() {
            self.degrees[variable]
        } else {
            0
        }
    }
}

/// Represents a multivariate polynomial over a finite field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiVariatePolynomial {
    /// The terms of the polynomial
    terms: Vec<Term>,
    /// The number of variables
    num_variables: usize,
}

impl MultiVariatePolynomial {
    /// Create a new multivariate polynomial.
    /// 
    /// # Arguments
    /// * `terms` - The terms of the polynomial
    /// * `num_variables` - The number of variables
    /// 
    /// # Returns
    /// A new multivariate polynomial
    pub fn new(terms: Vec<Term>, num_variables: usize) -> CryptoResult<Self> {
        if terms.is_empty() {
            return Err(CryptoError::InvalidDegree(0));
        }
        
        // Ensure all terms have the same modulus
        let modulus = terms[0].coefficient.modulus();
        for term in &terms {
            if term.coefficient.modulus() != modulus {
                return Err(CryptoError::InvalidFieldElement(
                    "All terms must belong to the same field".to_string()
                ));
            }
        }
        
        Ok(Self { terms, num_variables })
    }
    
    /// Create a zero polynomial.
    /// 
    /// # Arguments
    /// * `num_variables` - The number of variables
    /// * `modulus` - The modulus of the field
    /// 
    /// # Returns
    /// A zero polynomial
    pub fn zero(num_variables: usize, modulus: u64) -> CryptoResult<Self> {
        let term = Term::new(FiniteField::new(0, modulus)?, vec![0; num_variables]);
        Self::new(vec![term], num_variables)
    }
    
    /// Get the terms of this polynomial.
    pub fn terms(&self) -> &[Term] {
        &self.terms
    }
    
    /// Get the number of variables.
    pub fn num_variables(&self) -> usize {
        self.num_variables
    }
    
    /// Get the modulus of the field this polynomial is defined over.
    pub fn modulus(&self) -> u64 {
        self.terms[0].coefficient.modulus()
    }
    
    /// Get the maximum degree of each variable.
    pub fn degree_variables(&self) -> Vec<usize> {
        let mut max_degrees = vec![0; self.num_variables];
        
        for term in &self.terms {
            for (i, &degree) in term.degrees.iter().enumerate() {
                if i < self.num_variables {
                    max_degrees[i] = max_degrees[i].max(degree);
                }
            }
        }
        
        max_degrees
    }
    
    /// Evaluate the polynomial at a given point.
    /// 
    /// # Arguments
    /// * `point` - The point to evaluate at (values for each variable)
    /// 
    /// # Returns
    /// The value of the polynomial at the given point
    /// 
    /// # Errors
    /// Returns an error if the point has wrong dimension or belongs to a different field
    pub fn evaluate_point(&self, point: &[FiniteField]) -> CryptoResult<FiniteField> {
        if point.len() != self.num_variables {
            return Err(CryptoError::InvalidFieldElement(
                format!("Expected {} variables, got {}", self.num_variables, point.len())
            ));
        }
        
        let modulus = self.modulus();
        for var in point {
            if var.modulus() != modulus {
                return Err(CryptoError::InvalidFieldElement(
                    "Point must belong to the same field as the polynomial".to_string()
                ));
            }
        }
        
        let mut result = FiniteField::new(0, modulus)?;
        
        for term in &self.terms {
            let mut term_value = term.coefficient;
            
            for (i, &degree) in term.degrees.iter().enumerate() {
                if i < point.len() && degree > 0 {
                    let power = point[i].pow(degree as u64)?;
                    term_value = term_value.mul(&power)?;
                }
            }
            
            result = result.add(&term_value)?;
        }
        
        Ok(result)
    }
    
    /// Evaluate the sum of the polynomial over the boolean hypercube.
    /// 
    /// # Returns
    /// The sum of the polynomial over all boolean inputs
    pub fn evaluate_sum(&self) -> CryptoResult<FiniteField> {
        let modulus = self.modulus();
        let hypercube = FiniteField::boolean_hypercube(&FiniteField::new(0, modulus)?, self.num_variables);
        
        let mut sum = FiniteField::new(0, modulus)?;
        for point in &hypercube {
            sum = sum.add(&self.evaluate_point(point)?)?;
        }
        
        Ok(sum)
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
        
        let result_terms: CryptoResult<Vec<_>> = self.terms
            .iter()
            .map(|term| {
                let new_coeff = term.coefficient.mul(scalar)?;
                Ok(Term::new(new_coeff, term.degrees.clone()))
            })
            .collect();
        
        Self::new(result_terms?, self.num_variables)
    }
    
    /// Check if this polynomial is the zero polynomial.
    pub fn is_zero(&self) -> bool {
        self.terms.iter().all(|term| term.coefficient.value() == 0)
    }
}

impl std::fmt::Display for MultiVariatePolynomial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_zero() {
            return write!(f, "0");
        }
        
        let mut terms_str = Vec::new();
        
        for term in &self.terms {
            if term.coefficient.value() == 0 {
                continue;
            }
            
            let mut term_str = format!("{}", term.coefficient);
            
            for (i, &degree) in term.degrees.iter().enumerate() {
                if degree > 0 {
                    if degree == 1 {
                        term_str.push_str(&format!("x_{}", i + 1));
                    } else {
                        term_str.push_str(&format!("x_{}^{}", i + 1, degree));
                    }
                }
            }
            
            terms_str.push(term_str);
        }
        
        if terms_str.is_empty() {
            write!(f, "0")
        } else {
            write!(f, "{}", terms_str.join(" + "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multivariate_polynomial_creation() {
        let terms = vec![
            Term::new(FiniteField::new(1, 7).unwrap(), vec![2, 1, 0]),
            Term::new(FiniteField::new(2, 7).unwrap(), vec![0, 0, 1]),
        ];
        let poly = MultiVariatePolynomial::new(terms, 3).unwrap();
        assert_eq!(poly.num_variables(), 3);
        assert_eq!(poly.modulus(), 7);
    }

    #[test]
    fn test_multivariate_polynomial_evaluation() {
        let terms = vec![
            Term::new(FiniteField::new(1, 7).unwrap(), vec![1, 1]),
            Term::new(FiniteField::new(2, 7).unwrap(), vec![0, 1]),
        ];
        let poly = MultiVariatePolynomial::new(terms, 2).unwrap();
        
        let point = vec![
            FiniteField::new(2, 7).unwrap(),
            FiniteField::new(3, 7).unwrap(),
        ];
        
        let result = poly.evaluate_point(&point).unwrap();
        // 1*x₁*x₂ + 2*x₂ = 1*2*3 + 2*3 = 6 + 6 = 12 ≡ 5 (mod 7)
        assert_eq!(result.value(), 5);
    }

    #[test]
    fn test_degree_variables() {
        let terms = vec![
            Term::new(FiniteField::new(1, 7).unwrap(), vec![2, 1, 3]),
            Term::new(FiniteField::new(1, 7).unwrap(), vec![1, 2, 0]),
        ];
        let poly = MultiVariatePolynomial::new(terms, 3).unwrap();
        let degrees = poly.degree_variables();
        assert_eq!(degrees, vec![2, 2, 3]);
    }
} 