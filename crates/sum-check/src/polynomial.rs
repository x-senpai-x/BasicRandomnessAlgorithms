//! Multivariate polynomial implementation for sum-check protocol.
//!
//! This module provides a specialized multivariate polynomial implementation
//! optimized for the sum-check protocol.

use crypto_core::{CryptoError, CryptoResult};
use crypto_field::FiniteField;
use std::cmp::max;

/// Represents a multivariate polynomial optimized for sum-check protocol.
///
/// The polynomial is stored as a list of terms, where each term has:
/// - A coefficient
/// - A vector of degrees for each variable
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiVariatePolynomial {
    /// Coefficients of each term
    pub coefficients: Vec<FiniteField>,
    /// Degrees of each variable in each term
    /// `terms_with_degrees[i][j]` is the degree of variable j in term i
    pub terms_with_degrees: Vec<Vec<u64>>,
}

impl MultiVariatePolynomial {
    /// Create a new multivariate polynomial.
    ///
    /// # Arguments
    /// * `coefficients` - The coefficients of each term
    /// * `terms_with_degrees` - The degrees of each variable in each term
    ///
    /// # Returns
    /// A new multivariate polynomial
    ///
    /// # Errors
    /// Returns an error if the input is invalid
    pub fn new(
        coefficients: Vec<FiniteField>,
        terms_with_degrees: Vec<Vec<u64>>,
    ) -> CryptoResult<Self> {
        if coefficients.is_empty() {
            return Err(CryptoError::InvalidDegree(0));
        }

        if coefficients.len() != terms_with_degrees.len() {
            return Err(CryptoError::InvalidFieldElement(
                "Number of coefficients must match number of terms".to_string(),
            ));
        }

        // Ensure all coefficients have the same modulus
        let modulus = coefficients[0].modulus();
        for coeff in &coefficients {
            if coeff.modulus() != modulus {
                return Err(CryptoError::InvalidFieldElement(
                    "All coefficients must belong to the same field".to_string(),
                ));
            }
        }

        // Ensure all terms have the same number of variables
        if !terms_with_degrees.is_empty() {
            let num_vars = terms_with_degrees[0].len();
            for term in &terms_with_degrees {
                if term.len() != num_vars {
                    return Err(CryptoError::InvalidFieldElement(
                        "All terms must have the same number of variables".to_string(),
                    ));
                }
            }
        }

        Ok(Self {
            coefficients,
            terms_with_degrees,
        })
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
        let modulus = self.modulus();
        let n_terms = self.coefficients.len();

        if self.terms_with_degrees.is_empty() {
            return Ok(FiniteField::new(0, modulus)?);
        }

        let n_variables = self.terms_with_degrees[0].len();

        if point.len() != n_variables {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Expected {} variables, got {}",
                n_variables,
                point.len()
            )));
        }

        // Check that all points belong to the same field
        for var in point {
            if var.modulus() != modulus {
                return Err(CryptoError::InvalidFieldElement(
                    "Point must belong to the same field as the polynomial".to_string(),
                ));
            }
        }

        let mut result = FiniteField::new(0, modulus)?;

        for term_idx in 0..n_terms {
            let coeff = self.coefficients[term_idx];
            let mut term_value = FiniteField::new(1, modulus)?;

            for var_idx in 0..n_variables {
                let degree = self.terms_with_degrees[term_idx][var_idx];
                if degree > 0 {
                    let power = point[var_idx].pow(degree)?;
                    term_value = term_value.mul(&power)?;
                }
            }

            let term_result = coeff.mul(&term_value)?;
            result = result.add(&term_result)?;
        }

        Ok(result)
    }

    /// Evaluate the sum of the polynomial over the boolean hypercube.
    ///
    /// # Returns
    /// The sum of the polynomial over all boolean inputs
    ///
    /// # Errors
    /// Returns an error if the polynomial is invalid
    pub fn evaluate_sum(&self) -> CryptoResult<FiniteField> {
        let modulus = self.modulus();
        let n_variables = if self.terms_with_degrees.is_empty() {
            0
        } else {
            self.terms_with_degrees[0].len()
        };

        let hypercube = FiniteField::boolean_hypercube(&FiniteField::new(0, modulus)?, n_variables);
        let mut sum = FiniteField::new(0, modulus)?;

        for point in &hypercube {
            sum = sum.add(&self.evaluate_point(point)?)?;
        }

        Ok(sum)
    }

    /// Get the maximum degree of each variable.
    ///
    /// # Returns
    /// A vector where the i-th element is the maximum degree of variable i
    pub fn degree_variables(&self) -> Vec<u64> {
        if self.terms_with_degrees.is_empty() {
            return vec![];
        }

        let n_variables = self.terms_with_degrees[0].len();
        let mut degree_variables = vec![0; n_variables];

        for term in &self.terms_with_degrees {
            for (var_idx, &degree) in term.iter().enumerate() {
                degree_variables[var_idx] = max(degree_variables[var_idx], degree);
            }
        }

        degree_variables
    }

    /// Get the modulus of the field this polynomial is defined over.
    pub fn modulus(&self) -> u64 {
        if self.coefficients.is_empty() {
            0
        } else {
            self.coefficients[0].modulus()
        }
    }

    /// Get the number of variables in this polynomial.
    pub fn num_variables(&self) -> usize {
        if self.terms_with_degrees.is_empty() {
            0
        } else {
            self.terms_with_degrees[0].len()
        }
    }

    /// Get the number of terms in this polynomial.
    pub fn num_terms(&self) -> usize {
        self.coefficients.len()
    }

    /// Check if this polynomial is the zero polynomial.
    pub fn is_zero(&self) -> bool {
        self.coefficients.iter().all(|coeff| coeff.value() == 0)
    }
}

impl std::fmt::Display for MultiVariatePolynomial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_zero() {
            return write!(f, "0");
        }

        let mut terms_str = Vec::new();

        for (term_idx, &coeff) in self.coefficients.iter().enumerate() {
            if coeff.value() == 0 {
                continue;
            }

            let mut term_str = format!("{}", coeff);

            if !self.terms_with_degrees.is_empty() {
                for (var_idx, &degree) in self.terms_with_degrees[term_idx].iter().enumerate() {
                    if degree > 0 {
                        if degree == 1 {
                            term_str.push_str(&format!("x_{}", var_idx + 1));
                        } else {
                            term_str.push_str(&format!("x_{}^{}", var_idx + 1, degree));
                        }
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
        let coeffs = vec![
            FiniteField::new(2, 7).unwrap(),
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(1, 7).unwrap(),
        ];
        let degrees = vec![
            vec![3, 0, 0], // 2x₁³
            vec![1, 0, 1], // x₁x₃
            vec![0, 1, 1], // x₂x₃
        ];

        let poly = MultiVariatePolynomial::new(coeffs, degrees).unwrap();
        assert_eq!(poly.num_variables(), 3);
        assert_eq!(poly.num_terms(), 3);
        assert_eq!(poly.modulus(), 7);
    }

    #[test]
    fn test_multivariate_polynomial_evaluation() {
        let coeffs = vec![
            FiniteField::new(2, 7).unwrap(),
            FiniteField::new(1, 7).unwrap(),
        ];
        let degrees = vec![
            vec![1, 1], // 2x₁x₂
            vec![0, 1], // x₂
        ];

        let poly = MultiVariatePolynomial::new(coeffs, degrees).unwrap();

        let point = vec![
            FiniteField::new(2, 7).unwrap(),
            FiniteField::new(3, 7).unwrap(),
        ];

        let result = poly.evaluate_point(&point).unwrap();
        // 2*2*3 + 3 = 12 + 3 = 15 ≡ 1 (mod 7)
        assert_eq!(result.value(), 1);
    }

    #[test]
    fn test_degree_variables() {
        let coeffs = vec![
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(1, 7).unwrap(),
        ];
        let degrees = vec![
            vec![2, 1, 3], // x₁²x₂x₃³
            vec![1, 2, 0], // x₁x₂²
        ];

        let poly = MultiVariatePolynomial::new(coeffs, degrees).unwrap();
        let max_degrees = poly.degree_variables();
        assert_eq!(max_degrees, vec![2, 2, 3]);
    }

    #[test]
    fn test_evaluate_sum() {
        let coeffs = vec![FiniteField::new(1, 7).unwrap()];
        let degrees = vec![
            vec![1, 0], // x₁
        ];

        let poly = MultiVariatePolynomial::new(coeffs, degrees).unwrap();
        let sum = poly.evaluate_sum().unwrap();

        // Sum over {0,1} × {0,1}: f(0,0) + f(0,1) + f(1,0) + f(1,1)
        // = 0 + 0 + 1 + 1 = 2
        assert_eq!(sum.value(), 2);
    }
}
