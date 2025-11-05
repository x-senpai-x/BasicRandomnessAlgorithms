//! Multilinear extension implementation.
//!
//! This module provides the core multilinear extension (MLE) implementation,
//! which extends a function defined on the boolean hypercube to the entire field.

use super::binary::dec_to_bin_fixed;
use crypto_core::{CryptoError, CryptoResult};
use crypto_field::FiniteField;

/// Represents a multilinear extension of a function.
///
/// A multilinear extension takes a function defined on the boolean hypercube
/// and extends it to the entire field using Lagrange interpolation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultilinearExtension {
    /// The function values on the boolean hypercube
    /// `values[i]` is the value at the i-th point in lexicographic order
    pub values: Vec<FiniteField>,
    /// The number of variables
    pub num_variables: usize,
}

impl MultilinearExtension {
    /// Create a new multilinear extension from function values.
    ///
    /// # Arguments
    /// * `values` - The function values on the boolean hypercube
    ///
    /// # Returns
    /// A new multilinear extension
    ///
    /// # Errors
    /// Returns an error if the number of values is not a power of 2
    pub fn new(values: Vec<FiniteField>) -> CryptoResult<Self> {
        if values.is_empty() {
            return Err(CryptoError::InvalidFieldElement(
                "Values cannot be empty".to_string(),
            ));
        }

        let num_values = values.len();
        if !num_values.is_power_of_two() {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Number of values {} must be a power of 2",
                num_values
            )));
        }

        let num_variables = num_values.trailing_zeros() as usize;

        // Ensure all values belong to the same field
        let modulus = values[0].modulus();
        for value in &values {
            if value.modulus() != modulus {
                return Err(CryptoError::InvalidFieldElement(
                    "All values must belong to the same field".to_string(),
                ));
            }
        }

        Ok(Self {
            values,
            num_variables,
        })
    }

    /// Evaluate the multilinear extension at a given point.
    ///
    /// # Arguments
    /// * `point` - The point to evaluate at (field elements)
    ///
    /// # Returns
    /// The value of the multilinear extension at the given point
    ///
    /// # Errors
    /// Returns an error if the point has wrong dimension or belongs to a different field
    pub fn evaluate(&self, point: &[FiniteField]) -> CryptoResult<FiniteField> {
        if point.len() != self.num_variables {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Expected {} variables, got {}",
                self.num_variables,
                point.len()
            )));
        }

        let modulus = self.values[0].modulus();

        // Check that all points belong to the same field
        for var in point {
            if var.modulus() != modulus {
                return Err(CryptoError::InvalidFieldElement(
                    "Point must belong to the same field as the MLE".to_string(),
                ));
            }
        }

        let mut result = FiniteField::new(0, modulus)?;
        let num_points = self.values.len();

        for i in 0..num_points {
            let x = dec_to_bin_fixed(i as u64, self.num_variables)?;
            let mut chi = FiniteField::new(1, modulus)?;

            for j in 0..self.num_variables {
                let x_j = x[j];
                let point_j = &point[j];

                if x_j == 1 {
                    chi = chi.mul(point_j)?;
                } else {
                    let one_minus_point = FiniteField::new(1, modulus)?.sub(point_j)?;
                    chi = chi.mul(&one_minus_point)?;
                }
            }

            let term = self.values[i].mul(&chi)?;
            result = result.add(&term)?;
        }

        Ok(result)
    }

    /// Evaluate the multilinear extension at a binary point.
    ///
    /// # Arguments
    /// * `binary_point` - The binary point to evaluate at
    ///
    /// # Returns
    /// The value of the multilinear extension at the given binary point
    ///
    /// # Errors
    /// Returns an error if the point has wrong dimension
    pub fn evaluate_binary(&self, binary_point: &[u8]) -> CryptoResult<FiniteField> {
        if binary_point.len() != self.num_variables {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Expected {} variables, got {}",
                self.num_variables,
                binary_point.len()
            )));
        }

        // Convert binary point to decimal index
        let mut index = 0;
        for (i, &bit) in binary_point.iter().enumerate() {
            if bit == 1 {
                index += 1 << i;
            }
        }

        if index >= self.values.len() {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Index {} out of bounds for {} values",
                index,
                self.values.len()
            )));
        }

        Ok(self.values[index])
    }

    /// Get the modulus of the field this MLE is defined over.
    pub fn modulus(&self) -> u64 {
        if self.values.is_empty() {
            0
        } else {
            self.values[0].modulus()
        }
    }

    /// Get the number of variables in this MLE.
    pub fn num_variables(&self) -> usize {
        self.num_variables
    }

    /// Get the number of values in this MLE.
    pub fn num_values(&self) -> usize {
        self.values.len()
    }

    /// Check if this MLE is the zero function.
    pub fn is_zero(&self) -> bool {
        self.values.iter().all(|value| value.value() == 0)
    }

    /// Add two multilinear extensions.
    ///
    /// # Arguments
    /// * `other` - The other multilinear extension to add
    ///
    /// # Returns
    /// The sum of the two multilinear extensions
    ///
    /// # Errors
    /// Returns an error if the MLEs have different dimensions or fields
    pub fn add(&self, other: &Self) -> CryptoResult<Self> {
        if self.num_variables != other.num_variables {
            return Err(CryptoError::InvalidFieldElement(
                "MLEs must have the same number of variables".to_string(),
            ));
        }

        if self.modulus() != other.modulus() {
            return Err(CryptoError::InvalidFieldElement(
                "MLEs must be defined over the same field".to_string(),
            ));
        }

        let mut result_values = Vec::with_capacity(self.values.len());
        for (a, b) in self.values.iter().zip(other.values.iter()) {
            result_values.push(a.add(b)?);
        }

        Self::new(result_values)
    }

    /// Multiply two multilinear extensions.
    ///
    /// # Arguments
    /// * `other` - The other multilinear extension to multiply
    ///
    /// # Returns
    /// The product of the two multilinear extensions
    ///
    /// # Errors
    /// Returns an error if the MLEs have different dimensions or fields
    pub fn mul(&self, other: &Self) -> CryptoResult<Self> {
        if self.num_variables != other.num_variables {
            return Err(CryptoError::InvalidFieldElement(
                "MLEs must have the same number of variables".to_string(),
            ));
        }

        if self.modulus() != other.modulus() {
            return Err(CryptoError::InvalidFieldElement(
                "MLEs must be defined over the same field".to_string(),
            ));
        }

        let mut result_values = Vec::with_capacity(self.values.len());
        for (a, b) in self.values.iter().zip(other.values.iter()) {
            result_values.push(a.mul(b)?);
        }

        Self::new(result_values)
    }

    /// Scale a multilinear extension by a field element.
    ///
    /// # Arguments
    /// * `scalar` - The scalar to multiply by
    ///
    /// # Returns
    /// The scaled multilinear extension
    ///
    /// # Errors
    /// Returns an error if the scalar belongs to a different field
    pub fn scale(&self, scalar: &FiniteField) -> CryptoResult<Self> {
        if scalar.modulus() != self.modulus() {
            return Err(CryptoError::InvalidFieldElement(
                "Scalar must belong to the same field as the MLE".to_string(),
            ));
        }

        let mut result_values = Vec::with_capacity(self.values.len());
        for value in &self.values {
            result_values.push(value.mul(scalar)?);
        }

        Self::new(result_values)
    }
}

/// Type alias for MultilinearExtension
pub type MLE = MultilinearExtension;

impl std::fmt::Display for MultilinearExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MLE({} variables, {} values)",
            self.num_variables,
            self.num_values()
        )?;

        if self.num_variables <= 3 {
            write!(f, " [")?;
            for (i, value) in self.values.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                let binary = dec_to_bin_fixed(i as u64, self.num_variables).unwrap_or_default();
                write!(f, "f({:?})={}", binary, value)?;
            }
            write!(f, "]")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mle_creation() {
        let values = vec![
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(2, 7).unwrap(),
            FiniteField::new(3, 7).unwrap(),
            FiniteField::new(4, 7).unwrap(),
        ];

        let mle = MultilinearExtension::new(values).unwrap();
        assert_eq!(mle.num_variables(), 2);
        assert_eq!(mle.num_values(), 4);
        assert_eq!(mle.modulus(), 7);
    }

    #[test]
    fn test_mle_evaluation() {
        let values = vec![
            FiniteField::new(1, 7).unwrap(), // f(0,0)
            FiniteField::new(2, 7).unwrap(), // f(0,1)
            FiniteField::new(3, 7).unwrap(), // f(1,0)
            FiniteField::new(4, 7).unwrap(), // f(1,1)
        ];

        let mle = MultilinearExtension::new(values).unwrap();

        // Test evaluation at binary points
        let point_00 = vec![
            FiniteField::new(0, 7).unwrap(),
            FiniteField::new(0, 7).unwrap(),
        ];
        let point_01 = vec![
            FiniteField::new(0, 7).unwrap(),
            FiniteField::new(1, 7).unwrap(),
        ];
        let point_10 = vec![
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(0, 7).unwrap(),
        ];
        let point_11 = vec![
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(1, 7).unwrap(),
        ];

        assert_eq!(mle.evaluate(&point_00).unwrap().value(), 1);
        assert_eq!(mle.evaluate(&point_01).unwrap().value(), 2);
        assert_eq!(mle.evaluate(&point_10).unwrap().value(), 3);
        assert_eq!(mle.evaluate(&point_11).unwrap().value(), 4);
    }

    #[test]
    fn test_mle_binary_evaluation() {
        let values = vec![
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(2, 7).unwrap(),
            FiniteField::new(3, 7).unwrap(),
            FiniteField::new(4, 7).unwrap(),
        ];

        let mle = MultilinearExtension::new(values).unwrap();

        assert_eq!(mle.evaluate_binary(&[0, 0]).unwrap().value(), 1);
        assert_eq!(mle.evaluate_binary(&[0, 1]).unwrap().value(), 2);
        assert_eq!(mle.evaluate_binary(&[1, 0]).unwrap().value(), 3);
        assert_eq!(mle.evaluate_binary(&[1, 1]).unwrap().value(), 4);
    }

    #[test]
    fn test_mle_addition() {
        let values1 = vec![
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(2, 7).unwrap(),
        ];
        let values2 = vec![
            FiniteField::new(3, 7).unwrap(),
            FiniteField::new(4, 7).unwrap(),
        ];

        let mle1 = MultilinearExtension::new(values1).unwrap();
        let mle2 = MultilinearExtension::new(values2).unwrap();

        let sum = mle1.add(&mle2).unwrap();
        assert_eq!(sum.values[0].value(), 4); // 1 + 3 = 4
        assert_eq!(sum.values[1].value(), 6); // 2 + 4 = 6
    }

    #[test]
    fn test_mle_multiplication() {
        let values1 = vec![
            FiniteField::new(2, 7).unwrap(),
            FiniteField::new(3, 7).unwrap(),
        ];
        let values2 = vec![
            FiniteField::new(4, 7).unwrap(),
            FiniteField::new(5, 7).unwrap(),
        ];

        let mle1 = MultilinearExtension::new(values1).unwrap();
        let mle2 = MultilinearExtension::new(values2).unwrap();

        let product = mle1.mul(&mle2).unwrap();
        assert_eq!(product.values[0].value(), 1); // 2 * 4 = 8 ≡ 1 (mod 7)
        assert_eq!(product.values[1].value(), 1); // 3 * 5 = 15 ≡ 1 (mod 7)
    }
}
