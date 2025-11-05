//! Frievalds algorithm implementation.
//! 
//! This module provides the core Frievalds algorithm implementation,
//! which is a probabilistic algorithm for verifying matrix multiplication
//! without computing the full product.

use crypto_core::{CryptoError, CryptoResult};
use crypto_field::FiniteField;
use super::matrix::Matrix;

/// Result of the Frievalds algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrievaldsResult {
    /// The matrices are likely equal (AB = C)
    Equal,
    /// The matrices are definitely not equal (AB ≠ C)
    NotEqual,
    /// The test is inconclusive
    Inconclusive,
}

/// Execute the Frievalds algorithm to verify matrix multiplication.
/// 
/// The Frievalds algorithm verifies whether AB = C by checking if
/// ABr = Cr for a random vector r. If AB ≠ C, then with high probability
/// ABr ≠ Cr.
/// 
/// # Arguments
/// * `a` - The first matrix A
/// * `b` - The second matrix B
/// * `c` - The claimed product matrix C
/// * `num_trials` - The number of random trials to perform
/// 
/// # Returns
/// The result of the verification
/// 
/// # Errors
/// Returns an error if the matrices have incompatible dimensions or belong to different fields
pub fn frievalds_verify(
    a: &Matrix,
    b: &Matrix,
    c: &Matrix,
    num_trials: usize
) -> CryptoResult<FrievaldsResult> {
    // Check that the matrices have compatible dimensions
    if a.cols != b.rows {
        return Err(CryptoError::InvalidFieldElement(
            format!("Matrix A has {} columns but matrix B has {} rows", a.cols, b.rows)
        ));
    }
    
    if a.rows != c.rows || b.cols != c.cols {
        return Err(CryptoError::InvalidFieldElement(
            format!("Matrix C has dimensions {}x{} but should be {}x{}", 
                   c.rows, c.cols, a.rows, b.cols)
        ));
    }
    
    // Check that all matrices belong to the same field
    let modulus = a.modulus();
    if b.modulus() != modulus || c.modulus() != modulus {
        return Err(CryptoError::InvalidFieldElement(
            "All matrices must belong to the same field".to_string()
        ));
    }
    
    // Perform multiple trials with random vectors
    for _ in 0..num_trials {
        // Generate a random vector r
        let mut r = Vec::with_capacity(b.cols);
        for _ in 0..b.cols {
            r.push(FiniteField::random(modulus)?);
        }
        
        // Compute ABr
        let ab = a.mul(b)?;
        let abr = ab.mul_vector(&r)?;
        
        // Compute Cr
        let cr = c.mul_vector(&r)?;
        
        // Check if ABr = Cr
        if abr.len() != cr.len() {
            return Ok(FrievaldsResult::NotEqual);
        }
        
        for (abr_val, cr_val) in abr.iter().zip(cr.iter()) {
            if abr_val.value() != cr_val.value() {
                return Ok(FrievaldsResult::NotEqual);
            }
        }
    }
    
    // If all trials pass, the matrices are likely equal
    Ok(FrievaldsResult::Equal)
}

/// Execute a single trial of the Frievalds algorithm.
/// 
/// # Arguments
/// * `a` - The first matrix A
/// * `b` - The second matrix B
/// * `c` - The claimed product matrix C
/// 
/// # Returns
/// The result of the single trial
/// 
/// # Errors
/// Returns an error if the matrices have incompatible dimensions or belong to different fields
pub fn frievalds_single_trial(
    a: &Matrix,
    b: &Matrix,
    c: &Matrix
) -> CryptoResult<FrievaldsResult> {
    frievalds_verify(a, b, c, 1)
}

/// Execute the Frievalds algorithm with a specific random vector.
/// 
/// This function is useful for deterministic testing or when you want
/// to use a specific random vector.
/// 
/// # Arguments
/// * `a` - The first matrix A
/// * `b` - The second matrix B
/// * `c` - The claimed product matrix C
/// * `r` - The random vector to use
/// 
/// # Returns
/// The result of the verification
/// 
/// # Errors
/// Returns an error if the matrices have incompatible dimensions or the vector has wrong length
pub fn frievalds_with_vector(
    a: &Matrix,
    b: &Matrix,
    c: &Matrix,
    r: &[FiniteField]
) -> CryptoResult<FrievaldsResult> {
    // Check that the matrices have compatible dimensions
    if a.cols != b.rows {
        return Err(CryptoError::InvalidFieldElement(
            format!("Matrix A has {} columns but matrix B has {} rows", a.cols, b.rows)
        ));
    }
    
    if a.rows != c.rows || b.cols != c.cols {
        return Err(CryptoError::InvalidFieldElement(
            format!("Matrix C has dimensions {}x{} but should be {}x{}", 
                   c.rows, c.cols, a.rows, b.cols)
        ));
    }
    
    // Check that the vector has the correct length
    if r.len() != b.cols {
        return Err(CryptoError::InvalidFieldElement(
            format!("Vector has length {} but should have length {}", r.len(), b.cols)
        ));
    }
    
    // Check that all matrices and vector belong to the same field
    let modulus = a.modulus();
    if b.modulus() != modulus || c.modulus() != modulus {
        return Err(CryptoError::InvalidFieldElement(
            "All matrices must belong to the same field".to_string()
        ));
    }
    
    for &element in r {
        if element.modulus() != modulus {
            return Err(CryptoError::InvalidFieldElement(
                "Vector must belong to the same field as the matrices".to_string()
            ));
        }
    }
    
    // Compute ABr
    let ab = a.mul(b)?;
    let abr = ab.mul_vector(r)?;
    
    // Compute Cr
    let cr = c.mul_vector(r)?;
    
    // Check if ABr = Cr
    if abr.len() != cr.len() {
        return Ok(FrievaldsResult::NotEqual);
    }
    
    for (abr_val, cr_val) in abr.iter().zip(cr.iter()) {
        if abr_val.value() != cr_val.value() {
            return Ok(FrievaldsResult::NotEqual);
        }
    }
    
    Ok(FrievaldsResult::Equal)
}

/// Calculate the error probability of the Frievalds algorithm.
/// 
/// The error probability is the probability that the algorithm returns
/// "Equal" when AB ≠ C. This is at most 1/|F| for a single trial.
/// 
/// # Arguments
/// * `field_size` - The size of the finite field
/// * `num_trials` - The number of trials performed
/// 
/// # Returns
/// The error probability
pub fn frievalds_error_probability(field_size: u64, num_trials: usize) -> f64 {
    let field_size = field_size as f64;
    (1.0 / field_size).powi(num_trials as i32)
}

/// Calculate the number of trials needed for a given error probability.
/// 
/// # Arguments
/// * `error_prob` - The desired error probability
/// * `field_size` - The size of the finite field
/// 
/// # Returns
/// The number of trials needed
pub fn frievalds_trials_needed(error_prob: f64, field_size: u64) -> usize {
    let field_size = field_size as f64;
    let trials = (error_prob.ln() / (1.0 / field_size).ln()).ceil() as usize;
    trials.max(1) // At least 1 trial
}

/// Execute the Frievalds algorithm with optimal number of trials.
/// 
/// This function automatically determines the number of trials needed
/// to achieve a given error probability.
/// 
/// # Arguments
/// * `a` - The first matrix A
/// * `b` - The second matrix B
/// * `c` - The claimed product matrix C
/// * `error_prob` - The desired error probability
/// 
/// # Returns
/// The result of the verification
/// 
/// # Errors
/// Returns an error if the matrices have incompatible dimensions or belong to different fields
pub fn frievalds_verify_with_error_prob(
    a: &Matrix,
    b: &Matrix,
    c: &Matrix,
    error_prob: f64
) -> CryptoResult<FrievaldsResult> {
    let field_size = a.modulus();
    let num_trials = frievalds_trials_needed(error_prob, field_size);
    frievalds_verify(a, b, c, num_trials)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frievalds_correct_multiplication() {
        let a = Matrix::new(vec![
            vec![FiniteField::new(1, 7).unwrap(), FiniteField::new(2, 7).unwrap()],
            vec![FiniteField::new(3, 7).unwrap(), FiniteField::new(4, 7).unwrap()],
        ]).unwrap();
        
        let b = Matrix::new(vec![
            vec![FiniteField::new(5, 7).unwrap(), FiniteField::new(6, 7).unwrap()],
            vec![FiniteField::new(0, 7).unwrap(), FiniteField::new(1, 7).unwrap()],
        ]).unwrap();
        
        let c = a.mul(&b).unwrap(); // Correct product
        
        let result = frievalds_verify(&a, &b, &c, 5).unwrap();
        assert_eq!(result, FrievaldsResult::Equal);
    }

    #[test]
    fn test_frievalds_incorrect_multiplication() {
        let a = Matrix::new(vec![
            vec![FiniteField::new(1, 7).unwrap(), FiniteField::new(2, 7).unwrap()],
            vec![FiniteField::new(3, 7).unwrap(), FiniteField::new(4, 7).unwrap()],
        ]).unwrap();
        
        let b = Matrix::new(vec![
            vec![FiniteField::new(5, 7).unwrap(), FiniteField::new(6, 7).unwrap()],
            vec![FiniteField::new(0, 7).unwrap(), FiniteField::new(1, 7).unwrap()],
        ]).unwrap();
        
        let c = Matrix::new(vec![
            vec![FiniteField::new(0, 7).unwrap(), FiniteField::new(0, 7).unwrap()],
            vec![FiniteField::new(0, 7).unwrap(), FiniteField::new(0, 7).unwrap()],
        ]).unwrap(); // Incorrect product (zero matrix)
        
        let result = frievalds_verify(&a, &b, &c, 5).unwrap();
        assert_eq!(result, FrievaldsResult::NotEqual);
    }

    #[test]
    fn test_frievalds_single_trial() {
        let a = Matrix::new(vec![
            vec![FiniteField::new(1, 7).unwrap(), FiniteField::new(2, 7).unwrap()],
            vec![FiniteField::new(3, 7).unwrap(), FiniteField::new(4, 7).unwrap()],
        ]).unwrap();
        
        let b = Matrix::new(vec![
            vec![FiniteField::new(5, 7).unwrap(), FiniteField::new(6, 7).unwrap()],
            vec![FiniteField::new(0, 7).unwrap(), FiniteField::new(1, 7).unwrap()],
        ]).unwrap();
        
        let c = a.mul(&b).unwrap();
        
        let result = frievalds_single_trial(&a, &b, &c).unwrap();
        assert_eq!(result, FrievaldsResult::Equal);
    }

    #[test]
    fn test_frievalds_with_vector() {
        let a = Matrix::new(vec![
            vec![FiniteField::new(1, 7).unwrap(), FiniteField::new(2, 7).unwrap()],
            vec![FiniteField::new(3, 7).unwrap(), FiniteField::new(4, 7).unwrap()],
        ]).unwrap();
        
        let b = Matrix::new(vec![
            vec![FiniteField::new(5, 7).unwrap(), FiniteField::new(6, 7).unwrap()],
            vec![FiniteField::new(0, 7).unwrap(), FiniteField::new(1, 7).unwrap()],
        ]).unwrap();
        
        let c = a.mul(&b).unwrap();
        
        let r = vec![
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(2, 7).unwrap(),
        ];
        
        let result = frievalds_with_vector(&a, &b, &c, &r).unwrap();
        assert_eq!(result, FrievaldsResult::Equal);
    }

    #[test]
    fn test_error_probability() {
        let error_prob = frievalds_error_probability(7, 3);
        assert!(error_prob > 0.0);
        assert!(error_prob <= 1.0);
    }

    #[test]
    fn test_trials_needed() {
        let trials = frievalds_trials_needed(0.01, 7);
        assert!(trials > 0);
        
        // More trials should be needed for smaller error probability
        let trials_smaller_error = frievalds_trials_needed(0.001, 7);
        assert!(trials_smaller_error >= trials);
    }

    #[test]
    fn test_verify_with_error_prob() {
        let a = Matrix::new(vec![
            vec![FiniteField::new(1, 7).unwrap(), FiniteField::new(2, 7).unwrap()],
            vec![FiniteField::new(3, 7).unwrap(), FiniteField::new(4, 7).unwrap()],
        ]).unwrap();
        
        let b = Matrix::new(vec![
            vec![FiniteField::new(5, 7).unwrap(), FiniteField::new(6, 7).unwrap()],
            vec![FiniteField::new(0, 7).unwrap(), FiniteField::new(1, 7).unwrap()],
        ]).unwrap();
        
        let c = a.mul(&b).unwrap();
        
        let result = frievalds_verify_with_error_prob(&a, &b, &c, 0.01).unwrap();
        assert_eq!(result, FrievaldsResult::Equal);
    }
} 