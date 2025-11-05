//! Polynomial folding operations for FRI protocol.
//! 
//! This module provides implementations of polynomial folding,
//! which is a key operation in the FRI (Fast Reed-Solomon Interactive Oracle Proof) protocol.

use crypto_core::{CryptoError, CryptoResult};
use crypto_field::FiniteField;
use crypto_polynomial::Polynomial;

/// Fold a polynomial using the FRI folding technique.
/// 
/// This function implements the polynomial folding operation used in the FRI protocol.
/// Given a polynomial f(x) and a random field element β, it computes:
/// f_folded(x) = (f(x) + β * f(-x)) / 2
/// 
/// # Arguments
/// * `poly` - The polynomial to fold
/// * `beta` - The random field element for folding
/// 
/// # Returns
/// The folded polynomial
/// 
/// # Errors
/// Returns an error if the polynomial is invalid or the beta value belongs to a different field
pub fn fold_polynomial(poly: &Polynomial, beta: &FiniteField) -> CryptoResult<Polynomial> {
    if poly.coefficients().is_empty() {
        return Err(CryptoError::InvalidDegree(0));
    }
    
    if beta.modulus() != poly.modulus() {
        return Err(CryptoError::InvalidFieldElement(
            "Beta must belong to the same field as the polynomial".to_string()
        ));
    }
    
    let coeffs = poly.coefficients();
    let modulus = poly.modulus();
    let two_inv = FiniteField::new(2, modulus)?.inverse()?;
    
    // Separate even and odd coefficients
    let even_coeffs: Vec<FiniteField> = coeffs.iter().step_by(2).cloned().collect();
    let odd_coeffs: Vec<FiniteField> = coeffs.iter().skip(1).step_by(2).cloned().collect();
    
    // Compute the folded coefficients
    let mut folded_coeffs = Vec::new();
    let max_len = std::cmp::max(even_coeffs.len(), odd_coeffs.len());
    
    for i in 0..max_len {
        let even_coeff = if i < even_coeffs.len() {
            even_coeffs[i]
        } else {
            FiniteField::new(0, modulus)?
        };
        
        let odd_coeff = if i < odd_coeffs.len() {
            odd_coeffs[i]
        } else {
            FiniteField::new(0, modulus)?
        };
        
        // Compute: (even_coeff + beta * odd_coeff) / 2
        let beta_odd = beta.mul(&odd_coeff)?;
        let sum = even_coeff.add(&beta_odd)?;
        let folded_coeff = sum.mul(&two_inv)?;
        
        folded_coeffs.push(folded_coeff);
    }
    
    Polynomial::new(folded_coeffs)
}

/// Fold a polynomial in-place (modifies the input polynomial).
/// 
/// # Arguments
/// * `poly` - The polynomial to fold (will be modified)
/// * `beta` - The random field element for folding
/// 
/// # Errors
/// Returns an error if the polynomial is invalid or the beta value belongs to a different field
pub fn fold_polynomial_in_place(poly: &mut Polynomial, beta: &FiniteField) -> CryptoResult<()> {
    if poly.coefficients().is_empty() {
        return Err(CryptoError::InvalidDegree(0));
    }
    
    if beta.modulus() != poly.modulus() {
        return Err(CryptoError::InvalidFieldElement(
            "Beta must belong to the same field as the polynomial".to_string()
        ));
    }
    
    let coeffs = poly.coefficients().to_vec();
    let folded_poly = fold_polynomial(&Polynomial::new(coeffs)?, beta)?;
    
    // Replace the polynomial's coefficients
    *poly = folded_poly;
    Ok(())
}

/// Compute the folding quotient polynomial.
/// 
/// The folding quotient is used in the FRI protocol to prove that the folding
/// was done correctly. It is defined as:
/// q(x) = (f(x) - f(-x)) / (2x)
/// 
/// # Arguments
/// * `poly` - The original polynomial
/// 
/// # Returns
/// The folding quotient polynomial
/// 
/// # Errors
/// Returns an error if the polynomial is invalid
pub fn compute_folding_quotient(poly: &Polynomial) -> CryptoResult<Polynomial> {
    if poly.coefficients().is_empty() {
        return Err(CryptoError::InvalidDegree(0));
    }
    
    let coeffs = poly.coefficients();
    let modulus = poly.modulus();
    let two_inv = FiniteField::new(2, modulus)?.inverse()?;
    
    // Compute the quotient coefficients
    let mut quotient_coeffs = Vec::new();
    
    for (i, &coeff) in coeffs.iter().enumerate() {
        if i % 2 == 1 {  // Only odd-degree terms contribute
            let quotient_coeff = coeff.mul(&two_inv)?;
            quotient_coeffs.push(quotient_coeff);
        }
    }
    
    // If no odd coefficients, return zero polynomial
    if quotient_coeffs.is_empty() {
        quotient_coeffs.push(FiniteField::new(0, modulus)?);
    }
    
    Polynomial::new(quotient_coeffs)
}

/// Verify a folding operation.
/// 
/// This function verifies that a folded polynomial was computed correctly
/// from the original polynomial using the given beta value.
/// 
/// # Arguments
/// * `original` - The original polynomial
/// * `folded` - The folded polynomial
/// * `beta` - The beta value used for folding
/// 
/// # Returns
/// True if the folding is correct, false otherwise
/// 
/// # Errors
/// Returns an error if any of the polynomials are invalid
pub fn verify_folding(
    original: &Polynomial,
    folded: &Polynomial,
    beta: &FiniteField
) -> CryptoResult<bool> {
    if original.modulus() != folded.modulus() || original.modulus() != beta.modulus() {
        return Err(CryptoError::InvalidFieldElement(
            "All polynomials and beta must belong to the same field".to_string()
        ));
    }
    
    // Compute the expected folded polynomial
    let expected_folded = fold_polynomial(original, beta)?;
    
    // Compare the coefficients
    if expected_folded.coefficients().len() != folded.coefficients().len() {
        return Ok(false);
    }
    
    for (expected, actual) in expected_folded.coefficients().iter().zip(folded.coefficients()) {
        if expected != actual {
            return Ok(false);
        }
    }
    
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fold_polynomial() {
        let coeffs = vec![
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(2, 7).unwrap(),
            FiniteField::new(3, 7).unwrap(),
            FiniteField::new(4, 7).unwrap(),
        ];
        let poly = Polynomial::new(coeffs).unwrap();
        let beta = FiniteField::new(2, 7).unwrap();
        
        let folded = fold_polynomial(&poly, &beta).unwrap();
        
        // The folded polynomial should have fewer coefficients
        assert!(folded.coefficients().len() <= poly.coefficients().len());
        
        // Verify the folding
        let is_correct = verify_folding(&poly, &folded, &beta).unwrap();
        assert!(is_correct);
    }

    #[test]
    fn test_fold_polynomial_in_place() {
        let coeffs = vec![
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(2, 7).unwrap(),
        ];
        let mut poly = Polynomial::new(coeffs).unwrap();
        let beta = FiniteField::new(2, 7).unwrap();
        
        let original_coeffs = poly.coefficients().to_vec();
        fold_polynomial_in_place(&mut poly, &beta).unwrap();
        
        // The polynomial should be modified
        assert_ne!(original_coeffs, poly.coefficients());
    }

    #[test]
    fn test_compute_folding_quotient() {
        let coeffs = vec![
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(2, 7).unwrap(),
            FiniteField::new(3, 7).unwrap(),
        ];
        let poly = Polynomial::new(coeffs).unwrap();
        
        let quotient = compute_folding_quotient(&poly).unwrap();
        
        // The quotient should have fewer coefficients than the original
        assert!(quotient.coefficients().len() <= poly.coefficients().len());
    }

    #[test]
    fn test_verify_folding() {
        let coeffs = vec![
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(2, 7).unwrap(),
        ];
        let poly = Polynomial::new(coeffs).unwrap();
        let beta = FiniteField::new(2, 7).unwrap();
        
        let folded = fold_polynomial(&poly, &beta).unwrap();
        
        // Correct folding should verify successfully
        assert!(verify_folding(&poly, &folded, &beta).unwrap());
        
        // Incorrect folding should fail
        let wrong_folded = Polynomial::new(vec![FiniteField::new(0, 7).unwrap()]).unwrap();
        assert!(!verify_folding(&poly, &wrong_folded, &beta).unwrap());
    }
} 