//! Shamir secret sharing scheme implementation.
//! 
//! This module provides the core Shamir secret sharing scheme implementation,
//! which allows a secret to be split into n shares such that any k shares
//! can reconstruct the secret, but any k-1 shares reveal no information.

use crypto_core::{CryptoError, CryptoResult};
use crypto_field::FiniteField;
use crypto_polynomial::{Polynomial, Point, interpolate_monomial_basis};
use super::share::{Share, ShareSet};

/// Result of a Shamir secret sharing operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareResult {
    /// The operation was successful
    Success,
    /// The operation failed
    Failure,
}

/// Shamir secret sharing scheme implementation.
/// 
/// This struct provides methods for creating and reconstructing shares
/// using Shamir's secret sharing scheme.
#[derive(Debug, Clone)]
pub struct ShamirScheme {
    /// The threshold (minimum number of shares needed for reconstruction)
    pub threshold: usize,
    /// The total number of shares to create
    pub total_shares: usize,
    /// The field modulus
    pub modulus: u64,
}

impl ShamirScheme {
    /// Create a new Shamir secret sharing scheme.
    /// 
    /// # Arguments
    /// * `threshold` - The minimum number of shares needed for reconstruction
    /// * `total_shares` - The total number of shares to create
    /// * `modulus` - The field modulus (must be prime and > total_shares)
    /// 
    /// # Returns
    /// A new Shamir scheme
    /// 
    /// # Errors
    /// Returns an error if the parameters are invalid
    pub fn new(threshold: usize, total_shares: usize, modulus: u64) -> CryptoResult<Self> {
        if threshold == 0 {
            return Err(CryptoError::InvalidFieldElement(
                "Threshold must be positive".to_string()
            ));
        }
        
        if total_shares == 0 {
            return Err(CryptoError::InvalidFieldElement(
                "Total shares must be positive".to_string()
            ));
        }
        
        if threshold > total_shares {
            return Err(CryptoError::InvalidFieldElement(
                format!("Threshold {} cannot be greater than total shares {}", 
                       threshold, total_shares)
            ));
        }
        
        if total_shares >= modulus as usize {
            return Err(CryptoError::InvalidFieldElement(
                format!("Total shares {} must be less than field size {}", 
                       total_shares, modulus)
            ));
        }
        
        // Check if modulus is prime (simple check)
        if !is_prime(modulus) {
            return Err(CryptoError::InvalidFieldElement(
                format!("Modulus {} must be prime", modulus)
            ));
        }
        
        Ok(Self {
            threshold,
            total_shares,
            modulus,
        })
    }
    
    /// Share a secret using Shamir's secret sharing scheme.
    /// 
    /// This function creates a random polynomial of degree threshold-1
    /// with the secret as the constant term, and evaluates it at
    /// total_shares points to create the shares.
    /// 
    /// # Arguments
    /// * `secret` - The secret to share
    /// 
    /// # Returns
    /// A vector of shares
    /// 
    /// # Errors
    /// Returns an error if the secret is invalid or the sharing fails
    pub fn share(&self, secret: FiniteField) -> CryptoResult<Vec<Share>> {
        if secret.modulus() != self.modulus {
            return Err(CryptoError::InvalidFieldElement(
                "Secret must belong to the same field as the scheme".to_string()
            ));
        }
        
        // Create a random polynomial of degree threshold-1
        let mut coeffs = Vec::with_capacity(self.threshold);
        
        // First coefficient is the secret
        coeffs.push(secret);
        
        // Generate random coefficients for higher degree terms
        for _ in 1..self.threshold {
            coeffs.push(FiniteField::random(self.modulus)?);
        }
        
        let polynomial = Polynomial::new(coeffs)?;
        
        // Create shares by evaluating the polynomial at different points
        let mut shares = Vec::with_capacity(self.total_shares);
        
        for i in 1..=self.total_shares {
            let x = FiniteField::new(i as u64, self.modulus)?;
            let y = polynomial.evaluate(&x)?;
            
            let share = Share::new(i, y)?;
            shares.push(share);
        }
        
        Ok(shares)
    }
    
    /// Reconstruct a secret from shares using Lagrange interpolation.
    /// 
    /// This function uses Lagrange interpolation to reconstruct the
    /// polynomial and evaluate it at x=0 to recover the secret.
    /// 
    /// # Arguments
    /// * `shares` - The shares to use for reconstruction
    /// 
    /// # Returns
    /// The reconstructed secret
    /// 
    /// # Errors
    /// Returns an error if there are insufficient shares or reconstruction fails
    pub fn reconstruct(&self, shares: &[Share]) -> CryptoResult<FiniteField> {
        if shares.len() < self.threshold {
            return Err(CryptoError::InvalidFieldElement(
                format!("Need at least {} shares for reconstruction, got {}", 
                       self.threshold, shares.len())
            ));
        }
        
        // Check that all shares belong to the same field
        let modulus = shares[0].modulus();
        for share in shares {
            if share.modulus() != modulus {
                return Err(CryptoError::InvalidFieldElement(
                    "All shares must belong to the same field".to_string()
                ));
            }
        }
        
        // Convert shares to points for interpolation
        let mut points = Vec::with_capacity(shares.len());
        for share in shares {
            let (x, y) = share.to_point()?;
            points.push(Point::new(x, y)?);
        }

        // Interpolate the polynomial
        let polynomial = interpolate_monomial_basis(&points)?;
        
        // Evaluate at x=0 to get the secret (constant term)
        let zero = FiniteField::new(0, modulus)?;
        let secret = polynomial.evaluate(&zero)?;
        
        Ok(secret)
    }
    
    /// Reconstruct a secret from a share set.
    /// 
    /// # Arguments
    /// * `share_set` - The share set to use for reconstruction
    /// 
    /// # Returns
    /// The reconstructed secret
    /// 
    /// # Errors
    /// Returns an error if reconstruction fails
    pub fn reconstruct_from_set(&self, share_set: &ShareSet) -> CryptoResult<FiniteField> {
        if share_set.threshold() != self.threshold {
            return Err(CryptoError::InvalidFieldElement(
                format!("Share set threshold {} does not match scheme threshold {}", 
                       share_set.threshold(), self.threshold)
            ));
        }
        
        if share_set.modulus() != self.modulus {
            return Err(CryptoError::InvalidFieldElement(
                "Share set must belong to the same field as the scheme".to_string()
            ));
        }
        
        self.reconstruct(&share_set.shares)
    }
    
    /// Verify that a set of shares is consistent.
    /// 
    /// This function checks if the shares can be used to reconstruct
    /// a valid secret by attempting reconstruction.
    /// 
    /// # Arguments
    /// * `shares` - The shares to verify
    /// 
    /// # Returns
    /// True if the shares are consistent, false otherwise
    /// 
    /// # Errors
    /// Returns an error if verification fails
    pub fn verify_shares(&self, shares: &[Share]) -> CryptoResult<bool> {
        if shares.len() < self.threshold {
            return Ok(false);
        }
        
        // Try to reconstruct the secret
        match self.reconstruct(shares) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    /// Get the threshold for this scheme.
    pub fn threshold(&self) -> usize {
        self.threshold
    }
    
    /// Get the total number of shares for this scheme.
    pub fn total_shares(&self) -> usize {
        self.total_shares
    }
    
    /// Get the modulus of the field for this scheme.
    pub fn modulus(&self) -> u64 {
        self.modulus
    }
    
    /// Check if this scheme is valid.
    /// 
    /// A scheme is valid if all its parameters are consistent.
    pub fn is_valid(&self) -> bool {
        self.threshold > 0 
            && self.total_shares > 0 
            && self.threshold <= self.total_shares 
            && self.total_shares < self.modulus as usize
            && is_prime(self.modulus)
    }
}

/// Check if a number is prime (simple implementation).
/// 
/// This is a simple primality test that works for small numbers.
/// For production use, a more sophisticated primality test should be used.
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

/// Create shares for a secret using Shamir's scheme.
/// 
/// This is a convenience function that creates a scheme and shares
/// a secret in one step.
/// 
/// # Arguments
/// * `secret` - The secret to share
/// * `threshold` - The minimum number of shares needed for reconstruction
/// * `total_shares` - The total number of shares to create
/// * `modulus` - The field modulus
/// 
/// # Returns
/// A vector of shares
/// 
/// # Errors
/// Returns an error if the parameters are invalid or sharing fails
pub fn create_shares(
    secret: FiniteField,
    threshold: usize,
    total_shares: usize,
    modulus: u64
) -> CryptoResult<Vec<Share>> {
    let scheme = ShamirScheme::new(threshold, total_shares, modulus)?;
    scheme.share(secret)
}

/// Reconstruct a secret from shares.
/// 
/// This is a convenience function that creates a scheme and reconstructs
/// a secret in one step.
/// 
/// # Arguments
/// * `shares` - The shares to use for reconstruction
/// * `threshold` - The threshold for reconstruction
/// 
/// # Returns
/// The reconstructed secret
/// 
/// # Errors
/// Returns an error if reconstruction fails
pub fn reconstruct_secret(shares: &[Share], threshold: usize) -> CryptoResult<FiniteField> {
    if shares.is_empty() {
        return Err(CryptoError::InvalidFieldElement(
            "No shares provided for reconstruction".to_string()
        ));
    }
    
    let modulus = shares[0].modulus();
    let scheme = ShamirScheme::new(threshold, shares.len(), modulus)?;
    scheme.reconstruct(shares)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_scheme_creation() {
        let scheme = ShamirScheme::new(2, 5, 17).unwrap();
        assert_eq!(scheme.threshold(), 2);
        assert_eq!(scheme.total_shares(), 5);
        assert_eq!(scheme.modulus(), 17);
        assert!(scheme.is_valid());
    }

    #[test]
    fn test_shamir_scheme_invalid_params() {
        // Threshold greater than total shares
        let result = ShamirScheme::new(5, 3, 17);
        assert!(result.is_err());
        
        // Total shares greater than or equal to modulus
        let result = ShamirScheme::new(2, 17, 17);
        assert!(result.is_err());
        
        // Non-prime modulus
        let result = ShamirScheme::new(2, 5, 15);
        assert!(result.is_err());
    }

    #[test]
    fn test_shamir_sharing_and_reconstruction() {
        let scheme = ShamirScheme::new(2, 5, 17).unwrap();
        let secret = FiniteField::new(42, 17).unwrap();
        
        // Create shares
        let shares = scheme.share(secret).unwrap();
        assert_eq!(shares.len(), 5);
        
        // Reconstruct with all shares
        let reconstructed = scheme.reconstruct(&shares).unwrap();
        assert_eq!(reconstructed.value(), secret.value());
        
        // Reconstruct with threshold shares
        let threshold_shares = &shares[..2];
        let reconstructed = scheme.reconstruct(threshold_shares).unwrap();
        assert_eq!(reconstructed.value(), secret.value());
    }

    #[test]
    fn test_shamir_insufficient_shares() {
        let scheme = ShamirScheme::new(3, 5, 17).unwrap();
        let secret = FiniteField::new(42, 17).unwrap();
        
        let shares = scheme.share(secret).unwrap();
        
        // Try to reconstruct with insufficient shares
        let insufficient_shares = &shares[..2];
        let result = scheme.reconstruct(insufficient_shares);
        assert!(result.is_err());
    }

    #[test]
    fn test_shamir_share_set_reconstruction() {
        let scheme = ShamirScheme::new(2, 5, 17).unwrap();
        let secret = FiniteField::new(42, 17).unwrap();
        
        let shares = scheme.share(secret).unwrap();
        let share_set = ShareSet::new(shares, 2).unwrap();
        
        let reconstructed = scheme.reconstruct_from_set(&share_set).unwrap();
        assert_eq!(reconstructed.value(), secret.value());
    }

    #[test]
    fn test_shamir_verify_shares() {
        let scheme = ShamirScheme::new(2, 5, 17).unwrap();
        let secret = FiniteField::new(42, 17).unwrap();
        
        let shares = scheme.share(secret).unwrap();
        
        // Verify with sufficient shares
        let is_valid = scheme.verify_shares(&shares).unwrap();
        assert!(is_valid);
        
        // Verify with insufficient shares
        let insufficient_shares = &shares[..1];
        let is_valid = scheme.verify_shares(insufficient_shares).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_create_shares_convenience() {
        let secret = FiniteField::new(42, 17).unwrap();
        let shares = create_shares(secret, 2, 5, 17).unwrap();
        
        assert_eq!(shares.len(), 5);
        
        let reconstructed = reconstruct_secret(&shares, 2).unwrap();
        assert_eq!(reconstructed.value(), secret.value());
    }

    #[test]
    fn test_is_prime() {
        assert!(!is_prime(0));
        assert!(!is_prime(1));
        assert!(is_prime(2));
        assert!(is_prime(3));
        assert!(!is_prime(4));
        assert!(is_prime(5));
        assert!(!is_prime(6));
        assert!(is_prime(7));
        assert!(!is_prime(8));
        assert!(!is_prime(9));
        assert!(!is_prime(10));
        assert!(is_prime(11));
        assert!(is_prime(17));
    }
} 