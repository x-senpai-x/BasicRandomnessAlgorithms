//! Share implementation for Shamir secret sharing.
//!
//! This module provides the Share struct and related functionality
//! for representing and manipulating shares in Shamir's secret sharing scheme.

use crypto_core::{CryptoError, CryptoResult};
use crypto_field::FiniteField;
use thiserror::Error;

/// Error type for share operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ShareError {
    #[error("Invalid share index: {0}")]
    InvalidIndex(usize),
    #[error("Invalid share value: {0}")]
    InvalidValue(String),
    #[error("Insufficient shares for reconstruction: {0}")]
    InsufficientShares(String),
    #[error("Field error: {0}")]
    FieldError(String),
}

/// Represents a share in Shamir's secret sharing scheme.
///
/// A share consists of an index (x-coordinate) and a value (y-coordinate)
/// that lie on a polynomial of degree k-1, where k is the threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// The index (x-coordinate) of this share
    pub index: usize,
    /// The value (y-coordinate) of this share
    pub value: FiniteField,
}

impl Share {
    /// Create a new share.
    ///
    /// # Arguments
    /// * `index` - The index (x-coordinate) of the share
    /// * `value` - The value (y-coordinate) of the share
    ///
    /// # Returns
    /// A new share
    ///
    /// # Errors
    /// Returns an error if the index is invalid
    pub fn new(index: usize, value: FiniteField) -> CryptoResult<Self> {
        if index == 0 {
            return Err(CryptoError::InvalidFieldElement(
                "Share index cannot be zero".to_string(),
            ));
        }

        Ok(Self { index, value })
    }

    /// Get the index of this share.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Get the value of this share.
    pub fn value(&self) -> FiniteField {
        self.value
    }

    /// Get the modulus of the field this share belongs to.
    pub fn modulus(&self) -> u64 {
        self.value.modulus()
    }

    /// Check if this share is valid.
    ///
    /// A share is valid if its index is non-zero.
    /// The value is always valid since FiniteField validates on construction.
    pub fn is_valid(&self) -> bool {
        self.index != 0
    }

    /// Convert this share to a point for polynomial interpolation.
    ///
    /// # Returns
    /// A tuple of (x, y) coordinates as field elements
    ///
    /// # Errors
    /// Returns an error if the conversion fails
    pub fn to_point(&self) -> CryptoResult<(FiniteField, FiniteField)> {
        let x = FiniteField::new(self.index as u64, self.modulus())?;
        Ok((x, self.value))
    }

    /// Create a share from a point.
    ///
    /// # Arguments
    /// * `x` - The x-coordinate
    /// * `y` - The y-coordinate
    ///
    /// # Returns
    /// A new share
    ///
    /// # Errors
    /// Returns an error if the coordinates are invalid
    pub fn from_point(x: FiniteField, y: FiniteField) -> CryptoResult<Self> {
        if x.value() == 0 {
            return Err(CryptoError::InvalidFieldElement(
                "Share index cannot be zero".to_string(),
            ));
        }

        if x.modulus() != y.modulus() {
            return Err(CryptoError::InvalidFieldElement(
                "Coordinates must belong to the same field".to_string(),
            ));
        }

        Ok(Self {
            index: x.value() as usize,
            value: y,
        })
    }
}

impl std::fmt::Display for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Share({}, {})", self.index, self.value)
    }
}

/// A collection of shares for Shamir secret sharing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareSet {
    /// The shares in this set
    pub shares: Vec<Share>,
    /// The threshold (minimum number of shares needed for reconstruction)
    pub threshold: usize,
}

impl ShareSet {
    /// Create a new share set.
    ///
    /// # Arguments
    /// * `shares` - The shares in this set
    /// * `threshold` - The threshold for reconstruction
    ///
    /// # Returns
    /// A new share set
    ///
    /// # Errors
    /// Returns an error if the shares are invalid or the threshold is too high
    pub fn new(shares: Vec<Share>, threshold: usize) -> CryptoResult<Self> {
        if shares.is_empty() {
            return Err(CryptoError::InvalidFieldElement(
                "Share set cannot be empty".to_string(),
            ));
        }

        if threshold == 0 {
            return Err(CryptoError::InvalidFieldElement(
                "Threshold must be positive".to_string(),
            ));
        }

        if threshold > shares.len() {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Threshold {} cannot be greater than number of shares {}",
                threshold,
                shares.len()
            )));
        }

        // Check that all shares belong to the same field
        let modulus = shares[0].modulus();
        for share in &shares {
            if share.modulus() != modulus {
                return Err(CryptoError::InvalidFieldElement(
                    "All shares must belong to the same field".to_string(),
                ));
            }
        }

        // Check that all shares have unique indices
        let mut indices = std::collections::HashSet::new();
        for share in &shares {
            if !indices.insert(share.index) {
                return Err(CryptoError::InvalidFieldElement(format!(
                    "Duplicate share index: {}",
                    share.index
                )));
            }
        }

        Ok(Self { shares, threshold })
    }

    /// Get the number of shares in this set.
    pub fn len(&self) -> usize {
        self.shares.len()
    }

    /// Check if this share set is empty.
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    /// Get the threshold for reconstruction.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Get the modulus of the field this share set belongs to.
    pub fn modulus(&self) -> u64 {
        if self.shares.is_empty() {
            0
        } else {
            self.shares[0].modulus()
        }
    }

    /// Check if this share set has enough shares for reconstruction.
    pub fn has_sufficient_shares(&self) -> bool {
        self.shares.len() >= self.threshold
    }

    /// Get a subset of shares with the given indices.
    ///
    /// # Arguments
    /// * `indices` - The indices of shares to include
    ///
    /// # Returns
    /// A new share set containing only the specified shares
    ///
    /// # Errors
    /// Returns an error if any index is not found or the subset is invalid
    pub fn subset(&self, indices: &[usize]) -> CryptoResult<Self> {
        if indices.len() < self.threshold {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Need at least {} shares for reconstruction, got {}",
                self.threshold,
                indices.len()
            )));
        }

        let mut subset_shares = Vec::new();
        for &index in indices {
            let share = self
                .shares
                .iter()
                .find(|s| s.index == index)
                .ok_or_else(|| {
                    CryptoError::InvalidFieldElement(format!(
                        "Share with index {} not found",
                        index
                    ))
                })?;
            subset_shares.push(share.clone());
        }

        Self::new(subset_shares, self.threshold)
    }

    /// Get the first k shares where k is the threshold.
    ///
    /// # Returns
    /// A new share set containing the first threshold shares
    ///
    /// # Errors
    /// Returns an error if there are insufficient shares
    pub fn first_k_shares(&self) -> CryptoResult<Self> {
        if self.shares.len() < self.threshold {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Need at least {} shares, have {}",
                self.threshold,
                self.shares.len()
            )));
        }

        let subset_shares = self.shares[..self.threshold].to_vec();
        Self::new(subset_shares, self.threshold)
    }

    /// Convert this share set to points for polynomial interpolation.
    ///
    /// # Returns
    /// A vector of (x, y) coordinate pairs
    ///
    /// # Errors
    /// Returns an error if any share conversion fails
    pub fn to_points(&self) -> CryptoResult<Vec<(FiniteField, FiniteField)>> {
        let mut points = Vec::with_capacity(self.shares.len());
        for share in &self.shares {
            points.push(share.to_point()?);
        }
        Ok(points)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_creation() {
        let value = FiniteField::new(42, 17).unwrap();
        let share = Share::new(1, value).unwrap();

        assert_eq!(share.index(), 1);
        assert_eq!(share.value(), value);
        assert_eq!(share.modulus(), 17);
        assert!(share.is_valid());
    }

    #[test]
    fn test_share_invalid_index() {
        let value = FiniteField::new(42, 17).unwrap();
        let result = Share::new(0, value);
        assert!(result.is_err());
    }

    #[test]
    fn test_share_to_point() {
        let value = FiniteField::new(42, 17).unwrap();
        let share = Share::new(3, value).unwrap();

        let (x, y) = share.to_point().unwrap();
        assert_eq!(x.value(), 3);
        assert_eq!(y.value(), 42);
    }

    #[test]
    fn test_share_from_point() {
        let x = FiniteField::new(5, 17).unwrap();
        let y = FiniteField::new(42, 17).unwrap();

        let share = Share::from_point(x, y).unwrap();
        assert_eq!(share.index(), 5);
        assert_eq!(share.value().value(), 42);
    }

    #[test]
    fn test_share_set_creation() {
        let shares = vec![
            Share::new(1, FiniteField::new(10, 17).unwrap()).unwrap(),
            Share::new(2, FiniteField::new(20, 17).unwrap()).unwrap(),
            Share::new(3, FiniteField::new(30, 17).unwrap()).unwrap(),
        ];

        let share_set = ShareSet::new(shares, 2).unwrap();
        assert_eq!(share_set.len(), 3);
        assert_eq!(share_set.threshold(), 2);
        assert!(share_set.has_sufficient_shares());
    }

    #[test]
    fn test_share_set_insufficient_shares() {
        let shares = vec![Share::new(1, FiniteField::new(10, 17).unwrap()).unwrap()];

        let result = ShareSet::new(shares, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_share_set_subset() {
        let shares = vec![
            Share::new(1, FiniteField::new(10, 17).unwrap()).unwrap(),
            Share::new(2, FiniteField::new(20, 17).unwrap()).unwrap(),
            Share::new(3, FiniteField::new(30, 17).unwrap()).unwrap(),
        ];

        let share_set = ShareSet::new(shares, 2).unwrap();
        let subset = share_set.subset(&[1, 2]).unwrap();

        assert_eq!(subset.len(), 2);
        assert_eq!(subset.threshold(), 2);
    }

    #[test]
    fn test_share_set_first_k_shares() {
        let shares = vec![
            Share::new(1, FiniteField::new(10, 17).unwrap()).unwrap(),
            Share::new(2, FiniteField::new(20, 17).unwrap()).unwrap(),
            Share::new(3, FiniteField::new(30, 17).unwrap()).unwrap(),
        ];

        let share_set = ShareSet::new(shares, 2).unwrap();
        let first_k = share_set.first_k_shares().unwrap();

        assert_eq!(first_k.len(), 2);
        assert_eq!(first_k.shares[0].index(), 1);
        assert_eq!(first_k.shares[1].index(), 2);
    }
}
