//! Binary utilities for multilinear extensions.
//! 
//! This module provides utilities for converting between decimal and binary
//! representations, which are essential for multilinear extension operations.

use crypto_core::{CryptoError, CryptoResult};

/// Convert a decimal number to its binary representation.
/// 
/// # Arguments
/// * `decimal` - The decimal number to convert
/// 
/// # Returns
/// A vector representing the binary digits (least significant bit first)
/// 
/// # Examples
/// ```
/// use crypto_multilinear::dec_to_bin;
/// 
/// assert_eq!(dec_to_bin(0), vec![0]);
/// assert_eq!(dec_to_bin(1), vec![1]);
/// assert_eq!(dec_to_bin(2), vec![1, 0]);
/// assert_eq!(dec_to_bin(5), vec![1, 0, 1]);
/// ```
pub fn dec_to_bin(decimal: u64) -> Vec<u8> {
    if decimal == 0 {
        return vec![0];
    }
    
    let mut num = decimal;
    let mut binary = Vec::new();
    
    while num > 0 {
        binary.push((num % 2) as u8);
        num /= 2;
    }
    
    binary
}

/// Convert a decimal number to its binary representation with a fixed number of bits.
/// 
/// # Arguments
/// * `decimal` - The decimal number to convert
/// * `num_bits` - The number of bits in the output
/// 
/// # Returns
/// A vector representing the binary digits with exactly `num_bits` elements
/// 
/// # Errors
/// Returns an error if the decimal number is too large for the specified number of bits
/// 
/// # Examples
/// ```
/// use crypto_multilinear::dec_to_bin_fixed;
/// 
/// assert_eq!(dec_to_bin_fixed(5, 4).unwrap(), vec![1, 0, 1, 0]);
/// assert_eq!(dec_to_bin_fixed(0, 3).unwrap(), vec![0, 0, 0]);
/// ```
pub fn dec_to_bin_fixed(decimal: u64, num_bits: usize) -> CryptoResult<Vec<u8>> {
    if decimal >= (1 << num_bits) {
        return Err(CryptoError::InvalidFieldElement(
            format!("Decimal {} is too large for {} bits", decimal, num_bits)
        ));
    }
    
    let mut binary = vec![0; num_bits];
    let mut num = decimal;
    
    for i in 0..num_bits {
        binary[i] = (num % 2) as u8;
        num /= 2;
    }
    
    Ok(binary)
}

/// Convert a binary representation back to decimal.
/// 
/// # Arguments
/// * `binary` - The binary digits (least significant bit first)
/// 
/// # Returns
/// The decimal representation
/// 
/// # Examples
/// ```
/// use crypto_multilinear::bin_to_dec;
/// 
/// assert_eq!(bin_to_dec(&[0]), 0);
/// assert_eq!(bin_to_dec(&[1]), 1);
/// assert_eq!(bin_to_dec(&[1, 0]), 2);
/// assert_eq!(bin_to_dec(&[1, 0, 1]), 5);
/// ```
pub fn bin_to_dec(binary: &[u8]) -> u64 {
    let mut decimal = 0;
    let mut power = 1;
    
    for &bit in binary {
        decimal += (bit as u64) * power;
        power *= 2;
    }
    
    decimal
}

/// Compute the Hamming weight (number of 1s) in a binary representation.
/// 
/// # Arguments
/// * `binary` - The binary digits
/// 
/// # Returns
/// The number of 1s in the binary representation
/// 
/// # Examples
/// ```
/// use crypto_multilinear::hamming_weight;
/// 
/// assert_eq!(hamming_weight(&[0, 0, 0]), 0);
/// assert_eq!(hamming_weight(&[1, 0, 1]), 2);
/// assert_eq!(hamming_weight(&[1, 1, 1]), 3);
/// ```
pub fn hamming_weight(binary: &[u8]) -> usize {
    binary.iter().map(|&bit| bit as usize).sum()
}

/// Check if two binary representations are equal.
/// 
/// # Arguments
/// * `a` - First binary representation
/// * `b` - Second binary representation
/// 
/// # Returns
/// True if the binary representations are equal, false otherwise
/// 
/// # Examples
/// ```
/// use crypto_multilinear::binary_equal;
/// 
/// assert!(binary_equal(&[1, 0, 1], &[1, 0, 1]));
/// assert!(!binary_equal(&[1, 0, 1], &[1, 1, 0]));
/// ```
pub fn binary_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    a.iter().zip(b.iter()).all(|(&x, &y)| x == y)
}

/// Compute the bitwise AND of two binary representations.
/// 
/// # Arguments
/// * `a` - First binary representation
/// * `b` - Second binary representation
/// 
/// # Returns
/// The bitwise AND of the two binary representations
/// 
/// # Examples
/// ```
/// use crypto_multilinear::binary_and;
/// 
/// assert_eq!(binary_and(&[1, 0, 1], &[1, 1, 0]), vec![1, 0, 0]);
/// ```
pub fn binary_and(a: &[u8], b: &[u8]) -> Vec<u8> {
    let max_len = std::cmp::max(a.len(), b.len());
    let mut result = vec![0; max_len];
    
    for i in 0..max_len {
        let bit_a = if i < a.len() { a[i] } else { 0 };
        let bit_b = if i < b.len() { b[i] } else { 0 };
        result[i] = bit_a & bit_b;
    }
    
    result
}

/// Compute the bitwise XOR of two binary representations.
/// 
/// # Arguments
/// * `a` - First binary representation
/// * `b` - Second binary representation
/// 
/// # Returns
/// The bitwise XOR of the two binary representations
/// 
/// # Examples
/// ```
/// use crypto_multilinear::binary_xor;
/// 
/// assert_eq!(binary_xor(&[1, 0, 1], &[1, 1, 0]), vec![0, 1, 1]);
/// ```
pub fn binary_xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    let max_len = std::cmp::max(a.len(), b.len());
    let mut result = vec![0; max_len];
    
    for i in 0..max_len {
        let bit_a = if i < a.len() { a[i] } else { 0 };
        let bit_b = if i < b.len() { b[i] } else { 0 };
        result[i] = bit_a ^ bit_b;
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dec_to_bin() {
        assert_eq!(dec_to_bin(0), vec![0]);
        assert_eq!(dec_to_bin(1), vec![1]);
        assert_eq!(dec_to_bin(2), vec![1, 0]);
        assert_eq!(dec_to_bin(5), vec![1, 0, 1]);
        assert_eq!(dec_to_bin(10), vec![1, 0, 1, 0]);
        assert_eq!(dec_to_bin(255), vec![1, 1, 1, 1, 1, 1, 1, 1]);
    }

    #[test]
    fn test_dec_to_bin_fixed() {
        assert_eq!(dec_to_bin_fixed(5, 4).unwrap(), vec![1, 0, 1, 0]);
        assert_eq!(dec_to_bin_fixed(0, 3).unwrap(), vec![0, 0, 0]);
        assert_eq!(dec_to_bin_fixed(7, 3).unwrap(), vec![1, 1, 1]);
        
        // Test error case
        assert!(dec_to_bin_fixed(8, 3).is_err());
    }

    #[test]
    fn test_bin_to_dec() {
        assert_eq!(bin_to_dec(&[0]), 0);
        assert_eq!(bin_to_dec(&[1]), 1);
        assert_eq!(bin_to_dec(&[1, 0]), 2);
        assert_eq!(bin_to_dec(&[1, 0, 1]), 5);
        assert_eq!(bin_to_dec(&[1, 0, 1, 0]), 10);
    }

    #[test]
    fn test_hamming_weight() {
        assert_eq!(hamming_weight(&[0, 0, 0]), 0);
        assert_eq!(hamming_weight(&[1, 0, 1]), 2);
        assert_eq!(hamming_weight(&[1, 1, 1]), 3);
        assert_eq!(hamming_weight(&[1, 0, 1, 0]), 2);
    }

    #[test]
    fn test_binary_equal() {
        assert!(binary_equal(&[1, 0, 1], &[1, 0, 1]));
        assert!(!binary_equal(&[1, 0, 1], &[1, 1, 0]));
        assert!(!binary_equal(&[1, 0], &[1, 0, 1]));
    }

    #[test]
    fn test_binary_and() {
        assert_eq!(binary_and(&[1, 0, 1], &[1, 1, 0]), vec![1, 0, 0]);
        assert_eq!(binary_and(&[1, 1, 1], &[1, 1, 1]), vec![1, 1, 1]);
        assert_eq!(binary_and(&[1, 0], &[1, 1, 1]), vec![1, 0, 0]);
    }

    #[test]
    fn test_binary_xor() {
        assert_eq!(binary_xor(&[1, 0, 1], &[1, 1, 0]), vec![0, 1, 1]);
        assert_eq!(binary_xor(&[1, 1, 1], &[1, 1, 1]), vec![0, 0, 0]);
        assert_eq!(binary_xor(&[1, 0], &[1, 1, 1]), vec![0, 1, 1]);
    }
} 