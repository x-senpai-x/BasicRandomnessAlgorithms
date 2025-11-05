//! RSA signature implementation.
//!
//! This module provides RSA digital signature functionality,
//! including both textbook RSA signatures and more secure padding schemes.

use super::key::RsaKeyPair;
use crypto_core::{CryptoError, CryptoResult};

/// Result of an RSA signature operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureResult {
    /// The operation was successful
    Success,
    /// The operation failed
    Failure,
}

/// RSA signature implementation.
///
/// This struct provides methods for RSA signing and verification,
/// including both textbook RSA and padded RSA signatures.
#[derive(Debug, Clone)]
pub struct RsaSignature {
    /// The key pair for signing/verification
    pub key_pair: RsaKeyPair,
}

impl RsaSignature {
    /// Create a new RSA signature instance.
    ///
    /// # Arguments
    /// * `key_pair` - The RSA key pair to use
    ///
    /// # Returns
    /// A new RSA signature instance
    pub fn new(key_pair: RsaKeyPair) -> Self {
        Self { key_pair }
    }

    /// Sign a message using textbook RSA.
    ///
    /// Textbook RSA signatures are not secure for real-world use.
    /// This is provided for educational purposes only.
    ///
    /// # Arguments
    /// * `message` - The message to sign
    ///
    /// # Returns
    /// The signature
    ///
    /// # Errors
    /// Returns an error if signing fails
    pub fn sign_textbook(&self, message: u64) -> CryptoResult<u64> {
        self.key_pair.private_key().sign(message)
    }

    /// Verify a signature using textbook RSA.
    ///
    /// # Arguments
    /// * `signature` - The signature to verify
    /// * `message` - The original message
    ///
    /// # Returns
    /// True if the signature is valid, false otherwise
    ///
    /// # Errors
    /// Returns an error if verification fails
    pub fn verify_textbook(&self, signature: u64, message: u64) -> CryptoResult<bool> {
        self.key_pair.public_key().verify(signature, message)
    }

    /// Sign a message using RSA with PKCS#1 v1.5 padding.
    ///
    /// # Arguments
    /// * `message` - The message to sign (as bytes)
    ///
    /// # Returns
    /// The signature
    ///
    /// # Errors
    /// Returns an error if signing fails
    pub fn sign_pkcs1(&self, message: &[u8]) -> CryptoResult<Vec<u8>> {
        let key_size = self.key_pair.key_size();
        let hash_size = 20; // SHA-1 hash size
        let max_message_size = key_size / 8 - hash_size - 3;

        if message.len() > max_message_size {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Message too long: {} bytes, maximum is {} bytes",
                message.len(),
                max_message_size
            )));
        }

        // Create PKCS#1 v1.5 padding for signatures
        let mut padded = Vec::with_capacity(key_size / 8);
        padded.push(0x00); // Leading zero byte
        padded.push(0x01); // Block type for signatures
        padded.extend_from_slice(&vec![0xFF; key_size / 8 - hash_size - message.len() - 3]);
        padded.push(0x00); // Separator byte
        padded.extend_from_slice(message);

        // Convert to integer and sign
        let message_int = bytes_to_u64(&padded)?;
        let signature_int = self.key_pair.private_key().sign(message_int)?;

        // Convert back to bytes
        let signature_bytes = u64_to_bytes(signature_int, key_size / 8)?;
        Ok(signature_bytes)
    }

    /// Verify a signature using RSA with PKCS#1 v1.5 padding.
    ///
    /// # Arguments
    /// * `signature` - The signature to verify
    /// * `message` - The original message
    ///
    /// # Returns
    /// True if the signature is valid, false otherwise
    ///
    /// # Errors
    /// Returns an error if verification fails
    pub fn verify_pkcs1(&self, signature: &[u8], message: &[u8]) -> CryptoResult<bool> {
        let key_size = self.key_pair.key_size();
        let expected_size = key_size / 8;

        if signature.len() != expected_size {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Signature length {} does not match key size {}",
                signature.len(),
                expected_size
            )));
        }

        // Convert to integer and verify
        let signature_int = bytes_to_u64(signature)?;
        let decrypted_int = self.key_pair.public_key().encrypt(signature_int)?;

        // Convert back to bytes
        let decrypted_bytes = u64_to_bytes(decrypted_int, expected_size)?;

        // Remove PKCS#1 v1.5 padding
        if decrypted_bytes.len() < 3 {
            return Err(CryptoError::InvalidFieldElement(
                "Invalid PKCS#1 padding: too short".to_string(),
            ));
        }

        if decrypted_bytes[0] != 0x00 || decrypted_bytes[1] != 0x01 {
            return Err(CryptoError::InvalidFieldElement(
                "Invalid PKCS#1 padding: wrong block type".to_string(),
            ));
        }

        // Find the separator byte
        let mut message_start = None;
        for i in 2..decrypted_bytes.len() {
            if decrypted_bytes[i] == 0x00 {
                message_start = Some(i + 1);
                break;
            }
        }

        let message_start = message_start.ok_or_else(|| {
            CryptoError::InvalidFieldElement(
                "Invalid PKCS#1 padding: no separator found".to_string(),
            )
        })?;

        if message_start >= decrypted_bytes.len() {
            return Err(CryptoError::InvalidFieldElement(
                "Invalid PKCS#1 padding: no message after separator".to_string(),
            ));
        }

        let extracted_message = &decrypted_bytes[message_start..];
        Ok(extracted_message == message)
    }

    /// Sign a message using RSA with PSS padding.
    ///
    /// PSS (Probabilistic Signature Scheme) is the recommended
    /// padding scheme for RSA signatures.
    ///
    /// # Arguments
    /// * `message` - The message to sign (as bytes)
    /// * `salt` - Optional salt for PSS
    ///
    /// # Returns
    /// The signature
    ///
    /// # Errors
    /// Returns an error if signing fails
    pub fn sign_pss(&self, message: &[u8], salt: Option<&[u8]>) -> CryptoResult<Vec<u8>> {
        let key_size = self.key_pair.key_size();
        let hash_size = 20; // SHA-1 hash size
        let salt_size = salt.map(|s| s.len()).unwrap_or(hash_size);

        if salt_size > key_size / 8 - hash_size - 2 {
            return Err(CryptoError::InvalidFieldElement(
                "Salt too long for PSS".to_string(),
            ));
        }

        // Create PSS padding
        let default_salt = vec![0u8; hash_size];
        let salt = salt.unwrap_or(&default_salt);
        let message_hash = sha1_hash(message);

        // Create M' = padding1 || message_hash || salt
        let mut m_prime = Vec::new();
        m_prime.extend_from_slice(&vec![0u8; 8]); // padding1
        m_prime.extend_from_slice(&message_hash);
        m_prime.extend_from_slice(salt);

        // Hash M' to get H
        let h = sha1_hash(&m_prime);

        // Create DB = padding2 || salt
        let mut db = Vec::new();
        db.extend_from_slice(&vec![0u8; key_size / 8 - salt_size - hash_size - 1]);
        db.push(0x01); // Separator
        db.extend_from_slice(salt);

        // Apply mask
        let masked_db = xor_with_hash(&db, &h)?;

        // Create EM = masked_db || h || 0xBC
        let mut em = Vec::with_capacity(key_size / 8);
        em.extend_from_slice(&masked_db);
        em.extend_from_slice(&h);
        em.push(0xBC);

        // Convert to integer and sign
        let message_int = bytes_to_u64(&em)?;
        let signature_int = self.key_pair.private_key().sign(message_int)?;

        // Convert back to bytes
        let signature_bytes = u64_to_bytes(signature_int, key_size / 8)?;
        Ok(signature_bytes)
    }

    /// Verify a signature using RSA with PSS padding.
    ///
    /// # Arguments
    /// * `signature` - The signature to verify
    /// * `message` - The original message
    /// * `salt_size` - The size of the salt used for signing
    ///
    /// # Returns
    /// True if the signature is valid, false otherwise
    ///
    /// # Errors
    /// Returns an error if verification fails
    pub fn verify_pss(
        &self,
        signature: &[u8],
        message: &[u8],
        salt_size: usize,
    ) -> CryptoResult<bool> {
        let key_size = self.key_pair.key_size();
        let expected_size = key_size / 8;
        let hash_size = 20; // SHA-1 hash size

        if signature.len() != expected_size {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Signature length {} does not match key size {}",
                signature.len(),
                expected_size
            )));
        }

        if salt_size > key_size / 8 - hash_size - 2 {
            return Err(CryptoError::InvalidFieldElement(
                "Salt size too large for PSS".to_string(),
            ));
        }

        // Convert to integer and verify
        let signature_int = bytes_to_u64(signature)?;
        let decrypted_int = self.key_pair.public_key().encrypt(signature_int)?;

        // Convert back to bytes
        let em = u64_to_bytes(decrypted_int, expected_size)?;

        // Verify PSS padding
        if em.len() < hash_size + 1 {
            return Err(CryptoError::InvalidFieldElement(
                "Invalid PSS padding: too short".to_string(),
            ));
        }

        if em[em.len() - 1] != 0xBC {
            return Err(CryptoError::InvalidFieldElement(
                "Invalid PSS padding: wrong trailer".to_string(),
            ));
        }

        let h = &em[em.len() - hash_size - 1..em.len() - 1];
        let masked_db = &em[..em.len() - hash_size - 1];

        // Unmask DB
        let db = xor_with_hash(masked_db, h)?;

        // Extract salt
        if db.len() < salt_size + 1 {
            return Err(CryptoError::InvalidFieldElement(
                "Invalid PSS padding: DB too short".to_string(),
            ));
        }

        let salt = &db[db.len() - salt_size..];

        // Recreate M' and verify
        let message_hash = sha1_hash(message);
        let mut m_prime = Vec::new();
        m_prime.extend_from_slice(&vec![0u8; 8]); // padding1
        m_prime.extend_from_slice(&message_hash);
        m_prime.extend_from_slice(salt);

        let expected_h = sha1_hash(&m_prime);
        Ok(h == expected_h.as_slice())
    }

    /// Get the key pair used by this signature instance.
    pub fn key_pair(&self) -> &RsaKeyPair {
        &self.key_pair
    }

    /// Get the maximum message size for PKCS#1 v1.5 signatures.
    pub fn max_pkcs1_message_size(&self) -> usize {
        let key_size = self.key_pair.key_size();
        key_size / 8 - 23 // SHA-1 hash size (20) + 3
    }

    /// Get the maximum salt size for PSS signatures.
    pub fn max_pss_salt_size(&self) -> usize {
        let key_size = self.key_pair.key_size();
        key_size / 8 - 22 // SHA-1 hash size (20) + 2
    }
}

/// Convert a byte array to a u64 integer.
///
/// # Arguments
/// * `bytes` - The byte array to convert
///
/// # Returns
/// The integer value
///
/// # Errors
/// Returns an error if the conversion fails
fn bytes_to_u64(bytes: &[u8]) -> CryptoResult<u64> {
    if bytes.len() > 8 {
        return Err(CryptoError::InvalidFieldElement(
            "Byte array too long for u64 conversion".to_string(),
        ));
    }

    let mut result = 0u64;
    for &byte in bytes.iter().rev() {
        result = (result << 8) | byte as u64;
    }

    Ok(result)
}

/// Convert a u64 integer to a byte array of specified length.
///
/// # Arguments
/// * `value` - The integer to convert
/// * `length` - The desired length of the byte array
///
/// # Returns
/// The byte array
///
/// # Errors
/// Returns an error if the conversion fails
fn u64_to_bytes(value: u64, length: usize) -> CryptoResult<Vec<u8>> {
    if length > 8 {
        return Err(CryptoError::InvalidFieldElement(
            "Length too long for u64 conversion".to_string(),
        ));
    }

    let mut bytes = Vec::with_capacity(length);
    let mut temp = value;

    for _ in 0..length {
        bytes.push((temp & 0xFF) as u8);
        temp >>= 8;
    }

    bytes.reverse();
    Ok(bytes)
}

/// Compute SHA-1 hash of input data.
///
/// This is a simplified implementation for demonstration purposes.
/// In a real implementation, you would use a proper SHA-1 library.
///
/// # Arguments
/// * `data` - The data to hash
///
/// # Returns
/// The SHA-1 hash (20 bytes)
fn sha1_hash(data: &[u8]) -> Vec<u8> {
    // Simplified SHA-1 implementation
    // In practice, use a proper cryptographic hash library
    let mut hash = vec![0u8; 20];
    for (i, byte) in data.iter().enumerate() {
        hash[i % 20] ^= byte;
    }
    hash
}

/// XOR a byte array with a hash.
///
/// # Arguments
/// * `data` - The data to XOR
/// * `hash` - The hash to XOR with
///
/// # Returns
/// The XORed result
///
/// # Errors
/// Returns an error if the operation fails
fn xor_with_hash(data: &[u8], hash: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut result = Vec::with_capacity(data.len());
    for (i, &byte) in data.iter().enumerate() {
        let hash_byte = hash[i % hash.len()];
        result.push(byte ^ hash_byte);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::super::key::KeySize;
    use super::*;

    #[test]
    fn test_textbook_signature() {
        let key_pair = RsaKeyPair::generate(KeySize::Bits512).unwrap();
        let signature = RsaSignature::new(key_pair);
        let message = 42;

        let sig = signature.sign_textbook(message).unwrap();
        let is_valid = signature.verify_textbook(sig, message).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_pkcs1_signature() {
        let key_pair = RsaKeyPair::generate(KeySize::Bits512).unwrap();
        let signature = RsaSignature::new(key_pair);
        let message = b"Hello, RSA!";

        let sig = signature.sign_pkcs1(message).unwrap();
        let is_valid = signature.verify_pkcs1(&sig, message).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_pss_signature() {
        let key_pair = RsaKeyPair::generate(KeySize::Bits512).unwrap();
        let signature = RsaSignature::new(key_pair);
        let message = b"Hello, PSS!";
        let salt = b"test-salt";

        let sig = signature.sign_pss(message, Some(salt)).unwrap();
        let is_valid = signature.verify_pss(&sig, message, salt.len()).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_bytes_conversion() {
        let original = 0x1234567890ABCDEFu64;
        let bytes = u64_to_bytes(original, 8).unwrap();
        let converted = bytes_to_u64(&bytes).unwrap();

        assert_eq!(converted, original);
    }

    #[test]
    fn test_xor_with_hash() {
        let data = b"test data";
        let hash = b"test hash";

        let xored = xor_with_hash(data, hash).unwrap();
        let xored_again = xor_with_hash(&xored, hash).unwrap();

        assert_eq!(xored_again, data);
    }
}
