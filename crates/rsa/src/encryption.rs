//! RSA encryption implementation.
//!
//! This module provides RSA encryption and decryption functionality,
//! including both textbook RSA and more secure padding schemes.

use super::key::RsaKeyPair;
use crypto_core::{CryptoError, CryptoResult};

/// Result of an RSA encryption operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionResult {
    /// The operation was successful
    Success,
    /// The operation failed
    Failure,
}

/// RSA encryption implementation.
///
/// This struct provides methods for RSA encryption and decryption,
/// including both textbook RSA and padded RSA.
#[derive(Debug, Clone)]
pub struct RsaEncryption {
    /// The key pair for encryption/decryption
    pub key_pair: RsaKeyPair,
}

impl RsaEncryption {
    /// Create a new RSA encryption instance.
    ///
    /// # Arguments
    /// * `key_pair` - The RSA key pair to use
    ///
    /// # Returns
    /// A new RSA encryption instance
    pub fn new(key_pair: RsaKeyPair) -> Self {
        Self { key_pair }
    }

    /// Encrypt a message using textbook RSA.
    ///
    /// Textbook RSA is not secure for real-world use due to various
    /// attacks. This is provided for educational purposes only.
    ///
    /// # Arguments
    /// * `message` - The message to encrypt
    ///
    /// # Returns
    /// The encrypted message
    ///
    /// # Errors
    /// Returns an error if encryption fails
    pub fn encrypt_textbook(&self, message: u64) -> CryptoResult<u64> {
        self.key_pair.public_key().encrypt(message)
    }

    /// Decrypt a message using textbook RSA.
    ///
    /// # Arguments
    /// * `ciphertext` - The ciphertext to decrypt
    ///
    /// # Returns
    /// The decrypted message
    ///
    /// # Errors
    /// Returns an error if decryption fails
    pub fn decrypt_textbook(&self, ciphertext: u64) -> CryptoResult<u64> {
        self.key_pair.private_key().decrypt(ciphertext)
    }

    /// Encrypt a message using RSA with PKCS#1 v1.5 padding.
    ///
    /// This is a more secure padding scheme than textbook RSA,
    /// though PKCS#1 v2.0 (OAEP) is recommended for new applications.
    ///
    /// # Arguments
    /// * `message` - The message to encrypt (as bytes)
    ///
    /// # Returns
    /// The encrypted message
    ///
    /// # Errors
    /// Returns an error if encryption fails
    pub fn encrypt_pkcs1(&self, message: &[u8]) -> CryptoResult<Vec<u8>> {
        let _modulus = self.key_pair.public_key().modulus();
        let key_size = self.key_pair.key_size();
        let max_message_size = key_size / 8 - 11; // PKCS#1 v1.5 requires at least 11 bytes of padding

        if message.len() > max_message_size {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Message too long: {} bytes, maximum is {} bytes",
                message.len(),
                max_message_size
            )));
        }

        // Create PKCS#1 v1.5 padding
        let mut padded = Vec::with_capacity(key_size / 8);
        padded.push(0x00); // Leading zero byte
        padded.push(0x02); // Block type for encryption

        // Add random non-zero padding bytes
        let padding_length = key_size / 8 - message.len() - 3;
        for _ in 0..padding_length {
            let mut random_byte;
            loop {
                random_byte = rand::random::<u8>();
                if random_byte != 0 {
                    break;
                }
            }
            padded.push(random_byte);
        }

        padded.push(0x00); // Separator byte
        padded.extend_from_slice(message);

        // Convert to integer and encrypt
        let message_int = bytes_to_u64(&padded)?;
        let encrypted_int = self.key_pair.public_key().encrypt(message_int)?;

        // Convert back to bytes
        let encrypted_bytes = u64_to_bytes(encrypted_int, key_size / 8)?;
        Ok(encrypted_bytes)
    }

    /// Decrypt a message using RSA with PKCS#1 v1.5 padding.
    ///
    /// # Arguments
    /// * `ciphertext` - The ciphertext to decrypt
    ///
    /// # Returns
    /// The decrypted message
    ///
    /// # Errors
    /// Returns an error if decryption fails
    pub fn decrypt_pkcs1(&self, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        let key_size = self.key_pair.key_size();
        let expected_size = key_size / 8;

        if ciphertext.len() != expected_size {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Ciphertext length {} does not match key size {}",
                ciphertext.len(),
                expected_size
            )));
        }

        // Convert to integer and decrypt
        let ciphertext_int = bytes_to_u64(ciphertext)?;
        let decrypted_int = self.key_pair.private_key().decrypt(ciphertext_int)?;

        // Convert back to bytes
        let decrypted_bytes = u64_to_bytes(decrypted_int, expected_size)?;

        // Remove PKCS#1 v1.5 padding
        if decrypted_bytes.len() < 3 {
            return Err(CryptoError::InvalidFieldElement(
                "Invalid PKCS#1 padding: too short".to_string(),
            ));
        }

        if decrypted_bytes[0] != 0x00 || decrypted_bytes[1] != 0x02 {
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

        Ok(decrypted_bytes[message_start..].to_vec())
    }

    /// Encrypt a message using RSA with OAEP padding.
    ///
    /// OAEP (Optimal Asymmetric Encryption Padding) is the recommended
    /// padding scheme for RSA encryption.
    ///
    /// # Arguments
    /// * `message` - The message to encrypt (as bytes)
    /// * `label` - Optional label for OAEP
    ///
    /// # Returns
    /// The encrypted message
    ///
    /// # Errors
    /// Returns an error if encryption fails
    pub fn encrypt_oaep(&self, message: &[u8], label: Option<&[u8]>) -> CryptoResult<Vec<u8>> {
        let _modulus = self.key_pair.public_key().modulus();
        let key_size = self.key_pair.key_size();
        let hash_size = 20; // SHA-1 hash size
        let max_message_size = key_size / 8 - 2 * hash_size - 2;

        if message.len() > max_message_size {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Message too long: {} bytes, maximum is {} bytes",
                message.len(),
                max_message_size
            )));
        }

        // Create OAEP padding
        let label = label.unwrap_or(b"");
        let label_hash = sha1_hash(label);

        // Generate random seed
        let mut seed = vec![0u8; hash_size];
        for byte in &mut seed {
            *byte = rand::random::<u8>();
        }

        // Create masked data block
        let mut data_block = Vec::with_capacity(key_size / 8 - 1);
        data_block.extend_from_slice(&label_hash);
        data_block.extend_from_slice(&vec![0u8; key_size / 8 - 2 * hash_size - message.len() - 1]);
        data_block.push(0x01); // Separator
        data_block.extend_from_slice(message);

        // Apply OAEP masking
        let masked_data = xor_with_hash(&data_block, &seed)?;
        let masked_seed = xor_with_hash(&seed, &label_hash)?;

        // Combine into final padded message
        let mut padded = Vec::with_capacity(key_size / 8);
        padded.push(0x00); // Leading zero byte
        padded.extend_from_slice(&masked_seed);
        padded.extend_from_slice(&masked_data);

        // Convert to integer and encrypt
        let message_int = bytes_to_u64(&padded)?;
        let encrypted_int = self.key_pair.public_key().encrypt(message_int)?;

        // Convert back to bytes
        let encrypted_bytes = u64_to_bytes(encrypted_int, key_size / 8)?;
        Ok(encrypted_bytes)
    }

    /// Decrypt a message using RSA with OAEP padding.
    ///
    /// # Arguments
    /// * `ciphertext` - The ciphertext to decrypt
    /// * `label` - Optional label for OAEP (must match the one used for encryption)
    ///
    /// # Returns
    /// The decrypted message
    ///
    /// # Errors
    /// Returns an error if decryption fails
    pub fn decrypt_oaep(&self, ciphertext: &[u8], label: Option<&[u8]>) -> CryptoResult<Vec<u8>> {
        let key_size = self.key_pair.key_size();
        let expected_size = key_size / 8;
        let hash_size = 20; // SHA-1 hash size

        if ciphertext.len() != expected_size {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Ciphertext length {} does not match key size {}",
                ciphertext.len(),
                expected_size
            )));
        }

        // Convert to integer and decrypt
        let ciphertext_int = bytes_to_u64(ciphertext)?;
        let decrypted_int = self.key_pair.private_key().decrypt(ciphertext_int)?;

        // Convert back to bytes
        let decrypted_bytes = u64_to_bytes(decrypted_int, expected_size)?;

        // Remove OAEP padding
        if decrypted_bytes.len() < 2 * hash_size + 2 {
            return Err(CryptoError::InvalidFieldElement(
                "Invalid OAEP padding: too short".to_string(),
            ));
        }

        if decrypted_bytes[0] != 0x00 {
            return Err(CryptoError::InvalidFieldElement(
                "Invalid OAEP padding: wrong leading byte".to_string(),
            ));
        }

        let label = label.unwrap_or(b"");
        let label_hash = sha1_hash(label);

        let masked_seed = &decrypted_bytes[1..hash_size + 1];
        let masked_data = &decrypted_bytes[hash_size + 1..];

        // Unmask the data
        let seed = xor_with_hash(masked_seed, &label_hash)?;
        let data_block = xor_with_hash(masked_data, &seed)?;

        // Verify label hash
        if data_block.len() < hash_size {
            return Err(CryptoError::InvalidFieldElement(
                "Invalid OAEP padding: data block too short".to_string(),
            ));
        }

        let data_label_hash = &data_block[..hash_size];
        if data_label_hash != label_hash.as_slice() {
            return Err(CryptoError::InvalidFieldElement(
                "Invalid OAEP padding: label hash mismatch".to_string(),
            ));
        }

        // Find the separator
        let mut message_start = None;
        for i in hash_size..data_block.len() {
            if data_block[i] == 0x01 {
                message_start = Some(i + 1);
                break;
            } else if data_block[i] != 0x00 {
                return Err(CryptoError::InvalidFieldElement(
                    "Invalid OAEP padding: non-zero padding byte".to_string(),
                ));
            }
        }

        let message_start = message_start.ok_or_else(|| {
            CryptoError::InvalidFieldElement("Invalid OAEP padding: no separator found".to_string())
        })?;

        if message_start >= data_block.len() {
            return Err(CryptoError::InvalidFieldElement(
                "Invalid OAEP padding: no message after separator".to_string(),
            ));
        }

        Ok(data_block[message_start..].to_vec())
    }

    /// Get the key pair used by this encryption instance.
    pub fn key_pair(&self) -> &RsaKeyPair {
        &self.key_pair
    }

    /// Get the maximum message size for PKCS#1 v1.5 encryption.
    pub fn max_pkcs1_message_size(&self) -> usize {
        let key_size = self.key_pair.key_size();
        key_size / 8 - 11
    }

    /// Get the maximum message size for OAEP encryption.
    pub fn max_oaep_message_size(&self) -> usize {
        let key_size = self.key_pair.key_size();
        key_size / 8 - 42 // 2 * SHA-1 hash size (20) + 2
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
    fn test_textbook_encryption() {
        let key_pair = RsaKeyPair::generate(KeySize::Bits512).unwrap();
        let encryption = RsaEncryption::new(key_pair);
        let message = 42;

        let ciphertext = encryption.encrypt_textbook(message).unwrap();
        let decrypted = encryption.decrypt_textbook(ciphertext).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_pkcs1_encryption() {
        let key_pair = RsaKeyPair::generate(KeySize::Bits512).unwrap();
        let encryption = RsaEncryption::new(key_pair);
        let message = b"Hello, RSA!";

        let ciphertext = encryption.encrypt_pkcs1(message).unwrap();
        let decrypted = encryption.decrypt_pkcs1(&ciphertext).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_oaep_encryption() {
        let key_pair = RsaKeyPair::generate(KeySize::Bits512).unwrap();
        let encryption = RsaEncryption::new(key_pair);
        let message = b"Hello, OAEP!";
        let label = b"test-label";

        let ciphertext = encryption.encrypt_oaep(message, Some(label)).unwrap();
        let decrypted = encryption.decrypt_oaep(&ciphertext, Some(label)).unwrap();

        assert_eq!(decrypted, message);
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
