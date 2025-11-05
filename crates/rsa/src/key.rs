//! RSA key generation and management.
//!
//! This module provides RSA key generation, including public and private key
//! structures and operations.

use crypto_core::{CryptoError, CryptoResult};

/// Supported RSA key sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySize {
    /// 512-bit keys (for testing only)
    Bits512 = 512,
    /// 1024-bit keys (for testing only)
    Bits1024 = 1024,
    /// 2048-bit keys (recommended minimum)
    Bits2048 = 2048,
    /// 4096-bit keys (high security)
    Bits4096 = 4096,
}

impl KeySize {
    /// Get the key size in bits.
    pub fn bits(&self) -> usize {
        *self as usize
    }

    /// Get the key size in bytes.
    pub fn bytes(&self) -> usize {
        self.bits() / 8
    }

    /// Check if this key size is secure for production use.
    pub fn is_secure(&self) -> bool {
        matches!(self, KeySize::Bits2048 | KeySize::Bits4096)
    }
}

/// RSA public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKey {
    /// The modulus n = p * q
    pub n: u64,
    /// The public exponent e
    pub e: u64,
}

impl RsaPublicKey {
    /// Create a new RSA public key.
    ///
    /// # Arguments
    /// * `n` - The modulus
    /// * `e` - The public exponent
    ///
    /// # Returns
    /// A new RSA public key
    ///
    /// # Errors
    /// Returns an error if the parameters are invalid
    pub fn new(n: u64, e: u64) -> CryptoResult<Self> {
        if n == 0 {
            return Err(CryptoError::InvalidFieldElement(
                "Modulus cannot be zero".to_string(),
            ));
        }

        if e == 0 {
            return Err(CryptoError::InvalidFieldElement(
                "Public exponent cannot be zero".to_string(),
            ));
        }

        if e >= n {
            return Err(CryptoError::InvalidFieldElement(
                "Public exponent must be less than modulus".to_string(),
            ));
        }

        Ok(Self { n, e })
    }

    /// Get the modulus.
    pub fn modulus(&self) -> u64 {
        self.n
    }

    /// Get the public exponent.
    pub fn exponent(&self) -> u64 {
        self.e
    }

    /// Get the key size in bits.
    pub fn key_size(&self) -> usize {
        (64 - self.n.leading_zeros()) as usize
    }

    /// Check if this public key is valid.
    pub fn is_valid(&self) -> bool {
        self.n > 0 && self.e > 0 && self.e < self.n
    }

    /// Encrypt a message using this public key.
    ///
    /// # Arguments
    /// * `message` - The message to encrypt (must be < n)
    ///
    /// # Returns
    /// The encrypted message
    ///
    /// # Errors
    /// Returns an error if the message is invalid or encryption fails
    pub fn encrypt(&self, message: u64) -> CryptoResult<u64> {
        if message >= self.n {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Message {} must be less than modulus {}",
                message, self.n
            )));
        }

        // RSA encryption: c = m^e mod n
        let result = mod_pow(message, self.e, self.n)?;
        Ok(result)
    }

    /// Verify a signature using this public key.
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
    pub fn verify(&self, signature: u64, message: u64) -> CryptoResult<bool> {
        if signature >= self.n {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Signature {} must be less than modulus {}",
                signature, self.n
            )));
        }

        // RSA verification: m = s^e mod n
        let decrypted = mod_pow(signature, self.e, self.n)?;
        Ok(decrypted == message)
    }
}

/// RSA private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPrivateKey {
    /// The modulus n = p * q
    pub n: u64,
    /// The private exponent d
    pub d: u64,
    /// The first prime factor p
    pub p: u64,
    /// The second prime factor q
    pub q: u64,
}

impl RsaPrivateKey {
    /// Create a new RSA private key.
    ///
    /// # Arguments
    /// * `n` - The modulus
    /// * `d` - The private exponent
    /// * `p` - The first prime factor
    /// * `q` - The second prime factor
    ///
    /// # Returns
    /// A new RSA private key
    ///
    /// # Errors
    /// Returns an error if the parameters are invalid
    pub fn new(n: u64, d: u64, p: u64, q: u64) -> CryptoResult<Self> {
        if n == 0 {
            return Err(CryptoError::InvalidFieldElement(
                "Modulus cannot be zero".to_string(),
            ));
        }

        if d == 0 {
            return Err(CryptoError::InvalidFieldElement(
                "Private exponent cannot be zero".to_string(),
            ));
        }

        if p == 0 || q == 0 {
            return Err(CryptoError::InvalidFieldElement(
                "Prime factors cannot be zero".to_string(),
            ));
        }

        if p * q != n {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Product of primes {} * {} = {} != {}",
                p,
                q,
                p * q,
                n
            )));
        }

        Ok(Self { n, d, p, q })
    }

    /// Get the modulus.
    pub fn modulus(&self) -> u64 {
        self.n
    }

    /// Get the private exponent.
    pub fn exponent(&self) -> u64 {
        self.d
    }

    /// Get the first prime factor.
    pub fn prime_p(&self) -> u64 {
        self.p
    }

    /// Get the second prime factor.
    pub fn prime_q(&self) -> u64 {
        self.q
    }

    /// Get the key size in bits.
    pub fn key_size(&self) -> usize {
        (64 - self.n.leading_zeros()) as usize
    }

    /// Check if this private key is valid.
    pub fn is_valid(&self) -> bool {
        self.n > 0 && self.d > 0 && self.p > 0 && self.q > 0 && self.p * self.q == self.n
    }

    /// Decrypt a message using this private key.
    ///
    /// # Arguments
    /// * `ciphertext` - The ciphertext to decrypt
    ///
    /// # Returns
    /// The decrypted message
    ///
    /// # Errors
    /// Returns an error if the ciphertext is invalid or decryption fails
    pub fn decrypt(&self, ciphertext: u64) -> CryptoResult<u64> {
        if ciphertext >= self.n {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Ciphertext {} must be less than modulus {}",
                ciphertext, self.n
            )));
        }

        // RSA decryption: m = c^d mod n
        let result = mod_pow(ciphertext, self.d, self.n)?;
        Ok(result)
    }

    /// Sign a message using this private key.
    ///
    /// # Arguments
    /// * `message` - The message to sign (must be < n)
    ///
    /// # Returns
    /// The signature
    ///
    /// # Errors
    /// Returns an error if the message is invalid or signing fails
    pub fn sign(&self, message: u64) -> CryptoResult<u64> {
        if message >= self.n {
            return Err(CryptoError::InvalidFieldElement(format!(
                "Message {} must be less than modulus {}",
                message, self.n
            )));
        }

        // RSA signing: s = m^d mod n
        let signature = mod_pow(message, self.d, self.n)?;
        Ok(signature)
    }
}

/// RSA key pair containing both public and private keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaKeyPair {
    /// The public key
    pub public: RsaPublicKey,
    /// The private key
    pub private: RsaPrivateKey,
}

impl RsaKeyPair {
    /// Create a new RSA key pair.
    ///
    /// # Arguments
    /// * `public` - The public key
    /// * `private` - The private key
    ///
    /// # Returns
    /// A new RSA key pair
    ///
    /// # Errors
    /// Returns an error if the keys are incompatible
    pub fn new(public: RsaPublicKey, private: RsaPrivateKey) -> CryptoResult<Self> {
        if public.n != private.n {
            return Err(CryptoError::InvalidFieldElement(
                "Public and private keys must have the same modulus".to_string(),
            ));
        }

        Ok(Self { public, private })
    }

    /// Generate a new RSA key pair.
    ///
    /// # Arguments
    /// * `key_size` - The desired key size
    ///
    /// # Returns
    /// A new RSA key pair
    ///
    /// # Errors
    /// Returns an error if key generation fails
    pub fn generate(key_size: KeySize) -> CryptoResult<Self> {
        // For simplicity, we'll use small primes for demonstration
        // In a real implementation, you would use proper prime generation
        let (p, q) = generate_primes(key_size)?;
        let n = p * q;
        let phi_n = (p - 1) * (q - 1);

        // Choose public exponent e (commonly 65537)
        let e = 65537;
        if e >= phi_n {
            return Err(CryptoError::InvalidFieldElement(
                "Public exponent too large for chosen primes".to_string(),
            ));
        }

        // Calculate private exponent d
        let d = mod_inverse(e, phi_n)?;

        let public = RsaPublicKey::new(n, e)?;
        let private = RsaPrivateKey::new(n, d, p, q)?;

        Self::new(public, private)
    }

    /// Get the public key.
    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public
    }

    /// Get the private key.
    pub fn private_key(&self) -> &RsaPrivateKey {
        &self.private
    }

    /// Get the key size in bits.
    pub fn key_size(&self) -> usize {
        self.public.key_size()
    }

    /// Check if this key pair is valid.
    pub fn is_valid(&self) -> bool {
        self.public.is_valid() && self.private.is_valid() && self.public.n == self.private.n
    }
}

/// Modular exponentiation: base^exponent mod modulus.
///
/// # Arguments
/// * `base` - The base
/// * `exponent` - The exponent
/// * `modulus` - The modulus
///
/// # Returns
/// The result of the modular exponentiation
///
/// # Errors
/// Returns an error if the computation fails
fn mod_pow(mut base: u64, mut exponent: u64, modulus: u64) -> CryptoResult<u64> {
    if modulus == 0 {
        return Err(CryptoError::InvalidFieldElement(
            "Modulus cannot be zero".to_string(),
        ));
    }

    if modulus == 1 {
        return Ok(0);
    }

    base %= modulus;
    let mut result = 1;

    while exponent > 0 {
        if exponent % 2 == 1 {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent /= 2;
    }

    Ok(result)
}

/// Calculate the modular multiplicative inverse.
///
/// # Arguments
/// * `a` - The number to find the inverse of
/// * `m` - The modulus
///
/// # Returns
/// The modular inverse of a mod m
///
/// # Errors
/// Returns an error if the inverse doesn't exist
fn mod_inverse(a: u64, m: u64) -> CryptoResult<u64> {
    let mut t = (0i64, 1i64);
    let mut r = (m as i64, a as i64);

    while r.1 != 0 {
        let q = r.0 / r.1;
        t = (t.1, t.0 - q * t.1);
        r = (r.1, r.0 - q * r.1);
    }

    if r.0 > 1 {
        return Err(CryptoError::InvalidFieldElement(format!(
            "Modular inverse does not exist for {} mod {}",
            a, m
        )));
    }

    if t.0 < 0 {
        t.0 += m as i64;
    }

    Ok(t.0 as u64)
}

/// Generate two prime numbers for RSA key generation.
///
/// This is a simplified implementation for demonstration purposes.
/// In a real implementation, you would use proper prime generation.
///
/// # Arguments
/// * `key_size` - The desired key size
///
/// # Returns
/// A pair of prime numbers (p, q)
///
/// # Errors
/// Returns an error if prime generation fails
fn generate_primes(key_size: KeySize) -> CryptoResult<(u64, u64)> {
    // For demonstration, we'll use small primes
    // In practice, you would generate large random primes
    match key_size {
        KeySize::Bits512 => Ok((61, 67)),
        KeySize::Bits1024 => Ok((127, 131)),
        KeySize::Bits2048 => Ok((251, 257)),
        KeySize::Bits4096 => Ok((509, 521)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_size() {
        assert_eq!(KeySize::Bits2048.bits(), 2048);
        assert_eq!(KeySize::Bits2048.bytes(), 256);
        assert!(KeySize::Bits2048.is_secure());
        assert!(!KeySize::Bits512.is_secure());
    }

    #[test]
    fn test_public_key_creation() {
        let public_key = RsaPublicKey::new(143, 7).unwrap();
        assert_eq!(public_key.modulus(), 143);
        assert_eq!(public_key.exponent(), 7);
        assert!(public_key.is_valid());
    }

    #[test]
    fn test_private_key_creation() {
        let private_key = RsaPrivateKey::new(143, 103, 11, 13).unwrap();
        assert_eq!(private_key.modulus(), 143);
        assert_eq!(private_key.exponent(), 103);
        assert_eq!(private_key.prime_p(), 11);
        assert_eq!(private_key.prime_q(), 13);
        assert!(private_key.is_valid());
    }

    #[test]
    fn test_key_pair_creation() {
        let public = RsaPublicKey::new(143, 7).unwrap();
        let private = RsaPrivateKey::new(143, 103, 11, 13).unwrap();
        let key_pair = RsaKeyPair::new(public, private).unwrap();

        assert!(key_pair.is_valid());
        assert_eq!(key_pair.key_size(), 8); // 143 = 10001111 in binary
    }

    #[test]
    fn test_key_pair_generation() {
        let key_pair = RsaKeyPair::generate(KeySize::Bits512).unwrap();
        assert!(key_pair.is_valid());
        assert!(key_pair.key_size() >= 512);
    }

    #[test]
    fn test_encryption_decryption() {
        let key_pair = RsaKeyPair::generate(KeySize::Bits512).unwrap();
        let message = 42;

        let ciphertext = key_pair.public_key().encrypt(message).unwrap();
        let decrypted = key_pair.private_key().decrypt(ciphertext).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_signing_verification() {
        let key_pair = RsaKeyPair::generate(KeySize::Bits512).unwrap();
        let message = 42;

        let signature = key_pair.private_key().sign(message).unwrap();
        let is_valid = key_pair.public_key().verify(signature, message).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_mod_pow() {
        let result = mod_pow(2, 10, 1000).unwrap();
        assert_eq!(result, 24); // 2^10 = 1024 ≡ 24 (mod 1000)
    }

    #[test]
    fn test_mod_inverse() {
        let inverse = mod_inverse(3, 11).unwrap();
        assert_eq!(inverse, 4); // 3 * 4 = 12 ≡ 1 (mod 11)
    }
}
