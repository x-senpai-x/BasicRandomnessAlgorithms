//! RSA encryption and signature implementation.
//!
//! This crate provides an implementation of the RSA cryptosystem,
//! including key generation, encryption, decryption, and digital signatures.

pub mod key;
pub mod encryption;
pub mod signature;
pub mod ring;

pub use key::{RsaKeyPair, RsaPublicKey, RsaPrivateKey, KeySize};
pub use encryption::{RsaEncryption, EncryptionResult};
pub use signature::{RsaSignature, SignatureResult};
pub use ring::{Ring, generate_composite_modulus, generate_prime_of_bitsize};

/// Re-export commonly used types
pub mod prelude {
    pub use super::key::{RsaKeyPair, RsaPublicKey, RsaPrivateKey, KeySize};
    pub use super::encryption::{RsaEncryption, EncryptionResult};
    pub use super::signature::{RsaSignature, SignatureResult};
    pub use super::ring::{Ring, generate_composite_modulus, generate_prime_of_bitsize};
} 