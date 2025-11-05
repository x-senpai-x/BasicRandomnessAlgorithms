//! Pedersen commitment scheme implementation.
//!
//! This module provides a cryptographically secure commitment scheme based on
//! the discrete logarithm problem. Pedersen commitments are:
//! - Perfectly hiding: The commitment reveals nothing about the committed value
//! - Computationally binding: It's infeasible to find two different openings
//! - Homomorphic: Commitments can be combined algebraically
//!
//! The scheme also supports zero-knowledge proofs of knowledge (ZKPoK) of the
//! committed value using Sigma protocols.
//!
//! # Security Warning
//! This implementation uses small primes (configurable bit length) and is intended
//! for educational purposes and testing only. For production use, primes of at least
//! 2048 bits are recommended for adequate security.

use crate::utils::find_generator;
use crypto_core::{generate_random_prime, CryptoResult};
use crypto_field::FiniteField;
use rand::Rng;

/// Represents a Pedersen commitment scheme instance.
///
/// A Pedersen commitment to a message m with randomness z is computed as:
/// C = g^m * h^z (mod p)
///
/// where g and h are generators of a multiplicative group of prime order.
/// The scheme supports interactive zero-knowledge proofs of knowledge.
///
/// # Two Domains
/// - **Group elements** (g, h, C, A): Live in Z_p^*, use modulus p
/// - **Scalars/exponents** (m, z, d, r, e, m1, z1): Live in Z_q, use modulus q = p-1
pub struct PedersonCommitment {
    /// First generator of the multiplicative group (mod p)
    pub g: FiniteField,
    /// Second generator (h = g^x for some secret x) (mod p)
    pub h: FiniteField,
    /// The prime modulus p defining Z_p^*
    pub prime: u64,
    /// Order of the multiplicative group q = p - 1
    pub group_order: u64,
    /// The message being committed (private, scalar mod q)
    m: Option<FiniteField>,
    /// The randomness/blinding factor used in commitment (private, scalar mod q)
    z: Option<FiniteField>,
    /// The commitment value C = g^m * h^z (group element mod p)
    pub commitment: Option<FiniteField>,
    /// Challenge value in the Sigma protocol (scalar mod q)
    pub e: Option<FiniteField>,
    /// Randomness for the proof of knowledge (private, scalar mod q)
    d: Option<FiniteField>,
    /// Blinding factor for the proof of knowledge (private, scalar mod q)
    r: Option<FiniteField>,
    /// Initial commitment in the Sigma protocol A = g^d * h^r (group element mod p)
    pub a: Option<FiniteField>,
    /// First response in the Sigma protocol m1 = m*e + d (scalar mod q)
    pub m1: Option<FiniteField>,
    /// Second response in the Sigma protocol z1 = z*e + r (scalar mod q)
    pub z1: Option<FiniteField>,
}
impl PedersonCommitment {
    /// Generate a new Pedersen commitment scheme instance with random parameters.
    ///
    /// This function:
    /// 1. Generates a random prime p of specified bit length
    /// 2. Finds a generator g of the multiplicative group Z_p^*
    /// 3. Computes h = g^x (mod p) for a random secret x ∈ Z_q
    ///
    /// # Arguments
    /// * `bit_length` - Size of the prime in bits (e.g., 20 for testing, 2048+ for production)
    ///
    /// # Returns
    /// A new `PedersonCommitment` instance with randomly generated public parameters
    ///
    /// # Security
    /// - Uses cryptographically secure RNG (OsRng)
    /// - The discrete log relationship between g and h (i.e., x such that h = g^x)
    ///   must remain secret for the commitment to be binding
    /// - Small bit lengths (<2048) are insecure for real-world use
    pub fn keygen(bit_length: usize) -> CryptoResult<PedersonCommitment> {
        let prime = generate_random_prime(bit_length)?;
        let group_order = prime - 1;

        // Find generator g of Z_p^*
        let g_val = find_generator(prime)?;
        let g = FiniteField::new(g_val, prime)?;

        // Generate random x ∈ Z_q and compute h = g^x (mod p)
        let x = rand::rng().random_range(1..group_order);
        let h = g.pow(x)?;

        Ok(PedersonCommitment {
            g,
            h,
            prime,
            group_order,
            m: None,
            z: None,
            commitment: None,
            e: None,
            d: None,
            r: None,
            a: None,
            m1: None,
            z1: None,
        })
    }
    /// Create a commitment to a message.
    ///
    /// Computes C = g^m * h^z (mod p) where z is a random blinding factor in Z_q.
    /// The commitment is perfectly hiding (reveals no information about m)
    /// and computationally binding (can't find m' ≠ m with same commitment).
    ///
    /// # Arguments
    /// * `m` - The message (scalar mod q) to commit to
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if the computation fails
    ///
    /// # Side Effects
    /// Stores the commitment C (group element mod p), message m, and blinding factor z (both scalars mod q)
    pub fn commit_message(&mut self, m: FiniteField) -> CryptoResult<()> {
        // Generate random blinding factor z ∈ Z_q
        let z_val = rand::rng().random_range(1..self.group_order);
        let z = FiniteField::new(z_val, self.group_order)?;

        // Compute C = g^m * h^z (mod p) - both are group elements
        let commitment = (self.g.pow(m.value())? * self.h.pow(z.value())?)?;

        self.m = Some(m);
        self.z = Some(z);
        self.commitment = Some(commitment);

        Ok(())
    }
    /// Verify that a commitment opens to a given message with given randomness.
    ///
    /// Checks if C = g^m * h^z (mod p) by recomputing the commitment and comparing.
    ///
    /// # Arguments
    /// * `m` - The claimed message (scalar mod q)
    /// * `z` - The claimed blinding factor (scalar mod q)
    ///
    /// # Returns
    /// `Ok(true)` if the commitment correctly opens to (m, z),
    /// `Ok(false)` if it doesn't match,
    /// `Err` if no commitment exists or computation fails
    pub fn verify(&self, m: FiniteField, z: FiniteField) -> CryptoResult<bool> {
        let commitment = self.commitment.ok_or_else(|| {
            crypto_core::CryptoError::NotFound("No commitment to verify".to_string())
        })?;

        let recomputed = (self.g.pow(m.value())? * self.h.pow(z.value())?)?;
        Ok(commitment == recomputed)
    }
    /// First step of the Sigma protocol: Prover commits to random values.
    ///
    /// In a zero-knowledge proof of knowledge, the prover first commits to
    /// random values d and r by computing A = g^d * h^r (mod p). This ensures
    /// the proof doesn't leak information about the secret m.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if the computation fails
    ///
    /// # Side Effects
    /// Stores the commitment A (group element mod p) and the random values d, r (scalars mod q) internally
    pub fn commit_a(&mut self) -> CryptoResult<()> {
        // Generate random scalars d, r ∈ Z_q
        let mut rng = rand::rng();
        let d_val = rng.random_range(1..self.group_order);
        let r_val = rng.random_range(1..self.group_order);

        let d = FiniteField::new(d_val, self.group_order)?;
        let r = FiniteField::new(r_val, self.group_order)?;

        // Compute A = g^d * h^r (mod p) - group element
        let a = self.commit_values(d, r)?;

        self.d = Some(d);
        self.r = Some(r);
        self.a = Some(a);

        Ok(())
    }
    /// Second and third steps of the Sigma protocol: Challenge and response.
    ///
    /// After receiving a random challenge e from the verifier, the prover
    /// computes responses (all arithmetic mod q):
    /// - m1 = m*e + d (mod q)
    /// - z1 = z*e + r (mod q)
    ///
    /// These responses allow the verifier to check the proof without learning
    /// the secret values m and z.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if any stored values are missing or computation fails
    ///
    /// # Side Effects
    /// Generates challenge e and computes responses m1, z1 (all scalars mod q), storing them internally
    pub fn challenge_and_respond(&mut self) -> CryptoResult<()> {
        // Generate random challenge e ∈ Z_q
        let e_val = rand::rng().random_range(1..self.group_order);
        let e = FiniteField::new(e_val, self.group_order)?;

        // Retrieve stored values
        let m = self
            .m
            .ok_or_else(|| crypto_core::CryptoError::NotFound("Message m not set".to_string()))?;
        let z = self.z.ok_or_else(|| {
            crypto_core::CryptoError::NotFound("Randomness z not set".to_string())
        })?;
        let d = self.d.ok_or_else(|| {
            crypto_core::CryptoError::NotFound("Random value d not set".to_string())
        })?;
        let r = self.r.ok_or_else(|| {
            crypto_core::CryptoError::NotFound("Random value r not set".to_string())
        })?;

        // Compute responses: m1 = m*e + d (mod q), z1 = z*e + r (mod q)
        let m1 = ((m * e)? + d)?;
        let z1 = ((z * e)? + r)?;

        self.e = Some(e);
        self.m1 = Some(m1);
        self.z1 = Some(z1);

        Ok(())
    }
    /// Verify the zero-knowledge proof of knowledge.
    ///
    /// Checks the Sigma protocol verification equation (all group operations mod p):
    /// g^m1 * h^z1 = C^e * A (mod p)
    ///
    /// If this holds, the verifier is convinced the prover knows the opening
    /// (m, z) of commitment C, without learning anything about m or z.
    ///
    /// # Returns
    /// `Ok(true)` if the proof is valid,
    /// `Ok(false)` if the proof is invalid,
    /// `Err` if required values are missing or computation fails
    pub fn verify_zk_pok(&self) -> CryptoResult<bool> {
        // Retrieve all required values
        let m1 = self
            .m1
            .ok_or_else(|| crypto_core::CryptoError::NotFound("Response m1 not set".to_string()))?;
        let z1 = self
            .z1
            .ok_or_else(|| crypto_core::CryptoError::NotFound("Response z1 not set".to_string()))?;
        let e = self
            .e
            .ok_or_else(|| crypto_core::CryptoError::NotFound("Challenge e not set".to_string()))?;
        let commitment = self
            .commitment
            .ok_or_else(|| crypto_core::CryptoError::NotFound("Commitment not set".to_string()))?;
        let a = self.a.ok_or_else(|| {
            crypto_core::CryptoError::NotFound("Initial commitment A not set".to_string())
        })?;

        // Compute left side: g^m1 * h^z1 (mod p)
        let left = (self.g.pow(m1.value())? * self.h.pow(z1.value())?)?;

        // Compute right side: C^e * A (mod p)
        let right = (commitment.pow(e.value())? * a)?;

        Ok(left == right)
    }
    /// Helper function to compute a commitment for arbitrary values.
    ///
    /// Computes C = g^m * h^z (mod p) for given scalars m and z.
    /// Used internally by other commitment operations (e.g., computing A in Sigma protocol).
    ///
    /// # Arguments
    /// * `m` - The message/scalar (mod q) to commit to
    /// * `z` - The randomness/blinding factor (mod q)
    ///
    /// # Returns
    /// The commitment value g^m * h^z (mod p) as a group element
    pub fn commit_values(&self, m: FiniteField, z: FiniteField) -> CryptoResult<FiniteField> {
        // Both g and h are group elements (mod p)
        // m and z are scalars (mod q)
        // Result is a group element (mod p)
        (self.g.pow(m.value())? * self.h.pow(z.value())?).and_then(|x| Ok(x))
    }
}
